import base64
import struct

from pacwardx.checks import auth, changes, integrity, network, opsec, secrets, services


# --- logins ---------------------------------------------------------------------------
def test_ip_kind():
    assert auth.ip_kind("100.101.102.103") == "tailscale"
    assert auth.ip_kind("192.168.1.20") == "lan"
    assert auth.ip_kind("127.0.0.1") == "local"
    assert auth.ip_kind("8.8.8.8") == "public"
    assert auth.ip_kind("not-an-ip") == "unknown"


JOURNAL = [
    "2026-10-01T10:00:00+0000 host sshd-session[100]: Failed password for root from 45.155.205.10 port 4242 ssh2",
    "2026-10-01T10:00:01+0000 host sshd-session[101]: Invalid user admin from 45.155.205.10 port 4243",
    "2026-10-01T10:05:00+0000 host sshd-session[102]: Accepted publickey for me from 192.168.1.20 port 5000 ssh2",
    "2026-10-01T10:06:00+0000 host sudo[103]:       me : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/usr/bin/ls",
    "2026-10-01T10:07:00+0000 host sudo[104]:       me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/pacman -Syu",
    "2026-10-01T10:08:00+0000 host sudo[105]:       me : PWD=/ ; USER=root ; COMMAND=/usr/local/lib/pacwardx/pacwardx-priv sockets",
]


def test_login_analysis():
    a = auth.analyse(JOURNAL)
    assert a["ssh_fail"]["45.155.205.10"] == 2
    assert a["ssh_ok"][0]["user"] == "me" and a["ssh_ok"][0]["ip"] == "192.168.1.20"
    assert a["sudo_fail"] == 3
    assert list(a["sudo_cmds"]) == ["/usr/bin/pacman -Syu"]  # PacWardX's own helper calls are left out
    titles = {f.title: f.severity for f in auth.findings_from(a)}
    assert titles["2 failed SSH login attempts in 24 h"] == "medium"  # public source
    assert titles["1 successful SSH login in 24 h"] == "info"          # from the LAN


def test_quiet_sudo_setting():
    a = auth.analyse(JOURNAL, quiet=("pacman",))
    assert not a["sudo_cmds"]


# --- network --------------------------------------------------------------------------
SS = """tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=41822,fd=3))
tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=900,fd=7))
udp UNCONN 0 0 [::]:5353 [::]:* users:(("avahi-daemon",pid=700,fd=12))"""


def test_parse_ss():
    rows = network._parse_ss(SS)
    assert [(r["proto"], r["host"], r["port"], r["proc"], r["pid"]) for r in rows] == [
        ("tcp", "0.0.0.0", "8080", "python3", 41822),
        ("tcp", "127.0.0.1", "631", "cupsd", 900),
        ("udp", "[::]", "5353", "avahi-daemon", 700),
    ]
    assert network._is_wildcard("0.0.0.0") and network._is_loopback("127.0.0.1")


def test_firewall_judgement():
    rule = lambda to, frm="Anywhere": {"dir": "IN", "action": "ALLOW", "to": to, "from": frm}  # noqa: E731
    ufw = {"active": True, "default_in": "deny",
           "rules": [rule("25565/tcp"), rule("1714:1764/udp (KDE Connect)"), rule("22/tcp", "100.64.0.0/10")]}
    assert network._fw_state("25565", "tcp", ufw) == "allowed"
    assert network._fw_state("1720", "udp", ufw) == "allowed"
    assert network._fw_state("1720", "tcp", ufw) == "blocked"
    assert network._fw_state("22", "tcp", ufw) == "restricted"
    assert network._fw_state("8080", "tcp", ufw) == "blocked"
    assert network._fw_state("8080", "tcp", {"active": False}) == "open"
    assert network._fw_state("8080", "tcp", {"active": True, "default_in": "allow", "rules": []}) == "open"


# --- privacy --------------------------------------------------------------------------
def _openssh_key(cipher: bytes) -> str:
    blob = b"openssh-key-v1\x00" + struct.pack(">I", len(cipher)) + cipher + b"\x00" * 16
    body = base64.b64encode(blob).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


def test_private_key_passphrase_detection():
    assert opsec.private_key_encrypted(_openssh_key(b"none")) is False
    assert opsec.private_key_encrypted(_openssh_key(b"aes256-ctr")) is True
    assert opsec.private_key_encrypted("-----BEGIN RSA PRIVATE KEY-----\nabc\n") is False
    assert opsec.private_key_encrypted("Proc-Type: 4,ENCRYPTED\n") is True
    assert opsec.private_key_encrypted("ssh-ed25519 AAAA me@host") is None


def test_disk_encryption():
    plain = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "children": [
        {"name": "nvme0n1p1", "type": "part", "mountpoints": ["/boot"]},
        {"name": "nvme0n1p2", "type": "part", "mountpoints": ["/"]}]}]}
    luks = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "children": [
        {"name": "nvme0n1p2", "type": "part", "children": [
            {"name": "root", "type": "crypt", "mountpoints": ["/"]}]}]}]}
    assert opsec.disk_findings(plain)[0].severity == "medium"
    assert opsec.disk_findings(luks)[0].severity == "ok"


RESOLVED_PLAIN = """Global
       Protocols: LLMNR=no -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 2 (enp5s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute LLMNR=no -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 192.168.1.1
"""
RESOLVED_DOT = RESOLVED_PLAIN.replace("-DNSOverTLS", "+DNSOverTLS")


def test_dns_encryption():
    assert opsec.dns_findings(RESOLVED_PLAIN)[0].severity == "low"
    assert opsec.dns_findings(RESOLVED_DOT)[0].severity == "ok"
    assert opsec.dns_findings(RESOLVED_PLAIN, vpn_on=True)[0].severity == "ok"


# --- secrets --------------------------------------------------------------------------
def test_history_scan_reports_line_numbers_not_values():
    token = "ghp_" + "a1B2" * 9
    lines = ["ls -la", f"export GH={token}", "curl -H 'Authorization: Bearer $TOKEN' x", "mysql --password=hunter22"]
    hits = secrets.scan_history_text(lines)
    assert hits["GitHub token"] == [2]
    assert hits["Password flag"] == [4]
    assert "Bearer token" not in hits            # a $VARIABLE isn't a leaked value
    assert token not in repr(hits)


def test_secret_file_names():
    assert secrets._is_secret_name(".env") and secrets._is_secret_name("server.key")
    assert not secrets._is_secret_name(".env.example") and not secrets._is_secret_name("id_ed25519.pub")


# --- system files ---------------------------------------------------------------------
def test_tampered_binaries_are_high_and_get_a_fix():
    found = integrity.classify([
        {"pkg": "sudo", "path": "/usr/bin/sudo", "reason": "SHA256 checksum mismatch"},
        {"pkg": "hicolor", "path": "/usr/share/icons/x.png", "reason": "Size mismatch"},
        {"pkg": "man", "path": "/usr/share/man/a.1.gz", "reason": "No such file or directory"},
    ])
    by = {f.severity: f for f in found}
    assert "sudo" in by["high"].fix and "/usr/bin/sudo" in by["high"].detail
    assert by["low"].title == "1 packaged data files were modified"
    assert by["info"].title == "1 packaged files are missing"


def test_clean_integrity_is_ok():
    assert integrity.classify([])[0].severity == "ok"


# --- change tracking ------------------------------------------------------------------
def test_baseline_diff():
    base = {"users": {"alice": "1000"}, "ports": {"22/tcp": "sshd"}}
    cur = {"users": {"alice": "1000", "mallory": "1001"}, "ports": {"22/tcp": "dropbear"}, "new_group": {}}
    assert changes.diff(base, cur) == {
        "users": {"added": ["mallory"], "removed": [], "changed": []},
        "ports": {"added": [], "removed": [], "changed": ["22/tcp"]},
    }


def test_authorized_key_fingerprints(tmp_path):
    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"\x01" * 36).decode()
    f = tmp_path / "authorized_keys"
    f.write_text(f'# comment\nfrom="10.0.0.1" ssh-ed25519 {blob} laptop\nnot a key\n')
    keys = changes.authorized_key_fingerprints(f)
    (fp, label), = keys.items()
    assert fp.startswith("SHA256:") and label.startswith("laptop") and "from=" in label


# --- game servers ---------------------------------------------------------------------
def test_minecraft_settings():
    risky = services.evaluate_minecraft("/srv/mc/survival", services.parse_properties(
        "online-mode=false\nwhite-list=false\nenable-rcon=true\nrcon.password=abc\n"), {"jar_age_days": 400})
    sev = {f.title: f.severity for f in risky}
    assert sev["Minecraft (survival): online-mode is off"] == "high"
    assert sev["Minecraft (survival): RCON listens on all interfaces"] == "high"
    assert sev["Minecraft (survival): whitelist is off"] == "medium"
    assert sev["Minecraft (survival): server jar is 400 days old"] == "low"
    safe = services.evaluate_minecraft("/srv/mc/creative", {"white-list": "true"}, {"ops": ["me"], "whitelist": 3})
    assert [f.severity for f in safe] == ["ok"]
