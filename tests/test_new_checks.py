"""Checks added for 0.1.0: pacman signing, shares, Flatpak, IPv6, exposed databases and friends."""
from pacwardx.checks import hardening, network, opsec, secrets


def _titles(findings):
    return {f.title: f.severity for f in findings}


def test_pacman_signature_and_mirrors(tmp_path):
    mirrors = tmp_path / "mirrorlist"
    mirrors.write_text("#Server = http://commented.example/$repo\nServer = http://plain.example/$repo/os/$arch\n"
                       "Server = https://good.example/$repo/os/$arch\n")
    good = f"[options]\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n[core]\nInclude = {mirrors}\n"
    found = _titles(hardening.pacman_findings(good))
    assert found == {"1 package mirror uses plain HTTP": "low"}
    bad = "[options]\nSigLevel = Never\n[extra]\nSigLevel = Optional TrustAll\nServer = https://x.example\n"
    found = _titles(hardening.pacman_findings(bad))
    assert found["Package signature checking is turned off"] == "high"
    ok = "[options]\nSigLevel = Required DatabaseOptional\n[core]\nServer = https://x.example\n"
    assert _titles(hardening.pacman_findings(ok)) == {"Packages are signature-checked and mirrors use HTTPS": "ok"}


def test_samba_guest_shares():
    conf = "[global]\nworkgroup = WG\n[music]\npath=/srv/m\nguest ok = yes\n[private]\npath=/srv/p\n"
    assert _titles(network.samba_findings(conf)) == {"Samba shares 1 folder without a password": "medium"}
    conf += "[drop]\npath=/srv/d\npublic = yes\nread only = no\n"
    assert _titles(network.samba_findings(conf)) == {"Samba lets anyone write to 1 shared folder": "high"}
    assert network.samba_findings("[global]\n[a]\npath=/x\n")[0].severity == "info"


def test_nfs_exports():
    assert network.nfs_findings("# nothing\n") == []
    assert network.nfs_findings("/srv 192.168.1.5(ro,sync)\n")[0].severity == "info"
    f = network.nfs_findings("/srv *(rw,sync)\n/data 10.0.0.2(rw,no_root_squash)\n")[0]
    assert f.severity == "medium" and "2 NFS exports" in f.title


def test_flatpak_overrides():
    meta = "[Application]\nname=x\n[Context]\nfilesystems=home;host-etc:ro;xdg-download;\n"
    assert opsec.flatpak_access(meta, []) == {"home"}
    assert opsec.flatpak_access(meta, ["[Context]\nfilesystems=!home;\n"]) == set()
    assert opsec.flatpak_access("[Context]\nfilesystems=xdg-music:ro\n", ["[Context]\nfilesystems=host\n"]) == {"host"}


def test_ufw_ipv6_gap():
    v6 = "2: wlan0    inet6 2a01:4f8:1c1c::5/64 scope global dynamic"
    ula = "2: wlan0    inet6 fd12:3456::5/64 scope global\n5: tailscale0    inet6 fd7a:115c:a1e0::1/128 scope global"
    assert network._ufw_ipv6('IPV6=no\n', ula) == []
    assert network._ufw_ipv6('IPV6=no\n', v6)[0].severity == "medium"
    assert network._ufw_ipv6('IPV6=yes\n', v6) == []
    assert network._ufw_ipv6('IPV6=no\n', "") == []


def test_exposed_database_ports(monkeypatch):
    ss = ('tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=700,fd=6))\n'
          'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=701,fd=6))\n'
          'tcp LISTEN 0 128 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=702,fd=6))')
    monkeypatch.setattr(network, "priv", lambda *a, **k: {"text": ss})
    found = _titles(network._listeners({}, {"active": False}))
    assert found["Redis (port 6379) is reachable from the network"] == "high"
    assert found["Docker API without TLS (port 2375) is reachable from the network"] == "high"
    assert not any("PostgreSQL" in t for t in found)          # loopback only
    assert "redis-server is reachable from the network" not in found  # not reported twice
    blocked = _titles(network._listeners({}, {"active": True, "default_in": "deny", "rules": []}))
    assert not any("Redis" in t for t in blocked)


def test_ssh_without_bruteforce_protection(monkeypatch):
    ss = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))'
    monkeypatch.setattr(network, "priv", lambda name, **k: {"text": ss if name == "sockets" else
                                                             "passwordauthentication yes\n"})
    monkeypatch.setattr(network, "unit_active", lambda u: False)
    found = _titles(network._listeners({}, {"active": False}))
    assert found["Nothing slows down SSH login guessing"] == "low"
    monkeypatch.setattr(network, "unit_active", lambda u: u == "sshguard")
    assert "Nothing slows down SSH login guessing" not in _titles(network._listeners({}, {"active": False}))


def test_git_credential_store(monkeypatch, tmp_path):
    monkeypatch.setattr(secrets, "HOME", tmp_path)
    monkeypatch.setattr(secrets, "have", lambda b: True)
    monkeypatch.setattr(secrets, "sh", lambda *a, **k: "store\n")
    assert secrets.git_credentials({})[0].severity == "medium"
    monkeypatch.setattr(secrets, "sh", lambda *a, **k: "")
    assert secrets.git_credentials({}) == []
    (tmp_path / ".git-credentials").write_text("x")
    assert secrets.git_credentials({})[0].severity == "low"


def test_time_sync(monkeypatch):
    monkeypatch.setattr(hardening, "unit_active", lambda u: False)  # CI machines run chrony
    monkeypatch.setattr(hardening, "sh", lambda *a, **k: "NTP=no\nNTPSynchronized=no\n")
    assert _titles(hardening._time_sync()) == {"Automatic time sync is off": "low"}
    monkeypatch.setattr(hardening, "sh", lambda *a, **k: "NTP=yes\nNTPSynchronized=yes\n")
    assert hardening._time_sync()[0].severity == "ok"


def test_sshd_empty_passwords(monkeypatch):
    monkeypatch.setattr(hardening, "have", lambda b: True)
    monkeypatch.setattr(hardening, "unit_active", lambda u: True)
    monkeypatch.setattr(hardening, "sh", lambda *a, **k: "enabled")
    monkeypatch.setattr(hardening, "priv", lambda *a, **k: {"text": "passwordauthentication no\npermitemptypasswords yes\n"})
    assert _titles(hardening._sshd())["SSH allows accounts with empty passwords"] == "high"


def test_nmcli_split_keeps_escaped_colons():
    assert opsec._nm_split(r"Cafe\:Free:802-11-wireless:yes") == ["Cafe:Free", "802-11-wireless", "yes"]


# --- regressions from the pre-release review -------------------------------------------------


def test_docker_published_to_loopback_is_local(monkeypatch):
    ss = 'tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("docker-proxy",pid=900,fd=4))'
    monkeypatch.setattr(network, "priv", lambda *a, **k: {"text": ss})
    assert not any("PostgreSQL" in t for t in _titles(network._listeners({}, {"active": True, "default_in": "deny",
                                                                                 "rules": []})))


def test_ufw_limit_counts_as_brute_force_protection(monkeypatch):
    ss = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))'
    monkeypatch.setattr(network, "priv", lambda *a, **k: {"text": ss})
    monkeypatch.setattr(network, "unit_active", lambda u: False)
    ufw = {"active": True, "default_in": "deny",
           "rules": [{"dir": "IN", "action": "LIMIT", "to": "22/tcp", "from": "Anywhere"}]}
    assert "Nothing slows down SSH login guessing" not in _titles(network._listeners({}, ufw))


def test_pacman_reads_sections_inside_included_files(tmp_path):
    extra = tmp_path / "extra.conf"
    extra.write_text("[sketchy]\nSigLevel = Never\nServer = https://x.example/$repo\n")
    local = tmp_path / "local.conf"
    local.write_text("[mine]\nSigLevel = Optional TrustAll\nServer = file:///srv/repo\n")
    conf = f"[options]\nSigLevel = Required DatabaseOptional\nInclude = {tmp_path}/*.conf\n"
    found = _titles(hardening.pacman_findings(conf))
    assert found["Package signature checking is turned off"] == "high"
    assert found["A local package repository isn't signature-checked"] == "low"
    f = next(x for x in hardening.pacman_findings(conf) if x.severity == "high")
    assert "sketchy" in f.detail and "mine" not in f.detail


def test_samba_global_guest_and_bare_options():
    conf = "[global]\nguest ok = yes\nsome bare option\n[public]\npath = /srv\nread only = no\n"
    assert _titles(network.samba_findings(conf)) == {"Samba lets anyone write to 1 shared folder": "high"}


def test_nfs_matches_whole_options_only():
    assert network.nfs_findings("/srv/insecure-stuff 192.168.1.0/24(rw,insecure_locks)\n")[0].severity == "info"
    assert network.nfs_findings("/srv *.lan(ro)\n")[0].severity == "info"
    assert network.nfs_findings("/srv (rw)\n")[0].severity == "medium"


def test_flatpak_read_only_override_downgrades():
    meta = "[Context]\nfilesystems=home;\n"
    assert opsec.flatpak_access(meta, ["[Context]\nfilesystems=home:ro;\n"]) == set()


def test_nmcli_split_handles_escaped_backslash():
    assert opsec._nm_split(r"back\\:x:802-11-wireless:no") == ["back\\", "x", "802-11-wireless", "no"]


def test_time_sync_by_other_daemon(monkeypatch):
    monkeypatch.setattr(hardening, "sh", lambda *a, **k: "NTP=no\nNTPSynchronized=no\n")
    monkeypatch.setattr(hardening, "unit_active", lambda u: u == "chronyd")
    assert hardening._time_sync()[0].severity == "ok"


def test_own_helper_sudo_refusals_are_not_counted():
    from pacwardx.checks import auth
    lines = ["t host sudo[9]:  me : a password is required ; PWD=/ ; USER=root ; "
             "COMMAND=/usr/lib/pacwardx/pacwardx-priv ping"] * 8
    lines += ["t host sudo[9]:  me : user NOT in sudoers ; PWD=/ ; USER=root ; "
              "COMMAND=/usr/lib/pacwardx/pacwardx-priv sockets"] * 8
    assert auth.analyse(lines)["sudo_fail"] == 0
