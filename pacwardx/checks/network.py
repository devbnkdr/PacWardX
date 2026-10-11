"""Network exposure: listeners, firewall, Docker-published ports, tunnels, outbound."""
from __future__ import annotations

import configparser
import glob
import ipaddress
import re
import shlex
from collections import Counter
from pathlib import Path

from .. import config
from ..findings import Finding
from .common import have, priv, sh, tunnel_routes, unit_active

CAT = "network"

# Process -> why it's expected to listen on all interfaces.
BENIGN = {
    "avahi-daemon": "mDNS service discovery",
    "systemd-resolve": "systemd-resolved (mDNS/LLMNR)",
    "tailscaled": "Tailscale VPN",
    "kdeconnectd": "KDE Connect (phone integration)",
    "dnsmasq": "libvirt NAT for VMs",
    "cloudflared": "Cloudflare tunnel (outbound QUIC sockets)",
    "NetworkManager": "DHCP client",
    "wpa_supplicant": "Wi-Fi",
    "cupsd": "printing",
}
# Services that should almost never be reachable from other machines: most have no login by default, or
# hand out full control of the computer (the Docker API).
RISKY_PORTS = {
    "2375": "Docker API without TLS", "2376": "Docker API", "6379": "Redis", "27017": "MongoDB",
    "9200": "Elasticsearch", "11211": "Memcached", "5432": "PostgreSQL", "3306": "MySQL/MariaDB",
    "8888": "Jupyter", "5984": "CouchDB", "5900": "VNC remote desktop", "3389": "Remote Desktop (RDP)",
}
SSH_LIMIT_FIX = ("sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp   (use your own network range, "
                 "or 100.64.0.0/10 for Tailscale)")
COMMON_REMOTE_PORTS = {80, 443, 8443, 993, 995, 465, 587, 22, 53, 853, 123, 5228, 5223, 3478, 25565}

_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


NETIDS = {"tcp", "udp", "raw", "sctp", "dccp", "u_str", "u_dgr", "u_seq", "nl", "p_raw", "p_dgr", "v_str", "v_dgr", "tipc", "xdp"}


def _parse_ss(text: str) -> list[dict]:
    """Parse `ss -H` output. Works whether or not the Netid and State columns are present
    (ss drops Netid when a single protocol is requested, and State when a state filter is used)."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        i = 0
        proto = "?"
        if parts[i] in NETIDS:
            proto = parts[i]; i += 1
        state = "?"
        if i < len(parts) and parts[i].isupper() and not parts[i].isdigit():
            state = parts[i]; i += 1
        # next two are Recv-Q Send-Q, then Local, then Peer
        if len(parts) < i + 4:
            continue
        local = parts[i + 2]
        host, _, port = local.rpartition(":")
        host = host.split("%")[0]
        m = _PROC_RE.search(line)
        rows.append({
            "proto": proto, "state": state, "host": host, "port": port,
            "proc": m.group(1) if m else "?", "pid": int(m.group(2)) if m else 0,
            "raw": line.strip(),
        })
    return rows


def _is_wildcard(host: str) -> bool:
    return host in ("0.0.0.0", "*", "[::]", "::")


def _is_private_lan(host: str) -> bool:
    """A LAN-style address other devices could reach (not loopback, not the Tailscale range)."""
    try:
        a = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and a not in ipaddress.ip_network("100.64.0.0/10")


def _is_loopback(host: str) -> bool:
    return host.startswith("127.") or host in ("[::1]", "::1", "localhost")


def _ufw() -> tuple[list[Finding], dict]:
    """Returns findings plus a small summary used by the listener check."""
    data = priv("ufw")
    info = {"active": None, "rules": [], "default_in": None}
    if data is None or not data.get("text"):
        if not have("ufw"):
            return [Finding(CAT, "medium", "No ufw firewall installed",
                            "Nothing filters inbound connections except each service's own bind address.",
                            fix="sudo pacman -S ufw && sudo ufw enable")], info
        return [Finding(CAT, "info", "Firewall state unknown",
                        "Reading ufw needs the root helper.", fix=config.helper_setup())], info
    text = data["text"]
    findings = []
    if "Status: active" not in text:
        info["active"] = False
        return [Finding(CAT, "high", "Firewall (ufw) is inactive",
                        "Every listening service is reachable from the network.", fix="sudo ufw enable")], info
    info["active"] = True
    m = re.search(r"Default:\s*(\w+)\s*\(incoming\)", text)
    if m:
        info["default_in"] = m.group(1)
        if m.group(1) == "allow":
            findings.append(Finding(CAT, "high", "Firewall default is ALLOW incoming",
                                    "Only explicitly denied ports are blocked.",
                                    fix="sudo ufw default deny incoming"))
    for line in text.splitlines():
        mm = re.match(r"^(\S.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+?)\s*$", line)
        if mm:
            info["rules"].append({"to": mm.group(1).strip(), "action": mm.group(2),
                                  "dir": mm.group(3), "from": mm.group(4).strip()})
    open_rules = [r for r in info["rules"] if r["dir"] == "IN" and r["action"] in ("ALLOW", "LIMIT")
                  and r["from"].startswith("Anywhere") and " on " not in r["to"]]
    if open_rules:
        findings.append(Finding(CAT, "info", f"{len(open_rules)} firewall rule{'s' if len(open_rules) != 1 else ''} open to everyone",
                                "\n".join(f"{r['to']:30} {r['action']} from {r['from']}" for r in open_rules)))
    findings.extend(_ufw_ipv6())
    if not findings:
        findings.append(Finding(CAT, "ok", "Firewall active, default deny incoming"))
    return findings, info


def _ufw_ipv6(defaults: str | None = None, global_v6: str | None = None) -> list[Finding]:
    """ufw with IPV6=no leaves IPv6 unfiltered, which matters once the machine has a public IPv6 address."""
    try:
        defaults = defaults if defaults is not None else Path("/etc/default/ufw").read_text(errors="replace")
    except OSError:
        return []
    m = re.search(r"^\s*IPV6\s*=\s*\"?(\w+)", defaults, re.M)
    if not m or m.group(1).lower() != "no":
        return []
    if global_v6 is None:
        global_v6 = sh(["ip", "-6", "-o", "addr", "show", "scope", "global"]) or ""
    public = []
    for line in global_v6.splitlines():
        parts = line.split()
        if "inet6" not in parts or len(parts) < 4 or parts[1].startswith("tailscale"):
            continue
        addr = parts[parts.index("inet6") + 1].split("/")[0]
        try:
            if ipaddress.ip_address(addr).is_global:  # ULA (fd00::/8) and VPN ranges aren't reachable from outside
                public.append(addr)
        except ValueError:
            continue
    if not public:
        return []
    return [Finding(CAT, "medium", "Firewall doesn't cover IPv6",
                    "ufw is set to IPV6=no in /etc/default/ufw, but this computer has an IPv6 address. Connections "
                    "over IPv6 skip the firewall entirely.",
                    fix="sudo sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw && sudo ufw reload")]


def _port_in_spec(port: int, proto: str, to: str) -> bool:
    """Does a ufw 'To' column like '25565/tcp', '1714:1764/udp (KDE Connect)', '22', '80,443/tcp' cover port/proto?"""
    tok = to.split()[0]
    spec, _, rproto = tok.partition("/")
    if rproto and rproto != proto:
        return False
    for part in spec.split(","):
        a, _, b = part.partition(":")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            continue
        if lo <= port <= hi:
            return True
    return False


def _fw_state(port: str, proto: str, ufw: dict) -> str:
    """'open' = reachable from anywhere on the LAN, 'restricted' = only from specific sources,
    'blocked' = default deny with no matching rule, 'unknown' = can't tell."""
    if not ufw.get("active"):
        return "open" if ufw.get("active") is False else "unknown"
    if ufw.get("default_in") not in ("deny", "reject"):
        return "open"
    try:
        p = int(port)
    except ValueError:
        return "unknown"
    state = "blocked"
    for r in ufw.get("rules", []):
        if r["dir"] != "IN" or r["action"] not in ("ALLOW", "LIMIT"):
            continue
        if r["to"].startswith("Anywhere"):
            continue  # interface rules (virbr0, tailscale0) don't expose the LAN
        if _port_in_spec(p, proto, r["to"]):
            if r["from"].startswith("Anywhere"):
                return "allowed"
            state = "restricted"
    return state


FW_WORDS = {"open": "open to the LAN", "allowed": "opened on purpose by a ufw rule", "restricted": "limited to specific networks by ufw",
            "blocked": "blocked by ufw", "unknown": "firewall state unknown"}


def _socket_rows() -> tuple[list[dict], bool]:
    """Listening sockets, and whether the owning programs are known (they are with the root helper)."""
    data = priv("sockets")
    if data and data.get("text") is not None:
        return _parse_ss(data["text"]), True
    rows = _parse_ss(sh(["ss", "-tulpnH"]) or sh(["ss", "-tulnH"]) or "")
    return rows, any(r["proc"] != "?" for r in rows)


def _ufw_limits(port: str, proto: str, ufw: dict) -> bool:
    """Is there a ufw LIMIT rule (its built-in brute-force throttle) for this port?"""
    try:
        p = int(port)
    except ValueError:
        return False
    return any(r["dir"] == "IN" and r["action"] == "LIMIT" and not r["to"].startswith("Anywhere")
               and _port_in_spec(p, proto, r["to"]) for r in ufw.get("rules", []))


def _reach(r: dict, ufw: dict) -> str | None:
    """Firewall state for a socket other machines could talk to, or None if it's local-only."""
    if r["proc"] == "docker-proxy":
        # Docker's own iptables rules bypass ufw; only a loopback bind keeps it local.
        return None if _is_loopback(r["host"]) else "open"
    if _is_wildcard(r["host"]) or _is_private_lan(r["host"]):
        return _fw_state(r["port"], r["proto"], ufw)
    return None


def _risky(rows: list[dict], ufw: dict) -> tuple[list[Finding], set]:
    findings, seen = [], set()
    for r in rows:
        name = RISKY_PORTS.get(r["port"]) if r["proto"] == "tcp" else None
        state = _reach(r, ufw) if name else None
        if state not in ("open", "unknown", "allowed") or r["port"] in seen:
            continue
        seen.add(r["port"])
        sev = "high" if state == "open" else "medium"
        why = ("Anyone who can reach this port controls Docker, which means full root access to this computer."
               if r["port"] in ("2375", "2376") else
               "Databases, caches and notebooks like this often have no password by default, and are a favourite "
               "target of automated scans.")
        findings.append(Finding(CAT, sev, f"{name} (port {r['port']}) is reachable from the network",
                                f"{why}\n\n{r['proc']} listens on {r['host']}:{r['port']} ({FW_WORDS.get(state, state)}). "
                                "If only programs on this computer need it, bind it to 127.0.0.1.",
                                fix=f"Bind {r['proc']} to 127.0.0.1 in its config (or 127.0.0.1:{r['port']}:… in a compose "
                                    "file), or block the port: sudo ufw deny " + r["port"] + "/tcp"))
    return findings, seen


def _listeners(cfg: dict, ufw: dict) -> list[Finding]:
    rows, have_procs = _socket_rows()
    if not rows:
        return [Finding(CAT, "info", "Could not list listening sockets")]

    allowed = set(cfg.get("allowed_listeners", []))
    findings, risky_ports = _risky(rows, ufw)
    rows_left = [r for r in rows if r["port"] not in risky_ports or r["proto"] != "tcp"]
    exposed = [r for r in rows_left if _is_wildcard(r["host"])]
    iface = [r for r in rows_left if not _is_wildcard(r["host"]) and not _is_loopback(r["host"])]

    # Group by process so random ephemeral ports don't create a new finding every scan.
    groups: dict[str, list[dict]] = {}
    seen = set()
    for r in exposed:
        key = (r["proc"], r["proto"], r["port"])
        if key in seen:
            continue
        seen.add(key)
        groups.setdefault(r["proc"], []).append(r)

    unknown: list[str] = []
    for proc, rs in groups.items():
        ports = ", ".join(f"{r['proto']}/{r['port']}" for r in rs)
        if proc in allowed:
            findings.append(Finding(CAT, "info", f"{proc} listening on all interfaces", f"Allowed in settings. {ports}"))
        elif proc == "docker-proxy":
            for r in rs:
                findings.append(Finding(CAT, "medium", f"Docker publishes port {r['port']} on all interfaces",
                                        "Docker inserts its own firewall rules, so ufw does NOT block this. "
                                        "Anyone on your LAN can reach it.",
                                        fix='In compose: ports: - "127.0.0.1:%s:<container-port>"' % r["port"]))
        elif proc == "sshd":
            state = _fw_state("22", "tcp", ufw)
            if state == "restricted":
                findings.append(Finding(CAT, "ok", "SSH reachable only from the networks allowed by ufw"))
            elif state == "blocked":
                findings.append(Finding(CAT, "ok", "SSH is blocked by the firewall's default deny"))
            throttled = (_ufw_limits("22", "tcp", ufw) or unit_active("fail2ban") or unit_active("sshguard")
                         or unit_active("crowdsec"))
            if state in ("allowed", "open", "unknown") and not throttled:
                pw = "passwordauthentication yes" in ((priv("sshd") or {}).get("text") or "").lower()
                findings.append(Finding(CAT, "low" if pw else "info", "Nothing slows down SSH login guessing",
                                        "SSH is reachable, and there's no ufw limit rule, fail2ban, sshguard or CrowdSec, so a scanner can "
                                        "try logins as fast as it likes. With keys-only login this is mostly log noise; "
                                        "with passwords on it matters.",
                                        fix="sudo ufw limit 22/tcp   (or install sshguard: sudo pacman -S sshguard && "
                                            "sudo systemctl enable --now sshguard)"))
            if state == "allowed":
                findings.append(Finding(CAT, "low", "SSH is open to every network (a ufw rule allows it from anywhere)",
                                        "Anyone who can reach this machine can try to log in. Limit it to the networks "
                                        "you use, and keep password login off.",
                                        fix=SSH_LIMIT_FIX + "   (then delete the 'allow from anywhere' rule)"))
            elif state in ("open", "unknown"):
                findings.append(Finding(CAT, "medium", "SSH listening on all interfaces with no firewall protection",
                                        fix=SSH_LIMIT_FIX))
        elif proc == "systemd-resolve":
            if any(r["port"] == "5355" for r in rs):
                findings.append(Finding(CAT, "low", "LLMNR name resolution is enabled",
                                        "LLMNR (port 5355) is a legacy Windows protocol that is easy to spoof on a LAN. "
                                        "mDNS covers the same job.",
                                        fix="sudo mkdir -p /etc/systemd/resolved.conf.d && "
                                            "printf '[Resolve]\\nLLMNR=no\\n' | sudo tee /etc/systemd/resolved.conf.d/no-llmnr.conf && "
                                            "sudo systemctl restart systemd-resolved"))
            others = [r for r in rs if r["port"] != "5355"]
            if others:
                findings.append(Finding(CAT, "info", "systemd-resolve listening on all interfaces",
                                        BENIGN["systemd-resolve"] + "\n" + ", ".join(f"{r['proto']}/{r['port']}" for r in others)))
        elif proc in BENIGN:
            findings.append(Finding(CAT, "info", f"{proc} listening on all interfaces", f"{BENIGN[proc]}\n{ports}"))
        elif proc == "rustdesk":
            findings.append(Finding(CAT, "low", "RustDesk remote desktop is running",
                                    f"Listening on {ports}.\nIt's also reachable through RustDesk's relay servers, which "
                                    "ufw can't filter. Keep a strong permanent password and the IP whitelist set "
                                    "(Settings → Security), or stop it when you don't need it."))
        elif proc == "?":
            unknown.extend(f"{r['proto']}/{r['port']}" for r in rs)
        else:
            states = [(r, _fw_state(r["port"], r["proto"], ufw)) for r in rs]
            lines = "\n".join(f"{r['proto']}/{r['port']:6} {FW_WORDS[st]}" for r, st in states)
            open_ = [r for r, st in states if st in ("open", "unknown")]
            chosen = [r for r, st in states if st == "allowed"]
            if chosen and not open_:
                findings.append(Finding(CAT, "info", f"{proc} is reachable from the network (you allowed it)",
                                        "A ufw rule opens this port to everyone, so this is deliberate. Keep the "
                                        "program updated since anyone who can reach your IP can talk to it.\n\n" + lines))
            elif open_:
                sev = "medium" if any(r["proto"] == "tcp" for r in open_) else "low"
                findings.append(Finding(CAT, sev, f"{proc} is reachable from the network",
                                        "Listening on all interfaces and not blocked by the firewall. Reachable from "
                                        "your LAN, and from the internet if your router forwards the port. If it only "
                                        "needs local access, bind it to 127.0.0.1.\n\n" + lines))
            if not open_ and not chosen:
                findings.append(Finding(CAT, "info", f"{proc} listening on all interfaces, blocked by firewall",
                                        "The program accepts connections on every interface, but ufw drops them "
                                        "(or only lets specific networks in).\n\n" + lines))
    if unknown:
        findings.append(Finding(CAT, "low" if have_procs else "info",
                                f"{len(unknown)} sockets on all interfaces belong to processes PacWardX can't name",
                                "Ports: " + ", ".join(unknown) + "\n\nThese are owned by other users (root services). "
                                "Set up the root helper to see which program owns each one.",
                                fix=config.helper_setup()))
    seen_iface = set()
    for r in iface:
        key = (r["proc"], r["host"], r["port"])
        if key in seen_iface:
            continue
        seen_iface.add(key)
        state = _fw_state(r["port"], r["proto"], ufw)
        if state in ("open", "unknown") and _is_private_lan(r["host"]):
            findings.append(Finding(CAT, "low", f"{r['proc']} is reachable on {r['host']}:{r['port']}",
                                    "It listens on one address only, but the firewall doesn't block it, so other "
                                    "devices on that network can connect. If it only needs local access, bind it "
                                    "to 127.0.0.1."))
        else:
            findings.append(Finding(CAT, "info", f"{r['proc']} bound to {r['host']}:{r['port']}",
                                    f"Listens on one address only ({FW_WORDS.get(state, state)})."))
    if not have_procs:
        findings.append(Finding(CAT, "info", "Listener process names unavailable",
                                "Set up the root helper to see which program owns each port.",
                                fix=config.helper_setup()))
    if not any(f.severity in ("medium", "high") for f in findings):
        findings.insert(0, Finding(CAT, "ok", f"{len(rows)} listening sockets, nothing unexpected exposed"))
    return findings


def _docker() -> list[Finding]:
    if not have("docker"):
        return []
    out = sh(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], timeout=30)
    if out is None:
        return []
    findings = []
    for line in out.splitlines():
        name, _, ports = line.partition("\t")
        if "0.0.0.0:" in ports or "[::]:" in ports:
            findings.append(Finding(CAT, "medium", f"Container {name} is published on all interfaces",
                                    ports, fix='Prefix the host port with 127.0.0.1: in its compose file, then docker compose up -d'))
    return findings


def _cloudflared(cfg: dict | None = None) -> list[Finding]:
    may_be_down = set((cfg or {}).get("tunnel_hosts_may_be_down", []))
    routes = tunnel_routes()
    if not routes:
        return []
    running = unit_active("cloudflared") or bool(sh(["pgrep", "-x", "cloudflared"], ok_codes=(0, 1)))
    listening = set()
    out = sh(["ss", "-tulnH"]) or ""
    for r in _parse_ss(out):
        listening.add(r["port"])
    findings = []
    by_route: dict[tuple, list[str]] = {}
    for host, svc, p in routes:
        by_route.setdefault((host, svc), []).append(p)
    for (host, svc), paths in by_route.items():
        m = re.search(r":(\d+)\s*$", svc)
        port = m.group(1) if m else None
        where = "\n".join(dict.fromkeys(paths))
        if port and port not in listening:
            findings.append(Finding(CAT, "info" if host in may_be_down else "low", f"Tunnel route {host} points at nothing",
                                    f"{svc} has no listener right now. Anything that later starts on that port goes "
                                    f"straight onto the internet.\n{where}"))
        else:
            sev = "info" if running else "ok"
            findings.append(Finding(CAT, sev, f"{host} is published to the internet via Cloudflare Tunnel",
                                    f"→ {svc}\nMake sure the app behind it requires a login or token.\n{where}"))
    return findings


def samba_findings(conf: str) -> list[Finding]:
    cp = configparser.ConfigParser(strict=False, interpolation=None, allow_no_value=True,
                                   comment_prefixes=("#", ";"), inline_comment_prefixes=(";",))
    try:
        cp.read_string(conf)
    except configparser.Error:
        return []
    glob_ = {k.lower(): (v or "") for k, v in cp.items("global")} if cp.has_section("global") else {}

    def opt(sec, *keys, default="no"):
        # Options set in [global] apply to every share that doesn't set its own.
        for k in keys:
            if cp.has_option(sec, k):
                return (cp.get(sec, k) or "").strip().lower()
        for k in keys:
            if k in glob_:
                return glob_[k].strip().lower()
        return default

    def yes(v):
        return v in ("yes", "true", "1")

    shares = [sec for sec in cp.sections() if sec.lower() not in ("global", "printers", "print$", "homes")]
    guest = [sec for sec in shares if yes(opt(sec, "guest ok", "public"))]
    writable_guest = [sec for sec in guest if yes(opt(sec, "writable", "writeable", "write ok"))
                      or opt(sec, "read only", default="yes") in ("no", "false", "0")]
    if writable_guest:
        return [Finding(CAT, "high", f"Samba lets anyone write to {len(writable_guest)} shared folder"
                        f"{'s' if len(writable_guest) != 1 else ''}",
                        "These shares allow guest access with no password and can be written to by anyone on the "
                        "network:\n" + "\n".join(writable_guest), fix="Set guest ok = no in /etc/samba/smb.conf")]
    if guest:
        return [Finding(CAT, "medium", f"Samba shares {len(guest)} folder{'s' if len(guest) != 1 else ''} without a password",
                        "Anyone on the network can read: " + ", ".join(guest),
                        fix="Set guest ok = no in /etc/samba/smb.conf, then sudo systemctl restart smb")]
    if shares:
        return [Finding(CAT, "info", f"Samba shares {len(shares)} folder{'s' if len(shares) != 1 else ''}",
                        "Password required. " + ", ".join(shares))]
    return []


def nfs_findings(exports: str) -> list[Finding]:
    """Parse /etc/exports lines: path client(options) client(options) ..."""
    risky, total = [], 0
    for raw in exports.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        total += 1
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        reasons = set()
        for spec in parts[1:]:
            host, _, opts = spec.partition("(")
            options = {o.strip() for o in opts.rstrip(")").split(",")}
            if host in ("", "*"):
                reasons.add("any host")
            if "no_root_squash" in options:
                reasons.add("trusts remote root")
            if "insecure" in options:
                reasons.add("accepts unprivileged ports")
        if reasons:
            risky.append(f"{line}   ({', '.join(sorted(reasons))})")
    if risky:
        return [Finding(CAT, "medium", f"{len(risky)} NFS export{'s are' if len(risky) != 1 else ' is'} open to any host "
                        "or trusts remote root",
                        "NFS has no passwords: it trusts the client's address and user IDs. Limit each export to "
                        "specific hosts and keep root_squash on.\n\n" + "\n".join(risky),
                        fix="Edit /etc/exports to name specific clients, then sudo exportfs -arv")]
    if total:
        return [Finding(CAT, "info", f"{total} NFS export{'s' if total != 1 else ''} configured")]
    return []


def _shares() -> list[Finding]:
    out = []
    if unit_active("smb") or unit_active("smbd"):
        try:
            out += samba_findings(Path("/etc/samba/smb.conf").read_text(errors="replace"))
        except OSError:
            pass
    if unit_active("nfs-server"):
        text = ""
        for f in ["/etc/exports", *sorted(glob.glob("/etc/exports.d/*.exports"))]:
            try:
                text += Path(f).read_text(errors="replace") + "\n"
            except OSError:
                pass
        out += nfs_findings(text)
    return out


def _unit_of(pid: int) -> str | None:
    try:
        cg = Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return None
    m = re.search(r"/system\.slice/(?:[^/\n]+\.slice/)*([^/\n]+\.service)", cg)
    return m.group(1) if m else None


def _sandboxing(ufw: dict) -> list[Finding]:
    """How much systemd confines the services that other machines can talk to."""
    if not have("systemd-analyze"):
        return []
    rows, have_procs = _socket_rows()
    if not have_procs:
        return []
    units = sorted({u for r in rows if r["pid"] and _reach(r, ufw) in ("open", "allowed", "unknown")
                    for u in [_unit_of(r["pid"])] if u})
    weak = []
    for unit in units[:8]:
        out = sh(["systemd-analyze", "security", "--no-pager", unit], timeout=10) or ""
        m = re.search(r"Overall exposure level for \S+:\s*([\d.]+)\s+(\w+)", out)
        if m and float(m.group(1)) >= 7.0:
            weak.append(f"{unit:32} {m.group(1)}  {m.group(2)}")
    if not weak:
        return []
    return [Finding(CAT, "info", f"{len(weak)} network-facing service{'s run' if len(weak) != 1 else ' runs'} "
                    "with little sandboxing",
                    "systemd can confine a service so that, if it's broken into, the attacker reaches less of the "
                    "system. Scores are from systemd-analyze security (0 best, 10 worst). Most distributions ship "
                    "services unconfined, so this is a hardening idea, not a problem.\n\n" + "\n".join(weak),
                    fix="sudo systemctl edit <service>  and add under [Service]: ProtectSystem=strict, ProtectHome=yes, "
                        "PrivateTmp=yes, NoNewPrivileges=yes. Restart it and check it still works.")]


def _outbound() -> list[Finding]:
    out = sh(["ss", "-tunpH", "state", "established"]) or ""
    procs: Counter = Counter()
    odd = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        remote = parts[4]
        m = _PROC_RE.search(line)
        proc = m.group(1) if m else "?"
        procs[proc] += 1
        _, _, port = remote.rpartition(":")
        try:
            pn = int(port)
            if (pn not in COMMON_REMOTE_PORTS and not 27000 <= pn <= 27100
                    and not remote.startswith(("192.168.", "10.", "127.", "100."))):
                odd.append(f"{proc} → {remote}")
        except ValueError:
            pass
    findings = []
    if procs:
        top = ", ".join(f"{p} ({n})" for p, n in procs.most_common(8))
        findings.append(Finding(CAT, "info", f"{sum(procs.values())} outbound connections from {len(procs)} programs", top))
    if odd:
        findings.append(Finding(CAT, "low", f"{len(odd)} outbound connections on unusual ports",
                                "Not necessarily bad (games, VPNs, P2P), but worth recognising.\n\n" + "\n".join(odd[:30])))
    return findings


def run(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    ufw_info: dict = {}
    try:
        f, ufw_info = _ufw()
        out.extend(f)
    except Exception as e:
        out.append(Finding(CAT, "info", "Check ufw failed", repr(e)))
    from . import services
    for step in (lambda: _listeners(cfg, ufw_info), _docker, lambda: _cloudflared(cfg), _outbound, _shares,
                 lambda: _sandboxing(ufw_info),                 lambda: services.tunnel_auth(cfg), lambda: services.minecraft(cfg)):
        try:
            out.extend(step())
        except Exception as e:
            out.append(Finding(CAT, "info", f"Check {getattr(step, '__name__', 'services').strip('_<>')} failed", repr(e)))
    return out
