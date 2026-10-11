"""Login monitoring: SSH and sudo attempts over the last 24 h, and who's logged in now."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

from .. import config
from ..findings import Finding
from .common import priv, sh
from .secrets import redact

CAT = "system"

RX_SSH_FAIL = [
    re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from (\S+)"),
    re.compile(r"Invalid user (\S*) from (\S+)"),
    re.compile(r"Connection closed by (?:authenticating|invalid) user (\S*) (\S+) port"),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)"),
]
RX_SSH_OK = re.compile(r"^(\S+) \S+ sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port")
RX_SUDO_FAIL = [
    re.compile(r"sudo(?:\[\d+\])?:\s+(\S+) : (\d+) incorrect password attempt"),
    re.compile(r"sudo(?:\[\d+\])?:\s+(\S+) : user NOT in sudoers"),
    re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*ruser=(\S*)"),
]
RX_SUDO_CMD = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+) : .*COMMAND=(.*)$")
RX_SU_FAIL = re.compile(r"(?:FAILED SU|pam_unix\(su(?:-l)?:auth\): authentication failure)")
# PacWardX's own helper calls: exactly the helper plus one subcommand word, nothing else.
OWN_HELPER_CALL = re.compile(r"^/usr(?:/local)?/lib/pacwardx/pacwardx-priv \w+$")


def ip_kind(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "unknown"
    if a in ipaddress.ip_network("100.64.0.0/10") or (a.version == 6 and str(a).startswith("fd7a:115c:a1e0")):
        return "tailscale"
    if a.is_loopback:
        return "local"
    if a.is_private or a.is_link_local:
        return "lan"
    return "public"


def analyse(lines: list[str], quiet: tuple[str, ...] = ()) -> dict:
    """Exposed for tests."""
    fails, oks, sudo_fail, sudo_cmds, su_fail = Counter(), [], 0, Counter(), 0
    for l in lines:
        for rx in RX_SSH_FAIL:
            m = rx.search(l)
            if m:
                fails[m.group(2)] += 1
                break
        m = RX_SSH_OK.search(l)
        if m:
            oks.append({"when": m.group(1)[:16].replace("T", " "), "method": m.group(2),
                        "user": m.group(3), "ip": m.group(4)})
        own = RX_SUDO_CMD.search(l)
        if own and OWN_HELPER_CALL.match(own.group(2).strip()):
            continue  # PacWardX's own `sudo -n` calls, e.g. before the user joined the pacwardx group
        for rx in RX_SUDO_FAIL:
            m = rx.search(l)
            if m:
                sudo_fail += int(m.group(2)) if rx is RX_SUDO_FAIL[0] else 1
                break
        m = RX_SUDO_CMD.search(l)
        if m and "incorrect password" not in l and "NOT in sudoers" not in l:
            cmd = m.group(2).strip()
            if not OWN_HELPER_CALL.match(cmd) and not any(q in cmd for q in quiet):
                sudo_cmds[redact(cmd)[:120]] += 1
        if RX_SU_FAIL.search(l):
            su_fail += 1
    return {"ssh_fail": fails, "ssh_ok": oks, "sudo_fail": sudo_fail, "sudo_cmds": sudo_cmds, "su_fail": su_fail}


def findings_from(a: dict) -> list[Finding]:
    out = []
    fails: Counter = a["ssh_fail"]
    total = sum(fails.values())
    if total:
        sev = "medium" if total >= 10 or any(ip_kind(ip) == "public" for ip in fails) else "low"
        rows = [f"{n:5}  {ip}  ({ip_kind(ip)})" for ip, n in fails.most_common(15)]
        out.append(Finding(CAT, sev, f"{total} failed SSH login attempts in 24 h",
                           "Someone tried to log in and failed. From your own Tailscale devices this is usually a "
                           "wrong key; from a public address it's scanning.\n\n" + "\n".join(rows)))
    oks = a["ssh_ok"]
    if oks:
        public = [o for o in oks if ip_kind(o["ip"]) == "public"]
        rows = [f"{o['when']}  {o['user']} from {o['ip']} ({ip_kind(o['ip'])}, {o['method']})" for o in oks[-20:]]
        out.append(Finding(CAT, "medium" if public else "info",
                           f"{len(oks)} successful SSH login{'s' if len(oks) != 1 else ''} in 24 h"
                           + (" (from a public address)" if public else ""),
                           "Check each one was you.\n\n" + "\n".join(rows)))
    if a["sudo_fail"]:
        out.append(Finding(CAT, "medium" if a["sudo_fail"] >= 5 else "low",
                           f"{a['sudo_fail']} failed sudo password attempts in 24 h",
                           "Mistyped passwords show up here too. Repeated failures you didn't make mean something "
                           "running as you is trying to escalate."))
    if a["su_fail"]:
        out.append(Finding(CAT, "low", f"{a['su_fail']} failed su attempts in 24 h"))
    if a["sudo_cmds"]:
        rows = [f"{n:4}×  {c}" for c, n in a["sudo_cmds"].most_common(12)]
        out.append(Finding(CAT, "info", f"{sum(a['sudo_cmds'].values())} commands run with sudo in 24 h",
                           "PacWardX's own calls and anything matching quiet_sudo in config.json are left out.\n\n" + "\n".join(rows)))
    if not out:
        out.append(Finding(CAT, "ok", "No SSH or sudo failures in the last 24 h"))
    return out


def sessions() -> list[Finding]:
    ids = sh(["loginctl", "list-sessions", "--no-legend", "--no-pager"]) or ""
    remote = []
    for line in ids.splitlines():
        sid = line.split()[0] if line.split() else ""
        if not sid:
            continue
        info = sh(["loginctl", "show-session", sid, "-p", "Remote", "-p", "RemoteHost", "-p", "Name",
                   "-p", "Service", "-p", "State"]) or ""
        kv = dict(l.split("=", 1) for l in info.splitlines() if "=" in l)
        if kv.get("Remote") == "yes":
            host = kv.get("RemoteHost", "?")
            remote.append(f"{kv.get('Name', '?')} via {kv.get('Service', '?')} from {host} ({ip_kind(host)}), {kv.get('State', '')}")
    if not remote:
        return []
    return [Finding(CAT, "info", f"{len(remote)} remote session{'s' if len(remote) != 1 else ''} open right now",
                    "\n".join(remote))]


def run(cfg: dict) -> list[Finding]:
    data = priv("authlog", timeout=120)
    lines = data.get("lines") if isinstance(data, dict) else None
    if lines is None:
        txt = sh(["journalctl", "--since=-24h", "-o", "short-iso", "-q", "--no-pager",
                  "-t", "sshd", "-t", "sshd-session", "-t", "sudo", "-t", "su"], timeout=60)
        if txt is None:
            return [Finding(CAT, "info", "Login history unavailable",
                            "Needs the root helper.", fix=config.helper_setup())]
        lines = txt.splitlines()
    return findings_from(analyse(lines, tuple(cfg.get("quiet_sudo", [])))) + sessions()
