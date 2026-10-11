"""System hardening: SSH, sudo, SUID binaries, accounts, startup entries, kernel knobs."""
from __future__ import annotations

import glob
import os
import re
import shlex
from collections import Counter
from pathlib import Path

from .. import config
from ..findings import Finding
from .common import have, priv, recent_cutoff, sh, unit_active
from .secrets import redact

CAT = "system"
HOME = Path.home()


def _sshd() -> list[Finding]:
    if not have("sshd"):
        return [Finding(CAT, "ok", "No SSH server installed")]
    enabled = (sh(["systemctl", "is-enabled", "sshd"], ok_codes=(0, 1)) or "").strip()
    active = unit_active("sshd") or unit_active("ssh")
    data = priv("sshd")
    findings = []
    if not active and enabled not in ("enabled", "static"):
        return [Finding(CAT, "ok", "SSH server installed but not running or enabled")]
    if data is None or not data.get("text"):
        return [Finding(CAT, "info", "SSH config not inspected",
                        "Reading the effective sshd config needs the root helper.")]
    conf = {}
    for line in data["text"].splitlines():
        k, _, v = line.partition(" ")
        conf[k.lower()] = v.strip()
    if conf.get("passwordauthentication") == "yes":
        findings.append(Finding(CAT, "high", "SSH accepts passwords",
                                "Brute-force target. Use keys only.",
                                fix="echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/10-keys-only.conf && sudo systemctl restart sshd"))
    if conf.get("permitrootlogin") not in ("no", "prohibit-password", "forced-commands-only", None):
        findings.append(Finding(CAT, "high", "SSH allows root login with a password",
                                fix="echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl restart sshd"))
    if conf.get("permitemptypasswords") == "yes":
        findings.append(Finding(CAT, "high", "SSH allows accounts with empty passwords",
                                "An account without a password could log in over the network with no secret at all.",
                                fix="echo 'PermitEmptyPasswords no' | sudo tee /etc/ssh/sshd_config.d/10-no-empty.conf && sudo systemctl restart sshd"))
    if conf.get("x11forwarding") == "yes":
        findings.append(Finding(CAT, "low", "SSH X11 forwarding enabled", "Rarely needed; widens the attack surface of the server."))
    if not findings:
        findings.append(Finding(CAT, "ok", "SSH: keys only, root login disabled"))
    return findings


def _authorized_keys() -> list[Finding]:
    p = HOME / ".ssh" / "authorized_keys"
    try:
        lines = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    except OSError:
        return []
    findings = []
    dupes = [k for k, n in Counter(lines).items() if n > 1]
    if dupes:
        findings.append(Finding(CAT, "low", f"{len(dupes)} duplicate entries in authorized_keys",
                                fix="t=$(mktemp) && awk '!seen[$0]++' ~/.ssh/authorized_keys > \"$t\" && cat \"$t\" > ~/.ssh/authorized_keys && rm \"$t\""))
    comments = [l.split()[-1] if len(l.split()) > 2 else "(no comment)" for l in lines]
    findings.append(Finding(CAT, "info", f"{len(lines)} SSH keys may log in as you",
                            "\n".join(comments)))
    try:
        mode = p.stat().st_mode & 0o777
        if mode & 0o022:
            findings.append(Finding(CAT, "high", "authorized_keys is writable by others",
                                    f"mode {mode:o}", fix="chmod 600 ~/.ssh/authorized_keys"))
        smode = (HOME / ".ssh").stat().st_mode & 0o777
        if smode & 0o077:
            findings.append(Finding(CAT, "medium", "~/.ssh is readable by other users",
                                    f"mode {smode:o}", fix="chmod 700 ~/.ssh"))
    except OSError:
        pass
    return findings


def _sudoers() -> list[Finding]:
    data = priv("sudoers")
    if data is None:
        return [Finding(CAT, "info", "sudoers not inspected", "Needs the root helper.")]
    findings = []
    for entry in data.get("nopasswd", []):
        line = entry["line"]
        if re.search(r"NOPASSWD:\s*ALL\b", line):
            findings.append(Finding(CAT, "high", "Passwordless sudo for everything",
                                    f"{entry['file']}: {line}\nAny process running as this user is effectively root.",
                                    fix="Restrict to specific commands, or remove NOPASSWD"))
        else:
            findings.append(Finding(CAT, "info", "Passwordless sudo for specific commands",
                                    f"{entry['file']}: {line}"))
    if not findings:
        findings.append(Finding(CAT, "ok", "No passwordless sudo rules"))
    return findings


def _suid() -> list[Finding]:
    data = priv("suid")
    if data is None:
        return []
    files = data.get("files", [])
    if not files:
        return [Finding(CAT, "ok", "No SUID binaries outside the standard system paths")]
    return [Finding(CAT, "medium", f"{len(files)} SUID binaries outside standard paths",
                    "A setuid file in an unusual place is a classic persistence trick. Make sure you know each one.\n\n"
                    + "\n".join(files[:50]))]


def _accounts() -> list[Finding]:
    findings = []
    shells = []
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, uid, shell = parts[0], parts[2], parts[6]
            if uid == "0" and name != "root":
                findings.append(Finding(CAT, "high", f"Extra UID-0 account: {name}", line))
            if not shell.endswith(("nologin", "false", "git-shell")):
                shells.append(f"{name} (uid {uid}, {shell})")
    except OSError:
        pass
    findings.append(Finding(CAT, "info", f"{len(shells)} accounts can log in", "\n".join(shells)))
    data = priv("shadow")
    if data is not None:
        empty = data.get("empty_password", [])
        if empty:
            findings.append(Finding(CAT, "high", f"Accounts with an empty password: {', '.join(empty)}",
                                    fix="sudo passwd -l <user>  (or set a password)"))
    for g in ("docker", "wheel", "sudo", "libvirt"):
        out = sh(["getent", "group", g], ok_codes=(0, 2)) or ""
        if out.strip():
            members = out.strip().split(":")[-1]
            if members and g == "docker":
                findings.append(Finding(CAT, "info", f"Users in the docker group: {members}",
                                        "docker group membership is equivalent to root. Expected for a dev box, "
                                        "just remember it when running untrusted code."))
    return findings


def _startup(cfg: dict) -> list[Finding]:
    cutoff = recent_cutoff(int(cfg.get("recent_days", 7)))
    try:  # anything changed before the last "Accept changes" has already been reviewed
        cutoff = max(cutoff, config.BASELINE_PATH.stat().st_mtime)
    except OSError:
        pass
    findings = []
    recent = []
    entries = []
    autostart = sorted(glob.glob(str(HOME / ".config/autostart/*.desktop")))
    for p in autostart:
        try:
            text = Path(p).read_text(errors="replace")
        except OSError:
            continue
        exec_line = redact(next((l.split("=", 1)[1] for l in text.splitlines() if l.startswith("Exec=")), "?"))
        entries.append(f"{Path(p).name}: {exec_line}")
        if os.path.getmtime(p) > cutoff:
            recent.append(p)
        if re.search(r"/tmp/|/dev/shm|curl |wget |bash -c|sh -c|base64", exec_line):
            findings.append(Finding(CAT, "high", f"Suspicious autostart entry: {Path(p).name}",
                                    exec_line, fix=f"Inspect and remove: rm {shlex.quote(p)}"))
    user_units = sorted(glob.glob(str(HOME / ".config/systemd/user/*.service")))
    for p in user_units:
        if os.path.getmtime(p) > cutoff:
            recent.append(p)
    if entries:
        findings.append(Finding(CAT, "info", f"{len(entries)} desktop autostart entries", "\n".join(entries)))
    out = sh(["systemctl", "--user", "list-unit-files", "--type=service", "--state=enabled",
               "--no-legend", "--no-pager"]) or ""
    enabled_user = [l.split()[0] for l in out.splitlines() if l.strip()]
    if enabled_user:
        findings.append(Finding(CAT, "info", f"{len(enabled_user)} enabled user services", "\n".join(enabled_user)))
    out = sh(["systemctl", "list-unit-files", "--type=service", "--state=enabled",
               "--no-legend", "--no-pager"]) or ""
    enabled_sys = [l.split()[0] for l in out.splitlines() if l.strip()]
    for u in enabled_sys:
        for base in ("/etc/systemd/system",):
            p = os.path.join(base, u)
            if os.path.isfile(p) and os.path.getmtime(p) > cutoff:
                recent.append(p)
    if enabled_sys:
        findings.append(Finding(CAT, "info", f"{len(enabled_sys)} enabled system services", "\n".join(enabled_sys)))
    cron = sh(["crontab", "-l"], ok_codes=(0, 1)) or ""
    cron_lines = [redact(l) for l in cron.splitlines() if l.strip() and not l.startswith("#")]
    if cron_lines:
        findings.append(Finding(CAT, "info", f"{len(cron_lines)} user cron jobs", "\n".join(cron_lines)))
    for rc in (".bashrc", ".zshrc", ".profile", ".bash_profile", ".config/fish/config.fish", ".xprofile"):
        p = HOME / rc
        if p.is_file() and p.stat().st_mtime > cutoff:
            recent.append(str(p))
    own = {"pacwardx-tray.desktop", "pacwardx-daemon.service"}  # written by PacWardX's own installer
    recent = [p for p in recent if os.path.basename(p) not in own]
    if recent:
        findings.append(Finding(CAT, "low", f"{len(recent)} startup files changed in the last {cfg.get('recent_days', 7)} days",
                                "Expected if you edited them. Unexpected changes here are how persistence is planted.\n\n"
                                + "\n".join(recent)))
    return findings


def _kernel() -> list[Finding]:
    findings = []
    def sysctl(k):
        return (sh(["sysctl", "-n", k], ok_codes=(0, 255)) or "").strip()
    if sysctl("kernel.yama.ptrace_scope") == "0":
        findings.append(Finding(CAT, "low", "ptrace_scope is 0",
                                "Any of your processes can read another's memory (e.g. steal a browser session). "
                                "Debuggers still work at 1 for child processes.",
                                fix="echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/10-ptrace.conf && sudo sysctl --system"))
    if sysctl("net.ipv4.ip_forward") == "1":
        findings.append(Finding(CAT, "info", "IP forwarding enabled", "Normal with Docker/libvirt/Tailscale."))
    if sysctl("kernel.kptr_restrict") == "0":
        findings.append(Finding(CAT, "low", "kptr_restrict is 0", "Kernel addresses are visible to unprivileged users.",
                                fix="echo 'kernel.kptr_restrict = 1' | sudo tee /etc/sysctl.d/10-kptr.conf && sudo sysctl --system"))
    return findings


# SigLevel words that let unsigned packages in. DatabaseOptional (the default) only concerns the repo database.
WEAK_SIGLEVEL = {"Never", "Optional", "PackageNever", "PackageOptional"}


def pacman_findings(conf: str, read=lambda path: Path(path).read_text(errors="replace")) -> list[Finding]:
    """Package signature checking and mirror protocols, from pacman.conf and every file it includes."""
    weak: dict[str, list[str]] = {}       # section -> weak SigLevel lines
    servers: dict[str, list[str]] = {}    # section -> server URLs
    seen: set[str] = set()

    def walk(text: str, where: str, section: str, depth: int) -> str:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            key, _, val = (x.strip() for x in line.partition("="))
            # LocalFileSigLevel only covers `pacman -U` of local files, so it's not checked.
            if key == "SigLevel" and WEAK_SIGLEVEL & set(val.split()):
                weak.setdefault(section, []).append(f"[{section}] SigLevel = {val}{where}")
            elif key == "Server":
                servers.setdefault(section, []).append(val + where)
            elif key == "Include" and depth < 4:
                for path in sorted(glob.glob(val)):
                    if path in seen:
                        continue
                    seen.add(path)
                    try:
                        # pacman reads an included file as if it were pasted in, sections and all.
                        section = walk(read(path), f"  ({path})", section, depth + 1)
                    except OSError:
                        continue
        return section

    walk(conf, "", "options", 0)
    findings = []
    # A repo whose servers are all local files (a repo you build yourself) is a much smaller risk.
    local_only = {sec for sec, urls in servers.items() if urls and all(u.startswith("file://") for u in urls)}
    remote = [line for sec, lines in weak.items() if sec not in local_only for line in lines]
    local = [line for sec, lines in weak.items() if sec in local_only for line in lines]
    if remote:
        findings.append(Finding(CAT, "high", "Package signature checking is turned off",
                                "pacman will install packages without checking who signed them, so a tampered mirror "
                                "or download could install anything.\n\n" + "\n".join(remote),
                                fix="Set SigLevel = Required DatabaseOptional in /etc/pacman.conf (and remove the weaker "
                                    "per-repository SigLevel lines)"))
    if local:
        findings.append(Finding(CAT, "low", "A local package repository isn't signature-checked",
                                "Common for a repository you build yourself, but anything that can write to its folder "
                                "can slip packages into your updates.\n\n" + "\n".join(local)))
    plain = [f"[{sec}] {u}" for sec, urls in servers.items() for u in urls if u.startswith("http://")]
    if plain:
        findings.append(Finding(CAT, "low", f"{len(plain)} package mirror{'s use' if len(plain) != 1 else ' uses'} plain HTTP",
                                "Packages are still signature-checked, but anyone on the network path can see what you "
                                "install and can hold back updates. Prefer https:// mirrors.\n\n" + "\n".join(plain[:20]),
                                fix="sudo reflector --protocol https --latest 20 --sort rate --save /etc/pacman.d/mirrorlist"))
    if not findings:
        findings.append(Finding(CAT, "ok", "Packages are signature-checked and mirrors use HTTPS"))
    return findings


def _pacman() -> list[Finding]:
    try:
        conf = Path("/etc/pacman.conf").read_text(errors="replace")
    except OSError:
        return []
    return pacman_findings(conf)


def _time_sync() -> list[Finding]:
    out = sh(["timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized"])
    if out is None:
        return []
    props = dict(line.partition("=")[::2] for line in out.splitlines())
    if props.get("NTPSynchronized") == "yes":
        return [Finding(CAT, "ok", "Clock is synchronised")]
    other = next((d for d in ("chronyd", "ntpd", "openntpd") if unit_active(d)), None)
    if other:
        # timedatectl only knows about systemd-timesyncd; another daemon may be keeping time just fine.
        return [Finding(CAT, "ok", f"Clock is kept in sync by {other}")]
    detail = ("A wrong clock breaks certificate checks, makes logs misleading and can stop two-factor codes "
              "from working.")
    if props.get("NTP") != "yes":
        return [Finding(CAT, "low", "Automatic time sync is off", detail, fix="sudo timedatectl set-ntp true")]
    return [Finding(CAT, "info", "Clock not synchronised yet", detail + " Time sync is on but hasn't succeeded yet; "
                    "this is normal for a few minutes after boot or while offline.")]


def _mac() -> list[Finding]:
    """Mandatory access control (AppArmor or SELinux). Optional on Arch, so informational only."""
    try:
        aa = Path("/sys/module/apparmor/parameters/enabled").read_text().strip()
    except OSError:
        aa = ""
    if aa == "Y":
        return [Finding(CAT, "ok", "AppArmor is enabled in the kernel",
                        "Whether it protects anything depends on the profiles loaded: sudo aa-status")]
    try:
        if Path("/sys/fs/selinux/enforce").read_text().strip() == "1":
            return [Finding(CAT, "ok", "SELinux is enforcing")]
    except OSError:
        pass
    return [Finding(CAT, "info", "No AppArmor or enforcing SELinux",
                    "Arch doesn't enable one by default. AppArmor can confine browsers and network services so a "
                    "compromised program reaches less of your system. Optional, and takes some setup.",
                    fix="See the ArchWiki AppArmor page: install apparmor, add the kernel parameters, "
                        "then systemctl enable --now apparmor")]


def _firmware() -> list[Finding]:
    try:
        date = Path("/sys/class/dmi/id/bios_date").read_text().strip()
        ver = Path("/sys/class/dmi/id/bios_version").read_text().strip()
        board = Path("/sys/class/dmi/id/board_name").read_text().strip()
    except OSError:
        return []
    from datetime import datetime
    try:
        d = datetime.strptime(date, "%m/%d/%Y")
    except ValueError:
        return []
    age = (datetime.now() - d).days
    if age > 730:
        return [Finding(CAT, "low", f"Firmware (BIOS) is {age // 365} years old",
                        f"{board} version {ver}, dated {date}. CPU microcode/security fixes ship in BIOS updates.")]
    return [Finding(CAT, "ok", f"Firmware {ver} ({date})")]


def run(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    from . import auth, services
    for step in (_sshd, _authorized_keys, _sudoers, _suid, _accounts, lambda: _startup(cfg), _kernel, _firmware,
                 _pacman, _time_sync, _mac,
                 lambda: services.docker_hygiene(cfg), lambda: auth.run(cfg)):
        try:
            out.extend(step())
        except Exception as e:
            out.append(Finding(CAT, "info", f"Check {getattr(step, '__name__', 'extra').strip('_<>')} failed", repr(e)))
    return out
