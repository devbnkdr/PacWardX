"""Package health: pending updates, known CVEs, AUR packages, orphans, reboot state."""
from __future__ import annotations

import os
import re
from datetime import datetime

from ..findings import Finding
from .common import have, priv, sh

CAT = "packages"

# Packages whose pending update is worth more than an "info".
SENSITIVE = {
    "openssl", "openssh", "systemd", "sudo", "glibc", "curl", "wget", "nss",
    "ca-certificates", "ca-certificates-mozilla", "cloudflared", "tailscale",
    "docker", "containerd", "runc", "nodejs", "polkit", "dbus", "pam", "grub",
    "bash", "coreutils", "gnupg", "libxml2", "expat", "zlib", "xz", "git",
    # Things that parse untrusted internet content all day: updates are nearly always security fixes.
    "firefox", "chromium", "thunderbird", "python-cryptography", "libpng", "libwebp", "ffmpeg",
}

_SEV_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


def _pending_updates(grace: int = 7) -> list[Finding]:
    if not have("checkupdates"):
        return [Finding(CAT, "info", "Update check unavailable",
                        "checkupdates is missing. It comes from pacman-contrib.",
                        fix="sudo pacman -S pacman-contrib")]
    # exit 2 = nothing to do
    out = sh(["checkupdates"], timeout=180, ok_codes=(0, 2))
    if out is None:
        return [Finding(CAT, "info", "Update check failed",
                        "checkupdates returned an error (network down or pacman db locked).")]
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        return [Finding(CAT, "ok", "System packages are up to date")]
    names = [l.split()[0] for l in lines]
    hot = sorted(n for n in names if n in SENSITIVE or n.startswith(("linux", "electron")))
    detail = ""
    if hot:
        detail += "Security-relevant: " + ", ".join(hot) + "\n\n"
    detail += "\n".join(lines)
    got = _days_since_upgrade()
    waited = got[0] if got else None
    overdue = waited is None or waited >= grace
    sev = "medium" if hot and overdue else "info"
    if hot and not overdue:
        detail = (f"Last full upgrade {waited} day{'s' if waited != 1 else ''} ago. Updating weekly is fine on a "
                  f"rolling release; this becomes a warning if security-relevant updates wait {grace}+ days. "
                  "Known vulnerabilities with a fix are reported separately and immediately.\n\n") + detail
    return [Finding(CAT, sev, f"{len(names)} package update{'s' if len(names) != 1 else ''} pending",
                    detail, fix="sudo pacman -Syu")]


def _aur_updates(grace: int = 7) -> list[Finding]:
    helper = "paru" if have("paru") else "yay" if have("yay") else None
    if not helper:
        return []
    out = sh([helper, "-Qua"], timeout=120, ok_codes=(0, 1))
    if out is None:
        return []
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("::")]
    if not lines:
        return [Finding(CAT, "ok", "AUR packages are up to date")]
    got = _days_since_upgrade()
    sev = "low" if got is None or got[0] >= grace else "info"
    return [Finding(CAT, sev, f"{len(lines)} AUR update{'s' if len(lines) != 1 else ''} pending",
                    "pacman -Syu does not cover these.\n\n" + "\n".join(lines),
                    fix=f"{helper} -Sua")]


def _cves() -> list[Finding]:
    if not have("arch-audit"):
        return [Finding(CAT, "info", "CVE check unavailable",
                        "arch-audit is not installed.", fix="sudo pacman -S arch-audit")]
    out = sh(["arch-audit", "-u", "-f", "%n\t%s\t%v\t%c"], timeout=120, ok_codes=(0, 1))
    if out is None:
        out = sh(["arch-audit", "-u"], timeout=120, ok_codes=(0, 1))
    if out is None:
        return [Finding(CAT, "info", "CVE check failed", "arch-audit returned an error.")]
    found = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4:
            name, sev, fixed, cves = parts[0], parts[1].lower(), parts[2], parts[3]
            found.append(Finding(CAT, _SEV_MAP.get(sev, "medium"),
                                 f"{name} has a fixed vulnerability waiting to be installed",
                                 f"Severity: {sev}\nFixed in: {fixed}\n{cves}",
                                 fix="sudo pacman -Syu"))
        else:
            m = re.match(r"(\S+) is affected by (.*?)\. (\w+) risk!", line)
            if m:
                name, what, sev = m.group(1), m.group(2), m.group(3).lower()
                found.append(Finding(CAT, _SEV_MAP.get(sev, "medium"),
                                     f"{name} has a fixed vulnerability waiting to be installed",
                                     f"{what} ({sev} risk)", fix="sudo pacman -Syu"))
    if not found:
        found.append(Finding(CAT, "ok", "No unpatched vulnerabilities with an available fix"))
    # Advisories with no fix yet: informational only.
    out2 = sh(["arch-audit"], timeout=120, ok_codes=(0, 1)) or ""
    open_adv = [l for l in out2.splitlines() if " is affected by " in l]
    if open_adv:
        found.append(Finding(CAT, "info", f"{len(open_adv)} packages have open advisories with no fix yet",
                             "Nothing to install — upstream or Arch hasn't shipped a fix.\n\n" + "\n".join(open_adv)))
    return found


def _foreign_and_orphans() -> list[Finding]:
    out = []
    foreign = sh(["pacman", "-Qm"], ok_codes=(0, 1)) or ""
    fl = [l for l in foreign.splitlines() if l.strip()]
    if fl:
        out.append(Finding(CAT, "info", f"{len(fl)} packages from the AUR or built locally",
                           "These are not vetted by the Arch/CachyOS repos. Review PKGBUILD diffs when they update.\n\n"
                           + "\n".join(fl)))
    orphans = sh(["pacman", "-Qdtq"], ok_codes=(0, 1)) or ""
    ol = [l for l in orphans.splitlines() if l.strip()]
    if ol:
        out.append(Finding(CAT, "low", f"{len(ol)} orphaned packages",
                           "Installed as dependencies but nothing needs them any more.\n\n" + "\n".join(ol),
                           fix="sudo pacman -Rns $(pacman -Qdtq)"))
    return out


def _days_since_upgrade():
    """(days, datetime) of the last `pacman -Syu`, or None if pacman.log can't tell."""
    try:
        with open("/var/log/pacman.log", "r", errors="replace") as fh:
            stamps = [l[1:26] for l in fh if "starting full system upgrade" in l]
    except OSError:
        return None
    if not stamps:
        return None
    try:
        last = datetime.fromisoformat(stamps[-1].split("]")[0])
    except ValueError:
        return None
    return (datetime.now(last.tzinfo) - last).days, last


def _last_upgrade() -> list[Finding]:
    if not os.path.exists("/var/log/pacman.log"):
        return []
    got = _days_since_upgrade()
    if got is None:
        return [Finding(CAT, "medium", "No full system upgrade found in pacman.log", fix="sudo pacman -Syu")]
    days, last = got
    if days > 30:
        sev = "high"
    elif days > 14:
        sev = "medium"
    else:
        sev = "ok"
    return [Finding(CAT, sev, f"Last full upgrade {days} day{'s' if days != 1 else ''} ago",
                    f"{last:%Y-%m-%d %H:%M}", fix="sudo pacman -Syu" if sev != "ok" else "")]


def _reboot_needed() -> list[Finding]:
    rel = os.uname().release
    if not os.path.isdir(f"/usr/lib/modules/{rel}"):
        return [Finding(CAT, "medium", "Reboot needed — running kernel was replaced",
                        f"Running {rel}, but its module directory is gone, so a newer kernel is installed. "
                        "New kernel modules (USB devices, filesystems) can fail to load until you reboot.",
                        fix="reboot")]
    return [Finding(CAT, "ok", f"Running the installed kernel ({rel})")]


def _pacnew() -> list[Finding]:
    data = priv("pacnew")
    files = data.get("files", []) if isinstance(data, dict) else None
    if files is None:
        out = sh(["find", "/etc", "-name", "*.pacnew", "-o", "-name", "*.pacsave"], ok_codes=(0, 1)) or ""
        files = [l for l in out.splitlines() if l.strip()]
    if files:
        return [Finding(CAT, "low", f"{len(files)} .pacnew/.pacsave files waiting for review",
                        "A package shipped a new default config that differs from yours.\n\n" + "\n".join(files),
                        fix="sudo pacdiff")]
    return []


def run(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    from . import integrity
    grace = int(cfg.get("update_grace_days", 7))
    for step in (lambda: _pending_updates(grace), lambda: _aur_updates(grace), _cves, _foreign_and_orphans, _last_upgrade,
                 _reboot_needed, _pacnew, lambda: integrity.tampered(cfg), lambda: integrity.unowned(cfg)):
        try:
            out.extend(step())
        except Exception as e:  # a broken check must not take the whole scan down
            out.append(Finding(CAT, "info", f"Check {getattr(step, '__name__', 'integrity').strip('_<>')} failed", repr(e)))
    return out
