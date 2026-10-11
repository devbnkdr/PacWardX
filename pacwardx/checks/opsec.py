"""Privacy & OpSec: what someone could learn or take from this machine, and what it gives away."""
from __future__ import annotations

import base64
import configparser
import glob
import json
import os
import re
import socket
import struct
from pathlib import Path

from ..findings import Finding
from .common import have, sh, unit_active

CAT = "opsec"
HOME = Path.home()


# ----------------------------------------------------------------------------- disks
def _walk_blk(devs, parents=()):
    for d in devs or []:
        yield d, parents
        yield from _walk_blk(d.get("children"), parents + (d,))


def disk_findings(lsblk_json: dict) -> list[Finding]:
    """Exposed for tests."""
    plain, enc, swap_plain = [], [], []
    for d, parents in _walk_blk(lsblk_json.get("blockdevices")):
        mps = [m for m in (d.get("mountpoints") or [d.get("mountpoint")]) if m]
        encrypted = d.get("type") == "crypt" or any(p.get("type") == "crypt" for p in parents)
        name = d.get("name", "?")
        for mp in mps:
            if mp == "[SWAP]":
                if not encrypted and not name.startswith("zram"):
                    swap_plain.append(f"/dev/{name}")
                continue
            if mp.startswith(("/boot", "/efi", "/snap", "/var/lib/docker")):
                continue
            (enc if encrypted else plain).append((mp, name))
    out = []
    root_plain = [n for mp, n in plain if mp == "/"]
    others = sorted({f"{mp} (/dev/{n})" for mp, n in plain if mp != "/"})
    if root_plain:
        out.append(Finding(CAT, "medium", "System disk is not encrypted",
                           "Anyone who takes the machine or the drive can read everything on it: SSH keys, browser "
                           "sessions, saved credentials, your documents. Full-disk encryption (LUKS) fixes this; "
                           "on an existing install it means backing up and reinstalling with encryption enabled.\n\n"
                           + "\n".join(f"  {mp} (/dev/{n})" for mp, n in plain)))
    elif others:
        out.append(Finding(CAT, "low", f"{len(others)} data drives are not encrypted", "\n".join(others)))
    if swap_plain:
        out.append(Finding(CAT, "low", "Swap partition is not encrypted",
                           "Memory pages (which can hold passwords) get written to it in plain text.\n" + "\n".join(swap_plain)))
    if not out:
        out.append(Finding(CAT, "ok", "System disk is encrypted"))
    return out


def disks() -> list[Finding]:
    raw = sh(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"]) or sh(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
    try:
        return disk_findings(json.loads(raw or "{}"))
    except ValueError:
        return []


def secure_boot() -> list[Finding]:
    if not os.path.isdir("/sys/firmware/efi"):
        return [Finding(CAT, "info", "Legacy BIOS boot (no Secure Boot)")]
    files = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    try:
        on = open(files[0], "rb").read()[-1] == 1 if files else None
    except OSError:
        on = None
    if on is None:
        return []
    if on:
        return [Finding(CAT, "ok", "Secure Boot is on")]
    return [Finding(CAT, "low", "Secure Boot is off",
                    "Without it, someone with a few minutes of physical access (or malware with root) can swap the "
                    "bootloader or kernel. CachyOS supports it via sbctl; the NVIDIA module then needs signing too.",
                    fix="sudo pacman -S sbctl && sudo sbctl status   (then follow the CachyOS Secure Boot wiki)")]


# ----------------------------------------------------------------------------- desktop
def _kread(file: str, group: str, key: str) -> str | None:
    for tool in ("kreadconfig6", "kreadconfig5"):
        if have(tool):
            v = sh([tool, "--file", file, "--group", group, "--key", key], timeout=5)
            return (v or "").strip()
    return None


def screen_lock() -> list[Finding]:
    auto = _kread("kscreenlockerrc", "Daemon", "Autolock")
    if auto is None:
        return []
    timeout = _kread("kscreenlockerrc", "Daemon", "Timeout") or "5"
    resume = _kread("kscreenlockerrc", "Daemon", "LockOnResume") or "true"
    out = []
    if auto == "false":
        out.append(Finding(CAT, "medium", "Screen never locks automatically",
                           "Walk away and anyone at the desk has your session, your terminals and your browser.",
                           fix="System Settings → Screen Locking → Lock screen automatically"))
    else:
        try:
            if int(timeout) > 15:
                out.append(Finding(CAT, "low", f"Screen locks after {timeout} minutes idle",
                                   "10 minutes or less is typical.", fix="System Settings → Screen Locking"))
        except ValueError:
            pass
    if resume == "false":
        out.append(Finding(CAT, "low", "Screen doesn't lock when waking from sleep",
                           fix="System Settings → Screen Locking → After waking from sleep"))
    if not out:
        out.append(Finding(CAT, "ok", f"Screen locks after {timeout} min and on wake"))
    return out


def clipboard() -> list[Finding]:
    keep = _kread("klipperrc", "General", "KeepClipboardContents")
    if keep is None:
        return []
    hist = glob.glob(str(HOME / ".local/share/klipper/history*.lst"))
    if keep != "false":
        return [Finding(CAT, "low", "Clipboard history is saved to disk",
                        "Every password you copy (from KeePassXC, a terminal, a website) is kept in Klipper's history "
                        "file and survives reboots." + (f"\n{hist[0]}" if hist else ""),
                        fix="kwriteconfig6 --file klipperrc --group General --key KeepClipboardContents false && "
                            "rm -f ~/.local/share/klipper/history*.lst")]
    return [Finding(CAT, "ok", "Clipboard history isn't saved to disk")]


# ----------------------------------------------------------------------------- ssh
def private_key_encrypted(text: str) -> bool | None:
    """True/False for OpenSSH or PEM private keys; None if it isn't one. Exposed for tests."""
    if "BEGIN ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text:
        return True
    m = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----", text, re.S)  # gitleaks:allow
    if m:
        try:
            blob = base64.b64decode("".join(m.group(1).split()))
        except (ValueError, TypeError):
            return None
        magic = b"openssh-key-v1\x00"
        if not blob.startswith(magic):
            return None
        (n,) = struct.unpack(">I", blob[len(magic):len(magic) + 4])
        cipher = blob[len(magic) + 4:len(magic) + 4 + n]
        return cipher != b"none"
    if re.search(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", text):
        return False
    return None


def ssh_client() -> list[Finding]:
    out = []
    plain = []
    for p in sorted(set(glob.glob(str(HOME / ".ssh/*")))):
        if p.endswith((".pub", "known_hosts", "known_hosts.old", "config", "authorized_keys")) or os.path.isdir(p):
            continue
        try:
            if os.path.getsize(p) > 20000:
                continue
            enc = private_key_encrypted(Path(p).read_text(errors="replace"))
        except OSError:
            continue
        if enc is False:
            plain.append(p)
    if plain:
        out.append(Finding(CAT, "low", f"{len(plain)} SSH private key{'s have' if len(plain) != 1 else ' has'} no passphrase",
                           "Anyone who copies the file (backup, stolen disk, malware) can log in wherever it's "
                           "trusted — your mini, GitHub, servers. A passphrase plus ssh-agent costs one prompt per login.\n\n"
                           + "\n".join(plain), fix="ssh-keygen -p -f <keyfile>"))
    cfgp = HOME / ".ssh/config"
    try:
        host = "*"
        wild_fwd, named_fwd = False, []
        for line in cfgp.read_text().splitlines():
            s = line.strip()
            if s.lower().startswith("host "):
                host = s.split(None, 1)[1]
            elif re.match(r"(?i)forwardagent\s+yes", s):
                if host.strip() == "*":
                    wild_fwd = True
                else:
                    named_fwd.append(host)
        if wild_fwd:
            out.append(Finding(CAT, "medium", "SSH agent forwarding is on for every host",
                               "Any server you SSH into can use your keys while you're connected. Enable it only "
                               "for specific hosts you control.", fix="Remove ForwardAgent yes from Host * in ~/.ssh/config"))
        elif named_fwd:
            out.append(Finding(CAT, "info", f"SSH agent forwarding enabled for: {', '.join(named_fwd)}"))
    except OSError:
        pass
    if not out:
        out.append(Finding(CAT, "ok", "SSH keys have passphrases and agent forwarding is off"))
    return out


# ----------------------------------------------------------------------------- network privacy
def vpn_dns() -> list[Finding]:
    out = []
    vpn_on = False
    if have("mullvad"):
        st = (sh(["mullvad", "status"], timeout=8) or "").strip()
        lock = (sh(["mullvad", "lockdown-mode", "get"], timeout=8) or "").strip()
        vpn_on = st.lower().startswith("connected")
        lock_on = lock.lower().endswith("on")
        out.append(Finding(CAT, "info", f"Mullvad VPN: {'connected' if vpn_on else 'not connected'}"
                           + (", lockdown on" if lock_on else ""),
                           f"{st.splitlines()[0] if st else '?'}\n{lock}\n\nWhen it's off, sites and your ISP see your "
                           "home IP. Lockdown mode blocks all traffic if the tunnel drops."))
    rs = sh(["resolvectl", "status"], timeout=8) or ""
    if rs:
        out.extend(dns_findings(rs, vpn_on))
    return out


VPN_IFACE = re.compile(r"^(wg|tun|tap|mullvad|proton|nordlynx|ppp)", re.I)


def parse_resolvectl(text: str) -> list[dict]:
    """[{name, default_route, dot, servers}] for Global and each Link. Exposed for tests."""
    blocks, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^(Global|Link \d+ \(([^)]+)\))$", s)
        if m:
            cur = {"name": m.group(2) or "global", "default_route": m.group(1) == "Global",
                   "dot": False, "servers": [], "domains": []}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        if s.startswith("Protocols:"):
            cur["default_route"] = "+DefaultRoute" in s or cur["name"] == "global"
            cur["dot"] = "+DNSOverTLS" in s
        elif s.startswith("DNS Servers:"):
            cur["servers"] = s.split(":", 1)[1].split()
        elif s.startswith("DNS Domain:"):
            cur["domains"] = s.split(":", 1)[1].split()
        elif s.startswith("DNSOverTLS setting:") or s.startswith("DNS over TLS setting:"):
            cur["dot"] = cur["dot"] or s.split(":", 1)[1].strip() == "yes"
    return blocks


def dns_findings(text: str, vpn_on: bool = False) -> list[Finding]:
    """Judge only the DNS scopes that ordinary lookups use. Exposed for tests."""
    blocks = parse_resolvectl(text)
    glob = next((b for b in blocks if b["name"] == "global"), None)
    glob_dot = bool(glob and glob["dot"])
    if glob and glob["servers"] and "~." in glob["domains"]:
        used = [glob]              # "~." on Global routes every lookup to the global servers
    else:
        used = [b for b in blocks if b["servers"] and b["default_route"]]
    if not used:
        return []
    plain, fine = [], []
    for b in used:
        enc = b["dot"] or glob_dot
        if VPN_IFACE.match(b["name"]) or vpn_on:
            fine.append(f"{b['name']}: {' '.join(b['servers'])} (through the VPN)")
        elif b["name"].startswith("tailscale"):
            fine.append(f"{b['name']}: {' '.join(b['servers'])} (Tailscale DNS; encrypted only if its upstream is a DoH provider)")
        elif enc:
            fine.append(f"{b['name']}: {' '.join(b['servers'])} (DNS-over-TLS)")
        else:
            plain.append(f"{b['name']}: {' '.join(b['servers'])}")
    if plain:
        return [Finding(CAT, "low", "DNS lookups are sent unencrypted",
                        "Every site you visit is visible to your router and ISP (and anyone on the network path), "
                        "even over HTTPS. Switch to DNS-over-TLS or keep the VPN on.\n\nUsed for normal lookups:\n  "
                        + "\n  ".join(plain) + ("\n\nAlso:\n  " + "\n  ".join(fine) if fine else ""),
                        fix="See 'Fixing DNS lookups are sent unencrypted' in the README (resolved.conf.d/dot.conf + ignore router DNS)")]
    return [Finding(CAT, "ok", "DNS lookups are encrypted or go through the VPN", "\n".join(fine))]


def tailscale() -> list[Finding]:
    if not have("tailscale"):
        return []
    raw = sh(["tailscale", "status", "--json"], timeout=10)
    try:
        st = json.loads(raw or "{}")
    except ValueError:
        return []
    if not st.get("Self"):
        return []
    me = st["Self"].get("UserID")
    users = {str(k): v.get("LoginName", "?") for k, v in (st.get("User") or {}).items()}
    peers = list((st.get("Peer") or {}).values())
    foreign = [p for p in peers if p.get("UserID") != me]
    rows = [f"{'●' if p.get('Online') else '○'} {p.get('HostName', '?')} ({p.get('OS', '?')})"
            + (f" — owned by {users.get(str(p.get('UserID')), '?')}" if p.get("UserID") != me else "") for p in peers]
    out = [Finding(CAT, "info", f"{len(peers)} devices on your Tailscale network",
                   "Your firewall allows everything arriving on tailscale0, so each of these can reach every port on "
                   "this machine (SSH, dev servers, Docker dashboards).\n\n" + "\n".join(rows[:40]))]
    if foreign:
        out.append(Finding(CAT, "medium", f"{len(foreign)} tailnet devices belong to other people",
                           "Shared or other users' devices can reach every port here because ufw trusts tailscale0. "
                           "Use Tailscale ACLs to limit what they can reach.\n\n"
                           + "\n".join(f"{p.get('HostName')} — {users.get(str(p.get('UserID')), '?')}" for p in foreign),
                           fix="Tailscale admin console → Access controls"))
    return out


def lan_broadcast() -> list[Finding]:
    out = []
    host = socket.gethostname()
    user = os.environ.get("USER") or HOME.name
    if unit_active("avahi-daemon"):
        svcs = [Path(p).stem for p in glob.glob("/etc/avahi/services/*.service")]
        out.append(Finding(CAT, "info", f"Announces itself on the local network as {host}.local",
                           "Avahi (mDNS) broadcasts your hostname" + (f" and services ({', '.join(svcs)})" if svcs else "")
                           + " to everyone on the same Wi-Fi/LAN. Fine at home; on shared networks it tells others who you are."
                           + (f"\nYour hostname contains your username ({user})." if user and user.lower() in host.lower() else "")))
    if have("bluetoothctl"):
        show = sh(["bluetoothctl", "show"], timeout=5) or ""
        if "Discoverable: yes" in show:
            out.append(Finding(CAT, "low", "Bluetooth is discoverable",
                               "Nearby devices can see and try to pair with this machine.",
                               fix="bluetoothctl discoverable off"))
    if have("kdeconnect-cli"):
        lst = sh(["kdeconnect-cli", "-l"], timeout=8) or ""
        paired = [l.strip("- ").strip() for l in lst.splitlines() if "paired" in l and "unpaired" not in l.lower()]
        if paired:
            out.append(Finding(CAT, "info", f"{len(paired)} device{'s' if len(paired) != 1 else ''} paired with KDE Connect",
                               "Paired phones can read notifications, sync the clipboard, send files and run commands "
                               "you've configured. Unpair ones you no longer use.\n\n" + "\n".join(paired)))
    return out


# ----------------------------------------------------------------------------- live privacy
def camera_mic() -> list[Finding]:
    out = []
    mic = []
    if have("pactl"):
        raw = sh(["pactl", "-f", "json", "list", "source-outputs"], timeout=5)
        try:
            for so in json.loads(raw or "[]"):
                props = so.get("properties", {})
                app = props.get("application.name") or props.get("application.process.binary") or "?"
                if "monitor" in str(props.get("target.object", "")).lower():
                    continue
                mic.append(app)
        except ValueError:
            txt = sh(["pactl", "list", "source-outputs"], timeout=5) or ""
            mic = re.findall(r'application\.name = "([^"]+)"', txt)
    cams = set()
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.readlink(fd).startswith("/dev/video"):
                pid = fd.split("/")[2]
                cams.add(Path(f"/proc/{pid}/comm").read_text().strip())
        except OSError:
            continue
    if mic:
        out.append(Finding(CAT, "info", f"Microphone in use by: {', '.join(sorted(set(mic)))}",
                           "Captured at scan time. If you're not on a call or recording, check these apps."))
    if cams:
        out.append(Finding(CAT, "info", f"Camera in use by: {', '.join(sorted(cams))}",
                           "Captured at scan time."))
    return out


def crash_dumps() -> list[Finding]:
    try:
        pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    except OSError:
        return []
    if "systemd-coredump" not in pattern:
        return []
    storage = "external"
    for f in ["/etc/systemd/coredump.conf", *sorted(glob.glob("/etc/systemd/coredump.conf.d/*.conf"))]:
        try:
            for line in Path(f).read_text().splitlines():
                m = re.match(r"\s*Storage\s*=\s*(\S+)", line)
                if m:
                    storage = m.group(1)
        except OSError:
            continue
    if storage != "none":
        return [Finding(CAT, "low", "Crash dumps are saved to disk",
                        "When a program crashes its memory is kept under /var/lib/systemd/coredump, which can include "
                        "passwords and session tokens it was holding.",
                        fix="sudo mkdir -p /etc/systemd/coredump.conf.d && printf '[Coredump]\\nStorage=none\\nProcessSizeMax=0\\n' | "
                            "sudo tee /etc/systemd/coredump.conf.d/off.conf")]
    return [Finding(CAT, "ok", "Crash dumps are not stored")]


# ----------------------------------------------------------------------------- Wi-Fi
def _nm_split(line: str) -> list[str]:
    """Split nmcli terse output: fields are separated by ':', and '\\' escapes ':' or '\\' inside a value."""
    fields, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    return fields


def open_wifi() -> list[Finding]:
    if not have("nmcli"):
        return []
    out = sh(["nmcli", "-t", "-f", "NAME,UUID,TYPE,AUTOCONNECT", "connection", "show"]) or ""
    auto, manual = [], []
    wifi = [p for p in map(_nm_split, out.splitlines()) if len(p) >= 4 and p[2] == "802-11-wireless"]
    for name, uuid, _type, autoconnect in (p[:4] for p in wifi[:60]):
        km = sh(["nmcli", "-t", "-g", "802-11-wireless-security.key-mgmt", "connection", "show", "uuid", uuid], timeout=10)
        if km is None or km.strip():
            continue
        (auto if autoconnect == "yes" else manual).append(name)
    if auto:
        return [Finding(CAT, "low", f"Joins {len(auto)} open Wi-Fi network{'s' if len(auto) != 1 else ''} automatically",
                        "These saved networks have no password. Anyone can set up a hotspot with the same name, and "
                        "this computer will connect to it on its own and send traffic through it.\n\n"
                        + "\n".join(auto[:30]),
                        fix="nmcli connection modify id '<name>' connection.autoconnect no   (or delete networks you "
                            "no longer use)")]
    if manual:
        return [Finding(CAT, "info", f"{len(manual)} saved open Wi-Fi network{'s' if len(manual) != 1 else ''}",
                        "No password, but not joined automatically.")]
    return []


# ----------------------------------------------------------------------------- Flatpak
FLATPAK_WIDE = {"host": "your whole system", "host-os": "the system's programs and libraries",
                "host-etc": "system settings in /etc", "home": "your home folder"}


def flatpak_access(metadata: str, overrides: list[str]) -> set[str]:
    """Broad filesystem grants (read-write) an app ends up with after overrides."""
    def grants(text):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            cp.read_string(text)
        except configparser.Error:
            return []
        return [g.strip() for g in cp.get("Context", "filesystems", fallback="").split(";") if g.strip()]
    have_ = set()
    for text in [metadata, *overrides]:
        for g in grants(text):
            neg = g.startswith("!")
            name, _, mode = g.lstrip("!").partition(":")
            if name not in FLATPAK_WIDE:
                continue
            if neg or mode == "ro":
                have_.discard(name)  # removed, or narrowed to read-only by a later override
            else:
                have_.add(name)
    return have_


def flatpak() -> list[Finding]:
    roots = [Path("/var/lib/flatpak"), HOME / ".local/share/flatpak"]
    def read(p):
        try:
            return p.read_text(errors="replace")
        except OSError:
            return ""
    rows = []
    for root in roots:
        apps = root / "app"
        if not apps.is_dir():
            continue
        for app in sorted(apps.iterdir()):
            if any(r.startswith(f"{app.name}:") for r in rows):
                continue  # installed both system-wide and for this user
            meta = read(app / "current/active/metadata")
            if not meta:
                continue
            ovr = [read(r / "overrides" / name) for r in roots for name in ("global", app.name)]
            wide = flatpak_access(meta, ovr)
            if wide:
                rows.append(f"{app.name}: " + ", ".join(sorted(FLATPAK_WIDE[w] for w in wide)))
    if not rows:
        return []
    return [Finding(CAT, "low",
                    f"{len(rows)} Flatpak app{'s' if len(rows) != 1 else ''} can change files outside {'their' if len(rows) != 1 else 'its'} sandbox",
                    "These apps have read-write access to large parts of your files, so the Flatpak sandbox does little "
                    "to contain them. Often needed for editors and file tools, but worth knowing.\n\n" + "\n".join(rows),
                    fix="flatpak override --user --nofilesystem=home <app-id>   (or use Flatseal to review permissions)")]


def run(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    for step in (disks, secure_boot, screen_lock, clipboard, ssh_client, vpn_dns, tailscale, lan_broadcast,
                 camera_mic, crash_dumps, open_wifi, flatpak):
        try:
            out.extend(step())
        except Exception as e:
            out.append(Finding(CAT, "info", f"Check {step.__name__} failed", repr(e)))
    return out
