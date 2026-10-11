"""Change alerts: snapshot the places persistence and access get added, diff against a baseline.

A snapshot is {group: {key: value}}. Keys identify an item (a path, a key fingerprint, a
unit name); values fingerprint its content, so an edited file shows up as "changed".
Findings persist until the user accepts the current state as the new baseline.
"""
from __future__ import annotations

import glob
import hashlib
import json
import re
from pathlib import Path

from .. import config
from ..findings import Finding
from .common import have, priv, sh, tunnel_routes
from .secrets import redact

CAT = "changes"
HOME = Path.home()

# group -> (label, severity when something is added/changed, severity when removed)
GROUPS = {
    "ssh_keys":       ("SSH keys that can log in as you", "high", "info"),
    "root_ssh_keys":  ("SSH keys that can log in as root", "high", "info"),
    "users":          ("User accounts", "high", "info"),
    "admin_groups":   ("Admin group membership (wheel/docker/sudo…)", "high", "info"),
    "ld_preload":     ("/etc/ld.so.preload entries", "high", "info"),
    "root_files":     ("Root-owned security config (sudoers, PAM, sshd, cron, polkit…)", "medium", "low"),
    "root_cron":      ("Root cron jobs", "high", "info"),
    "user_cron":      ("Your cron jobs", "medium", "info"),
    "system_units":   ("Enabled system services/timers", "medium", "info"),
    "user_units":     ("Enabled user services/timers", "medium", "info"),
    "user_unit_files": ("User unit files (~/.config/systemd/user)", "medium", "info"),
    "autostart":      ("Desktop autostart entries", "medium", "info"),
    "shell_rc":       ("Shell startup files", "low", "info"),
    "listeners":      ("Listening TCP ports", "medium", "info"),
    "firewall":       ("Firewall rules", "medium", "low"),
    "tunnels":        ("Cloudflare tunnel routes", "medium", "info"),
    "containers":     ("Docker containers", "low", "info"),
}
# Files inside root_files whose change is worth a HIGH alert on its own.
CRITICAL_FILES = re.compile(r"^/etc/(sudoers|sudoers\.d/|pam\.d/|ld\.so\.preload|ssh/sshd_config)")


def _sha_file(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:16]
    except OSError:
        return None


KEY_TYPES = re.compile(r"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$")


def authorized_key_fingerprints(path) -> dict:
    """{SHA256 fingerprint: comment} computed in Python (same format as ssh-keygen -l)."""
    import base64
    keys = {}
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return keys
    for line in lines:
        parts = line.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        # options (from=..., command=...) may precede the key type
        idx = next((i for i, p in enumerate(parts) if KEY_TYPES.match(p)), None)
        if idx is None or idx + 1 >= len(parts):
            continue
        try:
            blob = base64.b64decode(parts[idx + 1])
        except ValueError:
            continue
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        opts = " ".join(parts[:idx])
        keys[fp] = (" ".join(parts[idx + 2:]) or "(no comment)") + (f"  [options: {opts}]" if opts else "")
    return keys


def _enabled_units(user: bool) -> dict:
    cmd = ["systemctl"] + (["--user"] if user else []) + [
        "list-unit-files", "--type=service,timer,socket,path", "--state=enabled", "--no-legend", "--no-pager"]
    out = sh(cmd)
    if out is None:
        return None
    return {l.split()[0]: "enabled" for l in out.splitlines() if l.strip()}


def snapshot(cfg: dict | None = None) -> dict:
    snap: dict[str, dict] = {}

    # SSH keys (yours)
    snap["ssh_keys"] = authorized_key_fingerprints(HOME / ".ssh" / "authorized_keys")

    # Accounts and admin groups (world-readable)
    try:
        users = {}
        for line in Path("/etc/passwd").read_text().splitlines():
            p = line.split(":")
            if len(p) >= 7:
                users[p[0]] = f"uid={p[2]} shell={p[6]}"
        snap["users"] = users
    except OSError:
        pass
    groups = {}
    for g in ("wheel", "sudo", "docker", "libvirt", "adm", "systemd-journal", "input", "kvm"):
        out = sh(["getent", "group", g], ok_codes=(0, 2)) or ""
        if out.strip():
            members = out.strip().split(":")[-1]
            for m in filter(None, members.split(",")):
                groups[f"{g}:{m}"] = "member"
    snap["admin_groups"] = groups

    # Root-only locations via the helper
    p = priv("persistence", timeout=60)
    if isinstance(p, dict):
        snap["root_ssh_keys"] = {k: "key" for k in p.get("root_ssh_keys", [])}
        # The helper hands back only a fingerprint per root cron line, never its text.
        snap["root_cron"] = _root_cron(p.get("root_crontab", []))
        snap["ld_preload"] = {l: "preload" for l in p.get("ld_preload", [])}
        snap["root_files"] = {k: v or "unreadable" for k, v in p.get("root_files", {}).items()}

    # Your cron
    cron = sh(["crontab", "-l"], ok_codes=(0, 1))
    if cron is not None:
        snap["user_cron"] = {hashlib.sha1(l.encode()).hexdigest()[:10]: redact(l.strip())
                             for l in cron.splitlines() if l.strip() and not l.startswith("#")}

    # Units
    su = _enabled_units(False)
    if su is not None:
        snap["system_units"] = su
    uu = _enabled_units(True)
    if uu is not None:
        snap["user_units"] = uu
    snap["user_unit_files"] = {f: _sha_file(f) for f in sorted(
        glob.glob(str(HOME / ".config/systemd/user/*.service")) +
        glob.glob(str(HOME / ".config/systemd/user/*.timer")) +
        glob.glob(str(HOME / ".config/systemd/user/*.path")))}

    # Autostart
    snap["autostart"] = {f: _sha_file(f) for f in sorted(glob.glob(str(HOME / ".config/autostart/*.desktop")))}

    # Shell startup files
    rc = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".xprofile", ".xinitrc",
          ".pam_environment", ".config/fish/config.fish"]
    files = [str(HOME / r) for r in rc if (HOME / r).is_file()]
    files += sorted(glob.glob(str(HOME / ".config/fish/conf.d/*.fish")))
    files += sorted(glob.glob(str(HOME / ".config/environment.d/*.conf")))
    files += sorted(glob.glob(str(HOME / ".config/plasma-workspace/env/*")))
    snap["shell_rc"] = {f: _sha_file(f) for f in files}

    # Listening TCP ports (ephemeral range excluded: those churn constantly)
    from .network import _is_loopback, _is_wildcard, _parse_ss
    data = priv("sockets")
    text = data.get("text") if isinstance(data, dict) else None
    if text is None:
        text = sh(["ss", "-tlpnH"]) or sh(["ss", "-tlnH"]) or ""
    lst = {}
    for r in _parse_ss(text):
        if r["proto"] not in ("tcp", "?") or r["state"] not in ("LISTEN", "?"):
            continue
        try:
            if int(r["port"]) >= 32768:
                continue
        except ValueError:
            continue
        scope = "all interfaces" if _is_wildcard(r["host"]) else "localhost" if _is_loopback(r["host"]) else r["host"]
        lst[f"tcp/{r['port']} ({scope})"] = r["proc"]
    if lst:
        snap["listeners"] = lst

    # Firewall rules
    from .network import _ufw
    try:
        _, info = _ufw()
        if info.get("active") is not None:
            snap["firewall"] = {f"{r['to']} {r['action']} {r['dir']} from {r['from']}": "rule"
                                for r in info.get("rules", [])}
            snap["firewall"]["status"] = "active" if info["active"] else "INACTIVE"
    except Exception:
        pass

    # Tunnel routes
    routes = {host: svc for host, svc, _path in tunnel_routes()}
    snap["tunnels"] = routes

    # Containers
    if have("docker"):
        out = sh(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}"], timeout=20)
        if out is not None:
            snap["containers"] = {l.split("\t")[0]: l.split("\t")[1] if "\t" in l else "?"
                                  for l in out.splitlines() if l.strip()}
    return snap


def load_baseline() -> dict | None:
    try:
        return json.loads(config.BASELINE_PATH.read_text())
    except (OSError, ValueError):
        return None


def save_baseline(snap: dict) -> None:
    config.BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = config.BASELINE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(snap, indent=1, sort_keys=True))
    tmp.replace(config.BASELINE_PATH)


def diff(base: dict, cur: dict) -> dict:
    """{group: {"added": [...], "removed": [...], "changed": [...]}} for groups present in both."""
    out = {}
    for g in cur:
        if g not in base:
            continue
        b, c = base[g], cur[g]
        added = [k for k in c if k not in b]
        removed = [k for k in b if k not in c]
        changed = [k for k in c if k in b and c[k] != b[k]]
        if added or removed or changed:
            out[g] = {"added": sorted(added), "removed": sorted(removed), "changed": sorted(changed)}
    return out


def _fmt(group: str, keys: list[str], snap: dict) -> str:
    vals = snap.get(group, {})
    lines = []
    for k in keys[:40]:
        v = vals.get(k)
        if group in ("root_cron", "user_cron"):
            lines.append(f"  {v}")
        elif group in ("listeners", "containers", "tunnels", "ssh_keys", "users"):
            lines.append(f"  {k}  →  {v}")
        else:
            lines.append(f"  {k}")
    if len(keys) > 40:
        lines.append(f"  … and {len(keys) - 40} more")
    return "\n".join(lines)


def findings_from_diff(d: dict, base: dict, cur: dict) -> list[Finding]:
    out: list[Finding] = []
    for g, ch in d.items():
        label, sev_add, sev_rm = GROUPS.get(g, (g, "medium", "info"))
        new = ch["added"] + ch["changed"]
        if new:
            sev = sev_add
            if g == "root_files" and any(CRITICAL_FILES.match(k) for k in new):
                sev = "high"
            if g == "firewall" and cur.get("firewall", {}).get("status") == "INACTIVE":
                sev = "high"
            parts = []
            if ch["added"]:
                parts.append(f"New:\n{_fmt(g, ch['added'], cur)}")
            if ch["changed"]:
                parts.append(f"Changed:\n{_fmt(g, ch['changed'], cur)}")
            n = len(new)
            out.append(Finding(CAT, sev, f"{label}: {n} new or changed since baseline",
                               "If you made this change, press “Accept changes”. If you didn't, investigate "
                               "before accepting — this is where attackers add persistence.\n\n" + "\n\n".join(parts),
                               fix="pacwardx accept   (or the Accept changes button)"))
        if ch["removed"]:
            out.append(Finding(CAT, sev_rm, f"{label}: {len(ch['removed'])} removed since baseline",
                               f"Removed:\n{_fmt(g, ch['removed'], base)}"))
    return out


def _root_cron(items: list[str]) -> dict:
    """{fingerprint: label}. A helper installed before fingerprinting returns raw lines: hash those here."""
    out = {}
    for item in items:
        h = item if re.fullmatch(r"[0-9a-f]{10}", item) else hashlib.sha1(item.strip().encode()).hexdigest()[:10]
        out[h] = f"root cron entry {h}"
    return out


def _upgrade_baseline(base: dict) -> bool:
    """Older baselines stored root cron lines in full. Keep the fingerprints, drop the text."""
    old = base.get("root_cron")
    if not old or all(v == f"root cron entry {k}" for k, v in old.items()):
        return False
    base["root_cron"] = {k: f"root cron entry {k}" for k in old}
    return True


def run(cfg: dict) -> list[Finding]:
    cur = snapshot(cfg)
    base = load_baseline()
    if base is not None and _upgrade_baseline(base):
        save_baseline(base)
    if base is None:
        save_baseline(cur)
        n = sum(len(v) for v in cur.values())
        return [Finding(CAT, "ok", "Baseline recorded",
                        f"{n} items across {len(cur)} groups. From now on anything new in these places is flagged.\n\n"
                        + "\n".join(f"  {GROUPS.get(g, (g,))[0]}: {len(v)}" for g, v in sorted(cur.items())))]
    # Groups that weren't available when the baseline was taken (e.g. helper installed later):
    # adopt silently instead of reporting everything as new.
    grew = [g for g in cur if g not in base]
    if grew:
        for g in grew:
            base[g] = cur[g]
        save_baseline(base)
    d = diff(base, cur)
    if not d:
        n = sum(len(v) for v in cur.values())
        return [Finding(CAT, "ok", "No changes since baseline", f"Watching {n} items across {len(cur)} groups.")]
    return findings_from_diff(d, base, cur)


def accept(cfg: dict | None = None) -> dict:
    snap = snapshot(cfg)
    save_baseline(snap)
    return snap
