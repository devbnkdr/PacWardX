"""Paths and user settings."""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path

APP = "pacwardx"

_HOME = Path.home()
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", _HOME / ".local/share")) / APP
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", _HOME / ".config")) / APP
RUNTIME_DIR = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))

SOCKET_PATH = RUNTIME_DIR / "pacwardx.sock"
STATE_PATH = DATA_DIR / "state.json"
HISTORY_PATH = DATA_DIR / "history.jsonl"
CONFIG_PATH = CONFIG_DIR / "config.json"
BASELINE_PATH = DATA_DIR / "baseline.json"
CACHE_PATH = DATA_DIR / "cache.json"

# Root helper, allowed via /etc/sudoers.d/pacwardx. The Arch package puts it in /usr/lib,
# packaging/install.sh in /usr/local/lib.
PACKAGED_HELPER = "/usr/lib/pacwardx/pacwardx-priv"
PRIV_HELPERS = (PACKAGED_HELPER, "/usr/local/lib/pacwardx/pacwardx-priv")


def priv_helper() -> str | None:
    return next((h for h in PRIV_HELPERS if os.path.exists(h)), None)


def helper_allowed(helper: str) -> bool:
    """The packaged helper is only allowed for members of the pacwardx group. Check that first, so a user who
    hasn't opted in doesn't fill the journal with refused sudo calls."""
    if helper != PACKAGED_HELPER:
        return True
    try:
        return grp.getgrnam("pacwardx").gr_gid in os.getgroups()
    except KeyError:
        return False


def helper_setup() -> str:
    """The command that turns the root helper on for this kind of install."""
    if os.path.exists(PACKAGED_HELPER):
        return "sudo usermod -aG pacwardx $USER   (then log out and back in)"
    return "bash packaging/install.sh"

DEFAULTS: dict = {
    # How often the daemon re-runs the quick checks (packages, network, system).
    "interval_minutes": 60,
    # Full file scan of the roots below, at most once per this many hours.
    "file_scan_every_hours": 24,
    "file_scan_roots": [str(_HOME)],
    # Directory names (or home-relative paths) skipped during file scans.
    "file_scan_exclude": [
        ".cache", ".npm", ".cargo", ".rustup", ".var", ".wine", ".steam",
        ".local/share/Steam", ".local/share/Trash", ".mozilla", ".thunderbird",
        "node_modules", ".venv", "venv", "__pycache__", ".git",
        "models", "OneDrive", "snap", ".nv",
    ],
    # "Recently changed" threshold for startup files and hidden executables.
    "recent_days": 7,
    # Run clamscan during full file scans if ClamAV is installed.
    "clamav": False,
    # Desktop notifications when new medium/high findings appear.
    "notify": True,
    # A short summary notification once a week, even when nothing new turned up.
    "weekly_summary": True,
    # Process names that may legitimately listen on all interfaces.
    "allowed_listeners": [],
    # How often the cheap change watcher runs (new keys, services, ports, sudo rules...).
    "change_watch_minutes": 5,
    # Tunnel hostnames that are meant to be public (no login expected).
    "tunnel_public_hosts": [],
    # Tunnel hostnames whose backend is often off on purpose (e.g. a game-server map).
    "tunnel_hosts_may_be_down": [],
    # Containers allowed to mount the Docker socket without a warning (name substrings).
    "docker_socket_ok": [],
    # Containers allowed to use the host network/PID namespace (name substrings); reported as info.
    "host_network_ok": [],
    # Images known to be old with no newer release upstream (image-name substrings); reported as info.
    "old_image_ok": [],
    # Folders searched for readable secret files and scanned by gitleaks.
    "secret_scan_roots": [str(_HOME / "Documents"), str(_HOME / "Projects")],
    # Run gitleaks (binary or Docker image) over git repos in secret_scan_roots, weekly.
    "gitleaks": True,
    # Hours between tampered-system-file checks (pacman -Qkk reads every installed file).
    "integrity_every_hours": 24,
    # Pending updates only warn once security-relevant ones have waited this many days
    # since the last full upgrade (rolling release: something is always pending).
    "update_grace_days": 7,
    # sudo commands left out of the login report (substrings), e.g. your own scripts.
    "quiet_sudo": [],
    # Findings you chose to ignore: {finding id: {"title", "category", "note", "ts"}}.
    "ignored": {},
    # Set once the Welcome page has been seen, so the app opens on the Overview after that.
    "welcomed": False,
}


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        cfg.update(json.loads(CONFIG_PATH.read_text()))
    except (OSError, ValueError):
        pass
    return cfg


def save(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def ensure_dirs() -> None:
    """Create the data and config folders, private to the user (they hold security findings)."""
    for d in (DATA_DIR, CONFIG_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
            for f in d.iterdir():
                if f.is_file() and not f.is_symlink():
                    f.chmod(0o600)
        except OSError:
            pass
