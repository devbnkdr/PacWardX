"""Small helpers shared by the check modules."""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta

from .. import config


def sh(cmd: list[str], timeout: int = 60, ok_codes=(0,)) -> str | None:
    """Run a command, return stdout, or None if it's missing/failed/timed out."""
    try:
        # Untranslated output: the checks parse English messages from pacman, ufw and friends.
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"})
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None
    if p.returncode not in ok_codes:
        return None
    return p.stdout


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


_PRIV_MEMO: dict[str, tuple[float, object]] = {}
_PRIV_TTL = 60.0


def priv(subcommand: str, timeout: int = 120):
    """Ask the root helper for something. Returns parsed JSON or None if the
    helper isn't installed / sudo rule missing. Callers must degrade gracefully.
    Results are memoised for a minute so several checks can share one call."""
    hit = _PRIV_MEMO.get(subcommand)
    if hit and time.time() - hit[0] < _PRIV_TTL:
        return hit[1]
    helper = config.priv_helper()
    if not helper or not config.helper_allowed(helper):
        return None
    out = sh(["sudo", "-n", helper, subcommand], timeout=timeout)
    if out is None:
        # Remember the failure too, so a missing sudo rule doesn't mean a failed sudo call per check.
        _PRIV_MEMO[subcommand] = (time.time(), None)
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    if isinstance(data, dict) and data.get("error"):
        return None          # helper too old for this subcommand
    _PRIV_MEMO[subcommand] = (time.time(), data)
    return data


TUNNEL_CONFIGS = ("/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml",
                  "~/.cloudflared/*.yml", "~/.cloudflared/*.yaml")


def _yaml_value(s: str) -> str:
    """The value after 'key:' with any trailing comment and surrounding quotes removed."""
    v = s.split(":", 1)[1].split(" #", 1)[0].strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v


def tunnel_routes() -> list[tuple[str, str, str]]:
    """(hostname, service, config file) for every Cloudflare Tunnel ingress rule."""
    paths = []
    for pat in TUNNEL_CONFIGS:
        paths += sorted(glob.glob(os.path.expanduser(pat)))
    routes = []
    for p in paths:
        try:
            text = open(p, errors="replace").read()
        except OSError:
            continue
        host = None
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("- hostname:"):
                host = _yaml_value(s)
            elif s.startswith("service:") and host:
                routes.append((host, _yaml_value(s), p))
                host = None
            elif s.startswith("- service:"):
                host = None
    return routes


def priv_available() -> bool:
    return priv("ping", timeout=10) is not None


def recent_cutoff(days: int) -> float:
    return (datetime.now() - timedelta(days=days)).timestamp()


def unit_active(unit: str) -> bool:
    out = sh(["systemctl", "is-active", unit], ok_codes=(0, 3))
    return (out or "").strip() == "active"
