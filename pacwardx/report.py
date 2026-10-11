"""Plain-text/Markdown report of the current state, for sharing when you ask someone for help.

The machine's name, your user name and your home folder path are swapped for placeholders.
Other details (IP addresses, device names, file names) can still appear: read before sharing."""
from __future__ import annotations

import os
import platform
import re
import socket
from datetime import datetime
from pathlib import Path

from . import __version__, config, engine
from .checks.common import priv_available
from .findings import CATEGORIES, CATEGORY_LABELS, SEV_RANK

SEV_TAG = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "info", "ok": "ok"}


def _os_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    return platform.system()


def _uptime() -> str:
    try:
        secs = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return "?"
    h, m = int(secs // 3600), int(secs % 3600 // 60)
    return f"{h // 24}d {h % 24}h {m}m" if h >= 24 else f"{h}h {m}m"


def _trim(text: str, max_lines: int | None) -> str:
    lines = text.rstrip().splitlines()
    if max_lines is not None and len(lines) > max_lines:
        extra = len(lines) - max_lines
        lines = lines[:max_lines] + [f"… ({extra} more lines)"]
    return "\n".join(lines)


def scrub(text: str) -> str:
    """Replace this machine's name, the user name and the home path with placeholders."""
    home = str(Path.home())
    user = Path(home).name
    host = socket.gethostname()
    if home not in ("", "/"):
        text = text.replace(home, "~")
    for value, placeholder in ((host, "<hostname>"), (user, "<user>")):
        if len(value) >= 3:
            text = re.sub(rf"(?<![\w.-]){re.escape(value)}(?![\w-])", placeholder, text)
    return text


def build(state: dict | None = None, *, full: bool = False, running: str | None = None,
          daemon: bool | None = None) -> str:
    """full=False keeps it short: details for low+ findings, info findings truncated,
    ok findings as one-liners. full=True includes every line of every finding."""
    state = state if state is not None else engine.load_state()
    s = engine.summary(state)
    cfg = config.load()
    detail_cap_serious = None if full else 40
    detail_cap_info = None if full else 12

    out: list[str] = []
    out.append(f"## PacWardX report — {datetime.now():%Y-%m-%d %H:%M}")
    out.append("")
    out.append("```")
    out.append(f"system    {_os_name()}, kernel {os.uname().release}, up {_uptime()}")
    out.append(f"pacwardx  {__version__}  daemon={'running' if daemon else 'not running' if daemon is not None else '?'}"
               f"  root-helper={'ok' if priv_available() else 'unavailable'}")
    c = s["counts"]
    out.append(f"overall   {s['worst'] or 'not scanned'}  score {s['score']}/100  "
               f"high {c['high']} / medium {c['medium']} / low {c['low']} / info {c['info']}")
    out.append(f"last scan {s['last_run'] or 'never'}" + (f"  (scan in progress: {running})" if running else ""))
    fs = s.get("file_scan")
    if fs:
        out.append(f"file scan {fs.get('ts')}  {fs.get('files', 0):,} files in {fs.get('seconds', 0)}s"
                   + ("  TRUNCATED" if fs.get("truncated") else ""))
    for cat in CATEGORIES:
        pc = s["categories"][cat]
        out.append(f"  {CATEGORY_LABELS[cat]:9} {pc['worst'] or 'not scanned':8} checked {pc['ts'] or 'never'}")
    out.append(f"settings  interval {cfg.get('interval_minutes')}m, file scan every {cfg.get('file_scan_every_hours')}h, "
               f"clamav={'on' if cfg.get('clamav') else 'off'}, allowed_listeners={cfg.get('allowed_listeners') or '[]'}")
    out.append("```")

    for cat in CATEGORIES:
        block = state.get("categories", {}).get(cat)
        out.append("")
        out.append(f"### {CATEGORY_LABELS[cat]}")
        if not block:
            out.append("_not scanned yet_")
            continue
        ignored = [f for f in block.get("findings", []) if f.get("ignored")]
        findings = sorted((f for f in block.get("findings", []) if not f.get("ignored")),
                          key=lambda f: -SEV_RANK[f["severity"]])
        oks = [f for f in findings if f["severity"] == "ok"]
        rest = [f for f in findings if f["severity"] != "ok"]
        for f in rest:
            out.append("")
            out.append(f"**[{SEV_TAG[f['severity']]}] {f['title']}**")
            cap = detail_cap_serious if SEV_RANK[f["severity"]] >= SEV_RANK["low"] else detail_cap_info
            if f.get("detail"):
                out.append("```")
                out.append(_trim(f["detail"], cap))
                out.append("```")
            if f.get("fix"):
                out.append(f"fix: `{f['fix']}`")
        if oks:
            out.append("")
            out.append("OK: " + "; ".join(f["title"] for f in oks))
        if ignored:
            out.append("")
            out.append("Ignored: " + "; ".join(f["title"] for f in ignored))
    out.append("")
    if not full:
        out.append("_Short report: long details are trimmed. Use “Save full report…” for everything._")
    out.append("_Machine name, user name and home path are replaced. Check for other personal details before sharing._")
    return scrub("\n".join(out))


def main(argv: list[str]) -> None:
    full = "--full" in argv
    daemon = None
    running = None
    try:
        from .client import DaemonClient
        d = DaemonClient()
        if d.available():
            daemon = True
            resp = d.call({"cmd": "results"})
            state, running = resp.get("state"), resp.get("running")
        else:
            daemon, state = False, None
    except Exception:
        state = None
    print(build(state, full=full, running=running, daemon=daemon))
