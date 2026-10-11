"""File scanning: suspicious permissions, planted executables, optional ClamAV."""
from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path

from ..findings import Finding
from .common import have, recent_cutoff
from .secrets import redact

CAT = "files"
HOME = Path.home()
TMP_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]
# Hidden dirs in $HOME that legitimately hold executables.
HIDDEN_EXEC_OK = (".local/bin", ".local/share", ".cargo", ".rustup", ".npm", ".nvm", ".pyenv",
                  ".cache", ".config", ".steam", ".wine", ".var", ".vscode", ".java", ".mozilla",
                  ".venv")

MAX_FILES = 3_000_000
MAX_SECONDS = 900


def is_program(path: str) -> bool:
    """True only for things that can actually run: ELF binaries and #! scripts.
    Shared-memory blobs, sockets and data files with a stray +x bit are not programs."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head.startswith(b"\x7fELF") or head.startswith(b"#!")


def _excluded(rel: str, name: str, excludes: set[str]) -> bool:
    return name in excludes or rel in excludes


def scan_tree(roots: list[str], excludes: list[str], recent_days: int, clam: bool = False) -> tuple[list[Finding], dict]:
    """Walk the given roots. Returns findings and a stats dict."""
    cutoff = recent_cutoff(recent_days)
    ex = set(excludes)
    stats = {"files": 0, "dirs": 0, "seconds": 0.0, "truncated": False, "roots": roots}
    world_writable, setuid, hidden_exec, susp_desktop = [], [], [], []
    t0 = time.time()

    for root in roots:
        root_p = Path(root)
        if not root_p.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root)
            # prune
            keep = []
            for d in dirnames:
                rel = os.path.normpath(os.path.join(rel_dir, d)) if rel_dir != "." else d
                if _excluded(rel, d, ex):
                    continue
                try:
                    if os.path.islink(os.path.join(dirpath, d)):
                        continue
                except OSError:
                    continue
                keep.append(d)
            dirnames[:] = keep
            stats["dirs"] += 1
            for name in filenames:
                stats["files"] += 1
                if stats["files"] > MAX_FILES or time.time() - t0 > MAX_SECONDS:
                    stats["truncated"] = True
                    break
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mode = st.st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    setuid.append(full)
                if mode & stat.S_IWOTH:
                    world_writable.append(full)
                if mode & 0o111 and st.st_mtime > cutoff:
                    relf = os.path.relpath(full, HOME) if full.startswith(str(HOME)) else full
                    top = relf.split(os.sep)[0]
                    if top.startswith(".") and not relf.startswith(HIDDEN_EXEC_OK) and is_program(full):
                        hidden_exec.append(full)
                if name.endswith(".desktop"):
                    try:
                        with open(full, "r", errors="replace") as fh:
                            for line in fh:
                                if line.startswith("Exec=") and any(t in line for t in
                                        ("/tmp/", "/dev/shm", "curl ", "wget ", "base64", "| sh", "| bash")):
                                    susp_desktop.append(f"{full}: {redact(line.strip())}")
                                    break
                    except OSError:
                        pass
            if stats["truncated"]:
                break
        if stats["truncated"]:
            break

    stats["seconds"] = round(time.time() - t0, 1)
    findings: list[Finding] = []
    if setuid:
        findings.append(Finding(CAT, "high", f"{len(setuid)} setuid/setgid files in scanned folders",
                                "User-owned setuid files are almost never legitimate.\n\n" + "\n".join(setuid[:40]),
                                fix="chmod u-s,g-s <file>"))
    if world_writable:
        findings.append(Finding(CAT, "low", f"{len(world_writable)} world-writable files",
                                "Any local user or sandboxed app could modify these.\n\n" + _grouped(world_writable),
                                fix="chmod -R o-w <folder>"))
    if hidden_exec:
        findings.append(Finding(CAT, "low", f"{len(hidden_exec)} executables in hidden folders changed in the last {recent_days} days",
                                "Hidden dotfolders are a favourite place to drop a payload. Fine if you put them there.\n\n"
                                + "\n".join(hidden_exec[:40])))
    if susp_desktop:
        findings.append(Finding(CAT, "high", f"{len(susp_desktop)} .desktop launchers with suspicious Exec lines",
                                "\n".join(susp_desktop[:20])))
    if clam and have("clamscan"):
        findings.extend(_clamscan(roots, excludes))
    elif clam:
        findings.append(Finding(CAT, "info", "ClamAV not installed", fix="sudo pacman -S clamav && sudo freshclam"))
    if not findings:
        findings.append(Finding(CAT, "ok", f"Scanned {stats['files']:,} files, nothing suspicious"))
    return findings, stats


def _grouped(paths: list[str], depth: int = 3, limit: int = 25) -> str:
    """Summarise a long path list by folder so one chatty app doesn't hide everything else."""
    from collections import Counter
    home = str(HOME)
    groups: Counter = Counter()
    for p in paths:
        rel = p[len(home) + 1:] if p.startswith(home + "/") else p
        parts = rel.split("/")
        key = ("~/" if p.startswith(home + "/") else "") + "/".join(parts[:depth])
        if len(parts) > depth:
            key += "/…"
        groups[key] += 1
    lines = [f"{n:5}  {k}" for k, n in groups.most_common(limit)]
    if len(groups) > limit:
        lines.append(f"      … and {len(groups) - limit} more folders")
    return "\n".join(lines)


def _clamscan(roots: list[str], excludes: list[str]) -> list[Finding]:
    cmd = ["clamscan", "-r", "-i", "--no-summary", "--stdout"]
    for e in excludes:
        cmd += ["--exclude-dir", e]
    cmd += roots
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.TimeoutExpired):
        return [Finding(CAT, "info", "ClamAV scan did not finish")]
    hits = [l for l in p.stdout.splitlines() if l.endswith("FOUND")]
    if p.returncode == 2:
        return [Finding(CAT, "info", "ClamAV reported errors", p.stderr[-2000:])]
    if hits:
        return [Finding(CAT, "high", f"ClamAV flagged {len(hits)} files", "\n".join(hits[:50]))]
    return [Finding(CAT, "ok", "ClamAV found nothing")]


def quick(cfg: dict, deep_secrets: bool = False) -> list[Finding]:
    """Cheap checks that are safe to run every hour: temp dirs, startup locations, secrets."""
    findings = []
    tmp_exec = []
    for d in TMP_DIRS:
        try:
            for entry in os.scandir(d):
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and st.st_uid == os.getuid()
                        and is_program(entry.path)):
                    tmp_exec.append(entry.path)
        except OSError:
            continue
    if tmp_exec:
        findings.append(Finding(CAT, "medium", f"{len(tmp_exec)} executable files in temp directories",
                                "Malware often runs from /tmp or /dev/shm because they're always writable.\n\n"
                                + "\n".join(tmp_exec[:30])))
    small_roots = [str(HOME / ".config/autostart"), str(HOME / ".config/systemd/user"),
                   str(HOME / ".local/share/applications"), str(HOME / "Desktop")]
    f, _ = scan_tree([r for r in small_roots if os.path.isdir(r)], [], int(cfg.get("recent_days", 7)))
    findings.extend(x for x in f if x.severity != "ok")
    if not findings:
        findings.append(Finding(CAT, "ok", "Temp and startup folders look clean"))
    from . import secrets
    for step in (lambda: secrets.readable_secrets(cfg, deep=deep_secrets), lambda: secrets.history_tokens(cfg),
                 lambda: secrets.git_credentials(cfg)):
        try:
            findings.extend(step())
        except Exception as e:
            findings.append(Finding(CAT, "info", "Secret check failed", repr(e)))
    return findings


def run(cfg: dict) -> list[Finding]:
    return quick(cfg)


def full(cfg: dict, roots: list[str] | None = None, clam: bool | None = None) -> tuple[list[Finding], dict]:
    roots = roots or cfg.get("file_scan_roots", [str(HOME)])
    clam = cfg.get("clamav", False) if clam is None else clam
    findings, stats = scan_tree(roots, cfg.get("file_scan_exclude", []), int(cfg.get("recent_days", 7)), clam)
    findings.extend(x for x in quick(cfg, deep_secrets=True) if x.severity != "ok")
    from . import secrets
    try:
        findings.extend(secrets.gitleaks(cfg))
    except Exception as e:
        findings.append(Finding(CAT, "info", "Git secret scan failed", repr(e)))
    seen, unique = set(), []
    for f in findings:           # the full walk and the quick pass overlap on startup folders
        if f.title not in seen:
            seen.add(f.title)
            unique.append(f)
    return unique, stats
