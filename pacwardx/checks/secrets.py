"""Leaked secrets: credential files other users can read, tokens pasted into shell
history, and secrets committed to git repos (gitleaks). Secret values are never shown."""
from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import stat
import time
from pathlib import Path

from ..findings import Finding
from .common import have, sh

CAT = "files"
HOME = Path.home()

KNOWN_SECRET_FILES = [
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
    ".git-credentials", ".netrc", ".pgpass", ".npmrc", ".pypirc",
    ".docker/config.json", ".aws/credentials", ".kube/config",
    ".config/gh/hosts.yml", ".config/rclone/rclone.conf", ".supabase/access-token",
    ".wrangler/config/default.toml", ".config/pacwardx/config.json",
]
KNOWN_SECRET_GLOBS = [".cloudflared/*.json", ".cloudflared/cert.pem", ".ssh/*_key", ".ssh/id_*"]
SECRET_NAME_PATTERNS = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.ovpn", "credentials.json",
                        "service-account*.json", "id_rsa", "id_ed25519", "id_ecdsa", ".git-credentials", "rclone.conf"]
NOT_SECRET = (".pub", ".example", ".sample", ".template", ".dist", ".md")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".cache", "site-packages", "target", "dist", "build"}

HISTORY_FILES = [".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".python_history",
                 ".psql_history", ".mysql_history", ".sqlite_history", ".node_repl_history", ".config/fish/fish_history"]

TOKEN_PATTERNS = {
    "GitHub token": re.compile(r"\b(ghp_[A-Za-z0-9]{36}|gh[ousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})"),
    "API key (sk-ant- prefix)": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "API key (sk- prefix)": re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "GitLab token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe live key": re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Bearer token": re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    "Password/secret assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?(?!\$)[^\s'\"]{8,}"),
    "Password flag": re.compile(r"(?i)--password[= ](?!\$)\S{4,}"),
}


def redact(text: str) -> str:
    """Replace anything that looks like a secret with a marker, so it can be shown and stored."""
    for rx in TOKEN_PATTERNS.values():
        text = rx.sub("‹redacted›", text)
    return text


def _readable_by_others(st_mode: int) -> bool:
    return bool(st_mode & (stat.S_IRGRP | stat.S_IROTH))


def _home_blocks_others() -> bool:
    try:
        return not (os.stat(HOME).st_mode & stat.S_IXOTH)
    except OSError:
        return False


def _is_secret_name(name: str) -> bool:
    if name.endswith(NOT_SECRET):
        return False
    return any(fnmatch.fnmatch(name, p) for p in SECRET_NAME_PATTERNS)


def _walk_secret_files(roots: list[str], max_depth: int = 6, max_files: int = 400_000) -> list[str]:
    found, seen = [], 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count("/") - base_depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for n in filenames:
                seen += 1
                if _is_secret_name(n):
                    found.append(os.path.join(dirpath, n))
            if seen > max_files:
                return found
    return found


def readable_secrets(cfg: dict, deep: bool = False) -> list[Finding]:
    candidates = [str(HOME / f) for f in KNOWN_SECRET_FILES]
    for g in KNOWN_SECRET_GLOBS:
        candidates += [p for p in glob.glob(str(HOME / g)) if not p.endswith(".pub")]
    if deep:
        candidates += _walk_secret_files(cfg.get("secret_scan_roots", []))
    exposed = []
    for p in sorted(set(candidates)):
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and _readable_by_others(st.st_mode) and st.st_uid == os.getuid():
            exposed.append(f"{stat.filemode(st.st_mode)}  {p}")
    if not exposed:
        return [Finding(CAT, "ok", "Credential files are private to you")]
    guarded = _home_blocks_others()
    return [Finding(CAT, "low" if guarded else "medium",
                    f"{len(exposed)} credential files are readable by other users",
                    ("Your home folder already blocks other users, so this is a second line of defence, "
                     "but sandboxed apps and backups copy permissions as-is.\n\n" if guarded else
                     "Any local account or service can read these.\n\n") + "\n".join(exposed[:60]),
                    fix="chmod 600 <file>   (or: chmod go-rwx <file>)")]


def scan_history_text(lines: list[str]) -> dict[str, list[int]]:
    """{kind: [line numbers]} — exposed for tests. Never returns the matched text."""
    hits: dict[str, list[int]] = {}
    for i, line in enumerate(lines, 1):
        for kind, rx in TOKEN_PATTERNS.items():
            if rx.search(line):
                hits.setdefault(kind, []).append(i)
    return hits


def history_tokens(cfg: dict) -> list[Finding]:
    rows = []
    for rel in HISTORY_FILES:
        p = HOME / rel
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        hits = scan_history_text(lines)
        if hits:
            desc = "; ".join(f"{k} (line{'s' if len(v) > 1 else ''} {', '.join(map(str, v[:6]))}{'…' if len(v) > 6 else ''})"
                             for k, v in sorted(hits.items()))
            rows.append(f"~/{rel}: {desc}")
    if not rows:
        return [Finding(CAT, "ok", "No tokens or passwords found in shell history")]
    return [Finding(CAT, "medium", f"Secrets found in {len(rows)} shell history file{'s' if len(rows) != 1 else ''}",
                    "Anything typed on the command line is saved in plain text. Delete those lines, and rotate "
                    "the keys if the machine was ever shared, backed up to the cloud, or synced. Values are not "
                    "shown here.\n\n" + "\n".join(rows),
                    fix="fish: history delete --contains '<part of the command>'; history save   |   "
                        "bash/zsh: edit the file and remove the lines. Tip: start a command with a space to keep it out of history.")]


# ----------------------------------------------------------------------------- git settings
def git_credentials(cfg: dict) -> list[Finding]:
    """Git told to save passwords and tokens unencrypted in ~/.git-credentials."""
    if not have("git"):
        return []
    helpers: list[str] = []
    for scope in ("--system", "--global"):  # not the working directory's repo config
        out = sh(["git", "config", scope, "--includes", "--get-all", "credential.helper"], ok_codes=(0, 1)) or ""
        for h in out.splitlines():
            h = h.strip()
            helpers = [] if not h else helpers + [h.split()[0]]  # an empty value resets the list, as in git
    if "store" in helpers:
        return [Finding(CAT, "medium", "Git saves passwords in plain text",
                        "credential.helper is set to 'store', so every password or token you give git is written "
                        "unencrypted to ~/.git-credentials. Any program running as you can read it.",
                        fix="git config --global --unset-all credential.helper; "
                            "git config --global credential.helper libsecret   (needs the libsecret package; "
                            "then delete ~/.git-credentials and rotate the tokens in it)")]
    if (HOME / ".git-credentials").is_file():
        return [Finding(CAT, "low", "Old ~/.git-credentials file still exists",
                        "Git isn't set to use it any more, but it may still hold working tokens in plain text.",
                        fix="Rotate the tokens it contains, then delete ~/.git-credentials")]
    return []


# ----------------------------------------------------------------------------- gitleaks
def _gitleaks_cmd(repo: str) -> list[str] | None:
    args = ["detect", "--no-banner", "--redact", "--report-format", "json", "--report-path", "/dev/stdout",
            "--exit-code", "0", "--log-level", "error"]
    if have("gitleaks"):
        return ["gitleaks", *args, "--source", repo]
    if have("docker"):
        imgs = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=20) or ""
        img = next((i for i in imgs.split() if i.startswith(("ghcr.io/gitleaks/gitleaks", "zricethezav/gitleaks"))), None)
        if img:
            return ["docker", "run", "--rm", "--network", "none", "-v", f"{repo}:/repo:ro", img, *args, "--source", "/repo"]
    return None


def _find_repos(roots: list[str], max_depth: int = 4, limit: int = 60) -> list[str]:
    repos = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        base = root.rstrip("/").count("/")
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames[:] = []           # don't descend into a repo's subfolders
                continue
            if dirpath.count("/") - base >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            if len(repos) >= limit:
                return repos
    return repos


def parse_gitleaks(stdout: str) -> list[dict]:
    s = stdout.strip()
    if not s:
        return []
    try:
        return json.loads(s)
    except ValueError:
        i = s.find("[")
        try:
            return json.loads(s[i:]) if i >= 0 else []
        except ValueError:
            return []


def gitleaks(cfg: dict) -> list[Finding]:
    if not cfg.get("gitleaks", True):
        return []
    from .integrity import _cache_get, _cache_put
    cached, t = _cache_get("gitleaks", 7 * 86400)
    if cached is None:
        repos = _find_repos(cfg.get("secret_scan_roots", []))
        if not repos:
            return []
        if _gitleaks_cmd(repos[0]) is None:
            return [Finding(CAT, "info", "Git secret scan unavailable",
                            "Install gitleaks (sudo pacman -S gitleaks) or keep the gitleaks Docker image.")]
        results, t0 = {}, time.time()
        for r in repos:
            if time.time() - t0 > 1500:
                break
            cmd = _gitleaks_cmd(r)
            out = sh(cmd, timeout=240) if cmd else None
            leaks = parse_gitleaks(out or "")
            if leaks:
                results[r] = [{"rule": l.get("RuleID", "?"), "file": l.get("File", "?"),
                               "line": l.get("StartLine"), "commit": (l.get("Commit") or "")[:8]} for l in leaks[:200]]
        cached = {"repos": len(repos), "results": results}
        t = time.time()
        _cache_put("gitleaks", cached)
    res = cached.get("results", {})
    when = time.strftime("%Y-%m-%d", time.localtime(t))
    if not res:
        return [Finding(CAT, "ok", f"No secrets found in {cached.get('repos', 0)} git repos",
                        f"Scanned with gitleaks on {when}; repeats weekly.")]
    lines = []
    for repo, leaks in sorted(res.items()):
        rules = sorted({l["rule"] for l in leaks})
        lines.append(f"{repo}: {len(leaks)} ({', '.join(rules)})")
        for l in leaks[:5]:
            lines.append(f"    {l['file']}:{l['line']}  commit {l['commit'] or 'working tree'}")
    return [Finding(CAT, "medium", f"Secrets committed in {len(res)} git repo{'s' if len(res) != 1 else ''}",
                    "Deleting the file doesn't remove it from git history. Rotate each secret (new key/password), "
                    "then move it to an untracked .env. Values are redacted.\n\n" + "\n".join(lines)
                    + f"\n\n(gitleaks scan {when}; repeats weekly)",
                    fix="Rotate the credential first; then add the file to .gitignore")]
