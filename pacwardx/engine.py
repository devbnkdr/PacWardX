"""Runs checks, keeps the last result on disk, and diffs runs for notifications."""
from __future__ import annotations

import json
import time
from datetime import datetime

from . import config
from .checks import CHECKS, files
from .findings import CATEGORIES, SEV_RANK, Finding, score, unique_ids, worst

QUICK = ("packages", "network", "system", "files", "changes", "opsec")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load_state() -> dict:
    try:
        return json.loads(config.STATE_PATH.read_text())
    except (OSError, ValueError):
        return {"categories": {}, "last_run": None, "file_scan": None}


def save_state(state: dict) -> None:
    config.ensure_dirs()
    tmp = config.STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(config.STATE_PATH)


HISTORY_KEEP = 2000     # rows kept in history.jsonl (about three months of hourly scans)


def append_history(state: dict) -> None:
    findings = all_findings(state)
    counts = {s: 0 for s in SEV_RANK}
    for f in findings:
        counts[f["severity"]] += 1
    # What was open at the time, so History can show it and what changed since the scan before. Ignored
    # findings are kept too (flagged), so ignoring one doesn't look like it was fixed.
    notable = [[f["id"], f["severity"], f["category"], f["title"], int(bool(f.get("ignored")))]
               for f in sorted(all_findings(state, include_ignored=True), key=lambda f: -SEV_RANK[f["severity"]])
               if f["severity"] != "ok"]
    row = {"ts": _now(), "score": score(findings), "worst": worst(findings), "counts": counts,
           "findings": notable[:300]}
    config.ensure_dirs()
    with open(config.HISTORY_PATH, "a") as fh:
        fh.write(json.dumps(row) + "\n")
    _trim_history()


def _trim_history() -> None:
    try:
        lines = config.HISTORY_PATH.read_text().splitlines()
    except OSError:
        return
    if len(lines) > HISTORY_KEEP + 200:
        tmp = config.HISTORY_PATH.with_suffix(".tmp")
        tmp.write_text("\n".join(lines[-HISTORY_KEEP:]) + "\n")
        tmp.replace(config.HISTORY_PATH)


def read_history(limit: int = 200) -> list[dict]:
    try:
        lines = config.HISTORY_PATH.read_text().splitlines()
    except OSError:
        return []
    rows = []
    for l in lines[-limit:]:
        try:
            rows.append(json.loads(l))
        except ValueError:
            pass
    return rows


def history_diff(rows: list[dict], i: int) -> dict:
    """What was open at scan i of `rows`, and what appeared or went away since the scan before it."""
    def by_id(row):
        return {f[0]: {"id": f[0], "severity": f[1], "category": f[2], "title": f[3],
                       "ignored": bool(f[4]) if len(f) > 4 else False}
                for f in row.get("findings") or [] if len(f) >= 4}
    now = by_id(rows[i])
    # A row from before details were recorded can't be compared against.
    before = by_id(rows[i - 1]) if i > 0 and "findings" in rows[i - 1] else None
    if before is None:
        return {"open": list(now.values()), "new": [], "resolved": [], "first": True}
    return {"open": list(now.values()),
            "new": [f for k, f in now.items() if k not in before],
            "resolved": [f for k, f in before.items() if k not in now],
            "first": False}


def all_findings(state: dict, include_ignored: bool = False) -> list[dict]:
    """Every finding in the state. Ignored ones are left out unless asked for: they don't count anywhere."""
    out = []
    for cat in CATEGORIES:
        out.extend(f for f in state.get("categories", {}).get(cat, {}).get("findings", [])
                   if include_ignored or not f.get("ignored"))
    return out


def mark_ignored(state: dict, cfg: dict) -> dict:
    """Flag findings the user chose to ignore."""
    ignored = cfg.get("ignored") or {}
    for block in state.get("categories", {}).values():
        for f in block.get("findings", []):
            f["ignored"] = f["id"] in ignored
    return state


def set_ignored(cfg: dict, state: dict, fid: str, ignore: bool, note: str = "", persist: bool = True) -> dict:
    """Ignore or stop ignoring one finding by id. Saves settings (and the state, unless a scan that will
    save it is running); returns the state."""
    ignored = dict(cfg.get("ignored") or {})
    if ignore:
        f = next((f for f in all_findings(state, include_ignored=True) if f["id"] == fid), None)
        ignored[fid] = {"title": f["title"] if f else fid, "category": f["category"] if f else "",
                        "note": note.strip()[:200], "ts": _now()}
    else:
        ignored.pop(fid, None)
    cfg["ignored"] = ignored
    config.save(cfg)
    mark_ignored(state, cfg)
    if persist:
        save_state(state)
    return state


def run_categories(cats, cfg: dict | None = None, state: dict | None = None) -> dict:
    """Run the given categories, merge into state, save, return state."""
    cfg = cfg or config.load()
    state = state or load_state()
    for cat in cats:
        fn = CHECKS.get(cat)
        if not fn:
            continue
        t0 = time.time()
        try:
            findings = fn(cfg)
        except Exception as e:
            findings = [Finding(cat, "info", "Check crashed", repr(e))]
        state.setdefault("categories", {})[cat] = {
            "ts": _now(),
            "seconds": round(time.time() - t0, 1),
            "findings": [f.to_dict() for f in unique_ids(findings)],
        }
    state["last_run"] = _now()
    mark_ignored(state, cfg)
    save_state(state)
    return state


def run_file_scan(cfg: dict | None = None, state: dict | None = None,
                  roots: list[str] | None = None, clam: bool | None = None) -> dict:
    cfg = cfg or config.load()
    state = state or load_state()
    findings, stats = files.full(cfg, roots=roots, clam=clam)
    state.setdefault("categories", {})["files"] = {
        "ts": _now(), "seconds": stats["seconds"], "findings": [f.to_dict() for f in unique_ids(findings)],
        "stats": stats,
    }
    state["file_scan"] = {"ts": _now(), **stats}
    state["last_run"] = _now()
    mark_ignored(state, cfg)
    save_state(state)
    return state


def new_serious(old: dict, new: dict) -> list[dict]:
    """Findings at medium/high that weren't present (by id) in the previous state."""
    before = {f["id"]: SEV_RANK[f["severity"]] for f in all_findings(old)}
    return [f for f in all_findings(new)
            if SEV_RANK[f["severity"]] >= SEV_RANK["medium"] and SEV_RANK[f["severity"]] > before.get(f["id"], -1)]


def summary(state: dict) -> dict:
    findings = all_findings(state)
    counts = {s: 0 for s in SEV_RANK}
    for f in findings:
        counts[f["severity"]] += 1
    per_cat = {}
    for cat in CATEGORIES:
        c = state.get("categories", {}).get(cat)
        if not c:
            per_cat[cat] = {"worst": None, "ts": None, "count": 0}
            continue
        live = [f for f in c["findings"] if not f.get("ignored")]
        per_cat[cat] = {"worst": worst(live), "ts": c["ts"], "count": len(live)}
    return {"worst": worst(findings) if findings else None, "score": score(findings),
            "counts": counts, "categories": per_cat, "last_run": state.get("last_run"),
            "file_scan": state.get("file_scan")}


def reset_data() -> dict:
    """Delete stored results, history, the change baseline and caches. Settings are kept."""
    for p in (config.STATE_PATH, config.HISTORY_PATH, config.BASELINE_PATH, config.CACHE_PATH):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    return load_state()


def accept_changes(cfg: dict | None = None, state: dict | None = None) -> dict:
    """Take the current snapshot as the new baseline, then refresh the Changes category."""
    from .checks import changes
    cfg = cfg or config.load()
    changes.accept(cfg)
    return run_categories(["changes"], cfg, state)
