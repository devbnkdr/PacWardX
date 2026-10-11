"""The Finding record every check produces, plus severity helpers."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("ok", "info", "low", "medium", "high")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CATEGORIES = ("packages", "network", "system", "files", "changes", "opsec")
CATEGORY_LABELS = {
    "packages": "Packages",
    "network": "Network",
    "system": "System",
    "files": "Files",
    "changes": "Changes",
    "opsec": "Privacy & OpSec",
}


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""          # a command or short instruction the user can copy
    id: str = field(default="")

    def __post_init__(self):
        if self.severity not in SEV_RANK:
            raise ValueError(f"bad severity {self.severity!r}")
        if not self.id:
            # Stable across runs so we can tell new findings from old ones. Numbers are left out, so
            # "12 orphaned packages" keeps its id (and its ignore setting) when it becomes 13.
            self.id = _hash(self.category, re.sub(r"\d+", "#", self.title))

    def to_dict(self) -> dict:
        return asdict(self)


def _hash(category: str, text: str) -> str:
    return hashlib.sha1(f"{category}|{text}".encode()).hexdigest()[:12]


def unique_ids(findings: list[Finding]) -> list[Finding]:
    """Findings whose titles differ only in a number ("port 8080" and "port 9090") get ids from the
    full title instead, so each can be ignored and tracked on its own."""
    seen: dict[str, int] = {}
    for f in findings:
        seen[f.id] = seen.get(f.id, 0) + 1
    for f in findings:
        if seen[f.id] > 1:
            f.id = _hash(f.category, f.title)
    return findings


def worst(findings) -> str:
    best = "ok"
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else f["severity"]
        if SEV_RANK[sev] > SEV_RANK[best]:
            best = sev
    return best


def score(findings) -> int:
    """0–100, purely for the dashboard. 100 = nothing above 'info'."""
    penalty = {"high": 25, "medium": 10, "low": 3}
    total = 0
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else f["severity"]
        total += penalty.get(sev, 0)
    return max(0, 100 - total)
