import pytest

from pacwardx import engine
from pacwardx.findings import Finding, score, worst


def test_finding_id_is_stable_and_ignores_detail():
    a = Finding("network", "high", "Port 8080 is open", "pid 1")
    b = Finding("network", "high", "Port 8080 is open", "pid 2")
    assert a.id == b.id
    assert a.id != Finding("system", "high", "Port 8080 is open").id


def test_bad_severity_is_rejected():
    with pytest.raises(ValueError):
        Finding("network", "critical", "nope")


def test_worst_and_score():
    found = [Finding("network", "low", "a"), Finding("system", "high", "b"), {"severity": "medium"}]
    assert worst(found) == "high"
    assert score(found) == 100 - 3 - 25 - 10
    assert worst([]) == "ok" and score([]) == 100
    assert score([Finding("x", "high", str(i)) for i in range(10)]) == 0


def test_new_serious_only_reports_new_medium_and_high():
    def state(*findings):
        return {"categories": {"network": {"ts": "", "findings": [f.to_dict() for f in findings]}}}
    old = state(Finding("network", "high", "old problem"))
    new = state(Finding("network", "high", "old problem"), Finding("network", "medium", "new problem"),
                Finding("network", "low", "new but minor"))
    assert [f["title"] for f in engine.new_serious(old, new)] == ["new problem"]


def test_summary_counts_by_severity_and_category():
    st = {"categories": {"network": {"ts": "t", "findings": [Finding("network", "high", "x").to_dict(),
                                                               Finding("network", "ok", "y").to_dict()]}}}
    s = engine.summary(st)
    assert s["worst"] == "high" and s["counts"]["high"] == 1 and s["counts"]["ok"] == 1
    assert s["categories"]["network"]["count"] == 2
    assert s["categories"]["packages"]["worst"] is None
