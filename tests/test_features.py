"""Ignoring findings, the command line, the weekly summary and history details."""
import json

import pytest

from pacwardx import __main__ as cli
from pacwardx import config, engine
from pacwardx.findings import Finding


def _state(*findings):
    st = {"categories": {}, "last_run": "2026-10-01T12:00:00", "file_scan": None}
    for f in findings:
        st["categories"].setdefault(f.category, {"ts": "t", "seconds": 0, "findings": []})["findings"].append(f.to_dict())
    return st


@pytest.fixture
def cfg(monkeypatch):
    c = dict(config.DEFAULTS, ignored={})
    monkeypatch.setattr(config, "save", lambda _c: None)
    monkeypatch.setattr(engine, "save_state", lambda _s: None)
    return c


def test_ignored_findings_stop_counting_but_stay_listed(cfg):
    noisy = Finding("network", "high", "Port 8080 is reachable")
    st = _state(noisy, Finding("system", "low", "kptr_restrict is 0"))
    assert engine.summary(st)["worst"] == "high"
    engine.set_ignored(cfg, st, noisy.id, True, "my dev server")
    s = engine.summary(st)
    assert s["worst"] == "low" and s["score"] == 97 and s["categories"]["network"]["count"] == 0
    assert [f["title"] for f in engine.all_findings(st, include_ignored=True)].count("Port 8080 is reachable") == 1
    assert cfg["ignored"][noisy.id]["note"] == "my dev server"
    # still ignored after the next scan produces the same finding again
    fresh = _state(noisy)
    engine.mark_ignored(fresh, cfg)
    assert engine.new_serious(_state(), fresh) == []
    engine.set_ignored(cfg, st, noisy.id, False)
    assert engine.summary(st)["worst"] == "high" and noisy.id not in cfg["ignored"]


def test_report_lists_ignored_separately(cfg):
    from pacwardx import report
    noisy = Finding("network", "high", "Port 8080 is reachable")
    st = _state(noisy)
    engine.set_ignored(cfg, st, noisy.id, True)
    text = report.build(st, daemon=False)
    assert "Ignored: Port 8080 is reachable" in text and "[HIGH]" not in text


def test_scan_json_and_exit_codes(monkeypatch, capsys, cfg):
    st = _state(Finding("network", "medium", "Something open", fix="close it"))
    monkeypatch.setattr(engine, "run_categories", lambda cats: st)
    assert cli.main(["scan", "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["worst"] == "medium" and out["findings"][0]["fix"] == "close it"
    monkeypatch.setattr(engine, "run_categories", lambda cats: _state(Finding("network", "ok", "fine")))
    assert cli.main(["scan"]) == 0
    assert cli.main(["scan", "--category", "nonsense"]) == 4


def test_weekly_summary_is_sent_once_a_week(monkeypatch):
    from pacwardx import daemon
    monkeypatch.setattr(engine, "save_state", lambda _s: None)
    d = daemon.Daemon()
    d.state = _state(Finding("system", "low", "x"))
    sent = []
    monkeypatch.setattr(d, "_send", lambda title, body, urgency="normal": sent.append(body))
    assert d.weekly_summary(now=1_000_000) is True
    assert d.weekly_summary(now=1_000_000 + 3600) is False
    assert d.weekly_summary(now=1_000_000 + 8 * 24 * 3600) is True
    assert "1 low" in sent[0]
    d.cfg["weekly_summary"] = False
    assert d.weekly_summary(now=1_000_000 + 30 * 24 * 3600) is False


def test_history_rows_record_open_findings_and_stay_bounded(monkeypatch):
    config.ensure_dirs()
    config.HISTORY_PATH.write_text("")
    monkeypatch.setattr(engine, "HISTORY_KEEP", 5)
    st = _state(Finding("network", "high", "open port"), Finding("system", "ok", "fine"))
    for _ in range(12):
        engine.append_history(st)
    rows = engine.read_history()
    assert len(rows) <= 5 + 200
    assert rows[-1]["findings"] == [[Finding("network", "high", "open port").id, "high", "network", "open port", 0]]


def test_ignore_does_not_wait_for_a_running_scan(cfg, monkeypatch):
    import time

    from pacwardx import daemon
    d = daemon.Daemon()
    d.cfg = cfg
    noisy = Finding("network", "high", "Port 8080 is reachable")
    d.state = _state(noisy)
    saved = []
    monkeypatch.setattr(engine, "save_state", lambda s: saved.append(1))
    d._lock.acquire()  # a long scan holds the lock
    try:
        t0 = time.time()
        assert d.handle({"cmd": "ignore", "id": noisy.id})["ok"]
        assert time.time() - t0 < 1
        assert noisy.id in cfg["ignored"] and saved == []  # the scan saves the state when it ends
        assert d.handle({"cmd": "reset_data"})["ok"] is False
    finally:
        d._lock.release()


def test_scan_exit_code_only_counts_the_categories_scanned(monkeypatch, capsys):
    st = _state(Finding("network", "high", "old network result"), Finding("system", "low", "kptr_restrict is 0"))
    monkeypatch.setattr(engine, "run_categories", lambda cats: st)
    assert cli.main(["scan", "--category", "system"]) == 1
