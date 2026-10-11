"""History drill-down, finding filters and the ArchWiki links."""
import os
import time

import pytest

from pacwardx import engine
from pacwardx.ui import help as helptext

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _row(*findings):
    return {"ts": "2026-10-01T12:00:00", "score": 90, "worst": "medium",
            "counts": {}, "findings": [list(f) for f in findings]}


A = ("a1", "medium", "network", "SSH accepts passwords")
B = ("b2", "low", "system", "Screen never locks automatically")
C = ("c3", "high", "packages", "Reboot needed — running kernel was replaced")


def test_history_diff_shows_new_and_resolved():
    rows = [_row(A, B), _row(B, C)]
    first = engine.history_diff(rows, 0)
    assert first["first"] and {f["id"] for f in first["open"]} == {"a1", "b2"}
    d = engine.history_diff(rows, 1)
    assert [f["id"] for f in d["new"]] == ["c3"]
    assert [f["id"] for f in d["resolved"]] == ["a1"]
    assert {f["id"] for f in d["open"]} == {"b2", "c3"}


def test_history_diff_treats_old_rows_without_findings_as_a_fresh_start():
    rows = [{"ts": "x", "counts": {}}, _row(A)]
    d = engine.history_diff(rows, 1)
    assert d["first"] and d["new"] == [] and [f["id"] for f in d["open"]] == ["a1"]


def test_ignoring_a_finding_is_not_shown_as_resolved():
    rows = [_row(A, B), _row(A + (1,), B)]
    d = engine.history_diff(rows, 1)
    assert d["new"] == [] and d["resolved"] == []
    assert next(f for f in d["open"] if f["id"] == "a1")["ignored"]


def test_ids_ignore_counts_but_stay_unique():
    from pacwardx.findings import Finding, unique_ids
    assert Finding("packages", "low", "12 orphaned packages").id == Finding("packages", "low", "13 orphaned packages").id
    a, b = unique_ids([Finding("network", "medium", "Docker publishes port 8080 on all interfaces"),
                       Finding("network", "medium", "Docker publishes port 9090 on all interfaces")])
    assert a.id != b.id


@pytest.mark.parametrize("title,page", [
    ("Firewall (ufw) is inactive", "Uncomplicated_Firewall"),
    ("SSH accepts passwords", "OpenSSH"),
    ("2 SSH private keys have no passphrase", "SSH_keys"),
    ("3 .pacnew/.pacsave files waiting for review", "Pacman/Pacnew_and_Pacsave"),
    ("Swap partition is not encrypted", "Dm-crypt/Swap_encryption"),
    ("Secure Boot is off", "Unified_Extensible_Firmware_Interface/Secure_Boot"),
])
def test_learn_more_links(title, page):
    assert helptext.learn_more(title) == helptext.WIKI + page


def test_learn_more_none_for_unknown():
    assert helptext.learn_more("Something nobody has heard of") is None


def test_findings_page_filters():
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtWidgets import QApplication

    from pacwardx.findings import Finding
    from pacwardx.ui import app as ui
    app = QApplication.instance() or QApplication([])  # keep a reference: widgets need a live app
    page = ui.FindingsPage("network", lambda cats: None, lambda *a: None)
    page.populate({"ts": "2026-10-01T12:00:00", "seconds": 1, "findings": [
        Finding("network", "high", "Redis listening on all interfaces", "port 6379").to_dict(),
        Finding("network", "low", "IP forwarding enabled").to_dict(),
        Finding("network", "ok", "Firewall active, default deny incoming").to_dict()]})
    assert page.tree.topLevelItemCount() == 3
    page.sev_filter.setCurrentIndex(page.sev_filter.findData("medium"))
    assert page.tree.topLevelItemCount() == 1
    page.sev_filter.setCurrentIndex(0)
    page.search.setText("6379")  # matches the detail text too
    assert page.tree.topLevelItemCount() == 1
    page.search.setText("")
    page.tree.setCurrentItem(page.tree.topLevelItem(0))
    assert page.wiki_btn.isVisibleTo(page) is False  # "Redis ..." has no wiki mapping
    page.tree.setCurrentItem(page.tree.topLevelItem(2))
    assert page._wiki == helptext.WIKI + "Uncomplicated_Firewall"
    page.deleteLater()
    app.processEvents()


def test_history_page_drilldown(monkeypatch):
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtWidgets import QApplication

    from pacwardx.ui import app as ui
    from pacwardx.ui import style
    rows = [_row(A, B), _row(B, C)]

    class Backend:
        def call(self, req, timeout=30):
            return {"history": {"ok": True, "history": rows}}.get(
                req["cmd"], {"ok": True, "running": None, "state": {}, "config": {}})

    monkeypatch.setattr(ui, "pick_backend", lambda: (Backend(), True))
    monkeypatch.setattr(ui.config, "load", lambda: {**ui.config.DEFAULTS, "welcomed": True})
    app = QApplication.instance() or QApplication([])
    style.apply(app)
    win = ui.MainWindow(True)
    win._load_history()
    deadline = time.time() + 5
    while win.hist_tree.topLevelItemCount() < 2 and time.time() < deadline:
        app.processEvents()
    assert win.hist_tree.topLevelItemCount() == 2
    heads = [win.hist_detail.topLevelItem(i).text(0) for i in range(win.hist_detail.topLevelItemCount())]
    assert heads == ["New since the scan before (1)", "Resolved since the scan before (1)", "Open at this time (2)"]
    assert "Reboot needed" in win.hist_detail.topLevelItem(0).child(0).text(0)
    win.close()
