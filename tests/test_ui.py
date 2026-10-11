"""Build the window from demo results and visit every page. Runs without a display."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtWidgets import QApplication, QSpinBox  # noqa: E402

from pacwardx import engine  # noqa: E402
from pacwardx.findings import CATEGORIES, Finding  # noqa: E402
from pacwardx.ui import app as ui  # noqa: E402
from pacwardx.ui import style  # noqa: E402

STATE = {"last_run": "2026-10-01T12:00:00", "file_scan": None, "categories": {
    cat: {"ts": "2026-10-01T12:00:00", "seconds": 0.1, "findings": [
        Finding(cat, "medium", f"{cat} needs a look", "detail", "a fix").to_dict(),
        Finding(cat, "ok", f"{cat} is fine").to_dict()]}
    for cat in CATEGORIES}}


class FakeBackend:
    def call(self, req, timeout=30):
        return {"results": {"ok": True, "running": None, "state": STATE},
                "history": {"ok": True, "history": []},
                "config": {"ok": True, "config": {}}}.get(req["cmd"], {"ok": True})


def test_window_shows_every_page(monkeypatch):
    monkeypatch.setattr(ui, "pick_backend", lambda: (FakeBackend(), True))
    app = QApplication.instance() or QApplication([])
    style.apply(app)
    win = ui.MainWindow(False)
    win.state = STATE
    win.summary = engine.summary(STATE)
    win._render(None)
    for key, item in win.nav_items.items():
        win.nav.setCurrentItem(item)
        app.processEvents()
        assert win.nav.currentItem() is item, key
    # Settings numbers must be visible (recent Qt can collapse a styled spin box's text to nothing).
    win.nav.setCurrentItem(win.nav_items["settings"])
    app.processEvents()
    for spin in win.findChildren(QSpinBox):
        assert spin.lineEdit().width() > 40
    win.close()


def _window(monkeypatch, backend, cfg):
    monkeypatch.setattr(ui, "pick_backend", lambda: (backend, False))
    monkeypatch.setattr(ui.config, "load", lambda: {**ui.config.DEFAULTS, **cfg})
    app = QApplication.instance() or QApplication([])
    style.apply(app)
    return app, ui.MainWindow(False)


class EmptyBackend:
    def call(self, req, timeout=30):
        return {"results": {"ok": True, "running": None,
                            "state": {"categories": {}, "last_run": None, "file_scan": None}},
                "config": {"ok": True, "config": {}}}.get(req["cmd"], {"ok": True})


def test_first_run_opens_welcome_and_never_claims_all_clear(monkeypatch):
    app, win = _window(monkeypatch, EmptyBackend(), {})
    assert win.nav.currentItem() is win.nav_items["welcome"]
    win._on_results(EmptyBackend().call({"cmd": "results"}))
    assert win.top_stack.currentIndex() == 2          # "Not scanned yet", not "All clear"
    # Settings show the real defaults before the saved ones arrive
    assert (win.s_interval.value(), win.s_files.value(), win.s_recent.value()) == (60, 24, 7)
    assert win.s_notify.isChecked()
    win.close()


def test_returning_users_start_on_overview(monkeypatch):
    app, win = _window(monkeypatch, EmptyBackend(), {"welcomed": True})
    assert win.nav.currentItem() is win.nav_items["overview"]
    win.close()
