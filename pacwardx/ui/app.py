"""PacWardX desktop window + tray icon."""
from __future__ import annotations

import html
import shutil
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QScrollArea, QSpinBox, QStackedWidget, QSystemTrayIcon, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from .. import __version__, config
from ..client import pick_backend
from ..findings import CATEGORIES, CATEGORY_LABELS, SEV_RANK
from . import help as helptext
from . import style
from .icons import COLORS, app_icon, app_pixmap, dot_icon, shield_icon, shield_pixmap, tile_icon, tile_pixmap
from .widgets import (
    EmptyState, Pill, ScoreRing, SidebarDelegate, Switch, button, card, label, row, separator, title_font,
)

REPO_URL = "https://github.com/devbnkdr/PacWardX"

SEV_LABEL = {"ok": "OK", "info": "Info", "low": "Low", "medium": "Medium", "high": "High", None: "Not scanned"}
STATUS_TEXT = {
    "ok": "All checks passed",
    "info": "Nothing needs attention",
    "low": "Minor items to review",
    "medium": "Action recommended",
    "high": "Action needed",
    None: "No scan yet",
}


# --------------------------------------------------------------------------- workers
class Worker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self):
        try:
            self.done.emit(self.fn(*self.args))
        except Exception as e:  # noqa: BLE001
            self.failed.emit(repr(e))


# --------------------------------------------------------------------------- widgets
def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "never"
    try:
        d = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    delta = datetime.now() - d
    m = int(delta.total_seconds() // 60)
    if m < 1:
        return "just now"
    if m < 60:
        return f"{m} min ago"
    if m < 60 * 24:
        return f"{m // 60} h ago"
    return d.strftime("%b %d, %H:%M")


def _mono() -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    f.setPointSizeF(9.5)
    return f


def _sev_item(item: QTreeWidgetItem, col: int, sev: str | None) -> None:
    item.setForeground(col, QColor(COLORS.get(sev, COLORS[None])))
    f = item.font(col)
    f.setWeight(QFont.DemiBold)
    item.setFont(col, f)


def _tree(headers: list[str]) -> QTreeWidget:
    t = QTreeWidget()
    t.setHeaderLabels(headers)
    t.setRootIsDecorated(False)
    t.setUniformRowHeights(True)
    t.setIndentation(0)
    t.setMouseTracking(True)
    t.setFrameShape(QFrame.NoFrame)
    hdr = t.header()
    hdr.setStretchLastSection(False)
    hdr.setSectionResizeMode(0, QHeaderView.Stretch)
    for i in range(1, len(headers)):
        hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
    hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return t


def _page() -> tuple[QWidget, QVBoxLayout]:
    w = QWidget()
    w.setObjectName("page")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(32, 28, 32, 24)
    lay.setSpacing(16)
    return w, lay


def _page_header(title: str) -> tuple[QHBoxLayout, QLabel]:
    head = QHBoxLayout()
    text = QVBoxLayout()
    text.setSpacing(2)
    t = title_font(label(title, "largeTitle"), -0.6)
    sub = label("", role="tertiary")
    text.addWidget(t)
    text.addWidget(sub)
    head.addLayout(text, 1)
    return head, sub


def _bullets(items: list[str]) -> QLabel:
    """A wrapped bullet list from our own static text."""
    lb = label("<br>".join(f"•&nbsp;&nbsp;{html.escape(i)}" for i in items), role="secondary", wrap=True)
    lb.setTextFormat(Qt.RichText)
    return lb


def _text_card(title: str, body: QWidget) -> QFrame:
    c = card()
    v = QVBoxLayout(c)
    v.setContentsMargins(20, 16, 20, 18)
    v.setSpacing(8)
    v.addWidget(label(title, "sectionTitle"))
    v.addWidget(body)
    v.addStretch(1)
    return c


class CategoryCard(QFrame):
    clicked = Signal(str)

    def __init__(self, cat: str):
        super().__init__()
        self.cat = cat
        self.setObjectName("categoryCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(92)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(14)
        tile = QLabel()
        tile.setPixmap(tile_pixmap(cat, 36))
        tile.setFixedSize(36, 36)
        lay.addWidget(tile, 0, Qt.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(3)
        top = QHBoxLayout()
        self.title = label(CATEGORY_LABELS[cat], "cardTitle")
        self.status = QLabel()
        self.status.setFixedSize(18, 18)
        top.addWidget(self.title, 1)
        top.addWidget(self.status)
        self.sub = label("Not scanned", role="secondary", wrap=True)
        self.when = label("", role="tertiary")
        text.addLayout(top)
        text.addWidget(self.sub)
        text.addStretch(1)
        text.addWidget(self.when)
        lay.addLayout(text, 1)
        self.set_status(None, 0, None)

    def set_status(self, worst, count, ts, extra: str = ""):
        self.status.setPixmap(shield_pixmap(worst, 18))
        if worst is None:
            self.sub.setText("Not scanned yet")
        elif worst in ("ok", "info"):
            self.sub.setText("No issues" + (f" · {extra}" if extra else ""))
        else:
            self.sub.setText(f"{SEV_LABEL[worst]} severity findings" + (f" · {extra}" if extra else ""))
        self.when.setText(f"Checked {_fmt_ts(ts)}" if ts else "")

    def mousePressEvent(self, ev):
        self.clicked.emit(self.cat)


class FindingsPage(QWidget):
    def __init__(self, cat: str, on_scan, on_ignore):
        super().__init__()
        self.cat = cat
        self._on_ignore = on_ignore
        self.setObjectName("page")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 24)
        lay.setSpacing(16)
        head, self.when = _page_header(CATEGORY_LABELS[cat])
        about = button("What's checked", "link")
        about.clicked.connect(self._explain)
        head.addWidget(about, 0, Qt.AlignVCenter)
        head.addSpacing(8)
        self.btn = button("Re-check")
        self.btn.clicked.connect(lambda: on_scan([cat]))
        head.addWidget(self.btn, 0, Qt.AlignVCenter)
        lay.addLayout(head)

        # page-specific controls go here (files: scan a folder; changes: accept)
        self.extras = QHBoxLayout()
        self.extras.setSpacing(12)
        lay.addLayout(self.extras)

        body = QHBoxLayout()
        body.setSpacing(16)
        list_card = card()
        lc = QVBoxLayout(list_card)
        lc.setContentsMargins(6, 6, 6, 6)
        frow = QHBoxLayout()
        frow.setContentsMargins(6, 4, 6, 2)
        frow.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter findings…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._render)
        self.sev_filter = QComboBox()
        for text, minimum in (("All", None), ("Needs attention", "low"), ("Medium and up", "medium"), ("High only", "high")):
            self.sev_filter.addItem(text, minimum)
        self.sev_filter.currentIndexChanged.connect(self._render)
        frow.addWidget(self.search, 1)
        frow.addWidget(self.sev_filter)
        lc.addLayout(frow)
        self.tree = _tree(["Finding", "Severity"])
        self.tree.itemSelectionChanged.connect(self._show_detail)
        lc.addWidget(self.tree)
        body.addWidget(list_card, 3)

        detail_card = card()
        dc = QVBoxLayout(detail_card)
        dc.setContentsMargins(0, 0, 0, 0)
        self.detail_stack = QStackedWidget()
        self.detail_stack.addWidget(EmptyState(tile_pixmap(cat, 44), "No finding selected",
                                               "Select a finding to see details and the suggested fix."))
        d = QWidget()
        dl = QVBoxLayout(d)
        dl.setContentsMargins(20, 18, 20, 18)
        dl.setSpacing(10)
        self.d_sev = Pill()
        self.d_title = label("", "sectionTitle", wrap=True)
        self.d_title.setTextFormat(Qt.PlainText)  # titles can contain process and file names
        self.d_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        sevrow = QHBoxLayout()
        sevrow.addWidget(self.d_sev)
        sevrow.addStretch(1)
        self.wiki_btn = button("Learn more", "link")
        self.wiki_btn.setToolTip("Open the related ArchWiki page in your browser")
        self.wiki_btn.clicked.connect(lambda: self._wiki and QDesktopServices.openUrl(QUrl(self._wiki)))
        sevrow.addWidget(self.wiki_btn)
        self.ignore_btn = button("Ignore", "link")
        self.ignore_btn.setToolTip("Stop counting this finding. It stays listed here, dimmed, and you can undo it.")
        self.ignore_btn.clicked.connect(self._toggle_ignore)
        sevrow.addWidget(self.ignore_btn)
        dl.addLayout(sevrow)
        dl.addWidget(self.d_title)
        dl.addWidget(separator())
        self.detail = QPlainTextEdit()
        self.detail.setObjectName("detail")
        self.detail.setReadOnly(True)
        self.detail.setFont(_mono())
        dl.addWidget(self.detail, 1)
        self.fix_box = QWidget()
        fb = QVBoxLayout(self.fix_box)
        fb.setContentsMargins(0, 0, 0, 0)
        fb.setSpacing(6)
        fhead = QHBoxLayout()
        fhead.addWidget(label("SUGGESTED FIX", "groupHeader"))
        fhead.addStretch(1)
        self.copy_btn = button("Copy", "link")
        self.copy_btn.clicked.connect(self._copy_fix)
        fhead.addWidget(self.copy_btn)
        fb.addLayout(fhead)
        code = card("codeBlock")
        cl = QVBoxLayout(code)
        cl.setContentsMargins(12, 10, 12, 10)
        self.fix_label = label("", "code", wrap=True)
        self.fix_label.setTextFormat(Qt.PlainText)
        self.fix_label.setFont(_mono())
        self.fix_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cl.addWidget(self.fix_label)
        fb.addWidget(code)
        dl.addWidget(self.fix_box)
        self.detail_stack.addWidget(d)
        dc.addWidget(self.detail_stack)
        body.addWidget(detail_card, 2)
        lay.addLayout(body, 1)
        self._current_fix = ""
        self._block: dict | None = None
        self._wiki: str | None = None

    def populate(self, block: dict | None):
        self._block = block
        if not block:
            self.when.setText("Not scanned yet")
        else:
            self.when.setText(f"Checked {_fmt_ts(block.get('ts'))} in {block.get('seconds', 0)}s")
        self._render()

    def _matches(self, f: dict) -> bool:
        minimum = self.sev_filter.currentData()
        if minimum and (f.get("ignored") or SEV_RANK[f["severity"]] < SEV_RANK[minimum]):
            return False
        q = self.search.text().strip().lower()
        return not q or q in f["title"].lower() or q in (f.get("detail") or "").lower()

    def _render(self):
        selected = self._selected_id()
        self.tree.clear()
        self.detail_stack.setCurrentIndex(0)
        self._current_fix = ""
        if not self._block:
            return
        findings = sorted(self._block.get("findings", []),
                          key=lambda f: (bool(f.get("ignored")), -SEV_RANK[f["severity"]]))
        for f in filter(self._matches, findings):
            ignored = bool(f.get("ignored"))
            item = QTreeWidgetItem([f["title"], "Ignored" if ignored else SEV_LABEL[f["severity"]]])
            item.setIcon(0, dot_icon(None if ignored else f["severity"]))
            item.setData(0, Qt.UserRole, f)
            item.setToolTip(0, f["title"] + ("  (ignored)" if ignored else ""))
            if ignored:
                for col in (0, 1):
                    item.setForeground(col, QColor(COLORS[None]))
            else:
                _sev_item(item, 1, f["severity"])
            self.tree.addTopLevelItem(item)
            if selected and f.get("id") == selected:
                item.setSelected(True)
                self.tree.setCurrentItem(item)

    def _explain(self):
        items = "\n".join(f"•  {i}" for i in helptext.CATEGORY_HELP[self.cat])
        QMessageBox.information(self, f"{CATEGORY_LABELS[self.cat]}: what's checked",
                                f"{items}\n\nEvery check only reads. Fixes are suggestions for you to review.")

    def _selected_id(self) -> str | None:
        items = self.tree.selectedItems()
        return items[0].data(0, Qt.UserRole).get("id") if items else None

    def _show_detail(self):
        items = self.tree.selectedItems()
        if not items:
            self.detail_stack.setCurrentIndex(0)
            return
        f = items[0].data(0, Qt.UserRole)
        self.d_sev.set(SEV_LABEL[f["severity"]], f["severity"])
        self.ignore_btn.setText("Stop ignoring" if f.get("ignored") else "Ignore")
        self.ignore_btn.setVisible(f["severity"] != "ok")
        self._wiki = helptext.learn_more(f["title"])
        self.wiki_btn.setVisible(bool(self._wiki))
        self.d_title.setText(f["title"])
        self.detail.setPlainText(f.get("detail") or "No further detail.")
        self._current_fix = f.get("fix") or ""
        self.fix_label.setText(self._current_fix)
        self.fix_box.setVisible(bool(self._current_fix))
        self.copy_btn.setText("Copy")
        self.detail_stack.setCurrentIndex(1)

    def _toggle_ignore(self):
        items = self.tree.selectedItems()
        if not items:
            return
        f = items[0].data(0, Qt.UserRole)
        if f.get("ignored"):
            self._on_ignore(f["id"], False, "")
            return
        note, ok = QInputDialog.getText(
            self, "Ignore finding",
            f"Ignore “{f['title']}”?\n\nIt won't count toward the score, badges or alerts. "
            "You can undo this here or in Settings.\n\nNote (optional), e.g. why it's fine:")
        if ok:
            self._on_ignore(f["id"], True, note)

    def _copy_fix(self):
        QGuiApplication.clipboard().setText(self._current_fix)
        self.copy_btn.setText("Copied")
        QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy"))


# --------------------------------------------------------------------------- main window
class MainWindow(QMainWindow):
    def __init__(self, start_hidden: bool):
        super().__init__()
        self.setWindowTitle("PacWardX")
        self.resize(1180, 800)
        self.setMinimumSize(980, 680)
        self.backend, self.have_daemon = pick_backend()
        self.state: dict = {}
        self.summary: dict = {}
        self._workers: list[Worker] = []
        self._quitting = False
        self._poll = QTimer(self); self._poll.setInterval(1500); self._poll.timeout.connect(self.refresh)

        self._build_ui()
        self._build_tray()
        self.refresh()
        if not start_hidden:
            self.show()
        # keep the dashboard fresh while the daemon works in the background
        self._auto = QTimer(self); self._auto.setInterval(60_000); self._auto.timeout.connect(self.refresh); self._auto.start()

    # -- layout
    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root)
        outer = QHBoxLayout(root); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)

        # sidebar
        side = QWidget(); side.setObjectName("sidebarPane"); side.setFixedWidth(232)
        sl = QVBoxLayout(side); sl.setContentsMargins(0, 22, 0, 14); sl.setSpacing(0)
        brand = QHBoxLayout(); brand.setContentsMargins(20, 0, 20, 0); brand.setSpacing(10)
        brand_icon = QLabel(); brand_icon.setPixmap(app_pixmap(32)); brand_icon.setFixedSize(32, 32)
        bt = QVBoxLayout(); bt.setSpacing(0)
        bt.addWidget(title_font(label("PacWardX", "brand"), -0.3))
        bt.addWidget(label(f"Version {__version__}", "version"))
        brand.addWidget(brand_icon); brand.addLayout(bt, 1)
        sl.addLayout(brand)
        sl.addSpacing(18)

        self.nav = QListWidget(); self.nav.setObjectName("sidebar")
        self.nav.setItemDelegate(SidebarDelegate(self.nav))
        self.nav.setMouseTracking(True)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setFrameShape(QFrame.NoFrame)
        self.nav_items: dict[str, QListWidgetItem] = {}
        entries = [("welcome", "Welcome"), ("overview", "Overview"), (None, "Checks"),
                   *[(c, CATEGORY_LABELS[c]) for c in CATEGORIES],
                   (None, "General"), ("history", "History"), ("settings", "Settings"), ("help", "Help")]
        for key, text in entries:
            it = QListWidgetItem(text, self.nav)
            if key is None:
                it.setData(SidebarDelegate.HEADER, True)
                it.setFlags(Qt.NoItemFlags)
                continue
            it.setData(SidebarDelegate.KEY, key)
            it.setIcon(tile_icon(key))
            self.nav_items[key] = it
        self.nav.currentItemChanged.connect(lambda cur, _prev: self._nav_changed(cur))
        sl.addWidget(self.nav, 1)

        foot = QHBoxLayout(); foot.setContentsMargins(20, 0, 16, 0); foot.setSpacing(8)
        self.svc_dot = QLabel(); self.svc_dot.setFixedSize(16, 16)
        self.backend_label = label("", role="tertiary", wrap=True)
        foot.addWidget(self.svc_dot, 0, Qt.AlignTop); foot.addWidget(self.backend_label, 1)
        sl.addLayout(foot)
        outer.addWidget(side)

        self.pages = QStackedWidget()
        outer.addWidget(self.pages, 1)
        self.page_index: dict[str, int] = {}

        self._build_welcome()
        self._build_help()

        # overview
        ov, ovl = _page()
        hero = card(); hl = QHBoxLayout(hero); hl.setContentsMargins(24, 22, 28, 22); hl.setSpacing(22)
        self.hero_icon = QLabel(); self.hero_icon.setFixedSize(84, 84)
        hl.addWidget(self.hero_icon, 0, Qt.AlignTop)
        hv = QVBoxLayout(); hv.setSpacing(6)
        self.hero_title = title_font(label("No scan yet", "heroTitle"), -0.5)
        self.hero_sub = label("", role="secondary", wrap=True)
        hv.addWidget(self.hero_title); hv.addWidget(self.hero_sub)
        chips = QHBoxLayout(); chips.setSpacing(6)
        self.chips = {}
        for sev in ("high", "medium", "low", "info"):
            self.chips[sev] = Pill("", sev)
            chips.addWidget(self.chips[sev])
        chips.addStretch(1)
        hv.addSpacing(2); hv.addLayout(chips); hv.addSpacing(8)
        btns = QHBoxLayout(); btns.setSpacing(8)
        self.scan_btn = button("Quick scan", "primary")
        self.scan_btn.clicked.connect(lambda: self.start_scan(list(CATEGORIES)))
        self.files_btn = button("Full file scan")
        self.files_btn.clicked.connect(lambda: self.start_file_scan(None))
        self.copy_btn = button("Copy report")
        self.copy_btn.setToolTip("Copy a summary of every finding. Your machine name, user name and home path are left out.")
        self.copy_btn.clicked.connect(self.copy_report)
        self.save_btn = button("Save full report…")
        self.save_btn.clicked.connect(self.save_report)
        for b in (self.scan_btn, self.files_btn, self.copy_btn, self.save_btn):
            btns.addWidget(b)
        btns.addStretch(1)
        hv.addLayout(btns)
        hl.addLayout(hv, 1)
        self.ring = ScoreRing(112)
        hl.addWidget(self.ring, 0, Qt.AlignVCenter)
        ovl.addWidget(hero)

        grid = QGridLayout(); grid.setSpacing(12)
        self.cards = {}
        for i, cat in enumerate(CATEGORIES):
            c = CategoryCard(cat)
            c.clicked.connect(self._open_category)
            self.cards[cat] = c
            grid.addWidget(c, i // 3, i % 3)
        ovl.addLayout(grid)

        top = card(); tl = QVBoxLayout(top); tl.setContentsMargins(6, 14, 6, 6); tl.setSpacing(6)
        th = QHBoxLayout(); th.setContentsMargins(14, 0, 14, 0)
        th.addWidget(label("Top findings", "sectionTitle")); th.addStretch(1)
        th.addWidget(label("Double-click to open", role="tertiary"))
        tl.addLayout(th)
        self.top_issues = _tree(["Finding", "Category", "Severity"])
        self.top_issues.itemDoubleClicked.connect(lambda it, _c: self._open_category(it.data(0, Qt.UserRole)))
        self.top_stack = QStackedWidget()
        self.top_stack.addWidget(EmptyState(shield_pixmap("ok", 44), "All clear",
                                            "No findings. PacWardX keeps checking in the background."))
        self.top_stack.addWidget(self.top_issues)
        self.top_stack.addWidget(EmptyState(shield_pixmap(None, 44), "Not scanned yet",
                                            "Press Quick scan to check this computer. It takes about a minute."))
        tl.addWidget(self.top_stack, 1)
        ovl.addWidget(top, 1)
        self._add_page("overview", ov)

        # category pages
        self.cat_pages = {}
        for cat in CATEGORIES:
            page = FindingsPage(cat, self.start_scan, self._set_ignored)
            self.cat_pages[cat] = page
            self._add_page(cat, page)
        # files page extras
        fp = self.cat_pages["files"]
        pick = button("Scan a folder…")
        pick.clicked.connect(self._pick_folder)
        self.clam_box = Switch("Use ClamAV if installed")
        fp.extras.addWidget(pick); fp.extras.addSpacing(8); fp.extras.addWidget(self.clam_box); fp.extras.addStretch(1)

        # changes page extras
        cp = self.cat_pages["changes"]
        acc = button("Accept changes", "primary")
        acc.setToolTip("Record the current state as normal. Only do this for changes you made yourself.")
        acc.clicked.connect(self._accept_changes)
        cp.extras.addWidget(label("Anything new since the last accepted baseline is listed here.", role="secondary"))
        cp.extras.addStretch(1); cp.extras.addWidget(acc)

        # history
        hist, hl2 = _page()
        head, self.hist_sub = _page_header("History")
        hl2.addLayout(head)
        hbody = QHBoxLayout(); hbody.setSpacing(16)
        hc = card(); hcl = QVBoxLayout(hc); hcl.setContentsMargins(6, 6, 6, 6)
        self.hist_tree = _tree(["When", "Status", "Score", "High", "Medium", "Low"])
        self.hist_tree.itemSelectionChanged.connect(self._show_history_row)
        hcl.addWidget(self.hist_tree)
        hbody.addWidget(hc, 3)
        hd = card(); hdl = QVBoxLayout(hd); hdl.setContentsMargins(6, 6, 6, 6)
        self.hist_detail = _tree(["Finding", "Severity"])
        self.hist_detail.setIndentation(14)
        self.hist_detail.setSelectionMode(QAbstractItemView.NoSelection)
        hdl.addWidget(self.hist_detail)
        hbody.addWidget(hd, 2)
        hl2.addLayout(hbody, 1)
        self._hist_rows: list[dict] = []
        self._add_page("history", hist)

        # settings
        st, sl2 = _page()
        head, sub = _page_header("Settings")
        sub.setText(f"Saved to {str(config.CONFIG_PATH).replace(str(Path.home()), '~', 1)}")
        sl2.addLayout(head)

        def spin(lo, hi, suffix):
            s = QSpinBox(); s.setRange(lo, hi); s.setSuffix(suffix); s.setFixedWidth(110)
            # Arrows are hidden by the stylesheet. NoButtons plus a styled border collapses
            # the text field to zero width on recent Qt versions.
            s.setAlignment(Qt.AlignRight); s.lineEdit().setTextMargins(0, 0, 6, 0)
            return s

        def group(title, rows):
            box = QVBoxLayout(); box.setSpacing(6)
            box.addWidget(label(title.upper(), "groupHeader"))
            g = card(); gl = QVBoxLayout(g); gl.setContentsMargins(0, 4, 0, 4); gl.setSpacing(0)
            for i, r in enumerate(rows):
                if i:
                    gl.addWidget(separator())
                gl.addWidget(r)
            box.addWidget(g)
            sl2.addLayout(box)

        def editor(caption, widget, hint=""):
            w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(16, 12, 16, 14); v.setSpacing(6)
            v.addWidget(label(caption))
            if hint:
                v.addWidget(label(hint, role="tertiary", wrap=True))
            v.addWidget(widget)
            return w

        self.s_interval = spin(5, 1440, " min")
        self.s_files = spin(1, 720, " h")
        self.s_recent = spin(1, 90, " days")
        self.s_notify = Switch()
        self.s_weekly = Switch()
        self.s_clam = Switch()
        self.s_roots = QPlainTextEdit(); self.s_roots.setFixedHeight(70)
        self.s_excl = QPlainTextEdit(); self.s_excl.setFixedHeight(120)
        self.s_allowed = QPlainTextEdit(); self.s_allowed.setFixedHeight(70)
        group("Schedule", [
            row(label("Quick scan every"), self.s_interval),
            row(label("Full file scan every"), self.s_files),
            row(label("“Recently changed” window"), self.s_recent),
        ])
        group("Alerts", [
            row(label("Desktop notifications for new medium and high findings"), self.s_notify),
            row(label("A short summary notification once a week"), self.s_weekly),
            row(label("Run ClamAV during scheduled file scans (slow)"), self.s_clam),
        ])
        group("File scanning", [
            editor("Folders to scan", self.s_roots, "One per line."),
            editor("Excluded folders", self.s_excl, "Folder names or home-relative paths, one per line."),
        ])
        group("Network", [
            editor("Processes allowed to listen on all interfaces", self.s_allowed, "Process names, one per line."),
        ])
        self.s_ignored = QListWidget(); self.s_ignored.setFixedHeight(110)
        self.s_ignored.setObjectName("plainList")
        unignore = button("Stop ignoring")
        unignore.clicked.connect(self._unignore_selected)
        ig = QWidget(); igl = QVBoxLayout(ig); igl.setContentsMargins(16, 12, 16, 14); igl.setSpacing(6)
        igl.addWidget(label("Findings you chose to ignore. They don't count toward the score, badges or alerts.",
                            role="tertiary", wrap=True))
        igl.addWidget(self.s_ignored)
        igr = QHBoxLayout(); igr.addStretch(1); igr.addWidget(unignore); igl.addLayout(igr)
        group("Ignored findings", [ig])
        wipe = button("Delete results and history")
        wipe.clicked.connect(self._reset_data)
        group("Your data", [
            row(label("Results, history and the change baseline are stored in ~/.local/share/pacwardx, "
                      "readable only by you.", role="secondary", wrap=True), wipe),
        ])
        self._fill_settings(config.DEFAULTS)  # until the saved settings arrive
        save = button("Save settings", "primary"); save.clicked.connect(self._save_settings)
        srow = QHBoxLayout(); srow.addStretch(1); srow.addWidget(save)
        sl2.addLayout(srow)
        sl2.addStretch(1)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(st)
        self._add_page("settings", scroll)

        first_run = not config.load().get("welcomed")
        self.nav.setCurrentItem(self.nav_items["welcome" if first_run else "overview"])
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().showMessage(f"PacWardX {__version__}")

    def _scroll(self, page: QWidget) -> QScrollArea:
        sc = QScrollArea(); sc.setWidgetResizable(True); sc.setFrameShape(QFrame.NoFrame)
        sc.setWidget(page)
        return sc

    def _build_welcome(self):
        pg, lay = _page()
        hero = QHBoxLayout(); hero.setSpacing(18)
        icon = QLabel(); icon.setPixmap(app_pixmap(64)); icon.setFixedSize(64, 64)
        words = QVBoxLayout(); words.setSpacing(4)
        words.addWidget(title_font(label("Welcome to PacWardX", "largeTitle"), -0.6))
        words.addWidget(label(helptext.ABOUT, role="secondary", wrap=True))
        hero.addWidget(icon, 0, Qt.AlignTop); hero.addLayout(words, 1)
        lay.addLayout(hero)

        cols = QHBoxLayout(); cols.setSpacing(12)
        cols.addWidget(_text_card("What it does", _bullets(helptext.DOES)), 1)
        cols.addWidget(_text_card("What it doesn't do", _bullets(helptext.DOESNT)), 1)
        lay.addLayout(cols)

        setup = card(); sv = QVBoxLayout(setup); sv.setContentsMargins(0, 12, 0, 8); sv.setSpacing(0)
        sh_ = QHBoxLayout(); sh_.setContentsMargins(20, 0, 16, 6)
        sh_.addWidget(label("Setup", "sectionTitle")); sh_.addStretch(1)
        recheck = button("Check again", "link"); recheck.clicked.connect(self._refresh_setup)
        sh_.addWidget(recheck)
        sv.addLayout(sh_)
        self.setup_rows = QVBoxLayout(); self.setup_rows.setSpacing(0)
        sv.addLayout(self.setup_rows)
        lay.addWidget(setup)

        note = label("PacWardX only reads your system and is provided as is, without warranty. It reports and "
                     "suggests. What you change is up to you. Details are under Help.", role="tertiary", wrap=True)
        lay.addWidget(note)
        btns = QHBoxLayout(); btns.setSpacing(8)
        first = button("Run first scan", "primary"); first.clicked.connect(self._first_scan)
        helpb = button("Open Help"); helpb.clicked.connect(lambda: self.nav.setCurrentItem(self.nav_items["help"]))
        btns.addWidget(first); btns.addWidget(helpb); btns.addStretch(1)
        lay.addLayout(btns)
        lay.addStretch(1)
        self._add_page("welcome", self._scroll(pg))
        self._refresh_setup()

    def _setup_row(self, ok: bool | None, title: str, detail: str, command: str = "") -> QWidget:
        w = QWidget(); h = QHBoxLayout(w); h.setContentsMargins(20, 10, 16, 10); h.setSpacing(12)
        dot = QLabel(); dot.setFixedSize(16, 16)
        dot.setPixmap(dot_icon("ok" if ok else "info" if ok is None else "medium").pixmap(16, 16))
        h.addWidget(dot, 0, Qt.AlignTop)
        text = QVBoxLayout(); text.setSpacing(2)
        text.addWidget(label(title))
        text.addWidget(label(detail, role="tertiary", wrap=True))
        if command:
            cmd = label(command, "code"); cmd.setTextFormat(Qt.PlainText); cmd.setFont(_mono())
            cmd.setTextInteractionFlags(Qt.TextSelectableByMouse)
            text.addWidget(cmd)
        h.addLayout(text, 1)
        if command:
            copy = button("Copy", "link")
            copy.clicked.connect(lambda: (QGuiApplication.clipboard().setText(command), copy.setText("Copied")))
            h.addWidget(copy, 0, Qt.AlignTop)
        return w

    def _refresh_setup(self):
        def done(helper_ok):
            while self.setup_rows.count():
                old = self.setup_rows.takeAt(0).widget()
                if old is not None:
                    old.deleteLater()
            rows = [
                self._setup_row(self.have_daemon, "Background service",
                                "Running: scans happen on schedule, even with this window closed." if self.have_daemon
                                else "Not running: scans only happen while this window is open.",
                                "" if self.have_daemon else "systemctl --user enable --now pacwardx-daemon"),
                self._setup_row(helper_ok, "Root helper",
                                "Installed: root-only checks (ports, firewall, logins, file integrity) are on." if helper_ok
                                else "Not set up: root-only checks are skipped. This command turns it on.",
                                "" if helper_ok else config.helper_setup()),
            ]
            for cmd, what, install, needed in helptext.TOOLS:
                have = shutil.which(cmd) is not None
                rows.append(self._setup_row(have if (have or needed) else None, what,
                                            f"{cmd} is installed." if have else f"{cmd} isn't installed.",
                                            "" if have else install))
            for i, r in enumerate(rows):
                if i:
                    self.setup_rows.addWidget(separator())
                self.setup_rows.addWidget(r)
        from ..checks.common import priv_available
        w = Worker(priv_available)
        w.done.connect(done)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _first_scan(self):
        self._call({"cmd": "set_config", "config": {"welcomed": True}}, lambda _r: None)
        self.nav.setCurrentItem(self.nav_items["overview"])
        self.start_scan(list(CATEGORIES))

    def _build_help(self):
        pg, lay = _page()
        head, sub = _page_header("Help")
        sub.setText("How PacWardX works, what it checks, and answers to common questions")
        lay.addLayout(head)
        lay.addWidget(_text_card("About PacWardX", label(helptext.ABOUT, role="secondary", wrap=True)))

        sev = card(); sv = QVBoxLayout(sev); sv.setContentsMargins(20, 16, 20, 14); sv.setSpacing(8)
        sv.addWidget(label("Severity levels", "sectionTitle"))
        for key, name, meaning in helptext.SEVERITIES:
            r = QHBoxLayout(); r.setSpacing(10)
            dot = QLabel(); dot.setFixedSize(16, 16); dot.setPixmap(dot_icon(key).pixmap(16, 16))
            n = label(name); n.setFixedWidth(64)
            r.addWidget(dot); r.addWidget(n); r.addWidget(label(meaning, role="secondary", wrap=True), 1)
            sv.addLayout(r)
        sv.addWidget(label("The score on the Overview starts at 100 and drops for each low, medium and high "
                           "finding. It's a quick summary, not a rating of how safe you are.", role="tertiary", wrap=True))
        lay.addWidget(sev)

        lay.addWidget(label("What each category checks", "sectionTitle"))
        grid = QGridLayout(); grid.setSpacing(12)
        for i, cat in enumerate(CATEGORIES):
            c = card(); v = QVBoxLayout(c); v.setContentsMargins(18, 14, 18, 16); v.setSpacing(8)
            t = QHBoxLayout(); t.setSpacing(8)
            ic = QLabel(); ic.setPixmap(tile_pixmap(cat, 22)); ic.setFixedSize(22, 22)
            t.addWidget(ic); t.addWidget(label(CATEGORY_LABELS[cat], "sectionTitle")); t.addStretch(1)
            v.addLayout(t)
            v.addWidget(_bullets(helptext.CATEGORY_HELP[cat]))
            v.addStretch(1)
            grid.addWidget(c, i // 2, i % 2)
        lay.addLayout(grid)

        def qa_card(title, pairs):
            c = card(); v = QVBoxLayout(c); v.setContentsMargins(20, 16, 20, 16); v.setSpacing(12)
            v.addWidget(label(title, "sectionTitle"))
            for q, a in pairs:
                qa = QVBoxLayout(); qa.setSpacing(3)
                ql = label(q); f = ql.font(); f.setWeight(QFont.DemiBold); ql.setFont(f)
                qa.addWidget(ql); qa.addWidget(label(a, role="secondary", wrap=True))
                v.addLayout(qa)
            return c
        lay.addWidget(qa_card("Questions", helptext.FAQ))
        lay.addWidget(qa_card("Troubleshooting", helptext.TROUBLESHOOTING))

        about = card(); av = QVBoxLayout(about); av.setContentsMargins(20, 16, 20, 16); av.setSpacing(8)
        av.addWidget(label(f"PacWardX {__version__}", "sectionTitle"))
        av.addWidget(label("Free and open source under the MIT License. Provided as is, without warranty of any "
                           "kind. PacWardX is a monitoring and reporting tool, not protection: a clean result doesn't "
                           "mean your computer is safe, and you're responsible for any change you make. The author "
                           "isn't liable for any loss or damage from using it.", role="secondary", wrap=True))
        links = QHBoxLayout(); links.setSpacing(8)
        for text, url in (("Project page", REPO_URL), ("Report a problem", REPO_URL + "/issues")):
            b = button(text, "link"); b.clicked.connect(lambda _c=False, u=url: QDesktopServices.openUrl(QUrl(u)))
            links.addWidget(b)
        links.addStretch(1)
        av.addLayout(links)
        lay.addWidget(about)
        lay.addStretch(1)
        self._add_page("help", self._scroll(pg))

    def _add_page(self, key: str, widget: QWidget):
        self.page_index[key] = self.pages.addWidget(widget)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(shield_icon(None), self)
        menu = QMenu()
        a_open = QAction("Open PacWardX", self); a_open.triggered.connect(self.show_window)
        a_scan = QAction("Quick scan now", self); a_scan.triggered.connect(lambda: self.start_scan(list(CATEGORIES)))
        a_copy = QAction("Copy report", self); a_copy.triggered.connect(self.copy_report)
        a_restart = QAction("Restart PacWardX", self); a_restart.triggered.connect(self.restart)
        a_quit = QAction("Quit", self); a_quit.triggered.connect(self.quit)
        menu.addAction(a_open); menu.addAction(a_scan); menu.addAction(a_copy); menu.addSeparator()
        menu.addAction(a_restart); menu.addAction(a_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self.show_window() if r == QSystemTrayIcon.Trigger else None)
        self.tray.setToolTip("PacWardX")
        self.tray.show()

    # -- navigation
    def _nav_changed(self, item: QListWidgetItem | None):
        key = item.data(SidebarDelegate.KEY) if item else None
        if key not in self.page_index:
            return
        self.pages.setCurrentIndex(self.page_index[key])
        if key == "welcome":
            self._refresh_setup()
        elif key == "history":
            self._load_history()
        elif key == "settings":
            self._load_settings()

    def _open_category(self, cat: str):
        if cat in CATEGORIES:
            self.nav.setCurrentItem(self.nav_items[cat])

    def show_window(self):
        self.show(); self.raise_(); self.activateWindow()

    def closeEvent(self, ev):
        if self._quitting or not self.tray.isVisible():
            ev.accept(); return
        ev.ignore()
        self.hide()
        if not getattr(self, "_told_tray", False):
            self.tray.showMessage("PacWardX keeps running", "Scans continue in the background. Right-click the tray icon to quit.",
                                  shield_icon("info"), 4000)
            self._told_tray = True

    def quit(self):
        self._quitting = True
        QApplication.instance().quit()

    def restart(self):
        """Restart the background service and relaunch this window (picks up code updates)."""
        import subprocess
        from PySide6.QtCore import QProcess
        self.tray.setIcon(shield_icon("scanning"))
        self.tray.setToolTip("PacWardX — restarting…")
        try:
            subprocess.run(["systemctl", "--user", "restart", "pacwardx-daemon"],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass  # the new window falls back to in-process scans if the service isn't up
        repo = str(Path(__file__).resolve().parents[2])
        args = ["-m", "pacwardx"] + ([] if self.isVisible() else ["--tray"])
        # small delay so the old tray icon is gone before the new one appears
        res = QProcess.startDetached("/bin/sh", ["-c", 'sleep 1; exec "$0" "$@"', sys.executable, *args], repo)
        if not (res[0] if isinstance(res, tuple) else res):
            QMessageBox.warning(self, "PacWardX", "Couldn't relaunch PacWardX. Start it again from the app menu.")
            return
        self.quit()

    # -- backend calls
    def _call(self, req: dict, on_done, timeout=60):
        w = Worker(lambda: self.backend.call(req, timeout))
        w.done.connect(on_done)
        w.failed.connect(self._on_fail)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _on_fail(self, msg: str):
        # daemon may have gone away; fall back to local
        self.backend, self.have_daemon = pick_backend()
        self.statusBar().showMessage(f"Backend error: {msg}", 8000)
        self._set_busy(False)

    def refresh(self):
        self._call({"cmd": "results"}, self._on_results)

    def _on_results(self, resp: dict):
        if not resp.get("ok"):
            return
        self.state = resp.get("state", {})
        running = resp.get("running")
        if running == "change watch":   # silent background pass, don't flash the UI
            running = None
        from ..engine import summary
        self.summary = summary(self.state)
        self._render(running)
        if running:
            if not self._poll.isActive():
                self._poll.start()
        else:
            self._poll.stop()
            self._set_busy(False)

    def start_scan(self, cats):
        self._set_busy(True, "Scanning…")
        self._call({"cmd": "scan", "categories": cats}, self._after_start, timeout=900)

    def start_file_scan(self, roots, clam=None):
        self._set_busy(True, "Scanning files…")
        req = {"cmd": "scan_files", "roots": roots, "clam": self.clam_box.isChecked() if clam is None else clam}
        self._call(req, self._after_start, timeout=3600)

    def _after_start(self, resp: dict):
        if resp.get("ok") and not resp.get("started") and resp.get("running"):
            self.statusBar().showMessage(f"A {resp['running']} is already running", 5000)
        self.refresh()
        if self.have_daemon:
            self._poll.start()

    def _set_busy(self, busy: bool, text: str = ""):
        self.scan_btn.setEnabled(not busy)
        self.files_btn.setEnabled(not busy)
        self.scan_btn.setText("Scanning…" if busy else "Quick scan")
        for p in self.cat_pages.values():
            p.btn.setEnabled(not busy)
        if busy:
            self.statusBar().showMessage(text)
            self.tray.setIcon(shield_icon("scanning"))
        else:
            self.statusBar().showMessage("Ready", 3000)

    def _accept_changes(self):
        r = QMessageBox.question(self, "Accept changes",
                                 "Mark everything currently listed under Changes as expected?\n\n"
                                 "Only do this if you made these changes yourself.")
        if r != QMessageBox.Yes:
            return
        def done(resp):
            if resp.get("ok"):
                self.statusBar().showMessage("Baseline updated", 4000)
            else:
                self.statusBar().showMessage(f"Could not accept: {resp.get('error')}", 6000)
            self.refresh()
        self._call({"cmd": "accept_changes"}, done, timeout=120)

    # -- export
    def _report_text(self, full: bool) -> str:
        from ..report import build
        running = None
        try:
            resp = self.backend.call({"cmd": "results"}, 10)
            if resp.get("ok"):
                self.state = resp.get("state", self.state)
                running = resp.get("running")
        except Exception:
            pass
        return build(self.state, full=full, running=running, daemon=self.have_daemon)

    def copy_report(self):
        text = self._report_text(full=False)
        QGuiApplication.clipboard().setText(text)
        n = text.count("\n") + 1
        self.statusBar().showMessage(f"Report copied to clipboard ({n} lines). Check it for personal details before sharing.", 6000)
        if not self.isVisible():
            self.tray.showMessage("PacWardX", "Report copied to clipboard.", shield_icon("info"), 3000)

    def save_report(self):
        default = str(Path.home() / f"pacwardx-report-{datetime.now():%Y%m%d-%H%M}.md")
        path, _ = QFileDialog.getSaveFileName(self, "Save full report", default, "Markdown (*.md);;Text (*.txt)")
        if not path:
            return
        Path(path).write_text(self._report_text(full=True))
        self.statusBar().showMessage(f"Saved {path}", 6000)

    def _pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to scan", str(config.DEFAULTS["file_scan_roots"][0]))
        if d:
            self.start_file_scan([d])

    # -- rendering
    def _render(self, running):
        s = self.summary
        worst = s.get("worst")
        self.hero_icon.setPixmap(shield_pixmap("scanning" if running else worst, 84))
        self.hero_title.setText(f"Scanning {running}…" if running else STATUS_TEXT.get(worst, "No scan yet"))
        c = s.get("counts", {})
        sub = f"Last scan {_fmt_ts(s.get('last_run'))}"
        fs = s.get("file_scan")
        if fs:
            sub += f" · file scan {_fmt_ts(fs.get('ts'))} ({fs.get('files', 0):,} files)"
        self.hero_sub.setText(sub)
        for sev, chip in self.chips.items():
            n = c.get(sev, 0)
            chip.set(f"{n} {SEV_LABEL[sev]}", sev if n else None)
        self.ring.set_score(s.get("score") if worst else None, worst)
        for cat, card_ in self.cards.items():
            pc = s.get("categories", {}).get(cat, {})
            extra = ""
            if cat == "files" and fs:
                extra = f"{fs.get('files', 0):,} files"
            card_.set_status(pc.get("worst"), pc.get("count", 0), pc.get("ts"), extra)
            block = self.state.get("categories", {}).get(cat)
            self.cat_pages[cat].populate(block)
            notable = [f for f in (block or {}).get("findings", [])
                       if f["severity"] in ("low", "medium", "high") and not f.get("ignored")]
            item = self.nav_items[cat]
            item.setData(SidebarDelegate.BADGE, len(notable) or None)
            item.setData(SidebarDelegate.BADGE_STATUS, pc.get("worst"))
        self.top_issues.clear()
        from ..engine import all_findings
        for f in sorted(all_findings(self.state), key=lambda f: -SEV_RANK[f["severity"]])[:12]:
            if f["severity"] in ("ok",):
                continue
            it = QTreeWidgetItem([f["title"], CATEGORY_LABELS[f["category"]], SEV_LABEL[f["severity"]]])
            it.setIcon(0, dot_icon(f["severity"]))
            it.setData(0, Qt.UserRole, f["category"])
            it.setToolTip(0, f["title"])
            _sev_item(it, 2, f["severity"])
            self.top_issues.addTopLevelItem(it)
        if not s.get("last_run"):
            self.top_stack.setCurrentIndex(2)      # nothing has run: don't claim "all clear"
        else:
            self.top_stack.setCurrentIndex(1 if self.top_issues.topLevelItemCount() else 0)
        self.svc_dot.setPixmap(dot_icon("ok" if self.have_daemon else "medium").pixmap(16, 16))
        if self.have_daemon:
            self.backend_label.setText("Background service running")
            self.backend_label.setToolTip("")
        else:
            self.backend_label.setText("Background service off — scans run in this window only")
            self.backend_label.setToolTip("Start it with: systemctl --user start pacwardx-daemon")
        icon_status = "scanning" if running else worst
        self.tray.setIcon(shield_icon(icon_status))
        self.tray.setToolTip(f"PacWardX — {STATUS_TEXT.get(worst, 'No scan yet')}")

    def _load_history(self):
        def done(resp):
            self.hist_tree.clear()
            self.hist_detail.clear()
            rows = resp.get("history", [])
            self._hist_rows = rows
            self.hist_sub.setText(f"{len(rows)} scans recorded · select one to see what changed" if rows
                                  else "No scans recorded yet")
            for i in range(len(rows) - 1, -1, -1):
                r = rows[i]
                c = r.get("counts", {})
                it = QTreeWidgetItem([r.get("ts", "")[:16].replace("T", " "), SEV_LABEL.get(r.get("worst")),
                                      str(r.get("score", "")), str(c.get("high", 0)), str(c.get("medium", 0)), str(c.get("low", 0))])
                it.setIcon(0, dot_icon(r.get("worst")))
                it.setData(0, Qt.UserRole, i)
                _sev_item(it, 1, r.get("worst"))
                self.hist_tree.addTopLevelItem(it)
            if rows:
                self.hist_tree.setCurrentItem(self.hist_tree.topLevelItem(0))
        self._call({"cmd": "history"}, done)

    def _show_history_row(self):
        from ..engine import history_diff
        self.hist_detail.clear()
        items = self.hist_tree.selectedItems()
        if not items or not self._hist_rows:
            return
        i = items[0].data(0, Qt.UserRole)
        if "findings" not in self._hist_rows[i]:
            self.hist_detail.addTopLevelItem(QTreeWidgetItem(["No details were recorded for this scan.", ""]))
            return
        d = history_diff(self._hist_rows, i)

        def group(title, findings, dim=False):
            # Ignored findings are listed dimmed, after the rest, and not counted in the heading.
            findings = sorted(findings, key=lambda x: x.get("ignored", False))
            counted = sum(1 for x in findings if not x.get("ignored"))
            head = QTreeWidgetItem([f"{title} ({counted})", ""])
            f = head.font(0); f.setBold(True); head.setFont(0, f)
            self.hist_detail.addTopLevelItem(head)
            for x in sorted(findings, key=lambda x: (x.get("ignored", False), -SEV_RANK.get(x["severity"], 0))):
                faded = dim or x.get("ignored")
                it = QTreeWidgetItem(head, [f"{CATEGORY_LABELS.get(x['category'], x['category'])}: {x['title']}",
                                            "Ignored" if x.get("ignored") else SEV_LABEL.get(x["severity"], x["severity"])])
                it.setToolTip(0, x["title"])
                it.setIcon(0, dot_icon(None if faded else x["severity"]))
                if faded:
                    for col in (0, 1):
                        it.setForeground(col, QColor(COLORS[None]))
                else:
                    _sev_item(it, 1, x["severity"])
            if not findings:
                QTreeWidgetItem(head, ["None", ""]).setForeground(0, QColor(COLORS[None]))

        if not d["first"]:
            group("New since the scan before", d["new"])
            group("Resolved since the scan before", d["resolved"], dim=True)
        group("Open at this time", d["open"])
        self.hist_detail.expandAll()

    def _load_settings(self):
        self._call({"cmd": "config"}, lambda resp: self._fill_settings({**config.DEFAULTS, **resp.get("config", {})}))

    def _reset_data(self):
        r = QMessageBox.question(self, "Delete results and history",
                                 "Delete all scan results, the scan history and the change baseline?\n\n"
                                 "Your settings are kept. The next scan starts fresh and records a new baseline.")
        if r != QMessageBox.Yes:
            return
        def done(resp):
            self.statusBar().showMessage("Results and history deleted" if resp.get("ok")
                                         else f"Couldn't delete: {resp.get('error')}", 5000)
            self.refresh()
        self._call({"cmd": "reset_data"}, done, timeout=120)

    def _set_ignored(self, fid: str, ignore: bool, note: str):
        def done(resp):
            if resp.get("ok"):
                self.statusBar().showMessage("Finding ignored" if ignore else "Finding no longer ignored", 4000)
                self._fill_ignored(resp.get("ignored", {}))
            else:
                self.statusBar().showMessage(f"Couldn't update: {resp.get('error')}", 6000)
            self.refresh()
        self._call({"cmd": "ignore" if ignore else "unignore", "id": fid, "note": note}, done)

    def _fill_ignored(self, ignored: dict):
        self.s_ignored.clear()
        for fid, info in sorted(ignored.items(), key=lambda kv: kv[1].get("ts", "")):
            cat = CATEGORY_LABELS.get(info.get("category"), "")
            text = info.get("title", fid) + (f"  ·  {cat}" if cat else "") + (f"  ·  {info['note']}" if info.get("note") else "")
            it = QListWidgetItem(text, self.s_ignored)
            it.setData(Qt.UserRole, fid)
        if not ignored:
            it = QListWidgetItem("Nothing ignored", self.s_ignored)
            it.setFlags(Qt.NoItemFlags)

    def _unignore_selected(self):
        it = self.s_ignored.currentItem()
        fid = it.data(Qt.UserRole) if it else None
        if fid:
            self._set_ignored(fid, False, "")

    def _fill_settings(self, cfg: dict):
        self.s_interval.setValue(int(cfg.get("interval_minutes", 60)))
        self.s_files.setValue(int(cfg.get("file_scan_every_hours", 24)))
        self.s_recent.setValue(int(cfg.get("recent_days", 7)))
        self.s_notify.setChecked(bool(cfg.get("notify", True)))
        self.s_weekly.setChecked(bool(cfg.get("weekly_summary", True)))
        self.s_clam.setChecked(bool(cfg.get("clamav", False)))
        self.s_roots.setPlainText("\n".join(cfg.get("file_scan_roots", [])))
        self.s_excl.setPlainText("\n".join(cfg.get("file_scan_exclude", [])))
        self.s_allowed.setPlainText("\n".join(cfg.get("allowed_listeners", [])))
        self._fill_ignored(cfg.get("ignored") or {})

    def _save_settings(self):
        cfg = {
            "interval_minutes": self.s_interval.value(),
            "file_scan_every_hours": self.s_files.value(),
            "recent_days": self.s_recent.value(),
            "notify": self.s_notify.isChecked(),
            "weekly_summary": self.s_weekly.isChecked(),
            "clamav": self.s_clam.isChecked(),
            "file_scan_roots": [l.strip() for l in self.s_roots.toPlainText().splitlines() if l.strip()],
            "file_scan_exclude": [l.strip() for l in self.s_excl.toPlainText().splitlines() if l.strip()],
            "allowed_listeners": [l.strip() for l in self.s_allowed.toPlainText().splitlines() if l.strip()],
        }
        self._call({"cmd": "set_config", "config": cfg}, lambda r: self.statusBar().showMessage("Settings saved", 3000))


def main():
    start_hidden = "--tray" in sys.argv
    app = QApplication(sys.argv)
    app.setApplicationName("PacWardX")
    app.setDesktopFileName("pacwardx")
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(app_icon())
    style.apply(app)
    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.warning(None, "PacWardX", "No system tray found; the window will close normally instead of minimising.")
    win = MainWindow(start_hidden)
    # follow the desktop's light/dark switch live
    QGuiApplication.styleHints().colorSchemeChanged.connect(lambda _s: (style.apply(app), win.update()))
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
