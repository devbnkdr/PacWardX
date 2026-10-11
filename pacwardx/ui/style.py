"""Apple-style theme: design tokens, a Fusion palette and one stylesheet, in light and dark."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

LIGHT = {
    "bg": "#f5f5f7",
    "sidebar": "#ebebef",
    "surface": "#ffffff",
    "surface_alt": "#f9f9fb",
    "fill": "rgba(0, 0, 0, 0.055)",
    "fill_hover": "rgba(0, 0, 0, 0.09)",
    "text": "#1d1d1f",
    "secondary": "#6e6e73",
    "tertiary": "#a1a1a6",
    "separator": "#e3e3e8",
    "accent": "#0071e3",
    "accent_hover": "#0077ed",
    "accent_tint": "rgba(0, 113, 227, 0.12)",
    "code_bg": "#f2f2f5",
    "track": "#e8e8ed",
}

DARK = {
    "bg": "#1c1c1e",
    "sidebar": "#242426",
    "surface": "#2c2c2e",
    "surface_alt": "#323234",
    "fill": "rgba(255, 255, 255, 0.08)",
    "fill_hover": "rgba(255, 255, 255, 0.13)",
    "text": "#f5f5f7",
    "secondary": "#98989d",
    "tertiary": "#636366",
    "separator": "#3a3a3c",
    "accent": "#0a84ff",
    "accent_hover": "#409cff",
    "accent_tint": "rgba(10, 132, 255, 0.22)",
    "code_bg": "#232325",
    "track": "#3a3a3c",
}

_tokens: dict = dict(LIGHT)


def tokens() -> dict:
    return _tokens


def is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        s = scheme()
        if s == Qt.ColorScheme.Dark:
            return True
        if s == Qt.ColorScheme.Light:
            return False
    # Unknown: judge by the platform palette (KDE sets it from the colour scheme).
    return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def _pick_font() -> QFont:
    families = set(QFontDatabase.families())
    for fam in ("SF Pro Text", "Inter Variable", "Inter", "Cantarell"):
        if fam in families:
            f = QFont(fam)
            break
    else:
        f = QFont(QGuiApplication.font())
    f.setPointSizeF(10.5)
    f.setHintingPreference(QFont.PreferNoHinting)
    return f


def _palette(t: dict) -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(t["bg"]))
    p.setColor(QPalette.WindowText, QColor(t["text"]))
    p.setColor(QPalette.Base, QColor(t["surface"]))
    p.setColor(QPalette.AlternateBase, QColor(t["surface_alt"]))
    p.setColor(QPalette.Text, QColor(t["text"]))
    p.setColor(QPalette.Button, QColor(t["surface"]))
    p.setColor(QPalette.ButtonText, QColor(t["text"]))
    p.setColor(QPalette.Highlight, QColor(t["accent"]))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.ToolTipBase, QColor(t["surface"]))
    p.setColor(QPalette.ToolTipText, QColor(t["text"]))
    p.setColor(QPalette.PlaceholderText, QColor(t["tertiary"]))
    p.setColor(QPalette.Mid, QColor(t["secondary"]))
    p.setColor(QPalette.Link, QColor(t["accent"]))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor(t["tertiary"]))
    return p


CHEVRON = (Path(__file__).parent / "chevron.svg").as_posix()


def stylesheet(t: dict) -> str:
    return f"""
* {{ outline: none; }}
QMainWindow, QWidget#page {{ background: {t['bg']}; }}
QWidget {{ color: {t['text']}; }}
QToolTip {{ background: {t['surface']}; color: {t['text']}; border: 1px solid {t['separator']};
           border-radius: 6px; padding: 5px 8px; }}

/* sidebar */
QWidget#sidebarPane {{ background: {t['sidebar']}; border-right: 1px solid {t['separator']}; }}
QListWidget#sidebar {{ background: transparent; border: none; }}
QListWidget#plainList {{ background: {t['surface_alt']}; border: 1px solid {t['separator']}; border-radius: 8px; padding: 4px; }}
QLabel#brand {{ font-size: 15pt; font-weight: 700; }}
QLabel#version {{ color: {t['tertiary']}; font-size: 9pt; }}

/* type */
QLabel#largeTitle {{ font-size: 24pt; font-weight: 700; }}
QLabel#heroTitle {{ font-size: 22pt; font-weight: 700; }}
QLabel#sectionTitle {{ font-size: 12pt; font-weight: 600; }}
QLabel#cardTitle {{ font-size: 11.5pt; font-weight: 600; }}
QLabel#groupHeader {{ color: {t['secondary']}; font-size: 9pt; font-weight: 600;
 padding-left: 4px; }}
QLabel[role="secondary"] {{ color: {t['secondary']}; }}
QLabel[role="tertiary"] {{ color: {t['tertiary']}; font-size: 9.5pt; }}

/* surfaces */
QFrame#card {{ background: {t['surface']}; border: 1px solid {t['separator']}; border-radius: 14px; }}
QFrame#categoryCard {{ background: {t['surface']}; border: 1px solid {t['separator']}; border-radius: 14px; }}
QFrame#categoryCard:hover {{ border: 1px solid {t['accent']}; }}
QFrame#rowSeparator {{ background: {t['separator']}; max-height: 1px; min-height: 1px; border: none; }}
QFrame#codeBlock {{ background: {t['code_bg']}; border-radius: 10px; }}

/* buttons */
QPushButton {{ background: {t['fill']}; color: {t['text']}; border: none; border-radius: 8px;
               padding: 7px 16px; font-weight: 500; }}
QPushButton:hover {{ background: {t['fill_hover']}; }}
QPushButton:pressed {{ background: {t['fill_hover']}; padding-top: 8px; padding-bottom: 6px; }}
QPushButton:disabled {{ color: {t['tertiary']}; background: {t['fill']}; }}
QPushButton[kind="primary"] {{ background: {t['accent']}; color: white; font-weight: 600; padding: 8px 20px; border-radius: 9px; }}
QPushButton[kind="primary"]:hover {{ background: {t['accent_hover']}; }}
QPushButton[kind="primary"]:disabled {{ background: {t['fill']}; color: {t['tertiary']}; }}
QPushButton[kind="link"] {{ background: transparent; color: {t['accent']}; padding: 4px 6px; }}
QPushButton[kind="link"]:hover {{ text-decoration: underline; }}

/* lists and trees */
QTreeWidget {{ background: transparent; border: none; alternate-background-color: transparent; }}
QTreeWidget::item {{ height: 34px; padding: 0 6px; border: none; }}
QTreeWidget::item:hover {{ background: {t['fill']}; }}
QTreeWidget::item:selected {{ background: {t['accent_tint']}; color: {t['text']}; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{ background: transparent; color: {t['secondary']}; border: none;
                        border-bottom: 1px solid {t['separator']}; padding: 6px 8px; font-weight: 600; font-size: 9.5pt; }}

/* inputs */
QPlainTextEdit, QAbstractSpinBox, QLineEdit, QComboBox {{ background: {t['surface_alt']}; border: 1px solid {t['separator']};
                                    border-radius: 8px; padding: 5px 8px; selection-background-color: {t['accent']}; }}
QPlainTextEdit:focus, QAbstractSpinBox:focus, QLineEdit:focus, QComboBox:focus {{ border: 1px solid {t['accent']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox::down-arrow {{ image: url({CHEVRON}); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{ background: {t['surface']}; border: 1px solid {t['separator']}; border-radius: 8px;
                               selection-background-color: {t['accent_tint']}; selection-color: {t['text']}; padding: 4px; }}
QPlainTextEdit#detail, QLabel#code {{ background: transparent; border: none; padding: 0; }}
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {{ width: 0; border: none; }}

/* scrollbars */
QScrollArea {{ background: transparent; border: none; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {t['fill_hover']}; border-radius: 3px; min-height: 30px; min-width: 30px; }}
QScrollBar::handle:hover {{ background: {t['tertiary']}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; height: 0; width: 0; }}

/* menus, status bar */
QMenu {{ background: {t['surface']}; border: 1px solid {t['separator']}; border-radius: 10px; padding: 5px; }}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 6px; }}
QMenu::item:selected {{ background: {t['accent']}; color: white; }}
QMenu::separator {{ height: 1px; background: {t['separator']}; margin: 4px 8px; }}
QStatusBar {{ background: {t['bg']}; color: {t['secondary']}; border-top: 1px solid {t['separator']}; font-size: 9.5pt; padding-left: 12px; }}
QStatusBar::item {{ border: none; }}
QMessageBox {{ background: {t['surface']}; }}
"""


def apply(app: QApplication) -> dict:
    """(Re)apply the theme for the current light/dark setting; returns the active tokens."""
    global _tokens
    if not getattr(app, "_pacwardx_styled", False):
        app.setStyle("Fusion")
        app.setFont(_pick_font())
        app._pacwardx_styled = True
    _tokens = dict(DARK if is_dark() else LIGHT)
    app.setPalette(_palette(_tokens))
    app.setStyleSheet(stylesheet(_tokens))
    return _tokens
