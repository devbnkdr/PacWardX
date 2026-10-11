"""Small custom-painted widgets: switch, score ring, pills, sidebar rows."""
from __future__ import annotations

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel, QPushButton, QStyle, QStyledItemDelegate, QVBoxLayout, QWidget,
)

from . import style
from .icons import COLORS


def label(text: str = "", name: str | None = None, role: str | None = None, wrap: bool = False) -> QLabel:
    lb = QLabel(text)
    if name:
        lb.setObjectName(name)
    if role:
        lb.setProperty("role", role)
    lb.setWordWrap(wrap)
    return lb


def title_font(lb: QLabel, spacing: float = -0.4) -> QLabel:
    f = lb.font()
    f.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    lb.setFont(f)
    return lb


def card(name: str = "card") -> QFrame:
    f = QFrame()
    f.setObjectName(name)
    return f


def separator() -> QFrame:
    f = QFrame()
    f.setObjectName("rowSeparator")
    return f


def button(text: str, kind: str | None = None) -> QPushButton:
    b = QPushButton(text)
    b.setCursor(Qt.PointingHandCursor)
    if kind:
        b.setProperty("kind", kind)
    return b


class Switch(QCheckBox):
    """An iOS-style toggle. Same API as QCheckBox; text, if any, is drawn to the right."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self._pos = 0.0
        self._anim = QPropertyAnimation(self, b"knob", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self.toggled.connect(self._animate)

    def _get_knob(self) -> float:
        return self._pos

    def _set_knob(self, v: float) -> None:
        self._pos = v
        self.update()

    knob = Property(float, _get_knob, _set_knob)

    def _animate(self, on: bool):
        self._anim.stop()
        if not self.isVisible():
            self._set_knob(1.0 if on else 0.0)
            return
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def setChecked(self, on: bool) -> None:  # noqa: N802 - Qt naming
        super().setChecked(on)
        self._set_knob(1.0 if on else 0.0)

    def sizeHint(self) -> QSize:
        w = 42
        if self.text():
            w += 10 + self.fontMetrics().horizontalAdvance(self.text())
        return QSize(w, 26)

    def hitButton(self, pos) -> bool:  # noqa: N802
        return self.rect().contains(pos)

    def paintEvent(self, _ev):
        t = style.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        track = QRectF(0, (self.height() - 24) / 2, 42, 24)
        off, on = QColor(t["track"]), QColor(COLORS["ok"])
        mix = QColor(
            round(off.red() + (on.red() - off.red()) * self._pos),
            round(off.green() + (on.green() - off.green()) * self._pos),
            round(off.blue() + (on.blue() - off.blue()) * self._pos),
        )
        if not self.isEnabled():
            mix.setAlpha(110)
        p.setPen(Qt.NoPen)
        p.setBrush(mix)
        p.drawRoundedRect(track, 12, 12)
        x = track.left() + 2 + self._pos * (track.width() - 24)
        p.setBrush(QColor(0, 0, 0, 40))
        p.drawEllipse(QRectF(x, track.top() + 2.6, 20, 20))
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(x, track.top() + 2, 20, 20))
        if self.text():
            p.setPen(self.palette().color(self.foregroundRole()))
            p.drawText(QRectF(track.right() + 10, 0, self.width() - track.right() - 10, self.height()),
                       Qt.AlignVCenter | Qt.AlignLeft, self.text())
        p.end()


class ScoreRing(QWidget):
    """Activity-style ring showing the 0–100 score."""

    def __init__(self, size: int = 112):
        super().__init__()
        self.setFixedSize(size, size)
        self._score: int | None = None
        self._color = QColor(COLORS[None])

    def set_score(self, score: int | None, status: str | None):
        self._score = score
        self._color = QColor(COLORS.get(status, COLORS[None]))
        self.update()

    def paintEvent(self, _ev):
        t = style.tokens()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = 10.0
        r = QRectF(w / 2 + 1, w / 2 + 1, self.width() - w - 2, self.height() - w - 2)
        p.setPen(QPen(QColor(t["track"]), w, Qt.SolidLine, Qt.RoundCap))
        p.drawEllipse(r)
        if self._score:
            p.setPen(QPen(self._color, w, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, 90 * 16, -int(360 * 16 * self._score / 100))
        f = QFont(self.font())
        f.setPointSizeF(22)
        f.setWeight(QFont.Bold)
        p.setFont(f)
        p.setPen(QColor(t["text"]))
        p.drawText(QRectF(0, -8, self.width(), self.height()), Qt.AlignCenter,
                   "–" if self._score is None else str(self._score))
        f.setPointSizeF(8.5)
        f.setWeight(QFont.DemiBold)
        p.setFont(f)
        p.setPen(QColor(t["secondary"]))
        p.drawText(QRectF(0, 22, self.width(), self.height()), Qt.AlignCenter, "SCORE")
        p.end()


class Pill(QLabel):
    """A rounded, tinted label, e.g. '3 High'."""

    def __init__(self, text: str = "", status: str | None = None):
        super().__init__(text)
        self.status = status
        f = self.font()
        f.setWeight(QFont.DemiBold)
        f.setPointSizeF(9.5)
        self.setFont(f)
        self.setContentsMargins(10, 3, 10, 3)

    def set(self, text: str, status: str | None):
        self.setText(text)
        self.status = status
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QColor(COLORS.get(self.status, COLORS[None]))
        bg = QColor(c)
        bg.setAlpha(36)
        p.setPen(Qt.NoPen)
        p.setBrush(bg)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        p.drawRoundedRect(r, r.height() / 2, r.height() / 2)
        if style.is_dark():
            fg = c.lighter(115)
        else:
            fg = c.darker(125) if self.status == "low" else c
        p.setPen(fg)
        p.setFont(self.font())
        p.drawText(self.contentsRect(), Qt.AlignCenter, self.text())
        p.end()


class SidebarDelegate(QStyledItemDelegate):
    """Rounded selection, coloured glyph tile, optional section header and count badge."""

    KEY, BADGE, BADGE_STATUS, HEADER = Qt.UserRole, Qt.UserRole + 1, Qt.UserRole + 2, Qt.UserRole + 3

    def sizeHint(self, option, index) -> QSize:
        return QSize(180, 30 if index.data(self.HEADER) else 34)

    def paint(self, p: QPainter, option, index):
        t = style.tokens()
        p.save()
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(option.rect).adjusted(10, 1, -10, -1)
        text = index.data(Qt.DisplayRole)
        if index.data(self.HEADER):
            f = QFont(option.font)
            f.setPointSizeF(8.5)
            f.setWeight(QFont.DemiBold)
            p.setFont(f)
            p.setPen(QColor(t["tertiary"]))
            p.drawText(r.adjusted(8, 8, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, text.upper())
            p.restore()
            return
        if option.state & QStyle.State_Selected:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(t["accent"]))
            p.drawRoundedRect(r, 8, 8)
        elif option.state & QStyle.State_MouseOver:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(255, 255, 255, 18) if style.is_dark() else QColor(0, 0, 0, 18))
            p.drawRoundedRect(r, 8, 8)
        icon = index.data(Qt.DecorationRole)
        x = r.left() + 7
        if icon is not None:
            icon.paint(p, int(x), int(r.center().y() - 11), 22, 22)
            x += 32
        selected = bool(option.state & QStyle.State_Selected)
        p.setPen(QColor("white") if selected else QColor(t["text"]))
        f = QFont(option.font)
        f.setWeight(QFont.Medium)
        p.setFont(f)
        badge = index.data(self.BADGE)
        right = r.right() - 8
        if badge:
            bf = QFont(option.font)
            bf.setPointSizeF(8.5)
            bf.setWeight(QFont.Bold)
            bw = max(20, QFontMetrics(bf).horizontalAdvance(str(badge)) + 12)
            br = QRectF(right - bw, r.center().y() - 9, bw, 18)
            c = QColor(COLORS.get(index.data(self.BADGE_STATUS), COLORS[None]))
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(255, 255, 255, 235) if selected else c)
            p.drawRoundedRect(br, 9, 9)
            p.setFont(bf)
            p.setPen(c if selected else QColor("white"))
            p.drawText(br, Qt.AlignCenter, str(badge))
            right = br.left() - 6
            p.setFont(f)
            p.setPen(QColor("white") if selected else QColor(t["text"]))
        p.drawText(QRectF(x, r.top(), right - x, r.height()), Qt.AlignLeft | Qt.AlignVCenter, text)
        p.restore()


class EmptyState(QWidget):
    def __init__(self, pixmap, title: str, sub: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addStretch(1)
        icon = QLabel()
        icon.setPixmap(pixmap)
        icon.setAlignment(Qt.AlignCenter)
        lay.addWidget(icon)
        t = label(title, "cardTitle")
        t.setAlignment(Qt.AlignCenter)
        s = label(sub, role="secondary", wrap=True)
        s.setAlignment(Qt.AlignCenter)
        lay.addSpacing(6)
        lay.addWidget(t)
        lay.addWidget(s)
        lay.addStretch(1)


def row(left: QWidget, right: QWidget | None = None, margins=(16, 10, 16, 10)) -> QWidget:
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(*margins)
    h.addWidget(left, 1)
    if right is not None:
        h.addWidget(right, 0, Qt.AlignRight | Qt.AlignVCenter)
    return w
