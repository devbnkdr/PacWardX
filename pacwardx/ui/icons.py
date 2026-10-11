"""Icons drawn with QPainter so the tray reflects the current status without image files."""
from __future__ import annotations

import math
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap

# Apple system colours (light-mode values read well on both themes).
COLORS = {
    "ok": "#34c759",
    "info": "#007aff",
    "low": "#e6b800",
    "medium": "#ff9500",
    "high": "#ff3b30",
    None: "#8e8e93",
    "scanning": "#8e8e93",
}

# Fixed tile colours for the sidebar, in the spirit of System Settings.
TILE_COLORS = {
    "overview": "#0a84ff",
    "packages": "#ff9f0a",
    "network": "#32ade6",
    "system": "#5e5ce6",
    "files": "#30b158",
    "changes": "#ff375f",
    "opsec": "#af52de",
    "history": "#a2845e",
    "settings": "#8e8e93",
    "welcome": "#00a39b",
    "help": "#2f6fde",
}


def _dpr_pixmap(size: int, dpr: float) -> QPixmap:
    pm = QPixmap(round(size * dpr), round(size * dpr))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.transparent)
    return pm


def shield_path(size: float, inset: float = 0.0) -> QPainterPath:
    s, i = size, inset
    p = QPainterPath()
    p.moveTo(s * 0.5, s * (0.06 + i))
    p.cubicTo(s * 0.62, s * (0.13 + i), s * (0.75 - i), s * (0.17 + i), s * (0.87 - i), s * (0.18 + i))
    p.cubicTo(s * (0.88 - i), s * 0.6, s * 0.72, s * (0.84 - i), s * 0.5, s * (0.95 - i))
    p.cubicTo(s * 0.28, s * (0.84 - i), s * (0.12 + i), s * 0.6, s * (0.13 + i), s * (0.18 + i))
    p.cubicTo(s * (0.25 + i), s * (0.17 + i), s * 0.38, s * (0.13 + i), s * 0.5, s * (0.06 + i))
    p.closeSubpath()
    return p


def _draw_mark(painter: QPainter, status: str | None, s: float, color: QColor) -> None:
    pen = QPen(color, max(1.5, s / 11), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    if status == "ok":
        path = QPainterPath(QPointF(s * 0.34, s * 0.5))
        path.lineTo(QPointF(s * 0.46, s * 0.62))
        path.lineTo(QPointF(s * 0.67, s * 0.38))
        painter.drawPath(path)
    elif status in ("low", "medium", "high"):
        painter.drawLine(QPointF(s * 0.5, s * 0.31), QPointF(s * 0.5, s * 0.55))
        painter.setBrush(color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(s * 0.5, s * 0.68), s * 0.055, s * 0.055)
    elif status == "info":
        painter.setBrush(color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(s * 0.5, s * 0.33), s * 0.055, s * 0.055)
        painter.setPen(pen)
        painter.drawLine(QPointF(s * 0.5, s * 0.47), QPointF(s * 0.5, s * 0.68))
    elif status == "scanning":
        painter.setBrush(color)
        painter.setPen(Qt.NoPen)
        for k in (-1, 0, 1):
            painter.drawEllipse(QPointF(s * (0.5 + k * 0.13), s * 0.5), s * 0.045, s * 0.045)


def shield_pixmap(status: str | None, size: int = 64, mark: bool = True, dpr: float = 2.0) -> QPixmap:
    pm = _dpr_pixmap(size, dpr)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing)
    base = QColor(COLORS.get(status, COLORS[None]))
    grad = QLinearGradient(0, 0, 0, size)
    grad.setColorAt(0.0, base.lighter(118))
    grad.setColorAt(1.0, base.darker(112))
    painter.setPen(Qt.NoPen)
    painter.setBrush(grad)
    painter.drawPath(shield_path(size))
    if size >= 32:
        # soft top highlight
        hi = QLinearGradient(0, 0, 0, size * 0.55)
        hi.setColorAt(0.0, QColor(255, 255, 255, 70))
        hi.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.setBrush(hi)
        painter.drawPath(shield_path(size, inset=0.03))
    if mark:
        _draw_mark(painter, status, size, QColor("white"))
    painter.end()
    return pm


def shield_icon(status: str | None) -> QIcon:
    icon = QIcon()
    for s in (16, 22, 24, 32, 48, 64, 128):
        icon.addPixmap(shield_pixmap(status, s, dpr=1.0))
    return icon


APP_SVG = Path(__file__).with_name("pacwardx.svg")


def app_pixmap(size: int = 64, dpr: float = 2.0) -> QPixmap:
    """The PacWardX app icon (shield on a teal-blue squircle)."""
    from PySide6.QtSvg import QSvgRenderer
    pm = _dpr_pixmap(size, dpr)
    p = QPainter(pm)
    QSvgRenderer(str(APP_SVG)).render(p, QRectF(0, 0, size, size))
    p.end()
    return pm


def app_icon() -> QIcon:
    icon = QIcon()
    for s in (16, 22, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(app_pixmap(s, dpr=1.0))
    return icon


def dot_icon(status: str | None) -> QIcon:
    pm = _dpr_pixmap(16, 2.0)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(COLORS.get(status, COLORS[None])))
    p.drawEllipse(QRectF(4, 4, 8, 8))
    p.end()
    icon = QIcon(pm)
    icon.addPixmap(pm, QIcon.Selected)  # keep the colour on selected rows
    return icon


# --------------------------------------------------------------------------- glyph tiles
def _glyph(p: QPainter, kind: str, s: float) -> None:
    """Draw a simple white line glyph centred in an s×s box."""
    w = max(1.2, s * 0.075)
    pen = QPen(QColor("white"), w, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    c = s / 2
    if kind == "overview":
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("white"))
        p.save(); p.translate(s * 0.2, s * 0.18); p.scale(0.6, 0.66)
        p.drawPath(shield_path(s)); p.restore()
    elif kind == "packages":
        r = s * 0.26
        top = [QPointF(c, c - r), QPointF(c + r, c - r * 0.5), QPointF(c, c), QPointF(c - r, c - r * 0.5)]
        p.drawPolygon(top)
        p.drawPolyline([QPointF(c - r, c - r * 0.5), QPointF(c - r, c + r * 0.5), QPointF(c, c + r),
                        QPointF(c + r, c + r * 0.5), QPointF(c + r, c - r * 0.5)])
        p.drawLine(QPointF(c, c), QPointF(c, c + r))
    elif kind == "network":
        r = s * 0.27
        p.drawEllipse(QPointF(c, c), r, r)
        p.drawEllipse(QPointF(c, c), r * 0.42, r)
        p.drawLine(QPointF(c - r, c), QPointF(c + r, c))
    elif kind == "system":
        r = s * 0.2
        p.drawRoundedRect(QRectF(c - r, c - r, 2 * r, 2 * r), s * 0.05, s * 0.05)
        p.drawRect(QRectF(c - r * 0.4, c - r * 0.4, r * 0.8, r * 0.8))
        for k in (-0.5, 0.5):
            for a, b in (((c + k * r, c - r), (c + k * r, c - r * 1.4)), ((c + k * r, c + r), (c + k * r, c + r * 1.4)),
                         ((c - r, c + k * r), (c - r * 1.4, c + k * r)), ((c + r, c + k * r), (c + r * 1.4, c + k * r))):
                p.drawLine(QPointF(*a), QPointF(*b))
    elif kind == "files":
        x0, y0, x1, y1, f = s * 0.3, s * 0.22, s * 0.7, s * 0.78, s * 0.13
        p.drawPolygon([QPointF(x0, y0), QPointF(x1 - f, y0), QPointF(x1, y0 + f), QPointF(x1, y1), QPointF(x0, y1)])
        for y in (0.48, 0.6):
            p.drawLine(QPointF(x0 + s * 0.09, s * y), QPointF(x1 - s * 0.09, s * y))
    elif kind == "changes":
        r = s * 0.24
        rect = QRectF(c - r, c - r, 2 * r, 2 * r)
        for start in (20, 200):
            p.drawArc(rect, start * 16, 130 * 16)
            a = math.radians(start + 130)
            tip = QPointF(c + r * math.cos(a), c - r * math.sin(a))
            t = math.radians(start + 130 + 90)  # direction of travel
            for off in (-35, 35):
                d = t + math.radians(180 + off)
                p.drawLine(tip, QPointF(tip.x() + s * 0.11 * math.cos(d), tip.y() - s * 0.11 * math.sin(d)))
    elif kind == "opsec":
        x0, x1 = s * 0.2, s * 0.8
        eye = QPainterPath(QPointF(x0, c))
        eye.quadTo(QPointF(c, c - s * 0.36), QPointF(x1, c))
        eye.quadTo(QPointF(c, c + s * 0.36), QPointF(x0, c))
        p.drawPath(eye)
        p.setBrush(QColor("white"))
        p.drawEllipse(QPointF(c, c), s * 0.08, s * 0.08)
    elif kind == "history":
        r = s * 0.27
        p.drawEllipse(QPointF(c, c), r, r)
        p.drawPolyline([QPointF(c, c - r * 0.6), QPointF(c, c), QPointF(c + r * 0.45, c + r * 0.3)])
    elif kind == "welcome":
        roof = [QPointF(s * 0.22, s * 0.5), QPointF(c, s * 0.25), QPointF(s * 0.78, s * 0.5)]
        p.drawPolyline(roof)
        p.drawPolyline([QPointF(s * 0.3, s * 0.45), QPointF(s * 0.3, s * 0.76), QPointF(s * 0.7, s * 0.76),
                        QPointF(s * 0.7, s * 0.45)])
        p.drawLine(QPointF(c, s * 0.76), QPointF(c, s * 0.6))
    elif kind == "help":
        r = s * 0.27
        p.drawEllipse(QPointF(c, c), r, r)
        q = QPainterPath(QPointF(c - s * 0.09, c - s * 0.07))
        q.cubicTo(QPointF(c - s * 0.09, c - s * 0.2), QPointF(c + s * 0.11, c - s * 0.2), QPointF(c + s * 0.1, c - s * 0.06))
        q.cubicTo(QPointF(c + s * 0.09, c + s * 0.02), QPointF(c, c + s * 0.01), QPointF(c, c + s * 0.08))
        p.drawPath(q)
        p.setBrush(QColor("white"))
        p.drawEllipse(QPointF(c, c + s * 0.16), w * 0.55, w * 0.55)
    elif kind == "settings":
        r = s * 0.17
        p.drawEllipse(QPointF(c, c), r, r)
        p.setPen(QPen(QColor("white"), w * 1.6, Qt.SolidLine, Qt.RoundCap))
        for k in range(8):
            a = math.radians(k * 45)
            p.drawLine(QPointF(c + r * 1.25 * math.cos(a), c + r * 1.25 * math.sin(a)),
                       QPointF(c + r * 1.6 * math.cos(a), c + r * 1.6 * math.sin(a)))
        p.setPen(pen)
        p.drawEllipse(QPointF(c, c), r * 0.35, r * 0.35)


def tile_pixmap(kind: str, size: int = 22, color: str | None = None, dpr: float = 2.0) -> QPixmap:
    pm = _dpr_pixmap(size, dpr)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    base = QColor(color or TILE_COLORS.get(kind, "#8e8e93"))
    grad = QLinearGradient(0, 0, 0, size)
    grad.setColorAt(0.0, base.lighter(112))
    grad.setColorAt(1.0, base)
    p.setPen(Qt.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.24, size * 0.24)
    _glyph(p, kind, size)
    p.end()
    return pm


def tile_icon(kind: str) -> QIcon:
    return QIcon(tile_pixmap(kind, 22))
