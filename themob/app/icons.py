"""A small geometric icon set, stroked in a single colour.

No emoji and no bitmaps. Each icon is drawn with QPainter on a 24x24 grid and
scaled, so it stays crisp at nav-rail and button sizes and takes its colour from
a theme token. Use geometry, not pictures.

Copied from the desktop UI kit (reference/icons.py) and extended with themob's
own nav icons, so the sidebar carries drawn strokes rather than Unicode glyphs
(several of which render as empty boxes on common Windows fonts).
"""

from __future__ import annotations

import math
from typing import Callable, Dict

from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap, QPolygonF


def _poly(pts):
    return QPolygonF([QPointF(x, y) for x, y in pts])


# ---- kit set ---------------------------------------------------------------

def _home(p: QPainter) -> None:
    p.drawPolyline(_poly([(4, 11.5), (12, 4.5), (20, 11.5)]))
    p.drawPolyline(_poly([(6, 10.5), (6, 20), (18, 20), (18, 10.5)]))


def _shield(p: QPainter) -> None:
    p.drawPolyline(_poly([(12, 3.5), (19, 6.5), (19, 12), (12, 20.5),
                          (5, 12), (5, 6.5), (12, 3.5)]))
    p.drawPolyline(_poly([(8.5, 12), (11, 14.5), (15.5, 9.5)]))


def _analytics(p: QPainter) -> None:
    p.drawLine(QPointF(5, 20), QPointF(20, 20))
    p.drawLine(QPointF(8, 20), QPointF(8, 13))
    p.drawLine(QPointF(12, 20), QPointF(12, 7.5))
    p.drawLine(QPointF(16, 20), QPointF(16, 15))


def _reports(p: QPainter) -> None:
    p.drawPolyline(_poly([(6, 4), (14, 4), (18, 8), (18, 20), (6, 20), (6, 4)]))
    p.drawPolyline(_poly([(14, 4), (14, 8), (18, 8)]))
    p.drawLine(QPointF(9, 12), QPointF(15, 12))
    p.drawLine(QPointF(9, 15), QPointF(15, 15))
    p.drawLine(QPointF(9, 18), QPointF(13, 18))


def _settings(p: QPainter) -> None:
    p.drawEllipse(QRectF(9, 9, 6, 6))
    cx, cy = 12, 12
    for k in range(8):
        a = k * math.pi / 4
        p.drawLine(QPointF(cx + 6.5 * math.cos(a), cy + 6.5 * math.sin(a)),
                   QPointF(cx + 9 * math.cos(a), cy + 9 * math.sin(a)))


def _menu(p: QPainter) -> None:
    for y in (8, 12, 16):
        p.drawLine(QPointF(5, y), QPointF(19, y))


def _chevron_left(p: QPainter) -> None:
    p.drawPolyline(_poly([(14.5, 6.5), (9, 12), (14.5, 17.5)]))


def _chevron_right(p: QPainter) -> None:
    p.drawPolyline(_poly([(9.5, 6.5), (15, 12), (9.5, 17.5)]))


def _clock(p: QPainter) -> None:
    p.drawEllipse(QRectF(4, 4, 16, 16))
    p.drawLine(QPointF(12, 12), QPointF(12, 7.5))
    p.drawLine(QPointF(12, 12), QPointF(15, 13.5))


def _upload(p: QPainter) -> None:
    p.drawPolyline(_poly([(5, 14), (5, 20), (19, 20), (19, 14)]))
    p.drawLine(QPointF(12, 16), QPointF(12, 4.5))
    p.drawPolyline(_poly([(8, 8), (12, 4.5), (16, 8)]))


def _add(p: QPainter) -> None:
    p.drawLine(QPointF(12, 6), QPointF(12, 18))
    p.drawLine(QPointF(6, 12), QPointF(18, 12))


def _trash(p: QPainter) -> None:
    p.drawLine(QPointF(5, 7), QPointF(19, 7))
    p.drawPolyline(_poly([(9, 7), (9, 5), (15, 5), (15, 7)]))
    p.drawPolyline(_poly([(7, 7), (8, 20), (16, 20), (17, 7)]))


def _play(p: QPainter) -> None:
    pen = p.pen()
    p.setBrush(QColor(pen.color()))
    p.drawPolygon(_poly([(9, 6), (19, 12), (9, 18)]))
    p.setBrush(Qt.BrushStyle.NoBrush)


def _workspace(p: QPainter) -> None:
    p.drawPolyline(_poly([(12, 4), (20, 8), (12, 12), (4, 8), (12, 4)]))
    p.drawPolyline(_poly([(4, 12), (12, 16), (20, 12)]))


def _search(p: QPainter) -> None:
    p.drawEllipse(QRectF(5, 5, 10, 10))
    p.drawLine(QPointF(14.5, 14.5), QPointF(19.5, 19.5))


def _export(p: QPainter) -> None:
    p.drawPolyline(_poly([(5, 14), (5, 20), (19, 20), (19, 14)]))
    p.drawLine(QPointF(12, 15), QPointF(12, 4.5))
    p.drawPolyline(_poly([(8.5, 8), (12, 4.5), (15.5, 8)]))


def _filter(p: QPainter) -> None:
    p.drawPolyline(_poly([(5, 6), (19, 6), (13.5, 12.5), (13.5, 18),
                          (10.5, 16), (10.5, 12.5), (5, 6)]))


def _sort(p: QPainter) -> None:
    p.drawLine(QPointF(6, 8), QPointF(18, 8))
    p.drawLine(QPointF(6, 12), QPointF(15, 12))
    p.drawLine(QPointF(6, 16), QPointF(12, 16))


def _wave(p: QPainter) -> None:
    for i, (x, hgt) in enumerate([(7, 5), (10, 9), (13, 13), (16, 9)]):
        p.drawLine(QPointF(x, 12 - hgt / 2), QPointF(x, 12 + hgt / 2))


def _film(p: QPainter) -> None:
    p.drawPolyline(_poly([(4, 6), (20, 6), (20, 18), (4, 18), (4, 6)]))
    for x in (8, 12, 16):
        p.drawLine(QPointF(x, 6), QPointF(x, 18))


def _link(p: QPainter) -> None:
    p.drawPolyline(_poly([(10, 9), (7, 9), (5, 11), (5, 13), (7, 15), (10, 15)]))
    p.drawPolyline(_poly([(14, 9), (17, 9), (19, 11), (19, 13), (17, 15), (14, 15)]))
    p.drawLine(QPointF(9, 12), QPointF(15, 12))


def _check(p: QPainter) -> None:
    p.drawPolyline(_poly([(5, 12.5), (10, 17), (19, 7)]))


def _alert(p: QPainter) -> None:
    p.drawPolyline(_poly([(12, 4), (20, 19), (4, 19), (12, 4)]))
    p.drawLine(QPointF(12, 10), QPointF(12, 14.5))
    p.drawPoint(QPointF(12, 17))


def _gauge(p: QPainter) -> None:
    p.drawArc(QRectF(4, 6, 16, 16), 20 * 16, 140 * 16)
    p.drawLine(QPointF(12, 18), QPointF(15.5, 9.5))


def _download(p: QPainter) -> None:
    p.drawPolyline(_poly([(5, 14), (5, 20), (19, 20), (19, 14)]))
    p.drawLine(QPointF(12, 4.5), QPointF(12, 15.5))
    p.drawPolyline(_poly([(8, 12), (12, 15.5), (16, 12)]))


def _win_min(p: QPainter) -> None:
    p.drawLine(QPointF(6, 13), QPointF(18, 13))


def _win_max(p: QPainter) -> None:
    p.drawRect(QRectF(6, 6, 12, 12))


def _win_restore(p: QPainter) -> None:
    p.drawPolyline(_poly([(9, 8), (9, 6), (18, 6), (18, 15), (16, 15)]))
    p.drawRect(QRectF(6, 9, 10, 9))


def _win_close(p: QPainter) -> None:
    p.drawLine(QPointF(7, 7), QPointF(17, 17))
    p.drawLine(QPointF(17, 7), QPointF(7, 17))


# ---- themob nav + action icons --------------------------------------------

def _overview(p: QPainter) -> None:
    for x, y in ((5, 5), (13, 5), (5, 13), (13, 13)):
        p.drawRect(QRectF(x, y, 6, 6))


def _platform(p: QPainter) -> None:
    # A chip: a square body with short legs on each side.
    p.drawRect(QRectF(8, 8, 8, 8))
    for x1, y1, x2, y2 in ((10, 6, 10, 8), (14, 6, 14, 8), (10, 16, 10, 18),
                           (14, 16, 14, 18), (6, 10, 8, 10), (6, 14, 8, 14),
                           (16, 10, 18, 10), (16, 14, 18, 14)):
        p.drawLine(QPointF(x1, y1), QPointF(x2, y2))


def _network(p: QPainter) -> None:
    p.drawEllipse(QRectF(4, 4, 16, 16))
    p.drawLine(QPointF(12, 4), QPointF(12, 20))
    p.drawLine(QPointF(4, 12), QPointF(20, 12))
    p.drawArc(QRectF(7.5, 4, 9, 16), 90 * 16, 180 * 16)
    p.drawArc(QRectF(7.5, 4, 9, 16), 270 * 16, 180 * 16)


def _secrets(p: QPainter) -> None:
    # A key: a ring on the left, a shaft to the right, two teeth.
    p.drawEllipse(QRectF(4, 9, 7, 7))
    p.drawLine(QPointF(10.5, 12.5), QPointF(20, 12.5))
    p.drawLine(QPointF(17, 12.5), QPointF(17, 16))
    p.drawLine(QPointF(20, 12.5), QPointF(20, 15.5))


def _crypto(p: QPainter) -> None:
    # A padlock: a body and a shackle.
    p.drawRect(QRectF(6, 11, 12, 8))
    p.drawArc(QRectF(8, 5, 8, 11), 0, 180 * 16)


def _storage(p: QPainter) -> None:
    # A database cylinder.
    p.drawEllipse(QRectF(5, 4, 14, 4))
    p.drawLine(QPointF(5, 6), QPointF(5, 16))
    p.drawLine(QPointF(19, 6), QPointF(19, 16))
    p.drawArc(QRectF(5, 12, 14, 4), 180 * 16, 180 * 16)
    p.drawArc(QRectF(5, 8, 14, 4), 180 * 16, 180 * 16)


def _dependencies(p: QPainter) -> None:
    # A package: a cube seen in projection.
    p.drawPolyline(_poly([(12, 4), (19, 8), (19, 16), (12, 20), (5, 16),
                          (5, 8), (12, 4)]))
    p.drawPolyline(_poly([(5, 8), (12, 12), (19, 8)]))
    p.drawLine(QPointF(12, 12), QPointF(12, 20))


def _code(p: QPainter) -> None:
    p.drawPolyline(_poly([(9, 7), (4.5, 12), (9, 17)]))
    p.drawPolyline(_poly([(15, 7), (19.5, 12), (15, 17)]))


def _graph(p: QPainter) -> None:
    nodes = ((6, 7), (18, 8), (12, 18))
    p.drawLine(QPointF(6, 7), QPointF(18, 8))
    p.drawLine(QPointF(6, 7), QPointF(12, 18))
    p.drawLine(QPointF(18, 8), QPointF(12, 18))
    for x, y in nodes:
        p.drawEllipse(QRectF(x - 2, y - 2, 4, 4))


def _dynamic(p: QPainter) -> None:
    # A pulse / heartbeat trace.
    p.drawPolyline(_poly([(4, 12), (8, 12), (10, 7), (13, 17), (15, 12),
                          (20, 12)]))


def _activity(p: QPainter) -> None:
    # A log: leading dots and lines of differing length.
    for y, x2 in ((8, 19), (12, 16), (16, 18)):
        p.drawEllipse(QRectF(5, y - 1, 2, 2))
        p.drawLine(QPointF(9, y), QPointF(x2, y))


def _stop(p: QPainter) -> None:
    pen = p.pen()
    p.setBrush(QColor(pen.color()))
    p.drawRect(QRectF(7, 7, 10, 10))
    p.setBrush(Qt.BrushStyle.NoBrush)


def _refresh(p: QPainter) -> None:
    p.drawArc(QRectF(5, 5, 14, 14), 60 * 16, 250 * 16)
    p.drawPolyline(_poly([(16, 4), (18.5, 7.5), (14.5, 8.5)]))


def _assistant(p: QPainter) -> None:
    # A speech bubble: a rounded body with a short tail at the bottom-left.
    p.drawRoundedRect(QRectF(4, 5, 16, 11), 3, 3)
    p.drawPolyline(_poly([(9, 16), (7.5, 20), (13, 16)]))


_ICONS: Dict[str, Callable[[QPainter], None]] = {
    # kit set
    "home": _home, "verification": _shield, "analytics": _analytics,
    "reports": _reports, "settings": _settings, "menu": _menu,
    "chevron_left": _chevron_left, "chevron_right": _chevron_right,
    "clock": _clock, "upload": _upload, "add": _add, "trash": _trash,
    "play": _play, "workspace": _workspace, "search": _search,
    "export": _export, "filter": _filter, "sort": _sort, "wave": _wave,
    "film": _film, "link": _link, "check": _check, "alert": _alert,
    "gauge": _gauge, "win_min": _win_min, "win_max": _win_max,
    "win_restore": _win_restore, "win_close": _win_close, "download": _download,
    # themob nav and actions
    "overview": _overview, "platform": _platform, "network": _network,
    "secrets": _secrets, "crypto": _crypto, "storage": _storage,
    "dependencies": _dependencies, "code": _code, "graph": _graph,
    "questions": _search, "dynamic": _dynamic, "activity": _activity,
    "assistant": _assistant, "stop": _stop, "refresh": _refresh,
}


def pixmap(name: str, size: int = 20, color: str = "#ebe3f7",
           width: float = 1.8) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    draw = _ICONS.get(name)
    if draw is None:
        return pm
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    scale = size / 24.0
    p.scale(scale, scale)
    pen = QPen(QColor(color))
    pen.setWidthF(width / scale)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    draw(p)
    p.end()
    return pm


def icon(name: str, size: int = 20, color: str = "#ebe3f7") -> QIcon:
    return QIcon(pixmap(name, size, color))
