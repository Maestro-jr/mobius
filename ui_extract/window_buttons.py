"""Minimise, maximise and close, drawn rather than typed.

The first version used text glyphs in a QPushButton, which is why they looked
wrong: "-" is a hyphen on the text baseline, not a centred rule, and the font
decides the weight, so the three never matched each other. These are painted at
a fixed 10px box with 1px strokes, so they line up and stay crisp.

The hit areas are 46x32, which is what Windows uses; a smaller target is the
usual reason a close button feels fiddly.

The close button rounds its top-right corner to match the window, because the
button sits in the corner and a square hover fill would paint over the radius
and make the window look like the rounding had failed.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QAbstractButton, QWidget

from .. import theme

MINIMISE = "minimise"
MAXIMISE = "maximise"
CLOSE = "close"

_WIDTH = 46
_HEIGHT = 32
_GLYPH = 10.0


class WindowButton(QAbstractButton):
    """One window control. ``kind`` is MINIMISE, MAXIMISE or CLOSE."""

    def __init__(self, kind: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._kind = kind
        self._maximized = False
        self._corner_radius = 0
        self.setFixedSize(_WIDTH, _HEIGHT)
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setToolTip({MINIMISE: "Minimise", MAXIMISE: "Maximise",
                         CLOSE: "Close"}[kind])

    def sizeHint(self) -> QSize:                               # noqa: N802
        return QSize(_WIDTH, _HEIGHT)

    # -- state ---------------------------------------------------------------

    def set_maximized(self, maximized: bool) -> None:
        """Swap the maximise glyph for the restore one."""
        if self._maximized != maximized:
            self._maximized = maximized
            self.setToolTip("Restore" if maximized else "Maximise")
            self.update()

    def set_corner_radius(self, radius: int) -> None:
        if self._corner_radius != radius:
            self._corner_radius = radius
            self.update()

    # -- painting ------------------------------------------------------------

    def _background(self) -> Optional[QColor]:
        if not self.underMouse() and not self.isDown():
            return None
        if self._kind == CLOSE:
            return QColor(theme.CLOSE_HOVER).darker(120 if self.isDown() else 100)
        colour = QColor(theme.BG_TITLEBAR_HOVER)
        return colour.lighter(115) if self.isDown() else colour

    def paintEvent(self, event) -> None:                       # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        background = self._background()
        if background is not None:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(background)
            painter.drawPath(self._background_path())

        colour = QColor("#ffffff") if (self._kind == CLOSE and self.underMouse()) \
            else QColor(theme.TEXT_BODY if self.underMouse() else theme.TEXT_SECONDARY)
        pen = QPen(colour)
        pen.setWidthF(1.1)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        box = QRectF(0, 0, _GLYPH, _GLYPH)
        box.moveCenter(QRectF(self.rect()).center())
        if self._kind == MINIMISE:
            self._draw_minimise(painter, box)
        elif self._kind == MAXIMISE:
            self._draw_maximise(painter, box)
        else:
            self._draw_close(painter, box)
        painter.end()

    def _background_path(self) -> QPainterPath:
        """The hover fill, with the window's corner rounded off on the close."""
        rect = QRectF(self.rect())
        path = QPainterPath()
        radius = float(self._corner_radius)
        if self._kind != CLOSE or radius <= 0:
            path.addRect(rect)
            return path

        # Square everywhere except the top-right, which follows the window.
        path.moveTo(rect.left(), rect.top())
        path.lineTo(rect.right() - radius, rect.top())
        path.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + radius)
        path.lineTo(rect.right(), rect.bottom())
        path.lineTo(rect.left(), rect.bottom())
        path.closeSubpath()
        return path

    @staticmethod
    def _draw_minimise(painter: QPainter, box: QRectF) -> None:
        # A centred rule, not a hyphen sitting on the text baseline.
        y = round(box.center().y()) + 0.5
        painter.drawLine(QPointF(box.left(), y), QPointF(box.right(), y))

    def _draw_maximise(self, painter: QPainter, box: QRectF) -> None:
        if not self._maximized:
            painter.drawRect(box.adjusted(0.5, 0.5, -0.5, -0.5))
            return
        # Restore: the front pane, and the one behind it peeking out.
        offset = 2.5
        front = QRectF(box.left(), box.top() + offset,
                       box.width() - offset, box.height() - offset)
        painter.drawRect(front.adjusted(0.5, 0.5, -0.5, -0.5))
        painter.drawPolyline(QPointF(box.left() + offset, box.top() + offset),
                             QPointF(box.left() + offset, box.top()),
                             QPointF(box.right(), box.top()),
                             QPointF(box.right(), box.bottom() - offset),
                             QPointF(box.right() - offset, box.bottom() - offset))

    @staticmethod
    def _draw_close(painter: QPainter, box: QRectF) -> None:
        painter.drawLine(box.topLeft(), box.bottomRight())
        painter.drawLine(box.topRight(), box.bottomLeft())


class WindowControls(QWidget):
    """The three controls as one strip, so the title bar stays readable."""

    minimize_requested = pyqtSignal()
    maximize_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        from PyQt6.QtWidgets import QHBoxLayout

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self._minimise = WindowButton(MINIMISE)
        self._maximise = WindowButton(MAXIMISE)
        self._close = WindowButton(CLOSE)

        self._minimise.clicked.connect(self.minimize_requested.emit)
        self._maximise.clicked.connect(self.maximize_requested.emit)
        self._close.clicked.connect(self.close_requested.emit)

        for button in (self._minimise, self._maximise, self._close):
            row.addWidget(button)

    def set_maximized(self, maximized: bool) -> None:
        self._maximise.set_maximized(maximized)
        # A maximised window has square corners, so the close button squares off
        # with it.
        self._close.set_corner_radius(0 if maximized else theme.WINDOW_RADIUS)

    def set_corner_radius(self, radius: int) -> None:
        self._close.set_corner_radius(radius)
