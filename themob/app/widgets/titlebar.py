"""Custom title bar for the frameless main window.

HiveDefend's shell is frameless with its own title bar; this is the same thing,
trimmed to what themob needs: wordmark, live target chip, window controls, and
drag-to-move / double-click-to-maximise.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QWidget

from .. import theme
from .common import label
from .logo import MobMark
from .window_buttons import WindowControls


class TitleBar(QFrame):
    """Draggable title bar with minimise / maximise / close."""

    minimize_requested = pyqtSignal()
    maximize_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("titleBar")
        self._drag_from: Optional[QPoint] = None

        row = QHBoxLayout(self)
        row.setContentsMargins(14, 0, 0, 0)
        row.setSpacing(10)

        # The installed artwork already reads "The M O B", so no wordmark beside
        # it: that would set the name twice. MobMark falls back to the painted
        # lockup only when no artwork is installed.
        #
        # 58px, not the 38px this started at: the supplied logo is a full lockup
        #, hexagon, photo and wordmark, and below about 50px the wordmark is a
        # smudge and it reads as a plain dark hexagon. The title bar is sized to
        # the artwork rather than the artwork squeezed into the title bar.
        row.addWidget(MobMark(size=58))
        row.addSpacing(6)
        row.addWidget(label("mobile attack surface", "titleSubLabel"))

        row.addSpacing(10)
        self._target = label("", "", f"color:{theme.TEXT_SECONDARY};"
                                     f"font-family:{theme.FONT_MONO}; font-size:11px;")
        row.addWidget(self._target)
        row.addStretch()

        self._status = label("", "", f"color:{theme.TEXT_MUTED};"
                                     f"font-family:{theme.FONT_MONO}; font-size:11px;")
        row.addWidget(self._status)
        row.addSpacing(10)

        # Painted, not typed: see widgets/window_buttons.py for why.
        self._controls = WindowControls()
        self._controls.minimize_requested.connect(self.minimize_requested.emit)
        self._controls.maximize_requested.connect(self.maximize_requested.emit)
        self._controls.close_requested.connect(self.close_requested.emit)
        self._controls.set_corner_radius(theme.WINDOW_RADIUS)
        row.addWidget(self._controls)

    @property
    def max_button(self):
        """The maximize control, so the native frame can hit-test it for the
        Windows 11 snap-layouts menu."""
        return self._controls.max_button

    def set_maximized(self, maximized: bool) -> None:
        """Swap the maximise glyph for the restore one."""
        self._controls.set_maximized(maximized)

    # -- live text ------------------------------------------------------------

    def set_target(self, text: str) -> None:
        """The project chip: which app is loaded, and its hash."""
        self._target.setText(text)

    def set_status(self, text: str) -> None:
        self._status.setText(text)

    # -- window dragging ------------------------------------------------------

    def mousePressEvent(self, event) -> None:                  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_from = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:                   # noqa: N802
        window = self.window()
        if self._drag_from is not None and window is not None:
            if window.isMaximized():                # un-maximise on drag, like Windows
                self.maximize_requested.emit()
                self._drag_from = event.globalPosition().toPoint()
            else:
                current = event.globalPosition().toPoint()
                window.move(window.pos() + (current - self._drag_from))
                self._drag_from = current
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:                # noqa: N802
        self._drag_from = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:            # noqa: N802
        self.maximize_requested.emit()
        super().mouseDoubleClickEvent(event)
