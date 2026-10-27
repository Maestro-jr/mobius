"""Minimise, maximise and close, on the kit's WinButton.

Each control is a drawn geometric icon (icons.py) in a flush button that fills
its slot. The title bar has no right margin and the buttons are the bar's full
height, so the close button sits in the top-right corner and its red hover fill
runs to the window edge, on the main window and on every frameless dialog.

The maximize button is reported to Windows as a caption button (object name
``winBtn``), which is what makes the Windows 11 snap-layouts menu appear; the
native frame drives its hover through :meth:`WinButton.set_hot` and toggles it,
so on Windows Qt never sees that click. Minimise and close are ordinary client
clicks whose signals fire normally.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QPushButton, QWidget

from .. import icons, theme

# The bar height is the title bar's; a window button fills it so it is flush.
_BTN_WIDTH = 46
_BAR_HEIGHT = 64


class WinButton(QPushButton):
    """A title-bar window control. A geometric icon that brightens on hover, and
    for close turns dark against the red hover fill. Fills its slot so it is
    flush in the corner."""

    def __init__(self, icon_name: str, tip: str, *, close: bool = False,
                 width: int = _BTN_WIDTH, height: int = _BAR_HEIGHT,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("winClose" if close else "winBtn")
        self._name = icon_name
        self._normal = theme.TEXT_SECONDARY
        # On the bright red close fill a dark X reads; elsewhere brighten to the
        # primary text.
        self._hover = theme.DANGER_BG if close else theme.TEXT_PRIMARY
        self.setFixedSize(width, height)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tip)
        self.setIconSize(QSize(16, 16))
        self._paint(self._normal)

    def set_icon_name(self, name: str) -> None:
        self._name = name
        self._paint(self._hover if self.underMouse() else self._normal)

    def set_hot(self, hot: bool) -> None:
        """Hover state driven by Windows for the maximize button, which the
        system owns (for snap layouts), so Qt never sees the cursor enter it."""
        if bool(self.property("hot")) == hot:
            return
        self.setProperty("hot", hot)
        self.style().unpolish(self)
        self.style().polish(self)
        self._paint(self._hover if hot else self._normal)

    def _paint(self, color: str) -> None:
        self.setIcon(icons.icon(self._name, 16, color))

    def enterEvent(self, event) -> None:                       # noqa: N802
        self._paint(self._hover)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:                       # noqa: N802
        self._paint(self._normal)
        super().leaveEvent(event)


class WindowControls(QWidget):
    """The three controls as one flush strip at the title bar's right edge."""

    minimize_requested = pyqtSignal()
    maximize_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(self, *, height: int = _BAR_HEIGHT,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self._minimise = WinButton("win_min", "Minimise", height=height)
        self._maximise = WinButton("win_max", "Maximise", height=height)
        self._close = WinButton("win_close", "Close", close=True, height=height)

        self._minimise.clicked.connect(self.minimize_requested.emit)
        self._maximise.clicked.connect(self.maximize_requested.emit)
        self._close.clicked.connect(self.close_requested.emit)

        for button in (self._minimise, self._maximise, self._close):
            row.addWidget(button)

    @property
    def max_button(self) -> WinButton:
        """The native frame hit-tests this one for the snap-layouts menu."""
        return self._maximise

    def set_maximized(self, maximized: bool) -> None:
        self._maximise.set_icon_name("win_restore" if maximized else "win_max")
        self._maximise.setToolTip("Restore" if maximized else "Maximise")

    def set_corner_radius(self, radius: int) -> None:
        """Kept for the title bar's call. The native frame rounds the window, so
        the close button no longer squares a corner itself."""
        return
