"""Collapsible navigation sidebar.

A vertical, exclusive, checkable nav that collapses to an icons-only rail, with
a footer slot for live status. Each item carries a drawn geometric icon from
``icons.py`` (not a Unicode glyph), and selection is quiet: the checked item
brightens its text and icon on a neutral step, with no accent bar.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import (QEasingCurve, QEvent, QPoint, QPropertyAnimation,
                          QRectF, QSize, Qt, pyqtSignal)
from PyQt6.QtGui import QColor, QPainter, QPen
from PyQt6.QtWidgets import (QAbstractButton, QButtonGroup, QFrame, QPushButton,
                             QSizePolicy, QVBoxLayout, QWidget)

from .. import icons, theme

_EXPANDED = 186
_COLLAPSED = 52

# How far past the sidebar's right edge the pointer can stray before the toggle
# hides. The button straddles the boundary, so the hot zone has to as well or it
# would vanish the moment you reached for it.
_HOT_MARGIN = 26
_TOGGLE_SIZE = 24
_TOGGLE_TOP = 78


class SidebarToggle(QAbstractButton):
    """The round collapse control that sits on the sidebar's edge.

    Docker Desktop's version appears only when the pointer is near the sidebar
    and hides again afterwards, so the chrome stays quiet until you reach for
    it. The glyph is a panel outline with one side filled, which says which way
    the panel will move rather than just pointing somewhere.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._collapsed = False
        self.setFixedSize(_TOGGLE_SIZE, _TOGGLE_SIZE)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setToolTip("Collapse the sidebar (Ctrl+B)")

    def set_collapsed(self, collapsed: bool) -> None:
        self._collapsed = collapsed
        self.setToolTip("Expand the sidebar (Ctrl+B)" if collapsed
                        else "Collapse the sidebar (Ctrl+B)")
        self.update()

    def paintEvent(self, event) -> None:                       # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        hovered = self.underMouse()
        painter.setPen(QPen(QColor(theme.RULE_STRONG), 1))
        painter.setBrush(QColor(theme.BG_HOVER if hovered else theme.BG_RAISED))
        painter.drawEllipse(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5))

        colour = QColor(theme.TEXT_PRIMARY if hovered else theme.TEXT_SECONDARY)
        painter.setPen(QPen(colour, 1.1))
        painter.setBrush(Qt.BrushStyle.NoBrush)

        box = QRectF(0, 0, 11, 10)
        box.moveCenter(QRectF(self.rect()).center())
        painter.drawRect(box.adjusted(0.5, 0.5, -0.5, -0.5))

        # The filled rail shows which side the panel lives on: on the left when
        # it is open and about to close, on the right when it is closed.
        rail = QRectF(box.left() + 0.5, box.top() + 0.5, 3.5, box.height() - 1)
        if self._collapsed:
            rail.moveRight(box.right() - 0.5)
        painter.setBrush(colour)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRect(rail)
        painter.end()


class Sidebar(QWidget):
    """Exclusive icon+label navigation with a collapse toggle and footer slot."""

    page_changed = pyqtSignal(str)          # emits the item key
    collapsed_changed = pyqtSignal(bool)    # so the footer can shed its labels

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        # A bare QWidget subclass does not paint a stylesheet background-color
        # unless it is told to. Without this the #sidebar dark band is dropped
        # and the rail shows the page ground, collapsing the three tone bands
        # into two.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._collapsed = False
        self._buttons: dict[str, QPushButton] = {}
        self._labels: dict[str, tuple[str, str]] = {}    # key -> (icon name, text)
        self._badges: dict[str, str] = {}                # key -> badge, kept across collapse
        self._anims: list[QPropertyAnimation] = []       # keep refs alive

        # min/max rather than setFixedWidth so the collapse animation can drive them.
        self.setMinimumWidth(_EXPANDED)
        self.setMaximumWidth(_EXPANDED)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 8, 0, 8)
        root.setSpacing(2)

        # The toggle is a floating circle on the sidebar's right edge, shown
        # only while the pointer is near it, which is Docker Desktop's pattern.
        # Parented to the sidebar's parent rather than the sidebar so it can
        # straddle the boundary instead of being clipped by it.
        self._toggle = SidebarToggle()
        self._toggle.clicked.connect(self.toggle)
        self._toggle.hide()
        self.setMouseTracking(True)

        nav = QFrame()
        nav.setObjectName("sidebarNav")
        self._nav = QVBoxLayout(nav)
        self._nav.setContentsMargins(0, 4, 0, 4)
        self._nav.setSpacing(0)
        root.addWidget(nav)
        root.addStretch()

        self._footer_slot = QVBoxLayout()
        self._footer_slot.setContentsMargins(0, 0, 0, 0)
        root.addLayout(self._footer_slot)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

    # ------------------------------------------------------- the hover toggle

    def attach_toggle(self, host: QWidget) -> None:
        """Parent the toggle to *host* so it can straddle the sidebar's edge.

        A child of the sidebar would be clipped by it, and the button is meant
        to sit half on the boundary. The host also gets the mouse tracking:
        the pointer has to be followed across the whole body to know when it
        has come near the rail.
        """
        self._toggle.setParent(host)
        self._toggle.raise_()
        host.setMouseTracking(True)
        host.installEventFilter(self)
        self._reposition_toggle()

    def _reposition_toggle(self) -> None:
        host = self._toggle.parentWidget()
        if host is None:
            return
        # Centred on the sidebar's right edge, below the first nav item.
        edge = self.mapTo(host, QPoint(self.width(), 0)).x()
        self._toggle.move(edge - _TOGGLE_SIZE // 2, _TOGGLE_TOP)
        self._toggle.raise_()

    def _pointer_is_near(self, position: QPoint) -> bool:
        """Whether the pointer is over the sidebar or just past its edge."""
        host = self._toggle.parentWidget()
        if host is None:
            return False
        edge = self.mapTo(host, QPoint(self.width(), 0)).x()
        left = self.mapTo(host, QPoint(0, 0)).x()
        return left - 4 <= position.x() <= edge + _HOT_MARGIN

    def eventFilter(self, watched, event):                     # noqa: N802
        kind = event.type()
        if kind == QEvent.Type.MouseMove:
            self._reposition_toggle()
            self._toggle.setVisible(
                self._pointer_is_near(event.position().toPoint()))
        elif kind == QEvent.Type.Leave:
            self._toggle.hide()
        elif kind == QEvent.Type.Resize:
            self._reposition_toggle()
        return super().eventFilter(watched, event)

    def resizeEvent(self, event) -> None:                      # noqa: N802
        super().resizeEvent(event)
        self._reposition_toggle()

    # ------------------------------------------------------------------ items

    def add_item(self, key: str, text: str, icon_name: str = "overview") -> QPushButton:
        # Qt reads "&" in button text as a mnemonic marker, so "Network & API"
        # renders as "Network _API" with the A underlined. "&&" is the escape.
        display = text.replace("&", "&&")
        button = QPushButton(display)
        button.setObjectName("navItem")
        button.setCheckable(True)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(32)
        button.setToolTip(text)
        # A drawn geometric icon, not a Unicode glyph: several of the glyphs this
        # used to carry render as empty boxes on common Windows fonts. The icon
        # is recoloured on selection, since a QIcon does not follow the
        # stylesheet colour.
        button.setIcon(icons.icon(icon_name, 20, theme.TEXT_SECONDARY))
        button.setIconSize(QSize(20, 20))
        button.clicked.connect(lambda _checked, k=key: self._on_click(k))

        self._buttons[key] = button
        self._labels[key] = (icon_name, display)
        self._badges[key] = ""
        self._group.addButton(button)
        self._nav.addWidget(button)
        return button

    def _on_click(self, key: str) -> None:
        self.page_changed.emit(key)
        self._sync_icons()

    def _sync_icons(self) -> None:
        """Brighten the selected item's icon to the primary text, the rest dim.

        Selection is quiet: the stylesheet gives the checked item brighter
        semibold text on a neutral step, and this matches the icon to it. No
        accent anywhere.
        """
        for key, button in self._buttons.items():
            name = self._labels[key][0]
            colour = theme.TEXT_PRIMARY if button.isChecked() else theme.TEXT_SECONDARY
            button.setIcon(icons.icon(name, 20, colour))

    def select(self, key: str) -> None:
        button = self._buttons.get(key)
        if button is None:
            return
        button.setChecked(True)
        self._sync_icons()
        self.page_changed.emit(key)

    def current(self) -> str:
        for key, button in self._buttons.items():
            if button.isChecked():
                return key
        return ""

    def set_enabled_item(self, key: str, enabled: bool) -> None:
        """Grey out a destination that is not reachable yet (e.g. no project)."""
        button = self._buttons.get(key)
        if button is not None:
            button.setEnabled(enabled)

    def set_badge(self, key: str, badge: str = "") -> None:
        """Append a small count to an item's label (e.g. finding counts).

        The count is stored, not kept only in the label text, so it survives a
        collapse and comes back on expand.
        """
        if key not in self._labels:
            return
        self._badges[key] = badge
        if not self._collapsed:
            _name, text = self._labels[key]
            suffix = f"   {badge}" if badge else ""
            self._buttons[key].setText(f"{text}{suffix}")

    def set_footer_widget(self, widget: QWidget) -> None:
        while self._footer_slot.count():
            item = self._footer_slot.takeAt(0)
            if item.widget() is not None:
                item.widget().setParent(None)
        self._footer_slot.addWidget(widget)

    # -------------------------------------------------------------- collapsing

    def toggle(self) -> None:
        self._collapsed = not self._collapsed
        target = _COLLAPSED if self._collapsed else _EXPANDED
        self._toggle.set_collapsed(self._collapsed)

        for key, button in self._buttons.items():
            if self._collapsed:
                button.setText("")
            else:
                _name, text = self._labels[key]
                badge = self._badges.get(key, "")
                suffix = f"   {badge}" if badge else ""
                button.setText(f"{text}{suffix}")
        self.collapsed_changed.emit(self._collapsed)

        self._anims = []
        for prop in (b"minimumWidth", b"maximumWidth"):
            anim = QPropertyAnimation(self, prop, self)
            anim.setDuration(140)
            anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
            anim.setEndValue(target)
            anim.valueChanged.connect(lambda _v: self._reposition_toggle())
            anim.start()
            self._anims.append(anim)
