"""Frameless dialog base and a themed message box.

The main window is frameless, so a stock ``QDialog`` with an OS title bar looks
grafted on. Same approach as TOPRECON's ``gui/widgets/dialog.py``: draw our own
header, keep the body a plain ``QVBoxLayout`` subclasses fill in.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QPushButton,
                             QVBoxLayout, QWidget)

from .. import theme
from ..winframe import IS_WINDOWS, WindowsFrame
from .window_buttons import WinButton


class FramelessDialog(QDialog):
    """A dialog with a drawn title bar and no OS chrome."""

    def __init__(self, parent: Optional[QWidget] = None, *, title: str = "",
                 width: int = 560, closable: bool = True) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setModal(True)
        self.setMinimumWidth(width)
        self._drag_from: Optional[QPoint] = None

        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        frame = QFrame()
        frame.setObjectName("root")
        # No painted border: the native frame (winframe) draws the edge and the
        # drop shadow, so with nothing drawn here the flush close button reaches
        # the window corner exactly as it does on the main window.
        frame.setStyleSheet(f"QFrame#root {{ background:{theme.BG_BASE}; }}")
        shell.addWidget(frame)

        outer = QVBoxLayout(frame)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._bar = QFrame()
        self._bar.setObjectName("dialogBar")
        bar_row = QHBoxLayout(self._bar)
        # No right margin, so the close button sits flush in the corner and its
        # red hover fill runs to the window edge.
        bar_row.setContentsMargins(18, 0, 0, 0)
        bar_row.setSpacing(0)
        self._title = QLabel(title)
        self._title.setObjectName("titleSubLabel")
        bar_row.addWidget(self._title)
        bar_row.addStretch()
        if closable:
            close = WinButton("win_close", "Close", close=True,
                              width=46, height=46)
            close.clicked.connect(self.reject)
            bar_row.addWidget(close)
        outer.addWidget(self._bar)

        body_host = QWidget()
        self.body = QVBoxLayout(body_host)
        self.body.setContentsMargins(24, 20, 24, 20)
        self.body.setSpacing(12)
        outer.addWidget(body_host)

        # The native Windows frame: the drop shadow and a truly flush close. A
        # message box is not resizable and carries no min/max boxes; it still
        # gets the shadow and a draggable title bar. Installed on first show,
        # once the dialog has a real native handle.
        self._frame = WindowsFrame(self, 46, None, resizable=False,
                                   maximizable=False)
        self._frame_installed = False

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def showEvent(self, event) -> None:                        # noqa: N802
        super().showEvent(event)
        if not self._frame_installed:
            self._frame.install()
            self._frame_installed = True

    def nativeEvent(self, event_type, message):                # noqa: N802
        """Route native messages to the frame; never call super (it crashes on
        this PyQt6 build during window creation)."""
        frame = getattr(self, "_frame", None)
        if frame is not None and event_type == "windows_generic_MSG":
            handled, result = frame.handle(message)
            if handled:
                return True, result
        return False, 0

    # -- dragging by the drawn title bar --------------------------------------

    def mousePressEvent(self, event) -> None:                  # noqa: N802
        # On Windows the native frame drags the title bar (HTCAPTION); this
        # manual move is only for platforms without the native frame.
        if not IS_WINDOWS and event.button() == Qt.MouseButton.LeftButton \
                and event.position().y() <= self._bar.height():
            self._drag_from = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:                   # noqa: N802
        if self._drag_from is not None:
            current = event.globalPosition().toPoint()
            self.move(self.pos() + (current - self._drag_from))
            self._drag_from = current
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:                # noqa: N802
        self._drag_from = None
        super().mouseReleaseEvent(event)


class MessageDialog(FramelessDialog):
    """A themed replacement for ``QMessageBox`` for information and errors."""

    def __init__(self, parent: Optional[QWidget], *, title: str, message: str,
                 detail: str = "", tone: str = "info") -> None:
        super().__init__(parent, title=title, width=520)
        accent = {"error": theme.ERROR, "warn": theme.WARN}.get(tone, theme.ACCENT)

        # No banner box: the message is the content of the dialog, and a
        # coloured frame around the only thing on screen says nothing.
        text = QLabel(message)
        text.setWordWrap(True)
        text.setStyleSheet(f"color:{accent}; font-size:13px;")
        self.body.addWidget(text)

        if detail:
            detail_label = QLabel(detail)
            detail_label.setWordWrap(True)
            detail_label.setObjectName("mono")
            self.body.addWidget(detail_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        ok = QPushButton("OK")
        ok.setObjectName("primary")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        buttons.addWidget(ok)
        self.body.addLayout(buttons)

    @staticmethod
    def show_error(parent, message: str, detail: str = "",
                   title: str = "themob: error") -> None:
        MessageDialog(parent, title=title, message=message, detail=detail,
                      tone="error").exec()

    @staticmethod
    def show_info(parent, message: str, detail: str = "",
                  title: str = "themob") -> None:
        MessageDialog(parent, title=title, message=message, detail=detail).exec()


class ConfirmDialog(FramelessDialog):
    """A two-choice dialog: a question, a confirm button and a cancel button.

    ``exec()`` returns ``Accepted`` only when the confirm button is pressed, so
    the :meth:`ask` helper reads back a plain yes/no. Cancel is the default and
    the close button both reject, so dismissing the dialog never confirms a
    destructive step by accident.
    """

    def __init__(self, parent: Optional[QWidget], *, title: str, message: str,
                 detail: str = "", confirm_text: str = "OK",
                 cancel_text: str = "Cancel", tone: str = "warn") -> None:
        super().__init__(parent, title=title, width=520)
        accent = {"error": theme.ERROR, "warn": theme.WARN}.get(tone, theme.ACCENT)

        text = QLabel(message)
        text.setWordWrap(True)
        text.setStyleSheet(f"color:{accent}; font-size:13px;")
        self.body.addWidget(text)

        if detail:
            detail_label = QLabel(detail)
            detail_label.setWordWrap(True)
            detail_label.setStyleSheet(
                f"color:{theme.TEXT_SECONDARY}; font-size:12px;")
            self.body.addWidget(detail_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton(cancel_text)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        confirm = QPushButton(confirm_text)
        confirm.setObjectName("primary")
        confirm.setDefault(True)
        confirm.clicked.connect(self.accept)
        buttons.addWidget(confirm)
        self.body.addLayout(buttons)

    @staticmethod
    def ask(parent, message: str, detail: str = "", *, title: str = "themob",
            confirm_text: str = "OK", cancel_text: str = "Cancel",
            tone: str = "warn") -> bool:
        """Show the dialog and return True only if the confirm button was used."""
        dialog = ConfirmDialog(parent, title=title, message=message,
                               detail=detail, confirm_text=confirm_text,
                               cancel_text=cancel_text, tone=tone)
        return dialog.exec() == QDialog.DialogCode.Accepted
