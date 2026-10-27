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
        frame.setStyleSheet(
            f"QFrame#root {{ background:{theme.BG_BASE};"
            f" border:1px solid {theme.BORDER}; border-radius:12px; }}")
        shell.addWidget(frame)

        outer = QVBoxLayout(frame)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._bar = QFrame()
        self._bar.setObjectName("titleBar")
        bar_row = QHBoxLayout(self._bar)
        bar_row.setContentsMargins(18, 0, 8, 0)
        self._title = QLabel(title)
        self._title.setObjectName("titleSubLabel")
        bar_row.addWidget(self._title)
        bar_row.addStretch()
        if closable:
            close = QPushButton("✕")
            close.setObjectName("windowClose")
            close.setCursor(Qt.CursorShape.PointingHandCursor)
            close.clicked.connect(self.reject)
            bar_row.addWidget(close)
        outer.addWidget(self._bar)

        body_host = QWidget()
        self.body = QVBoxLayout(body_host)
        self.body.setContentsMargins(24, 20, 24, 20)
        self.body.setSpacing(12)
        outer.addWidget(body_host)

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    # -- dragging by the drawn title bar --------------------------------------

    def mousePressEvent(self, event) -> None:                  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton \
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
