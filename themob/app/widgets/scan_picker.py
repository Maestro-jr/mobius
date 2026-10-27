"""The saved-scan switcher.

Every scan is a persisted project: its findings, entities and graph live in the
database under the project id, and its artifacts live in the workspace on disk.
So there is nothing to snapshot separately. Reopening a scan is just adopting
its project again and rebuilding the views from it, which restores the scan to
exactly the state it finished in. This dialog lists the stored scans, newest
first, and hands the chosen one's id back to the window.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QScrollArea, QVBoxLayout,
                             QWidget)

from .. import theme
from .common import Rule, caption, value
from .dialog import FramelessDialog


def _when(iso: str) -> str:
    """A short local date for a stored ISO timestamp, or the raw text if it
    cannot be parsed."""
    try:
        moment = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return iso or "unknown"
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%Y-%m-%d %H:%M")


class _ScanRow(QWidget):
    """One selectable scan line. A flat row, not a card: a hairline separates it
    from its neighbours and a quiet hover fill shows it is clickable."""

    clicked = pyqtSignal(str)

    def __init__(self, project_id: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._id = project_id
        self.setObjectName("scanRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            "#scanRow { background: transparent; }"
            f"#scanRow:hover {{ background: {theme.BG_HOVER}; }}")

    def mousePressEvent(self, event) -> None:               # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._id)
        super().mousePressEvent(event)


class ScanPicker(FramelessDialog):
    """Pick a finished scan to reopen, restored to the state it finished in."""

    def __init__(self, parent, repos) -> None:
        super().__init__(parent, title="Open a saved scan", width=640)
        self.chosen: str | None = None
        self._repos = repos

        hint = caption("Each scan is restored to the state it finished in. "
                       "Reopening one does not re-run it.")
        hint.setWordWrap(True)
        self.body.addWidget(hint)
        self.body.addWidget(Rule())

        projects = repos.projects.list(limit=100)
        if not projects:
            empty = caption("No scans yet. Use New scan to analyze an app.")
            empty.setWordWrap(True)
            self.body.addWidget(empty)
            return

        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        host = QWidget()
        column = QVBoxLayout(host)
        column.setContentsMargins(0, 0, 6, 0)
        column.setSpacing(0)
        for index, project in enumerate(projects):
            if index:
                column.addWidget(Rule())
            column.addWidget(self._row(project))
        column.addStretch()
        area.setWidget(host)
        area.setMinimumHeight(min(420, max(120, 58 * len(projects))))
        self.body.addWidget(area, 1)

    def _row(self, project) -> QWidget:
        findings = self._repos.findings.count(project.id)
        entities = self._repos.entities.count(project.id)

        row = _ScanRow(project.id)
        row.clicked.connect(self._choose)
        line = QVBoxLayout(row)
        line.setContentsMargins(6, 9, 6, 9)
        line.setSpacing(2)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(10)
        top.addWidget(value(project.name or "(unnamed)"))
        top.addStretch()
        top.addWidget(caption(f"{findings} findings  ·  {entities} entities"))
        line.addLayout(top)

        meta = caption(
            f"{(project.source_sha256 or '')[:16]}...   ·   "
            f"{_when(project.created_at)}   ·   "
            f"{project.target_platform.value}")
        line.addWidget(meta)
        return row

    def _choose(self, project_id: str) -> None:
        self.chosen = project_id
        self.accept()
