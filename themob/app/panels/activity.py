"""Activity: the live run log, per-analyzer status, and the audit trail.

The run log is what a tester watches while the pipeline works; the analyzer
table is the re-run surface; the audit view is the record they will be asked
for afterwards, including whether its hash chain still verifies.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView,
                             QPlainTextEdit, QPushButton, QTableWidget,
                             QTableWidgetItem, QVBoxLayout, QWidget)

from ...adapters.base import Analyzer
from ...audit.attestation import AuditTrail
from ...storage.repositories import AuditEntry, Job
from .. import theme
from ..widgets.common import Rule, Section, caption, mono, page_layout

_LOG_COLORS = {
    "discovery": theme.ACCENT,
    "warn": theme.WARN,
    "error": theme.ERROR,
    "info": theme.TEXT_SECONDARY,
}
_MAX_LOG_LINES = 2000


class ActivityPanel(QWidget):
    """Run log, analyzer roster and audit trail."""

    rerun_requested = pyqtSignal(str)           # analyzer name

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        root = page_layout(self)

        top = QHBoxLayout()
        top.setSpacing(14)

        self._analyzers_panel = Section("Analyzers")
        # The re-run hint lives once in the header, not repeated on every row.
        # As a fifth column it truncated to a single letter at the minimum
        # window width; here it stays readable and says the same thing.
        self._analyzers_panel.add_header_widget(
            caption("double-click a row to re-run"))
        self._analyzers = QTableWidget(0, 4)
        self._analyzers.setHorizontalHeaderLabels(
            ["Analyzer", "Stage", "Status", "Last result"])
        _prep_table(self._analyzers, stretch_column=0)
        self._analyzers.cellDoubleClicked.connect(self._on_rerun)
        self._analyzers_panel.body.addWidget(self._analyzers)
        top.addWidget(self._analyzers_panel, 3)

        self._log_panel = Section("Run log")
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(_MAX_LOG_LINES)
        self._log.setStyleSheet(
            f"background:transparent; border:none;"
            f"font-family:{theme.FONT_MONO}; font-size:11.5px;"
            f"color:{theme.TEXT_SECONDARY};")
        self._log_panel.body.addWidget(self._log)
        top.addWidget(self._log_panel, 4)
        root.addLayout(top, 3)

        self._audit_panel = Section("Audit trail")
        self._chain = caption("")
        self._audit_panel.add_header_widget(self._chain)
        self._audit_panel.add_action("Verify chain", self._verify_clicked)
        self._audit = QTableWidget(0, 4)
        self._audit.setHorizontalHeaderLabels(
            ["Time", "Actor", "Action", "Detail"])
        _prep_table(self._audit, stretch_column=3)
        self._audit_panel.body.addWidget(self._audit)
        root.addWidget(self._audit_panel, 2)

        self._trail: AuditTrail | None = None
        self._project_id: str = ""
        self._analyzer_rows: dict[str, int] = {}

    # -------------------------------------------------------------------- log

    def append_log(self, entry: dict) -> None:
        stamp = datetime.fromtimestamp(entry.get("ts", 0)).strftime("%H:%M:%S")
        level = entry.get("level", "info")
        color = _LOG_COLORS.get(level, theme.TEXT_SECONDARY)
        text = str(entry.get("text", "")).replace("<", "&lt;").replace(">", "&gt;")
        self._log.appendHtml(
            f'<span style="color:{theme.TEXT_MUTED}">{stamp}</span> '
            f'<span style="color:{color}">{text}</span>')

    def clear_log(self) -> None:
        self._log.clear()

    # -------------------------------------------------------------- analyzers

    def set_analyzers(self, analyzers: list[Analyzer]) -> None:
        """Render the roster. Availability is filled in later, off the UI thread.

        Probing each analyzer here means a Docker subprocess per row (an
        ``is_available`` check and a cold ``image inspect``), and this runs
        inside ``load_project`` before the window is even shown: a dozen of them
        in series is the startup hang the operator reported. So the rows go up
        at once with a neutral status, and :meth:`set_analyzer_status` paints the
        real verdict when the background sweep returns.
        """
        self._analyzers.setRowCount(len(analyzers))
        self._analyzer_rows = {}
        for row, analyzer in enumerate(analyzers):
            self._analyzer_rows[analyzer.name] = row
            self._analyzers.setItem(row, 0, QTableWidgetItem(analyzer.display))
            self._analyzers.setItem(
                row, 1, QTableWidgetItem(analyzer.stage.value.replace("_", " ")))
            status = QTableWidgetItem("checking")
            status.setForeground(_brush(theme.TEXT_MUTED))
            self._analyzers.setItem(row, 2, status)
            self._analyzers.setItem(row, 3, QTableWidgetItem("-"))
            self._analyzers.item(row, 0).setData(Qt.ItemDataRole.UserRole,
                                                 analyzer.name)

    def set_analyzer_status(self, name: str, status: str,
                            color: str = theme.TEXT_SECONDARY) -> None:
        row = self._analyzer_rows.get(name)
        if row is None:
            return
        item = QTableWidgetItem(status)
        item.setForeground(_brush(color))
        self._analyzers.setItem(row, 2, item)

    def set_analyzer_result(self, name: str, text: str) -> None:
        row = self._analyzer_rows.get(name)
        if row is not None:
            self._analyzers.setItem(row, 3, QTableWidgetItem(text))

    def apply_jobs(self, jobs: list[Job]) -> None:
        """Reflect persisted job outcomes (e.g. after reopening a project)."""
        for job in jobs:
            if job.analyzer:
                self.set_analyzer_result(
                    job.analyzer,
                    f"{job.status.value}"
                    + (f": {job.error}" if job.error else ""))

    def _on_rerun(self, row: int, _column: int) -> None:
        item = self._analyzers.item(row, 0)
        if item is None:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        if name:
            self.rerun_requested.emit(str(name))

    # ------------------------------------------------------------------ audit

    def bind_audit(self, trail: AuditTrail, project_id: str) -> None:
        self._trail = trail
        self._project_id = project_id
        self.refresh_audit()

    def refresh_audit(self) -> None:
        if self._trail is None:
            return
        entries = self._trail.entries(self._project_id or None, limit=250)
        self._render_audit(entries)
        self._audit_panel.set_meta(str(len(entries)))

    def _render_audit(self, entries: list[AuditEntry]) -> None:
        self._audit.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self._audit.setItem(row, 0, QTableWidgetItem(entry.ts))
            self._audit.setItem(row, 1, QTableWidgetItem(entry.actor))
            action = QTableWidgetItem(entry.action)
            if entry.action.endswith(("failed", "deleted")):
                action.setForeground(_brush(theme.ERROR))
            elif entry.action.endswith("authorized"):
                action.setForeground(_brush(theme.ACCENT))
            self._audit.setItem(row, 2, action)
            detail = ", ".join(f"{k}={v}" for k, v in entry.detail.items()
                               if not k.startswith("_"))
            self._audit.setItem(row, 3, QTableWidgetItem(detail[:400]))

    def _verify_clicked(self) -> None:
        if self._trail is None:
            return
        ok, message = self._trail.verify_chain()
        # The colour carries ok vs broken; no glyph needed (and none above
        # U+00FF, which render as boxes on some Windows fonts).
        self._chain.setText(message)
        self._chain.setStyleSheet(
            f"color:{theme.OK if ok else theme.ERROR};"
            f"font-family:{theme.FONT_MONO}; font-size:11px;")
        self.refresh_audit()


# ----------------------------------------------------------------------- utils

def _prep_table(table: QTableWidget, stretch_column: int) -> None:
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    header = table.horizontalHeader()
    for column in range(table.columnCount()):
        header.setSectionResizeMode(
            column, QHeaderView.ResizeMode.Stretch if column == stretch_column
            else QHeaderView.ResizeMode.ResizeToContents)


def _brush(color: str):
    from PyQt6.QtGui import QBrush, QColor
    return QBrush(QColor(color))
