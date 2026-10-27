"""Queries: the built-in questions, plus the ones this tester keeps.

The sections answer "what is in this category". This page answers "show me the
thing I actually came here for", which is a different question and usually a
narrower one: exported components with no permission, secrets something outside
can reach, the findings only one tool reported.

Ten built-in questions ship, because a query builder handed over empty is a
feature nobody uses. A saved query is the eleventh: the one this tester works
out on this engagement and wants again next week.

The layout is the section panel's, deliberately. A query result is a list of
entities and the findings on them, which is exactly what a section is, so it
reads the same and a tester learns one table rather than two.
"""
from __future__ import annotations

from typing import Optional, Sequence

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout,
                             QHeaderView, QLineEdit, QListWidget,
                             QListWidgetItem, QPushButton, QScrollArea,
                             QSizePolicy, QTableWidget,
                             QTableWidgetItem, QWidget)

from ...correlate import GraphSnapshot, empty_snapshot
from ...correlate import queries as q
from ...model.enums import Severity
from ...model.findings import Finding
from ...storage.repositories import Repositories
from .. import theme
from ..widgets.common import Rule, Section, caption, page_layout

_COLUMNS = ["Severity", "Entity", "Type", "Why it matched", "Findings"]
_ROW_HEIGHT = 30
_MAX_ROWS = 500


def _brush(color: str):
    from PyQt6.QtGui import QBrush, QColor

    return QBrush(QColor(color))


class QueriesPanel(QScrollArea):
    """The question list on the left, the answer on the right."""

    entity_selected = pyqtSignal(str)           # entity id
    finding_selected = pyqtSignal(str)          # fingerprint

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._repos: Repositories | None = None
        self._snapshot: GraphSnapshot = empty_snapshot()
        self._findings: list[Finding] = []
        self._result: q.QueryResult | None = None
        self._rows: list[q.Match] = []

        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(20)

        self._questions_panel = Section("Questions")
        self._questions = QListWidget()
        self._questions.setObjectName("queryList")
        self._questions.setSizePolicy(QSizePolicy.Policy.Preferred,
                                      QSizePolicy.Policy.Preferred)
        self._questions.currentRowChanged.connect(self._on_pick)
        self._questions_panel.body.addWidget(self._questions)

        # Saving is one line, not a dialog: the query being saved is the one
        # already on screen, so the only thing missing is what to call it.
        self._name = QLineEdit()
        self._name.setPlaceholderText("save this question as...")
        self._name.returnPressed.connect(self._on_save)
        self._questions_panel.body.addWidget(self._name)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        self._save = QPushButton("Save")
        self._save.clicked.connect(self._on_save)
        self._delete = QPushButton("Delete")
        self._delete.clicked.connect(self._on_delete)
        buttons.addWidget(self._save)
        buttons.addWidget(self._delete)
        buttons.addStretch()
        self._questions_panel.body.addLayout(buttons)
        # The controls belong under the list, not stranded at the foot of the
        # column. The empty space goes below them.
        self._questions_panel.body.addStretch()

        row.addWidget(self._questions_panel, 2)

        self._answer_panel = Section("Answer")
        self._description = caption("")
        self._description.setWordWrap(True)
        self._answer_panel.body.addWidget(self._description)
        self._answer_panel.body.addWidget(Rule())

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(False)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.cellDoubleClicked.connect(self._on_row)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._answer_panel.body.addWidget(self._table, 1)
        row.addWidget(self._answer_panel, 5)

        self._root.addLayout(row, 1)

    # ------------------------------------------------------------------- data

    def bind(self, repos: Repositories) -> None:
        """Give the panel the store its saved questions live in."""
        self._repos = repos
        self._refresh_questions()

    def load(self, snapshot: GraphSnapshot, findings: Sequence[Finding]) -> None:
        self._snapshot = snapshot
        self._findings = list(findings)
        self._refresh_questions()
        if self._questions.count() and self._questions.currentRow() < 0:
            self._questions.setCurrentRow(0)
        else:
            self._rerun()

    def clear(self) -> None:
        self._snapshot = empty_snapshot()
        self._findings = []
        self._result = None
        self._rows = []
        self._table.setRowCount(0)
        self._description.setText("")
        self._answer_panel.set_meta("")

    def _refresh_questions(self) -> None:
        """The builtins, then whatever this tester saved, kept apart.

        Apart because they answer to different people: a builtin is themob's
        claim about what matters, a saved one is the tester's. Mixing them
        would make it unclear which is which the moment one behaves oddly.
        """
        current = self._current_key()
        self._questions.blockSignals(True)
        self._questions.clear()

        for query in q.BUILTINS:
            item = QListWidgetItem(query.title)
            item.setData(Qt.ItemDataRole.UserRole, query.key)
            self._questions.addItem(item)

        for saved in self._saved():
            item = QListWidgetItem(saved.title)
            item.setData(Qt.ItemDataRole.UserRole, saved.key)
            item.setForeground(_brush(theme.ACCENT_SOFT))
            self._questions.addItem(item)

        self._questions.blockSignals(False)
        if current:
            self._select(current)

    def _saved(self) -> list:
        if self._repos is None:
            return []
        try:
            return self._repos.queries.list()
        except Exception:                                  # noqa: BLE001
            return []

    def _select(self, key: str) -> None:
        for row in range(self._questions.count()):
            item = self._questions.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == key:
                self._questions.setCurrentRow(row)
                return

    def _current_key(self) -> str:
        item = self._questions.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def _current_query(self) -> q.Query | None:
        key = self._current_key()
        if not key:
            return None
        found = q.builtin(key)
        if found is not None:
            return found
        if self._repos is None:
            return None
        try:
            return self._repos.queries.load(key)
        except Exception as exc:                           # noqa: BLE001
            self._description.setText(str(exc))
            return None

    # ---------------------------------------------------------------- actions

    def _on_pick(self, _row: int) -> None:
        self._rerun()

    def _rerun(self) -> None:
        query = self._current_query()
        if query is None:
            self._table.setRowCount(0)
            return
        self._result = q.run(self._snapshot, self._findings, query)
        self._rows = self._result.matches[:_MAX_ROWS]
        self._description.setText(query.description)
        self._answer_panel.set_meta(self._result.summary)
        self._fill()

    def _on_save(self) -> None:
        """Save the question on screen under the name in the box."""
        if self._repos is None:
            return
        title = self._name.text().strip()
        query = self._current_query()
        if not title or query is None:
            return

        from ...correlate.queries import Query

        # A copy, so saving a builtin under a new name stores the question
        # rather than a reference to something that may change under it.
        saved = Query(
            key=title.lower().replace(" ", "-")[:60],
            title=title, description=query.description,
            entity_types=list(query.entity_types),
            attributes=list(query.attributes), exposed=query.exposed,
            severity_at_least=query.severity_at_least,
            has_findings=query.has_findings,
            weakness_prefix=query.weakness_prefix, max_tools=query.max_tools,
            reachable_from=query.reachable_from, limit=query.limit)
        try:
            self._repos.queries.save(saved)
        except Exception as exc:                           # noqa: BLE001
            self._description.setText(str(exc))
            return
        self._name.clear()
        self._refresh_questions()
        self._select(saved.key)

    def _on_delete(self) -> None:
        """Only a saved question. A builtin is not the tester's to remove."""
        key = self._current_key()
        if self._repos is None or not key or q.builtin(key) is not None:
            return
        self._repos.queries.delete(key)
        self._refresh_questions()

    # ----------------------------------------------------------------- render

    def _fill(self) -> None:
        table = self._table
        table.setRowCount(len(self._rows))
        for row, match in enumerate(self._rows):
            table.setRowHeight(row, _ROW_HEIGHT)
            worst = match.worst

            severity = QTableWidgetItem(worst.value.title() if worst else "-")
            if worst:
                severity.setForeground(_brush(theme.severity_color(worst)))
            table.setItem(row, 0, severity)
            table.setItem(row, 1, QTableWidgetItem(
                match.entity.label or match.entity.key))
            table.setItem(row, 2, QTableWidgetItem(
                theme.entity_label(match.entity.type)))
            table.setItem(row, 3, QTableWidgetItem(", ".join(match.reasons)))

            count = QTableWidgetItem(str(len(match.findings)) if match.findings
                                     else "")
            table.setItem(row, 4, count)

    def _on_row(self, row: int, _column: int) -> None:
        """A finding if there is one, otherwise the entity."""
        if not 0 <= row < len(self._rows):
            return
        match = self._rows[row]
        if match.findings:
            self.finding_selected.emit(match.findings[0].fingerprint)
        else:
            self.entity_selected.emit(match.entity.id)
