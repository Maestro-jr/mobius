"""One panel that draws any section, because a section is a query.

The build plan lists seven left-nav destinations, and it would be seven near
identical files if each were written separately. They are not seven screens:
they are one screen over seven projections, which is what
``correlate.sections`` already established. So this is a single widget
configured by a :class:`SectionView`.

The column that earns its place is **Exposed**. Severity says how bad a finding
would be; exposure says whether anything outside the app can reach the thing it
is about. A hardcoded key used by an internal class and the same key behind an
exported Activity are both HIGH, and only one of them gets exploited on Monday.
That is what the correlator computed, and a table that omits it is asking the
tester to rediscover it by hand.

The entity list sits below the findings rather than beside them. A section with
no findings still has contents worth reading, and what shipped matters even when
nothing is wrong with it.
"""
from __future__ import annotations

from typing import Optional, Sequence

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QFrame, QHeaderView,
                             QScrollArea, QSizePolicy, QTableWidget,
                             QTableWidgetItem, QWidget)

from ...correlate import GraphSnapshot, SectionView, empty_snapshot
from ...correlate.sections import Section as SectionSpec
from ...correlate.pivots import Exposure, entry_points, exposure
from ...model.entities import Entity
from ...model.enums import Severity
from ...model.findings import Finding
from .. import theme
from ..widgets.common import (Rule, Section, SeverityCounts, caption,
                              page_layout)

_FINDING_COLUMNS = ["Severity", "Confidence", "Exposed", "Title", "MASVS",
                    "Reported by"]
_ENTITY_COLUMNS = ["Type", "Name", "Detail"]

# What a cleared panel shows, so the widget never renders a
# half-configured state.
_BLANK = SectionSpec(key="", title="", types=(), description="")

# Beyond this the table stops being a list and becomes a scroll. The count in
# the section header still reports the true total.
_MAX_ROWS = 500

# Dense, and the same for every row.
_ROW_HEIGHT = 30


def _brush(color: str):
    from PyQt6.QtGui import QBrush, QColor

    return QBrush(QColor(color))


class SectionPanel(QScrollArea):
    """A projection of the graph: its findings, then its entities."""

    finding_selected = pyqtSignal(str)          # fingerprint
    entity_selected = pyqtSignal(str)           # entity id

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._snapshot: GraphSnapshot = empty_snapshot()
        self._findings: list[Finding] = []
        self._entities: list[Entity] = []

        self._title = Section("")
        self._description = caption("")
        self._title.body.addWidget(self._description)
        self._root.addWidget(self._title)

        self._severity = SeverityCounts()
        self._root.addWidget(self._severity)
        self._root.addWidget(Rule())

        self._findings_panel = Section("Findings")
        self._findings_table = self._build_table(_FINDING_COLUMNS, stretch=3)
        self._findings_table.cellDoubleClicked.connect(self._on_finding)
        self._findings_panel.body.addWidget(self._findings_table)
        self._root.addWidget(self._findings_panel)

        self._entities_panel = Section("In this section")
        self._entities_table = self._build_table(_ENTITY_COLUMNS, stretch=2)
        self._entities_table.cellDoubleClicked.connect(self._on_entity)
        self._entities_panel.body.addWidget(self._entities_table)
        self._root.addWidget(self._entities_panel)
        # The page scrolls; the tables do not. A table with its own
        # scrollbar inside a scrolling page is two competing scrollbars.
        self._root.addStretch()

    @staticmethod
    def _build_table(columns: Sequence[str], stretch: int) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(list(columns))
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setSizePolicy(QSizePolicy.Policy.Expanding,
                            QSizePolicy.Policy.Fixed)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        header = table.horizontalHeader()
        header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
        for column in range(len(columns)):
            if column != stretch:
                header.setSectionResizeMode(
                    column, QHeaderView.ResizeMode.ResizeToContents)
        return table

    # -------------------------------------------------------------------- data

    def load(self, view: SectionView, snapshot: GraphSnapshot) -> None:
        """Render one section. The snapshot is needed to compute exposure."""
        self._snapshot = snapshot
        self._findings = list(view.findings)
        self._entities = list(view.entities)

        self._title.set_title(view.title)
        self._description.setText(view.section.description)
        self._severity.set_counts(view.counts_by_severity())

        self._render_findings(view)
        self._render_entities(view)

    def clear(self) -> None:
        self.load(SectionView(section=_BLANK), empty_snapshot())

    # --------------------------------------------------------------- rendering

    def _render_findings(self, view: SectionView) -> None:
        table = self._findings_table
        findings = _worst_first(view.findings)
        self._findings_panel.set_meta(str(len(findings)) if findings else "")

        if not findings:
            self._empty(table, len(_FINDING_COLUMNS), 3,
                        "Nothing found in this section.")
            self._fit(table)
            return

        exposed = self._exposure_by_entity(findings)
        table.setRowCount(min(len(findings), _MAX_ROWS))
        for row, finding in enumerate(findings[:_MAX_ROWS]):
            severity = QTableWidgetItem(finding.severity.value.title())
            severity.setForeground(_brush(theme.severity_color(finding.severity)))
            table.setItem(row, 0, severity)
            table.setItem(row, 1, QTableWidgetItem(
                f"{int(round(finding.confidence * 100))}%"))

            reach = self._reachable(finding, exposed)
            cell = QTableWidgetItem("Yes" if reach else "")
            if reach:
                # The one thing on this row that changes what a tester does
                # first, so it is the one thing that carries a colour.
                cell.setForeground(_brush(theme.WARN))
                cell.setToolTip(reach)
            table.setItem(row, 2, cell)

            table.setItem(row, 3, QTableWidgetItem(finding.title))
            table.setItem(row, 4, QTableWidgetItem(
                finding.masvs_control
                or (finding.masvs_category.value if finding.masvs_category else "-")))
            table.setItem(row, 5, QTableWidgetItem(
                ", ".join(sorted({s.tool for s in finding.sources})) or "-"))
        self._fit(table)

    def _render_entities(self, view: SectionView) -> None:
        table = self._entities_table
        entities = sorted(view.entities, key=lambda e: (e.type.value, e.key))
        self._entities_panel.set_meta(str(len(entities)) if entities else "")

        if not entities:
            self._empty(table, len(_ENTITY_COLUMNS), 1,
                        "No entities of this kind were discovered.")
            self._fit(table)
            return

        table.setRowCount(min(len(entities), _MAX_ROWS))
        for row, entity in enumerate(entities[:_MAX_ROWS]):
            kind = QTableWidgetItem(theme.entity_label(entity.type))
            kind.setForeground(_brush(theme.entity_color(entity.type)))
            table.setItem(row, 0, kind)
            table.setItem(row, 1, QTableWidgetItem(entity.label or entity.key))
            table.setItem(row, 2, QTableWidgetItem(_detail(entity)))
        self._fit(table)

    @staticmethod
    def _fit(table: QTableWidget) -> None:
        """Size the table to its rows, so the page scrolls and it does not.

        A table with its own scrollbar inside a scrolling page gives the reader
        two scrollbars for one list, and the inner one hides how much is there.
        """
        # A uniform row height rather than resizeRowsToContents: the latter
        # grows a row wherever text wraps, and a table whose rows are different
        # heights reads as though the tall ones matter more.
        table.verticalHeader().setDefaultSectionSize(_ROW_HEIGHT)
        for row in range(table.rowCount()):
            table.setRowHeight(row, _ROW_HEIGHT)
        table.setFixedHeight(table.horizontalHeader().height()
                             + _ROW_HEIGHT * table.rowCount() + 2)

    @staticmethod
    def _empty(table: QTableWidget, columns: int, message_column: int,
               message: str) -> None:
        table.setRowCount(1)
        placeholder = QTableWidgetItem(message)
        placeholder.setForeground(_brush(theme.TEXT_MUTED))
        table.setItem(0, message_column, placeholder)
        for column in range(columns):
            if column != message_column:
                table.setItem(0, column, QTableWidgetItem(""))

    # -------------------------------------------------------------- exposure

    def _exposure_by_entity(self,
                            findings: Sequence[Finding]) -> dict[str, Exposure]:
        """Exposure for every entity these findings touch, computed once.

        Per entity rather than per finding: several findings routinely share an
        entity, and the graph walk is the expensive part.
        """
        entries = entry_points(self._snapshot)
        if not entries:
            return {}
        wanted = {eid for f in findings for eid in f.entity_ids}
        return {eid: exposure(self._snapshot, eid, entries) for eid in wanted}

    @staticmethod
    def _reachable(finding: Finding, exposed: dict[str, Exposure]) -> str:
        """The shortest external route to this finding, or empty if none."""
        best: Exposure | None = None
        for entity_id in finding.entity_ids:
            reach = exposed.get(entity_id)
            if reach is not None and reach.reachable:
                if best is None or reach.hops < best.hops:
                    best = reach
        if best is None:
            return ""
        return f"{best.hops} hop(s) from an exported entry point"

    # ------------------------------------------------------------ interaction

    def _on_finding(self, row: int, _column: int) -> None:
        findings = _worst_first(self._findings)
        if 0 <= row < len(findings):
            self.finding_selected.emit(findings[row].fingerprint)

    def _on_entity(self, row: int, _column: int) -> None:
        entities = sorted(self._entities, key=lambda e: (e.type.value, e.key))
        if 0 <= row < len(entities):
            self.entity_selected.emit(entities[row].id)


def _worst_first(findings: Sequence[Finding]) -> list[Finding]:
    rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4}
    return sorted(findings, key=lambda f: (rank[f.severity], -f.confidence,
                                           f.title))


def _detail(entity: Entity) -> str:
    """The one attribute worth showing beside a name, per entity type.

    Chosen rather than dumped: a row that prints every attribute is a row
    nobody reads.
    """
    attributes = entity.attributes
    for key in ("version", "host", "provider", "kind", "protection_level",
                "arch", "scheme", "algorithm"):
        value = attributes.get(key)
        if value:
            return str(value)[:200]
    if attributes.get("exported") is True:
        return "exported"
    return ""
