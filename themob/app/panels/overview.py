"""Overview: the 30-second read.

Risk summary, entity counts, the app's own facts, top findings, and a zoomed-out
attack-surface graph. Composed from HiveDefend's dashboard vocabulary: a KPI row
across the top, then cards.

Everything on this page is a projection of the graph plus the findings table, so
it is rebuilt from a :class:`GraphSnapshot` on every refresh rather than mutated
in place: cheap at this size, and it cannot drift from the database.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QAbstractItemView, QFrame, QGridLayout, QHBoxLayout,
                             QHeaderView, QLabel, QScrollArea, QTableWidget,
                             QTableWidgetItem, QVBoxLayout, QWidget)

from ...correlate.graph import GraphSnapshot, empty_snapshot
from ...model.enums import EntityType, Severity
from ...model.findings import Finding
from ...storage.repositories import Project
from .. import theme
from ..widgets.common import (CountRow, KeyValues, Metric, MetricRow, Rule,
                              Section, SeverityCounts, page_layout)
from ..widgets.graph_view import GraphView

# Entity types that make up the externally reachable surface.
_ATTACK_SURFACE = (EntityType.COMPONENT, EntityType.DEEP_LINK,
                   EntityType.ENDPOINT, EntityType.CLOUD_ASSET)


class OverviewPanel(QScrollArea):
    """The landing page for a loaded project."""

    finding_selected = pyqtSignal(str)          # fingerprint
    entity_selected = pyqtSignal(str)           # entity id
    open_graph_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._snapshot: GraphSnapshot = empty_snapshot()
        self._findings: list[Finding] = []
        self._finding_ids: list[str] = []

        self._build_kpis()
        self._build_middle()
        self._build_bottom()

    # ------------------------------------------------------------------ build

    def _build_kpis(self) -> None:
        row = MetricRow()
        self._kpi_entities = row.add(Metric("Graph entities", "0",
                                            "awaiting analysis"))
        self._kpi_surface = row.add(Metric("Attack surface", "0",
                                           "exported and reachable"))
        self._kpi_findings = row.add(Metric("Findings", "0", "awaiting analysis"))
        # The one figure that carries the accent: the worst thing on the page.
        self._kpi_risk = row.add(Metric("Highest severity", "-", "no findings yet",
                                        emphasis=theme.TEXT_MUTED))
        self._root.addWidget(row)
        self._root.addWidget(Rule())

        self._severity = SeverityCounts()
        self._root.addWidget(self._severity)

    def _build_middle(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)

        self._app_panel = Section("Application")
        self._app_facts = KeyValues()
        self._app_panel.body.addWidget(self._app_facts)
        self._app_panel.body.addStretch()
        row.addWidget(self._app_panel, 3)

        self._types_panel = Section("Entities by type", scrollable=True)
        row.addWidget(self._types_panel, 2)

        graph_holder = Section("Attack surface")
        graph_holder.add_action("Open graph", self.open_graph_requested.emit)
        self._graph = GraphView()
        self._graph.setMinimumHeight(300)
        self._graph.node_selected.connect(self._on_node)
        graph_holder.body.addWidget(self._graph, 1)
        row.addWidget(graph_holder, 4)

        # The reference block does not stretch, the findings table below is the
        # working surface, so it gets the leftover height instead of a dead gap.
        self._graph.setMinimumHeight(260)
        self._root.addLayout(row)

    def _build_bottom(self) -> None:
        self._findings_panel = Section("Top findings")
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Severity", "Confidence", "Title", "MASVS", "Reported by"])
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(False)
        self._table.setMinimumHeight(200)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for column in (0, 1, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self._table.cellDoubleClicked.connect(self._on_row)
        self._findings_panel.body.addWidget(self._table)
        self._root.addWidget(self._findings_panel, 1)

    # ------------------------------------------------------------------- data

    def load(self, project: Project | None, snapshot: GraphSnapshot,
             findings: list[Finding]) -> None:
        """Re-render the whole page from the current state of the project."""
        self._snapshot = snapshot
        self._findings = findings
        self._render_kpis(findings, snapshot)
        self._render_app(project, snapshot)
        self._render_types(snapshot)
        self._render_findings(findings)
        self._graph.load(snapshot)
        if not snapshot.is_empty:
            self._graph.fit()

    def clear(self) -> None:
        self.load(None, empty_snapshot(), [])
        self._graph.clear()

    # -------------------------------------------------------------- rendering

    def _render_kpis(self, findings: list[Finding],
                     snapshot: GraphSnapshot) -> None:
        counts = snapshot.counts_by_type()
        entity_total = len(snapshot)
        surface = sum(counts.get(t, 0) for t in _ATTACK_SURFACE)

        self._kpi_entities.set(
            entity_total,
            f"{snapshot.edge_count} relationships" if entity_total
            else "awaiting analysis")
        self._kpi_surface.set(
            surface, "components, links, endpoints" if surface else "none mapped yet")

        by_severity: dict[Severity, int] = {s: 0 for s in Severity}
        for finding in findings:
            by_severity[finding.severity] += 1
        self._severity.set_counts(by_severity)

        unresolved = sum(1 for f in findings if f.status.value == "new")
        self._kpi_findings.set(
            len(findings),
            f"{unresolved} awaiting validation" if findings else "awaiting analysis")

        worst = next((s for s in Severity if by_severity[s]), None)
        if worst is None:
            self._kpi_risk.set("-", "no findings yet", theme.TEXT_MUTED)
        else:
            self._kpi_risk.set(worst.value.title(),
                               f"{by_severity[worst]} at this level",
                               theme.severity_color(worst))

    def _render_app(self, project: Project | None,
                    snapshot: GraphSnapshot) -> None:
        self._app_facts.clear()
        app = next(iter(snapshot.of_type(EntityType.APP)), None)

        if project is None:
            self._app_facts.add("", "No project loaded.", monospace=False)
            return

        rows: list[tuple[str, str]] = [
            ("Project", project.name),
            ("Platform", project.target_platform.value.upper()),
            ("SHA-256", project.source_sha256),
            ("Authorization", project.authorization_ref or "-"),
            ("Authorized by", project.authorized_by or "-"),
        ]
        if app is not None:
            attributes = app.attributes
            signing = attributes.get("signing") or {}
            signed = ", ".join(v for v, on in (("v1", signing.get("v1")),
                                               ("v2", signing.get("v2")),
                                               ("v3", signing.get("v3"))) if on)
            rows = [
                ("Package", attributes.get("package") or app.key),
                ("Version", _version(attributes)),
                ("SDK", _sdk_range(attributes)),
                ("Signing", signed or "unsigned / unknown"),
                ("Debuggable", _tri(attributes.get("debuggable"))),
                ("Backup allowed", _tri(attributes.get("allow_backup"))),
                ("Cleartext traffic", _tri(attributes.get("uses_cleartext_traffic"))),
                *rows,
            ]

        for key, text in rows:
            # A dangerous flag is coloured; everything else stays neutral, so
            # the colour still means something when it does appear.
            risky = (key in ("Debuggable", "Backup allowed", "Cleartext traffic")
                     and text == "yes")
            self._app_facts.add(
                key, str(text),
                tone=theme.severity_color(Severity.HIGH) if risky else "")

    def _render_types(self, snapshot: GraphSnapshot) -> None:
        self._types_panel.clear_body()
        counts = snapshot.counts_by_type()
        present = [(t, n) for t, n in counts.items() if n]
        if not present:
            self._types_panel.show_empty(
                "Nothing discovered yet. Run the pipeline.")
            self._types_panel.set_meta("")
            return
        self._types_panel.set_meta(str(sum(n for _t, n in present)))
        for etype, count in sorted(present, key=lambda kv: -kv[1]):
            self._types_panel.body.addWidget(CountRow(
                theme.entity_color(etype), theme.entity_label(etype), count))
        self._types_panel.body.addStretch()

    def _render_findings(self, findings: list[Finding]) -> None:
        top = findings[:25]
        # The fingerprint, not the row id: it is the natural key, and it is
        # what every other panel emits, so one handler serves them all.
        self._finding_ids = [f.fingerprint for f in top]
        self._findings_panel.set_meta(str(len(findings)) if findings else "")
        self._table.setRowCount(len(top))

        if not top:
            self._table.setRowCount(1)
            placeholder = QTableWidgetItem(
                "No findings yet. Run the config audit stage.")
            placeholder.setForeground(_brush(theme.TEXT_MUTED))
            self._table.setItem(0, 2, placeholder)
            for column in (0, 1, 3, 4):
                self._table.setItem(0, column, QTableWidgetItem(""))
            return

        for row, finding in enumerate(top):
            severity = QTableWidgetItem(finding.severity.value.title())
            severity.setForeground(_brush(theme.severity_color(finding.severity)))
            self._table.setItem(row, 0, severity)
            self._table.setItem(row, 1,
                                QTableWidgetItem(f"{finding.confidence:.0%}"))
            self._table.setItem(row, 2, QTableWidgetItem(finding.title))
            self._table.setItem(row, 3, QTableWidgetItem(
                finding.masvs_control or (finding.masvs_category.value
                                          if finding.masvs_category else "-")))
            self._table.setItem(row, 4, QTableWidgetItem(
                ", ".join(sorted({s.tool for s in finding.sources})) or "-"))

    # ------------------------------------------------------------- interaction

    def _on_row(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._finding_ids):
            self.finding_selected.emit(self._finding_ids[row])

    def _on_node(self, entity_id: str) -> None:
        if entity_id:
            self.entity_selected.emit(entity_id)


# ----------------------------------------------------------------------- utils

def _brush(color: str):
    from PyQt6.QtGui import QBrush, QColor
    return QBrush(QColor(color))


def _tri(value: object) -> str:
    """Android flags are tri-state: on, off, or never declared."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "not declared"


def _version(attributes: dict) -> str:
    name = attributes.get("version_name") or "?"
    code = attributes.get("version_code")
    return f"{name} ({code})" if code else str(name)


def _sdk_range(attributes: dict) -> str:
    minimum = attributes.get("min_sdk")
    target = attributes.get("target_sdk")
    if minimum is None and target is None:
        return "-"
    return f"min {minimum or '?'} · target {target or '?'}"
