"""The full-page attack-surface graph, with filters and an entity inspector.

This is the TOPRECON graph experience, mobile edition: select an entity, see its
path from the app, isolate its subtree, filter by type. Each section page is
this same widget with a type filter pre-applied.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFrame, QGridLayout,
                             QHBoxLayout, QPushButton, QSplitter, QVBoxLayout,
                             QWidget)

from ...correlate.graph import GraphSnapshot, empty_snapshot
from ...model.enums import EntityType
from .. import theme
from ..widgets.common import (CountRow, KeyValues, Rule, Section, caption,
                              page_layout)
from ..widgets.graph_view import GraphView

_ALL = "__all__"


class GraphPanel(QWidget):
    """Graph canvas plus filter bar and an entity detail pane."""

    entity_selected = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._snapshot: GraphSnapshot = empty_snapshot()
        self._selected: str | None = None

        root = page_layout(self)
        root.setSpacing(12)
        root.addWidget(self._build_toolbar())
        root.addWidget(Rule())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        canvas = Section("Attack-surface graph")
        self._graph = GraphView()
        self._graph.node_selected.connect(self._on_node)
        canvas.body.addWidget(self._graph, 1)
        splitter.addWidget(canvas)

        side = QWidget()
        side_column = QVBoxLayout(side)
        side_column.setContentsMargins(0, 0, 0, 0)
        side_column.setSpacing(12)

        self._detail = Section("Entity", scrollable=True)
        self._detail_facts = KeyValues()
        self._detail_facts.GUTTER = 104
        self._detail.body.addWidget(self._detail_facts)
        self._detail.body.addStretch()
        side_column.addWidget(self._detail, 3)

        self._legend = Section("Legend", scrollable=True)
        side_column.addWidget(self._legend, 2)
        splitter.addWidget(side)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([900, 340])
        root.addWidget(splitter, 1)

        self._show_empty_detail()

    # --------------------------------------------------------------- toolbar

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        row.addWidget(caption("Filter"))
        self._filter = QComboBox()
        self._filter.addItem("All entity types", _ALL)
        for etype in EntityType:
            self._filter.addItem(theme.entity_label(etype), etype.value)
        self._filter.currentIndexChanged.connect(self._on_filter)
        self._filter.setMinimumWidth(190)
        row.addWidget(self._filter)

        self._isolate = QCheckBox("Isolate selection")
        self._isolate.setToolTip(
            "Show only the selected entity and everything reachable from it")
        self._isolate.stateChanged.connect(self._on_isolate)
        row.addWidget(self._isolate)

        self._labels = QCheckBox("Show all relationships")
        self._labels.stateChanged.connect(
            lambda state: self._graph.set_show_labels(bool(state)))
        row.addWidget(self._labels)

        row.addStretch()
        self._count = caption("")
        row.addWidget(self._count)

        relayout = QPushButton("Re-layout")
        relayout.clicked.connect(self._graph_relayout)
        fit = QPushButton("Fit")
        fit.clicked.connect(lambda: self._graph.fit())
        row.addWidget(relayout)
        row.addWidget(fit)
        return bar

    def _graph_relayout(self) -> None:
        self._graph.auto_layout()

    # ------------------------------------------------------------------ data

    def load(self, snapshot: GraphSnapshot) -> None:
        self._snapshot = snapshot
        self._graph.load(snapshot)
        self._count.setText(
            f"{len(snapshot)} entities · {snapshot.edge_count} relationships")
        self._render_legend(snapshot)
        if self._selected and snapshot.get(self._selected) is None:
            self._selected = None
            self._show_empty_detail()
        elif self._selected:
            self._render_detail(self._selected)
        if not snapshot.is_empty:
            self._graph.fit()

    def clear(self) -> None:
        self._selected = None
        self._graph.clear()
        self.load(empty_snapshot())

    def focus_entity(self, entity_id: str) -> None:
        """Select an entity from elsewhere in the app (e.g. the Overview)."""
        self._graph.select(entity_id)
        self._on_node(entity_id)

    # -------------------------------------------------------------- rendering

    def _render_legend(self, snapshot: GraphSnapshot) -> None:
        self._legend.clear_body()
        counts = snapshot.counts_by_type()
        present = [(t, n) for t, n in counts.items() if n]
        if not present:
            self._legend.show_empty("The graph is empty.")
            return
        for etype, count in sorted(present, key=lambda kv: -kv[1]):
            self._legend.body.addWidget(CountRow(
                theme.entity_color(etype), theme.entity_label(etype), count))
        self._legend.body.addStretch()

    def _show_empty_detail(self) -> None:
        self._detail_facts.clear()
        self._detail.set_meta("")
        self._detail_facts.add(
            "", "Select a node to inspect it and trace its path from the app.",
            monospace=False)

    def _render_detail(self, entity_id: str) -> None:
        entity = self._snapshot.get(entity_id)
        if entity is None:
            self._show_empty_detail()
            return

        self._detail_facts.clear()
        self._detail.set_meta(theme.entity_label(entity.type))

        path = self._snapshot.path_from_root(entity_id)
        path_text = " -> ".join(
            (self._snapshot.get(node).label or self._snapshot.get(node).key)
            for node in path if self._snapshot.get(node) is not None) or "-"

        rows: list[tuple[str, str]] = [
            ("Key", entity.key),
            ("Type", theme.entity_label(entity.type)),
            ("Connections", str(self._snapshot.degree(entity_id))),
            ("Path from app", path_text),
        ]
        for key, value in sorted(entity.attributes.items()):
            if value in (None, "", [], {}):
                continue
            rows.append((key.replace("_", " ").capitalize(), _short(value)))

        for key, text in rows:
            self._detail_facts.add(key, text)

    # ------------------------------------------------------------- interaction

    def _on_node(self, entity_id: str) -> None:
        self._selected = entity_id or None
        if self._selected:
            self._render_detail(self._selected)
            self.entity_selected.emit(self._selected)
        else:
            self._show_empty_detail()
        if self._isolate.isChecked():
            self._graph.isolate(self._selected)

    def _on_filter(self) -> None:
        value = self._filter.currentData()
        if value == _ALL:
            self._graph.set_filter(None)
        else:
            self._graph.set_filter([EntityType(value)])
        self._graph.fit()

    def _on_isolate(self, state: int) -> None:
        self._graph.isolate(self._selected if state else None)


# ----------------------------------------------------------------------- utils

def _short(value: object, limit: int = 400) -> str:
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        text = ", ".join(f"{k}={v}" for k, v in value.items())
    else:
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."
