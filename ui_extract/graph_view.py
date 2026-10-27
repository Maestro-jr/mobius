"""The attack-surface graph: pure PyQt6 ``QGraphicsView``, no web dependency.

Adapted from TOPRECON's ``EntityGraphView``, which is the same problem in the
same toolkit: colour-coded typed nodes, typed edges, a force-directed layout,
and click-a-node-to-trace-its-path-from-the-root. HiveDefend renders its
topology the same way. Keeping the graph Qt-native means no ``QWebEngineView``
and no bundled JavaScript in a security tool.

Reading it:
  * node colour  = entity type, overridden by the worst finding touching it;
  * node size    = connectivity (a hub Provider is visibly a hub);
  * solid edge   = a declared relationship; dashed = inferred;
  * click a node = trace and highlight the path from the App, dimming the rest.

The renderer is deliberately isolated behind :class:`GraphView`'s small API
(``load``, ``select``, ``set_filter``, ``isolate``, ``fit``) so it can be
swapped for a different one later without touching any panel.
"""
from __future__ import annotations

import math
from typing import Optional, Sequence

import networkx as nx
from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (QBrush, QColor, QFont, QPainter, QPen, QPolygonF)
from PyQt6.QtWidgets import (QGraphicsItem, QGraphicsObject, QGraphicsScene,
                             QGraphicsView)

from ...correlate.graph import GraphSnapshot, empty_snapshot
from ...model.enums import EdgeType, EntityType, Severity
from .. import theme

# Short tags painted inside a node, so type reads without hovering.
_TYPE_TAG: dict[EntityType, str] = {
    EntityType.APP: "APP",
    EntityType.COMPONENT: "CMP",
    EntityType.PERMISSION: "PRM",
    EntityType.DEEP_LINK: "LNK",
    EntityType.ENDPOINT: "EP",
    EntityType.CLOUD_ASSET: "CLD",
    EntityType.SECRET: "SEC",
    EntityType.LIBRARY: "LIB",
    EntityType.NATIVE_LIB: "SO",
    EntityType.CRYPTO_USAGE: "CRY",
    EntityType.STORAGE_SINK: "STO",
}

# Edges the app declares vs. relationships we inferred. Inferred draws dashed.
_INFERRED_EDGES = {EdgeType.CALLS, EdgeType.TALKS_TO, EdgeType.RESOLVES_TO}

_EDGE_LABELS: dict[EdgeType, str] = {
    EdgeType.DECLARES: "declares",
    EdgeType.EXPORTS: "exports",
    EdgeType.REQUESTS_PERMISSION: "requires",
    EdgeType.CALLS: "calls",
    EdgeType.TALKS_TO: "talks to",
    EdgeType.EMBEDS: "embeds",
    EdgeType.USES: "uses",
    EdgeType.STORES_IN: "stores in",
    EdgeType.EVIDENCES: "evidences",
    EdgeType.RESOLVES_TO: "resolves to",
}

_SEVERITY_BUMP = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 3}

# View scale below which node captions stop being legible and are hidden.
_DETAIL_SCALE = 0.62

# Width of a node's caption box, in scene units.
_CAPTION_WIDTH = 160.0


def _octagon(radius: float) -> QPolygonF:
    return QPolygonF([
        QPointF(radius * math.cos(math.pi / 8 + i * math.pi / 4),
                radius * math.sin(math.pi / 8 + i * math.pi / 4))
        for i in range(8)])


class _NodeItem(QGraphicsObject):
    """One octagon node, sized by connectivity and coloured by type/severity."""

    def __init__(self, entity_id: str, etype: EntityType, text: str,
                 root: bool = False) -> None:
        super().__init__()
        self.entity_id = entity_id
        self.etype = etype
        self._text = text
        self._root = root
        self._severity: Severity | None = None
        self._hover = False
        self._chosen = False
        self._dim = False
        self._radius = 26.0 if root else 14.0
        self._detail = True
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)

    def boundingRect(self) -> QRectF:                          # noqa: N802
        # Wide enough for the caption box, which extends well past the octagon.
        half = max(self._radius + 26, _CAPTION_WIDTH / 2)
        return QRectF(-half, -(self._radius + 26), 2 * half,
                      self._radius + 26 + self._radius + 20)

    def set_chosen(self, on: bool) -> None:
        self._chosen = on
        self.update()

    def set_detail(self, on: bool) -> None:
        """Level of detail: captions are noise below a readable zoom."""
        if on != self._detail:
            self._detail = on
            self.update()

    def circle(self) -> QRectF:
        """The node's own circle in scene space, without its caption.

        ``fit`` uses this rather than :meth:`boundingRect`: including the
        140px-wide caption in the fitted rect zooms a busy graph out to the
        point where the captions are unreadable anyway.
        """
        return QRectF(self.pos().x() - self._radius, self.pos().y() - self._radius,
                      2 * self._radius, 2 * self._radius)

    def set_dim(self, on: bool) -> None:
        if on != self._dim:
            self._dim = on
            self.update()

    def set_metrics(self, severity: Severity | None, degree: int) -> None:
        self._severity = severity
        if not self._root:
            self.prepareGeometryChange()
            self._radius = 14.0 + min(
                11, _SEVERITY_BUMP.get(severity, 0) + min(6, degree // 3))
        self.update()

    def paint(self, painter: QPainter, *_args) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        base = QColor(theme.entity_color(self.etype))
        alpha = 90 if self._dim else 255

        if self._chosen or self._hover:
            painter.setPen(QPen(base.lighter(130), 2.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPolygon(_octagon(self._radius + 5))

        border = (QColor(theme.severity_color(self._severity))
                  if self._severity is not None else QColor(base))
        border.setAlpha(alpha)
        fill = QColor(base)
        fill.setAlpha((70 if self._root else 46) * alpha // 255)
        painter.setPen(QPen(border, 2.4 if self._root else 1.6))
        painter.setBrush(QBrush(fill))
        painter.drawPolygon(_octagon(self._radius))

        if self._detail or self._root:
            tag = QColor(theme.TEXT_PRIMARY if self._root else base).lighter(140)
            tag.setAlpha(alpha)
            painter.setPen(tag)
            painter.setFont(QFont("Consolas", 9 if self._root else 8,
                                  QFont.Weight.Bold))
            painter.drawText(
                QRectF(-self._radius, -self._radius,
                       2 * self._radius, 2 * self._radius),
                Qt.AlignmentFlag.AlignCenter, _TYPE_TAG.get(self.etype, "?"))

        # The caption is drawn only when the view is zoomed far enough in for it
        # to be legible; below that it is a grey smear over the structure.
        if self._detail or self._chosen or self._hover:
            caption = QColor(theme.TEXT_PRIMARY if self._root else theme.TEXT_SECONDARY)
            caption.setAlpha(alpha)
            painter.setPen(caption)
            painter.setFont(QFont("Consolas", 8))
            box = QRectF(-_CAPTION_WIDTH / 2, self._radius + 2, _CAPTION_WIDTH, 14)
            # Elide against the real font metrics: a fixed character count
            # centre-clips a long key ("...shop.example.com/order" losing its
            # scheme), which is the half that identifies it.
            text = painter.fontMetrics().elidedText(
                self._text, Qt.TextElideMode.ElideRight, int(_CAPTION_WIDTH))
            painter.drawText(box, Qt.AlignmentFlag.AlignHCenter, text)

    def hoverEnterEvent(self, event) -> None:                  # noqa: N802
        self._hover = True
        self.update()

    def hoverLeaveEvent(self, event) -> None:                  # noqa: N802
        self._hover = False
        self.update()


class _EdgeItem(QGraphicsItem):
    """A directed, typed edge: line, arrowhead, and an on-demand label."""

    def __init__(self, relation: str, color: QColor, inferred: bool) -> None:
        super().__init__()
        self._a = QPointF()
        self._b = QPointF()
        self._relation = relation
        self._color = color
        self._inferred = inferred
        self._label = False
        self._dim = False
        self._hot = False
        self.setZValue(1)

    def set_endpoints(self, a: QPointF, b: QPointF) -> None:
        self.prepareGeometryChange()
        self._a, self._b = a, b

    def set_label(self, on: bool) -> None:
        if on != self._label:
            self._label = on
            self.update()

    def set_dim(self, on: bool) -> None:
        if on != self._dim:
            self._dim = on
            self.update()

    def set_highlight(self, on: bool) -> None:
        if on != self._hot:
            self._hot = on
            self.update()

    def boundingRect(self) -> QRectF:                          # noqa: N802
        pad = 34
        return QRectF(self._a, self._b).normalized().adjusted(-pad, -pad, pad, pad)

    def paint(self, painter: QPainter, *_args) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(self._color)
        color.setAlpha(38 if self._dim else (220 if self._hot else 110))
        pen = QPen(color, 2.2 if self._hot else 1.1)
        if self._inferred:
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([4, 4])
        painter.setPen(pen)
        painter.drawLine(self._a, self._b)

        dx, dy = self._b.x() - self._a.x(), self._b.y() - self._a.y()
        distance = math.hypot(dx, dy) or 1.0
        ux, uy = dx / distance, dy / distance
        tip = QPointF(self._b.x() - ux * 16, self._b.y() - uy * 16)
        size = 6.0
        left = QPointF(tip.x() - ux * size + uy * size, tip.y() - uy * size - ux * size)
        right = QPointF(tip.x() - ux * size - uy * size, tip.y() - uy * size + ux * size)
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(QPolygonF([tip, left, right]))

        if self._label and self._relation:
            mid = QPointF((self._a.x() + self._b.x()) / 2,
                          (self._a.y() + self._b.y()) / 2)
            painter.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
            width = painter.fontMetrics().horizontalAdvance(self._relation) + 8
            box = QRectF(mid.x() - width / 2, mid.y() - 8, width, 14)
            background = QColor(theme.BG_OVERLAY)
            background.setAlpha(235)
            painter.setBrush(background)
            painter.setPen(QPen(QColor(self._color), 0.8))
            painter.drawRoundedRect(box, 3, 3)
            painter.setPen(QColor(theme.TEXT_PRIMARY if self._hot else theme.TEXT_MUTED))
            painter.drawText(box, Qt.AlignmentFlag.AlignCenter, self._relation)


class GraphView(QGraphicsView):
    """The interactive attack-surface graph."""

    node_selected = pyqtSignal(str)          # entity id, "" when cleared

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setViewportUpdateMode(
            QGraphicsView.ViewportUpdateMode.BoundingRectViewportUpdate)
        self.setBackgroundBrush(QColor(theme.BG_BASE))
        self.setMinimumHeight(280)

        self._snapshot: GraphSnapshot = empty_snapshot()
        self._nodes: dict[str, _NodeItem] = {}
        self._edges: dict[tuple[str, str, str], _EdgeItem] = {}
        self._pos: dict[str, tuple[float, float]] = {}
        self._filter: tuple[EntityType, ...] = ()
        self._selected: str | None = None
        self._isolated: str | None = None
        self._show_all_labels = False
        self._dirty = False
        self._fit_pending = False
        self._detailed = True
        self._user_adjusted = False

        # Relayout on a timer rather than per-insert: a stage can add hundreds of
        # nodes in a burst and re-running spring layout on each would stall the UI.
        self._timer = QTimer(self)
        self._timer.setInterval(1200)
        self._timer.timeout.connect(self._maybe_relayout)
        self._timer.start()

    # ------------------------------------------------------------------- data

    def load(self, snapshot: GraphSnapshot) -> None:
        """Render *snapshot*, reusing items for entities already on screen."""
        self._snapshot = snapshot
        degrees = snapshot.degrees()
        changed = False

        live_ids = {e.id for e in snapshot.entities}
        for stale in [i for i in self._nodes if i not in live_ids]:
            self._scene.removeItem(self._nodes.pop(stale))
            self._pos.pop(stale, None)
            changed = True

        for entity in snapshot.entities:
            item = self._nodes.get(entity.id)
            if item is None:
                item = _NodeItem(entity.id, entity.type,
                                 entity.label or entity.key,
                                 root=(entity.id == snapshot.root_id))
                position = self._initial_position(entity.id, snapshot)
                item.setPos(*position)
                self._pos[entity.id] = position
                self._scene.addItem(item)
                self._nodes[entity.id] = item
                changed = True
            item.set_metrics(snapshot.finding_severity.get(entity.id),
                             degrees.get(entity.id, 0))

        live_edges: set[tuple[str, str, str]] = set()
        for edge in snapshot.edges:
            key = (edge.src_id, edge.dst_id, edge.type.value)
            live_edges.add(key)
            if key in self._edges or edge.src_id not in self._nodes \
                    or edge.dst_id not in self._nodes:
                continue
            destination = snapshot.get(edge.dst_id)
            color = QColor(theme.entity_color(destination.type) if destination
                           else theme.BORDER)
            item = _EdgeItem(_EDGE_LABELS.get(edge.type, edge.type.value), color,
                             inferred=edge.type in _INFERRED_EDGES)
            self._scene.addItem(item)
            self._edges[key] = item
            changed = True

        for stale in [k for k in self._edges if k not in live_edges]:
            self._scene.removeItem(self._edges.pop(stale))
            changed = True

        self._dirty = self._dirty or changed
        self._reposition_edges()
        self._apply_visibility()
        if self._selected or self._show_all_labels:
            self.select(self._selected)

    def clear(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._pos.clear()
        self._snapshot = empty_snapshot()
        self._selected = None
        self._isolated = None
        self._filter = ()
        self._dirty = False
        self._fit_pending = False
        self._detailed = True
        self._user_adjusted = False
        self.resetTransform()

    # -------------------------------------------------------------- selection

    def select(self, entity_id: Optional[str]) -> None:
        """Select a node and highlight its exposure path from the App."""
        self._selected = entity_id or None
        path = self._snapshot.path_from_root(entity_id) if entity_id else []
        on_path = set(path)
        path_edges = {frozenset(pair) for pair in zip(path, path[1:])}
        active = bool(on_path)

        for node_id, item in self._nodes.items():
            item.set_chosen(node_id == entity_id)
            item.set_dim(active and node_id not in on_path)

        for (src, dst, _type), item in self._edges.items():
            highlighted = frozenset((src, dst)) in path_edges
            item.set_highlight(highlighted)
            item.set_dim(active and not highlighted)
            item.set_label(self._show_all_labels or highlighted
                           or entity_id in (src, dst))

        item = self._nodes.get(entity_id) if entity_id else None
        if item is not None:
            self.centerOn(item)

    def clear_selection(self) -> None:
        self.select(None)
        self.node_selected.emit("")

    def set_show_labels(self, on: bool) -> None:
        self._show_all_labels = on
        self.select(self._selected)

    # ------------------------------------------------------------- projections

    def set_filter(self, types: Sequence[EntityType] | None) -> None:
        """Show only these entity types: how a section projects the graph."""
        self._filter = tuple(types or ())
        self._apply_visibility()

    def isolate(self, entity_id: Optional[str]) -> None:
        """Show only *entity_id* and what it reaches, the pivot view."""
        self._isolated = entity_id or None
        self._apply_visibility()
        self._relayout(force=True)
        self.fit()

    def _apply_visibility(self) -> None:
        visible_ids: set[str] | None = None
        if self._isolated:
            visible_ids = self._snapshot.reachable_from(self._isolated)
        elif self._filter:
            visible_ids = self._snapshot.subgraph_ids(self._filter)
            if self._snapshot.root_id:       # the App anchors every projection
                visible_ids.add(self._snapshot.root_id)

        for node_id, item in self._nodes.items():
            item.setVisible(visible_ids is None or node_id in visible_ids)
        for (src, dst, _type), item in self._edges.items():
            a, b = self._nodes.get(src), self._nodes.get(dst)
            item.setVisible(bool(a and b and a.isVisible() and b.isVisible()))

    # ------------------------------------------------------------------ layout

    def fit(self) -> None:
        """Zoom to the visible nodes.

        A panel that has not been shown yet has a degenerate viewport, and
        ``fitInView`` against it locks in a wildly wrong scale that survives the
        later resize: the graph ends up a cloud of dots. Defer instead, and
        re-fit once the widget actually has a size.
        """
        rect = None
        for item in self._nodes.values():
            if item.isVisible():
                bounds = item.circle()
                rect = bounds if rect is None else rect.united(bounds)
        if rect is None:
            return
        viewport = self.viewport()
        if viewport.width() < 80 or viewport.height() < 80:
            self._fit_pending = True
            return
        self._fit_pending = False
        self.fitInView(rect.adjusted(-60, -60, 60, 60),
                       Qt.AspectRatioMode.KeepAspectRatio)
        self._apply_detail()

    def showEvent(self, event) -> None:                        # noqa: N802
        super().showEvent(event)
        self._refit_if_automatic()

    def resizeEvent(self, event) -> None:                      # noqa: N802
        super().resizeEvent(event)
        self._refit_if_automatic()

    def _refit_if_automatic(self) -> None:
        """Keep the graph fitted until the tester takes control of the view.

        A panel inside a ``QStackedWidget`` is laid out in stages, so an early
        fit locks in a scale computed against a viewport that is not the final
        one. Re-fitting on every resize: until the first manual zoom or pan,
        is what makes the graph fill the canvas whatever the window size.
        """
        if self._user_adjusted:
            return
        self._relayout(force=True)
        self.fit()

    def auto_layout(self) -> None:
        """Re-run the layout and re-fit: the 'Re-layout' button.

        Also hands the view back to automatic fitting, which is what a tester
        who pressed it is asking for.
        """
        self._user_adjusted = False
        self._relayout(force=True)
        self.fit()

    def _initial_position(self, entity_id: str,
                          snapshot: GraphSnapshot) -> tuple[float, float]:
        """Place a new node near a neighbour, so layout has a sane starting point."""
        if entity_id == snapshot.root_id:
            return (0.0, 0.0)
        for neighbour, _direction in snapshot.neighbors(entity_id):
            if neighbour.id in self._pos:
                x, y = self._pos[neighbour.id]
                angle = (hash(entity_id) % 360) * math.pi / 180
                return (x + 80 * math.cos(angle), y + 80 * math.sin(angle))
        count = len(self._nodes) + 1
        angle = count * 2.399963                       # golden angle
        radius = 60 + 12 * math.sqrt(count)
        return (radius * math.cos(angle), radius * math.sin(angle))

    def _maybe_relayout(self) -> None:
        if self._dirty:
            self._relayout()
            self._dirty = False

    def _relayout(self, force: bool = False) -> None:
        ids = ([i for i, item in self._nodes.items() if item.isVisible()]
               if self._isolated or self._filter else list(self._nodes))
        if len(ids) < 2:
            return
        wanted = set(ids)

        graph = nx.Graph()
        graph.add_nodes_from(ids)
        graph.add_edges_from((src, dst) for (src, dst, _t) in self._edges
                             if src in wanted and dst in wanted)

        initial = {i: (self._pos.get(i, (0.0, 0.0))[0] / 400.0,
                       self._pos.get(i, (0.0, 0.0))[1] / 400.0) for i in ids}
        root = self._isolated or self._snapshot.root_id
        fixed = [root] if root in initial else None
        if fixed:
            initial[root] = (0.0, 0.0)

        try:
            positions = nx.spring_layout(
                graph, pos=initial, fixed=fixed,
                k=1.8 / math.sqrt(max(len(ids), 1)),
                iterations=40 if force else 22, seed=7, scale=1.0)
        except Exception:            # noqa: BLE001, layout must never crash the UI
            return

        for entity_id, (x, y) in self._to_scene(positions, len(ids)).items():
            item = self._nodes.get(entity_id)
            if item is None:
                continue
            self._pos[entity_id] = (x, y)
            item.setPos(x, y)
        self._reposition_edges()

    def _to_scene(self, positions: dict, count: int) -> dict[str, tuple[float, float]]:
        """Map layout coordinates onto a rect shaped like the viewport.

        ``spring_layout`` returns a roughly circular arrangement. Scaling both
        axes by one constant then fitting a tall result into a wide canvas
        wastes most of the width and zooms everything down until it is
        unreadable, so stretch each axis to the viewport's own aspect instead.
        """
        xs = [p[0] for p in positions.values()]
        ys = [p[1] for p in positions.values()]
        if not xs:
            return {}
        span_x = max(max(xs) - min(xs), 1e-6)
        span_y = max(max(ys) - min(ys), 1e-6)
        mid_x = (max(xs) + min(xs)) / 2
        mid_y = (max(ys) + min(ys)) / 2

        viewport = self.viewport()
        width = max(viewport.width(), 320)
        height = max(viewport.height(), 240)
        longest = max(width, height)
        spread = 260 + 42 * math.sqrt(max(count, 1))
        half_w = spread * width / longest
        half_h = spread * height / longest

        return {
            key: ((x - mid_x) / (span_x / 2) * half_w,
                  (y - mid_y) / (span_y / 2) * half_h)
            for key, (x, y) in positions.items()
        }

    def _reposition_edges(self) -> None:
        for (src, dst, _type), item in self._edges.items():
            a, b = self._nodes.get(src), self._nodes.get(dst)
            if a is not None and b is not None:
                item.set_endpoints(a.pos(), b.pos())

    # ------------------------------------------------------------- interaction

    def wheelEvent(self, event) -> None:                       # noqa: N802
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        current = self.transform().m11()
        if not 0.08 < current * factor < 6:
            return
        self._user_adjusted = True
        self.scale(factor, factor)
        self._apply_detail()

    def _apply_detail(self) -> None:
        """Level of detail: show captions only once they would be legible.

        Below the threshold the graph reads as a structural map, coloured nodes
        and typed edges, which is the useful thing at that zoom. Captions come
        back as the tester zooms in.
        """
        detailed = self.transform().m11() >= _DETAIL_SCALE
        if detailed == self._detailed:
            return
        self._detailed = detailed
        for item in self._nodes.values():
            item.set_detail(detailed)

    def mousePressEvent(self, event) -> None:                  # noqa: N802
        item = self.itemAt(event.pos())
        while item is not None and not isinstance(item, _NodeItem):
            item = item.parentItem()
        if isinstance(item, _NodeItem):
            self.select(item.entity_id)
            self.node_selected.emit(item.entity_id)
        elif event.button() == Qt.MouseButton.LeftButton:
            self.clear_selection()
        super().mousePressEvent(event)
