"""The attack-surface graph as a read model.

The database is the store; this is the in-memory view the UI renders and pivots
over. Entities and edges are loaded once per refresh into a NetworkX graph so
"what is reachable from this exported Provider?" is a graph query rather than a
pile of recursive SQL: the same split TOPRECON uses between its SQLite-free
``EntityGraph`` and its transforms.

Sections are projections of this: "Network & API" is
``snapshot.of_type(ENDPOINT, CLOUD_ASSET)`` plus the edges between them.

This module is the read model only: the snapshot, the root, neighbours and
paths. Entry points, exposure and attack paths live in ``pivots``; the section
projections in ``sections``; dedup and voting upstream in ``normalize``.
"""
from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

import networkx as nx

from ..model.entities import Edge, Entity
from ..model.enums import EntityType, Severity
from ..storage.repositories import Repositories

# Serialises building the graph read model. The desktop console builds snapshots
# on a background thread to keep the views updating live during a run, while the
# engine thread builds its own for the analyzers that judge the graph. Two such
# builds running at once (and the UI's NumPy spring_layout racing one) corrupted
# the heap into a native crash on Windows. This lock guarantees only one graph
# build or layout runs at a time. It is held only for the build, never across
# rendering or anything that blocks, so contention is a short wait, not a stall.
GRAPH_LOCK = threading.RLock()

# The graph is rooted on the App; every other node hangs off it.
_ROOT_TYPE = EntityType.APP


@dataclass
class GraphSnapshot:
    """A consistent copy of one project's graph, safe to render from."""
    project_id: str
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    root_id: str | None = None
    finding_severity: dict[str, Severity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_id = {e.id: e for e in self.entities}
        # MultiDiGraph, not DiGraph: an app both *declares* and *exports* the
        # same component, and those are two distinct typed edges. A DiGraph
        # collapses them into one, which under-reports the relationship count
        # and loses the distinction the graph exists to carry.
        self._graph = nx.MultiDiGraph()
        self._graph.add_nodes_from(self._by_id)
        for edge in self.edges:
            if edge.src_id in self._by_id and edge.dst_id in self._by_id:
                self._graph.add_edge(edge.src_id, edge.dst_id, key=edge.type.value,
                                     type=edge.type, attributes=edge.attributes)

    # -- lookups -------------------------------------------------------------

    def get(self, entity_id: str) -> Entity | None:
        return self._by_id.get(entity_id)

    def of_type(self, *types: EntityType) -> list[Entity]:
        wanted = set(types)
        return [e for e in self.entities if e.type in wanted]

    def counts_by_type(self) -> dict[EntityType, int]:
        counter = Counter(e.type for e in self.entities)
        return {t: counter.get(t, 0) for t in EntityType}

    @property
    def root(self) -> Entity | None:
        return self._by_id.get(self.root_id) if self.root_id else None

    def __len__(self) -> int:
        return len(self.entities)

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    @property
    def is_empty(self) -> bool:
        return not self.entities

    # -- graph queries -------------------------------------------------------

    @property
    def graph(self) -> "nx.MultiDiGraph":
        """The underlying graph, for pivots that need NetworkX directly.

        Read-only by convention: a pivot answers questions about a snapshot, it
        does not edit one. Mutating this would desynchronise it from
        ``entities`` and ``edges``, which are what everything else reads.
        """
        return self._graph

    def degree(self, entity_id: str) -> int:
        return self._graph.degree(entity_id) if self._graph.has_node(entity_id) else 0

    def degrees(self) -> dict[str, int]:
        """Every node's degree in one pass: the per-frame path in the UI."""
        return dict(self._graph.degree())

    def neighbors(self, entity_id: str) -> list[tuple[Entity, str]]:
        """``(entity, direction)`` pairs, direction being ``"out"`` or ``"in"``."""
        if not self._graph.has_node(entity_id):
            return []
        # Deduplicated: two typed edges to the same node are one neighbour.
        out: list[tuple[Entity, str]] = []
        for dst in dict.fromkeys(d for _s, d in self._graph.out_edges(entity_id)):
            neighbour = self._by_id.get(dst)
            if neighbour is not None:
                out.append((neighbour, "out"))
        for src in dict.fromkeys(s for s, _d in self._graph.in_edges(entity_id)):
            neighbour = self._by_id.get(src)
            if neighbour is not None:
                out.append((neighbour, "in"))
        return out

    def path_from_root(self, entity_id: str) -> list[str]:
        """Ids along the shortest path root -> *entity_id*.

        Traced on the undirected view so a chain like App -> Component -> DeepLink
        reads regardless of individual edge direction. Empty if unreachable.
        """
        if not self.root_id or not self._graph.has_node(entity_id):
            return []
        if entity_id == self.root_id:
            return [entity_id]
        try:
            return nx.shortest_path(self._graph.to_undirected(as_view=True),
                                    self.root_id, entity_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def reachable_from(self, entity_id: str) -> set[str]:
        """*entity_id* plus everything downstream of it, the pivot query."""
        if not self._graph.has_node(entity_id):
            return set()
        return {entity_id} | nx.descendants(self._graph, entity_id)

    def subgraph_ids(self, types: Sequence[EntityType]) -> set[str]:
        """Ids for a section projection (the type filter the UI applies)."""
        wanted = set(types)
        return {e.id for e in self.entities if e.type in wanted}


def build_snapshot(repos: Repositories, project_id: str) -> GraphSnapshot:
    """Load one project's graph out of the database.

    Serialised by :data:`GRAPH_LOCK`: the engine thread and the console's live
    background builder must never construct a graph at the same moment.
    """
    with GRAPH_LOCK:
        entities = repos.entities.list(project_id)
        edges = repos.edges.list(project_id)
        root = next((e for e in entities if e.type is _ROOT_TYPE), None)
        return GraphSnapshot(
            project_id=project_id,
            entities=entities,
            edges=edges,
            root_id=root.id if root else (entities[0].id if entities else None),
            finding_severity=_worst_severity_by_entity(repos, project_id),
        )


def _worst_severity_by_entity(repos: Repositories,
                              project_id: str) -> dict[str, Severity]:
    """The most severe finding touching each entity, drives node colour."""
    rank = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4}
    worst: dict[str, Severity] = {}
    for finding in repos.findings.list(project_id):
        for entity_id in finding.entity_ids:
            current = worst.get(entity_id)
            if current is None or rank[finding.severity] > rank[current]:
                worst[entity_id] = finding.severity
    return worst


def empty_snapshot(project_id: str = "") -> GraphSnapshot:
    """A snapshot with nothing in it: what the UI shows before a run."""
    return GraphSnapshot(project_id=project_id)
