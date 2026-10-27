"""Pivots: the questions a tester asks once the graph exists.

The build plan's §4 gives the shape of one directly: "a pivot is *show every
entity reachable from this exported Provider*". :meth:`GraphSnapshot.reachable_from`
already answers that. What this module adds is the question underneath it, which
is the reason the graph was built rather than a list.

**Is anyone outside the app able to get here?**

An app's attack surface is not its findings; it is the findings something else
on the device can reach. An exported Activity with no permission is a door. A
hardcoded key used only by an internal class is a problem, and a hardcoded key
reachable from that door is an incident. Both are HIGH in a severity table and
they are not the same thing, and nothing before this module could tell them
apart.

So this computes:

* **entry points**: the nodes another app on the device can address, which is
  exported components plus the deep links that route into them
* **exposure**: for any entity, whether an entry point reaches it, and by which
  path, so the answer can be shown rather than asserted
* **attack paths**: entry point to a finding, ranked, which is the list a
  tester should work through first

``scoring/`` is what turns exposure into a number. This module only
establishes the fact, because "reachable from an exported Provider" is a graph
property and a severity is a judgement, and mixing them makes both harder to
argue with.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import networkx as nx

from ..model.entities import Entity
from ..model.enums import EntityType, Severity
from ..model.findings import Finding
from .graph import GraphSnapshot

# Ranking, so "worst first" means the same thing here as everywhere else.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Exposure:
    """Whether something outside the app can reach an entity, and how."""

    entity_id: str
    reachable: bool
    entry_point_id: str | None = None
    path: tuple[str, ...] = ()

    @property
    def hops(self) -> int:
        """Edges between the entry point and the entity. Zero means it is one."""
        return max(len(self.path) - 1, 0)


@dataclass
class AttackPath:
    """A finding, and the externally reachable route to what it is about."""

    finding: Finding
    entity: Entity
    exposure: Exposure
    path_labels: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return self.finding.severity

    def describe(self) -> str:
        return " -> ".join(self.path_labels)


def entry_points(snapshot: GraphSnapshot) -> list[Entity]:
    """Nodes another app on the device can address.

    Exported components are the doors. Deep links are included because a link
    is a route into a component from a browser or another app, which is the
    same reachability with a different caller.

    A component the manifest exports but guards with a permission is still an
    entry point: a permission narrows who may knock, it does not remove the
    door, and treating it as closed would hide the case where the guarding
    permission is itself weak.
    """
    found: list[Entity] = []
    for entity in snapshot.entities:
        if entity.type is EntityType.DEEP_LINK:
            found.append(entity)
        elif (entity.type is EntityType.COMPONENT
              and entity.attributes.get("exported") is True):
            found.append(entity)
    return found


def _seeds(snapshot: GraphSnapshot, entries: Sequence[Entity]) -> list[str]:
    """Where an outside caller actually lands, which is not always the door.

    An exported component is entered directly. A deep link is not a place: it is
    a route *into* the component that declares it, and themob records that as
    ``Activity --declares--> DeepLink``. Descending from the link itself would
    reach nothing, so the traversal starts at the component instead.
    """
    graph = snapshot.graph
    seeds: list[str] = []
    for entry in entries:
        if entry.type is EntityType.DEEP_LINK:
            if graph.has_node(entry.id):
                seeds.extend(src for src, _dst in graph.in_edges(entry.id))
        else:
            seeds.append(entry.id)
    return list(dict.fromkeys(seeds))


def exposure(snapshot: GraphSnapshot, entity_id: str,
             entries: Sequence[Entity] | None = None) -> Exposure:
    """Whether any entry point reaches *entity_id*, and by the shortest route.

    Followed along the edges, not across them. An earlier draft traced this on
    the undirected view, reasoning that themob's edges record a relationship
    rather than a direction of control. That is true of a single edge and wrong
    for a path: the App node touches everything, so undirected traversal walks
    up from any exported component into the App and back down into every
    unrelated branch, and every node in the package comes out "exposed". The
    distinction the module exists to draw disappears.

    Directed is also what the edges already mean. ``Activity --uses--> Secret``
    and ``Activity --talks-to--> Endpoint`` both point away from the caller, so
    descending from an entry point is exactly "what can this door reach".
    """
    if not snapshot.get(entity_id):
        return Exposure(entity_id=entity_id, reachable=False)

    candidates = list(entries) if entries is not None else entry_points(snapshot)
    starts = _seeds(snapshot, candidates)
    if not starts:
        return Exposure(entity_id=entity_id, reachable=False)

    graph = snapshot.graph
    best: tuple[int, str, tuple[str, ...]] | None = None
    for start in starts:
        if start == entity_id:
            return Exposure(entity_id=entity_id, reachable=True,
                            entry_point_id=start, path=(start,))
        try:
            path = nx.shortest_path(graph, start, entity_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        # Shortest wins; the id breaks ties so the answer is stable rather than
        # dependent on iteration order.
        candidate = (len(path), start, tuple(path))
        if best is None or candidate < best:
            best = candidate

    if best is None:
        return Exposure(entity_id=entity_id, reachable=False)
    _length, entry_id, path = best
    return Exposure(entity_id=entity_id, reachable=True,
                    entry_point_id=entry_id, path=path)


def attack_paths(snapshot: GraphSnapshot, findings: Sequence[Finding],
                 limit: int = 100) -> list[AttackPath]:
    """Findings something outside the app can reach, worst first.

    This is the list a tester works through before anything else: a finding on
    an entity nothing external reaches may still be worth fixing, but it is not
    what gets exploited on Monday.

    One path per finding, via whichever affected entity is most exposed, so a
    finding touching five nodes appears once rather than five times.
    """
    entries = entry_points(snapshot)
    if not entries:
        return []

    cache: dict[str, Exposure] = {}
    paths: list[AttackPath] = []

    for finding in findings:
        best: tuple[int, AttackPath] | None = None
        for entity_id in finding.entity_ids:
            entity = snapshot.get(entity_id)
            if entity is None:
                continue
            if entity_id not in cache:
                cache[entity_id] = exposure(snapshot, entity_id, entries)
            reached = cache[entity_id]
            if not reached.reachable:
                continue
            candidate = AttackPath(
                finding=finding, entity=entity, exposure=reached,
                path_labels=[_label(snapshot, node) for node in reached.path])
            # Fewest hops is the most direct route to this finding.
            if best is None or reached.hops < best[0]:
                best = (reached.hops, candidate)
        if best is not None:
            paths.append(best[1])

    paths.sort(key=lambda p: (-_SEVERITY_RANK[p.severity], p.exposure.hops,
                              p.finding.fingerprint))
    return paths[:limit]


def exposed_findings(snapshot: GraphSnapshot,
                     findings: Sequence[Finding]) -> set[str]:
    """Fingerprints of the findings an entry point can reach.

    The cheap form of :func:`attack_paths` for when only the fact is needed,
    such as the scorer asking whether to raise a severity.
    """
    return {p.finding.fingerprint for p in attack_paths(snapshot, findings,
                                                        limit=len(findings) or 1)}


def _label(snapshot: GraphSnapshot, entity_id: str) -> str:
    entity = snapshot.get(entity_id)
    if entity is None:
        return entity_id
    return entity.label or entity.key
