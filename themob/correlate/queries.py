"""Saved queries: the questions a tester asks twice.

:mod:`themob.correlate.pivots` answers one question very well, "can something
outside the app reach this". The rest of an assessment is a dozen other
questions, asked of every app, and before this they lived in whoever happened to
remember them. A saved query is that memory, written down and re-runnable
against the next package.

**Not an expression language.** The obvious design is a filter string that gets
parsed, and it is the wrong one twice over: a parser over operator-supplied text
is a surface nobody asked for, and a general language means every consumer
implements its own half of it. What is here instead is a small fixed set of
predicates that compose. They cover every question in :data:`BUILTINS`, which
are the questions this tool exists to answer, and a question they cannot express
is a reason to add a predicate deliberately rather than to have invented a
grammar up front.

**Every clause is optional and they combine with AND.** An empty query matches
everything, which is what makes the builtins readable: each one is two or three
lines that say exactly what it looks for.

**A query returns entities and the findings on them, with a reason.** Returning
only ids would push the work of explaining a result back onto every caller, and
"why did this match" is the first thing a tester asks of any filter.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Sequence

from ..model.entities import Entity
from ..model.enums import EntityType, Severity
from ..model.findings import Finding
from .graph import GraphSnapshot
from .pivots import Exposure, entry_points, exposure

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}

# A query is a saved artefact, so its shape is versioned like the report's.
FORMAT = "themob.query/1"


class QueryError(ValueError):
    """A query asks for something that cannot be expressed."""


@dataclass(frozen=True)
class Attribute:
    """One condition on an entity attribute.

    ``op`` is a fixed vocabulary rather than anything evaluated: "eq", "ne",
    "truthy", "falsy", "contains", "in", "missing". No operator here can run
    code, which is the point of not accepting an expression.
    """

    key: str
    op: str = "truthy"
    value: Any = None

    _OPS = ("eq", "ne", "truthy", "falsy", "contains", "in", "missing")

    def validate(self) -> None:
        if not self.key:
            raise QueryError("an attribute condition needs a key")
        if self.op not in self._OPS:
            raise QueryError(f"unknown operator {self.op!r}; "
                             f"expected one of {', '.join(self._OPS)}")

    def matches(self, attributes: dict[str, Any]) -> bool:
        present = self.key in attributes
        held = attributes.get(self.key)

        if self.op == "missing":
            return not present or held is None
        if self.op == "truthy":
            return bool(held)
        if self.op == "falsy":
            # Deliberately not "not truthy": an attribute nobody set is unknown,
            # and reporting an unknown as False is how a scanner invents facts.
            return present and not held
        if self.op == "eq":
            return held == self.value
        if self.op == "ne":
            return present and held != self.value
        if self.op == "contains":
            if isinstance(held, str):
                return str(self.value).lower() in held.lower()
            if isinstance(held, (list, tuple, set)):
                return self.value in held
            return False
        if self.op == "in":
            values = self.value if isinstance(self.value, (list, tuple, set)) else ()
            return held in values
        return False


@dataclass
class Query:
    """A question about the graph. Every clause is optional, and they AND.

    ``key`` is stable and is what a saved query is stored under, so renaming the
    title of a builtin does not orphan anything referring to it.
    """

    key: str = ""
    title: str = ""
    description: str = ""
    entity_types: list[EntityType] = field(default_factory=list)
    attributes: list[Attribute] = field(default_factory=list)
    # None means "do not care". True is the interesting one: an entity an
    # exported entry point can reach.
    exposed: bool | None = None
    severity_at_least: Severity | None = None
    has_findings: bool | None = None
    weakness_prefix: str = ""
    # Findings only one tool reported: the triage queue, because agreement is
    # what the voting model turns into confidence.
    max_tools: int | None = None
    # Everything reachable from one entity. The build plan's own example of a
    # pivot: "show every entity reachable from this exported Provider".
    reachable_from: str = ""
    limit: int = 500

    def validate(self) -> None:
        if self.limit <= 0:
            raise QueryError("limit must be positive")
        if self.max_tools is not None and self.max_tools < 1:
            raise QueryError("max_tools must be at least 1")
        for attribute in self.attributes:
            attribute.validate()


@dataclass
class Match:
    """One entity a query matched, with the findings and reason behind it."""

    entity: Entity
    findings: list[Finding] = field(default_factory=list)
    exposure: Exposure | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings),
                   key=lambda s: _SEVERITY_RANK[s])


@dataclass
class QueryResult:
    """What a query found, and what it was."""

    query: Query
    matches: list[Match] = field(default_factory=list)
    scanned: int = 0

    @property
    def entities(self) -> list[Entity]:
        return [m.entity for m in self.matches]

    @property
    def findings(self) -> list[Finding]:
        """Every finding on a matched entity, once each, worst first."""
        seen: dict[str, Finding] = {}
        for match in self.matches:
            for finding in match.findings:
                seen.setdefault(finding.fingerprint, finding)
        return sorted(seen.values(),
                      key=lambda f: (-_SEVERITY_RANK[f.severity], f.title))

    @property
    def summary(self) -> str:
        if not self.matches:
            return "nothing matched"
        return (f"{len(self.matches)} of {self.scanned} entities, "
                f"{len(self.findings)} finding(s)")


def run(snapshot: GraphSnapshot, findings: Sequence[Finding],
        query: Query) -> QueryResult:
    """Answer *query* against one graph and its findings."""
    query.validate()

    by_entity: dict[str, list[Finding]] = {}
    for finding in findings:
        for entity_id in finding.entity_ids:
            by_entity.setdefault(entity_id, []).append(finding)

    candidates = _candidates(snapshot, query)
    result = QueryResult(query=query, scanned=len(candidates))

    # Computed once and only when a clause needs it: entry_points walks the
    # graph, and most queries never ask about exposure at all.
    entries = None
    cache: dict[str, Exposure] = {}

    for entity in candidates:
        reasons: list[str] = []

        if query.entity_types and entity.type not in query.entity_types:
            continue
        if not _attributes_match(entity, query, reasons):
            continue

        on_entity = by_entity.get(entity.id, [])
        matched_findings = _findings_match(on_entity, query, reasons)
        if matched_findings is None:
            continue

        reached: Exposure | None = None
        if query.exposed is not None:
            if entries is None:
                entries = entry_points(snapshot)
            if entity.id not in cache:
                cache[entity.id] = exposure(snapshot, entity.id, entries)
            reached = cache[entity.id]
            if reached.reachable is not query.exposed:
                continue
            reasons.append("reachable from an exported entry point"
                           if reached.reachable
                           else "no exported entry point reaches it")

        result.matches.append(Match(entity=entity, findings=matched_findings,
                                    exposure=reached, reasons=reasons))
        if len(result.matches) >= query.limit:
            break

    result.matches.sort(key=_worst_first)
    return result


def _candidates(snapshot: GraphSnapshot, query: Query) -> list[Entity]:
    if query.reachable_from:
        ids = snapshot.reachable_from(query.reachable_from)
        found = [snapshot.get(i) for i in sorted(ids)]
        return [e for e in found if e is not None]
    if query.entity_types:
        return snapshot.of_type(*query.entity_types)
    return snapshot.entities


def _attributes_match(entity: Entity, query: Query,
                      reasons: list[str]) -> bool:
    for condition in query.attributes:
        if not condition.matches(entity.attributes):
            return False
        reasons.append(f"{condition.key} {condition.op}"
                       + (f" {condition.value}" if condition.value is not None
                          else ""))
    return True


def _findings_match(on_entity: list[Finding], query: Query,
                    reasons: list[str]) -> list[Finding] | None:
    """The findings that survive the finding clauses, or None if the entity fails.

    None and [] mean different things: None is "this entity does not match",
    [] is "it matches and carries no findings", which is a real answer for a
    query about the graph rather than about findings.
    """
    kept = list(on_entity)

    if query.severity_at_least is not None:
        floor = _SEVERITY_RANK[query.severity_at_least]
        kept = [f for f in kept if _SEVERITY_RANK[f.severity] >= floor]
    if query.weakness_prefix:
        kept = [f for f in kept
                if (f.weakness_key or "").startswith(query.weakness_prefix)]
    if query.max_tools is not None:
        kept = [f for f in kept
                if len({s.tool for s in f.sources}) <= query.max_tools]

    wants_findings = (query.has_findings
                      or query.severity_at_least is not None
                      or query.weakness_prefix
                      or query.max_tools is not None)

    if wants_findings and not kept:
        return None
    if query.has_findings is False and on_entity:
        return None
    if kept:
        reasons.append(f"{len(kept)} finding(s)")
    return kept


def _worst_first(match: Match):
    worst = match.worst
    return (-(_SEVERITY_RANK[worst] if worst else -1),
            -len(match.findings),
            match.entity.label or match.entity.key)


# ------------------------------------------------------------------ round trip

def to_json(query: Query) -> str:
    """A query as storable JSON. Only the clauses that are set travel."""
    query.validate()
    document: dict[str, Any] = {"format": FORMAT, "key": query.key,
                                "title": query.title,
                                "description": query.description}
    if query.entity_types:
        document["entity_types"] = [t.value for t in query.entity_types]
    if query.attributes:
        document["attributes"] = [
            {"key": a.key, "op": a.op, "value": a.value} for a in query.attributes]
    if query.exposed is not None:
        document["exposed"] = query.exposed
    if query.severity_at_least is not None:
        document["severity_at_least"] = query.severity_at_least.value
    if query.has_findings is not None:
        document["has_findings"] = query.has_findings
    if query.weakness_prefix:
        document["weakness_prefix"] = query.weakness_prefix
    if query.max_tools is not None:
        document["max_tools"] = query.max_tools
    if query.reachable_from:
        document["reachable_from"] = query.reachable_from
    document["limit"] = query.limit
    return json.dumps(document, sort_keys=True)


def from_json(payload: str) -> Query:
    """Read a stored query, refusing anything it cannot honour exactly.

    A row can be older than the code reading it, or hand-edited. Dropping a
    clause it does not recognise would answer a *different, broader* question
    than the one that was saved, which for a query like "exported components
    with no permission" means quietly returning every component. So an unknown
    field is an error, not something to skip.
    """
    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise QueryError(f"not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise QueryError("a query must be a JSON object")

    known = {"format", "key", "title", "description", "entity_types",
             "attributes", "exposed", "severity_at_least", "has_findings",
             "weakness_prefix", "max_tools", "reachable_from", "limit"}
    unknown = sorted(set(document) - known)
    if unknown:
        raise QueryError(
            "this query uses clauses this version does not understand: "
            + ", ".join(unknown)
            + ". Running it would answer a broader question than the one saved.")

    query = Query(
        key=str(document.get("key") or ""),
        title=str(document.get("title") or ""),
        description=str(document.get("description") or ""),
        weakness_prefix=str(document.get("weakness_prefix") or ""),
        reachable_from=str(document.get("reachable_from") or ""),
        limit=int(document.get("limit") or 500),
    )

    for raw in document.get("entity_types") or []:
        try:
            query.entity_types.append(EntityType(raw))
        except ValueError:
            raise QueryError(f"unknown entity type: {raw!r}") from None

    for raw in document.get("attributes") or []:
        if not isinstance(raw, dict):
            raise QueryError("each attribute condition must be an object")
        condition = Attribute(key=str(raw.get("key") or ""),
                              op=str(raw.get("op") or "truthy"),
                              value=raw.get("value"))
        condition.validate()
        query.attributes.append(condition)

    if "exposed" in document and document["exposed"] is not None:
        query.exposed = bool(document["exposed"])
    if "has_findings" in document and document["has_findings"] is not None:
        query.has_findings = bool(document["has_findings"])
    if document.get("severity_at_least"):
        try:
            query.severity_at_least = Severity(document["severity_at_least"])
        except ValueError:
            raise QueryError(
                f"unknown severity: {document['severity_at_least']!r}") from None
    if document.get("max_tools") is not None:
        query.max_tools = int(document["max_tools"])

    query.validate()
    return query


# --------------------------------------------------------------------- builtins

BUILTINS: list[Query] = [
    Query(
        key="exported-no-permission",
        title="Exported components with no permission",
        description="A door anything on the device can open. The first thing "
                    "to check on any Android package.",
        entity_types=[EntityType.COMPONENT],
        attributes=[Attribute("exported", "truthy"),
                    Attribute("permission", "missing")],
    ),
    Query(
        key="reachable-secrets",
        title="Secrets something outside the app can reach",
        description="A hardcoded key is a problem. A hardcoded key an exported "
                    "component reaches is an incident, and a severity table "
                    "cannot tell them apart.",
        entity_types=[EntityType.SECRET],
        exposed=True,
    ),
    Query(
        key="cleartext-endpoints",
        title="Endpoints contacted over cleartext",
        description="Anything on the same network reads and rewrites these.",
        entity_types=[EntityType.ENDPOINT],
        attributes=[Attribute("cleartext", "truthy")],
    ),
    Query(
        key="reachable-endpoints",
        title="Endpoints reachable from an exported component",
        description="The backend surface another app on the device can drive, "
                    "which is what the TOPRECON handoff is built from.",
        entity_types=[EntityType.ENDPOINT],
        exposed=True,
    ),
    Query(
        key="deep-link-surface",
        title="Deep links into the app",
        description="A URL any website can send the user to. Every one is "
                    "attacker-controlled input arriving at a component.",
        entity_types=[EntityType.DEEP_LINK],
    ),
    Query(
        key="vulnerable-dependencies",
        title="Bundled libraries with advisories",
        description="Code the app ships but nobody on the team wrote.",
        entity_types=[EntityType.LIBRARY],
        weakness_prefix="android.dependencies.",
    ),
    Query(
        key="single-tool-findings",
        title="Findings only one tool reported",
        description="The triage queue. Agreement is what the voting model "
                    "turns into confidence, so these are the ones carrying the "
                    "least of it and needing a human most.",
        max_tools=1,
    ),
    Query(
        key="critical-anywhere",
        title="Critical and high findings",
        description="The report's opening section, as a query.",
        severity_at_least=Severity.HIGH,
    ),
    Query(
        key="dangerous-permissions",
        title="Dangerous permissions the app requests",
        description="What the app can do to the user once granted, which is "
                    "the other half of what it can do to a network.",
        entity_types=[EntityType.PERMISSION],
        attributes=[Attribute("protection", "eq", "dangerous")],
    ),
    Query(
        key="weak-crypto",
        title="Weak cryptography in use",
        description="Ciphers and modes that were fine a decade ago.",
        entity_types=[EntityType.CRYPTO_USAGE],
        weakness_prefix="android.crypto.",
    ),
]

_BY_KEY = {q.key: q for q in BUILTINS}
if len(_BY_KEY) != len(BUILTINS):
    # A duplicate key silently shadows a saved query, so it fails at import
    # rather than at the moment somebody's saved question stops working.
    seen: set[str] = set()
    duplicates = sorted({q.key for q in BUILTINS if q.key in seen or seen.add(q.key)})
    raise QueryError(f"duplicate builtin query keys: {', '.join(duplicates)}")


def builtin(key: str) -> Query | None:
    return _BY_KEY.get(key)


def pivot_from(entity: Entity) -> Query:
    """The build plan's own example: everything reachable from this node."""
    return Query(
        key=f"pivot:{entity.id}",
        title=f"Everything reachable from {entity.label or entity.key}",
        description="One step at a time from this node, following the "
                    "direction the edges point.",
        reachable_from=entity.id,
    )
