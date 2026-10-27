"""The tester-facing sections, defined as projections rather than as screens.

The build plan's §8 lists a left-nav: Reverse Engineering, Storage, Network &
API, Cryptography, Platform & IPC, Dependencies & SDKs, Secrets. Its §4 says why
that list is not a set of pages: "the Network & API section is
``entities WHERE type IN (Endpoint, CloudAsset)`` plus their edges". A section is
a query, and the panel that draws it is a consequence.

Keeping the definitions here rather than in ``app/`` matters for two reasons.
The report (1.13) has to produce the same grouping as the UI without importing
Qt, and a section is the unit a tester thinks in, so a finding landing in the
wrong one is a real defect rather than a cosmetic one. Both need this to be one
list that nothing else duplicates.

A finding belongs to a section by the *entities it touches*, and only falls back
to the stage that produced it when it touches nothing. Entity membership is the
better signal: a hardcoded key found by semgrep is a Secrets finding, not a SAST
finding, because what a tester wants is every secret in one place regardless of
which tool noticed it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from ..model.entities import Entity
from ..model.enums import EntityType, Severity, Stage
from ..model.findings import Finding
from .graph import GraphSnapshot


@dataclass(frozen=True)
class Section:
    """One projection of the graph, plus the findings that belong to it."""

    key: str
    title: str
    types: tuple[EntityType, ...]
    # Findings from these stages land here when they touch no entity at all.
    # A fallback, not the primary rule.
    stages: tuple[Stage, ...] = ()
    description: str = ""


# The plan's §8 left-nav, in its order. Dynamic/Runtime is phase 3 and absent
# on purpose: an empty section that can never fill is worse than no section.
SECTIONS: tuple[Section, ...] = (
    Section(
        key="platform", title="Platform & IPC",
        types=(EntityType.COMPONENT, EntityType.PERMISSION,
               EntityType.DEEP_LINK),
        stages=(Stage.CONFIG_AUDIT,),
        description="Exported surface, permissions and the links that reach it.",
    ),
    Section(
        key="network", title="Network & API",
        types=(EntityType.ENDPOINT, EntityType.CLOUD_ASSET),
        stages=(Stage.API_RECON,),
        description="The backend attack surface, and the handoff to TOPRECON.",
    ),
    Section(
        key="secrets", title="Secrets",
        types=(EntityType.SECRET,),
        stages=(Stage.SECRETS,),
        description="Credentials and keys shipped inside the package.",
    ),
    Section(
        key="crypto", title="Cryptography",
        types=(EntityType.CRYPTO_USAGE,),
        stages=(),
        description="Where the app encrypts, hashes and signs.",
    ),
    Section(
        key="storage", title="Storage",
        types=(EntityType.STORAGE_SINK,),
        stages=(),
        description="Where the app puts data, and what reaches it.",
    ),
    Section(
        key="dependencies", title="Dependencies & SDKs",
        types=(EntityType.LIBRARY, EntityType.NATIVE_LIB),
        stages=(Stage.DEPENDENCIES,),
        description="What the package bundles, and which of it has advisories.",
    ),
    Section(
        key="code", title="Reverse engineering",
        types=(EntityType.APP,),
        stages=(Stage.REVERSE_ENGINEERING, Stage.SAST),
        description="The code map, and what static analysis found in it.",
    ),
)

_BY_KEY = {s.key: s for s in SECTIONS}

# Which section owns each entity type. Built from SECTIONS so the two can never
# disagree; a type claimed by two sections is a definition bug and is refused
# at import rather than silently resolved by ordering.
_OWNER: dict[EntityType, str] = {}
for _section in SECTIONS:
    for _type in _section.types:
        if _type in _OWNER:
            raise RuntimeError(
                f"{_type.value} is claimed by both {_OWNER[_type]!r} and "
                f"{_section.key!r}; a finding cannot be in two sections")
        _OWNER[_type] = _section.key


@dataclass
class SectionView:
    """What one section shows: its slice of the graph and its findings."""

    section: Section
    entities: list[Entity] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.section.key

    @property
    def title(self) -> str:
        return self.section.title

    @property
    def is_empty(self) -> bool:
        return not self.entities and not self.findings

    @property
    def worst_severity(self) -> Severity | None:
        """The most severe finding here, which is what the nav badge shows."""
        if not self.findings:
            return None
        rank = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                Severity.HIGH: 3, Severity.CRITICAL: 4}
        return max((f.severity for f in self.findings), key=lambda s: rank[s])

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


def get(key: str) -> Section:
    """Look up a section, failing loudly rather than returning a blank one."""
    try:
        return _BY_KEY[key]
    except KeyError:
        raise KeyError(f"unknown section {key!r}; known: "
                       f"{', '.join(sorted(_BY_KEY))}") from None


def section_for_entity(entity_type: EntityType) -> str | None:
    """Which section owns this entity type, if any."""
    return _OWNER.get(entity_type)


def project(snapshot: GraphSnapshot, findings: Sequence[Finding],
            sections: Sequence[Section] = SECTIONS) -> list[SectionView]:
    """Split the graph and its findings into the tester-facing sections.

    Every finding lands in exactly one section, so a total across sections is a
    real total and not a number inflated by double counting.
    """
    by_id = {e.id: e for e in snapshot.entities}
    views = {s.key: SectionView(section=s) for s in sections}
    keys = set(views)

    for entity in snapshot.entities:
        owner = _OWNER.get(entity.type)
        if owner in keys:
            views[owner].entities.append(entity)

    for finding in findings:
        owner = _section_for_finding(finding, by_id, keys)
        if owner is not None:
            views[owner].findings.append(finding)

    return [views[s.key] for s in sections]


def counts_without_graph(entities: Sequence[Entity],
                         findings: Sequence[Finding],
                         sections: Sequence[Section] = SECTIONS
                         ) -> dict[str, int]:
    """Per-section finding counts from entities and findings alone.

    The live view during a run needs the nav badges to keep moving, but it must
    not pay for the NetworkX graph that :func:`project` works from: rebuilding
    that on the UI thread while the engine builds its own corrupted memory into
    a crash (see the project_themob_ui_freeze note). The section a finding
    belongs to is decided only by the *types* of the entities it touches and by
    its weakness key, never by the edges, so this reproduces exactly the
    assignment :func:`project` makes, from two cheap database reads and no graph.
    """
    by_id = {e.id: e for e in entities}
    keys = {s.key for s in sections}
    counts = {s.key: 0 for s in sections}
    for finding in findings:
        owner = _section_for_finding(finding, by_id, keys)
        if owner is not None:
            counts[owner] += 1
    return counts


def _section_for_finding(finding: Finding, by_id: dict[str, Entity],
                         keys: set[str]) -> str | None:
    """The one section a finding belongs to.

    Entities first: a hardcoded key is a Secrets finding whether semgrep or
    gitleaks noticed it, and grouping by the reporting stage would scatter one
    class of issue across the nav. The stage is only consulted when the finding
    touches nothing, which happens for whole-app judgements such as "the package
    is signed with v1 only".
    """
    for entity_id in finding.entity_ids:
        entity = by_id.get(entity_id)
        if entity is None:
            continue
        owner = _OWNER.get(entity.type)
        # The App node is every finding's last resort, so it never decides a
        # section while a more specific entity is also attached.
        if owner in keys and entity.type is not EntityType.APP:
            return owner

    # Nothing specific was attached, so the weakness key decides. A stored
    # finding does not carry the stage that produced it, and the key is a
    # better signal anyway: it says what the issue *is* rather than which
    # scanner happened to notice it.
    fallback = _weakness_section(finding)
    if fallback in keys:
        return fallback
    # An app-wide judgement with no better home. Platform & IPC is where the
    # manifest lives, and manifest-level judgements are what these are.
    if "platform" in keys and finding.entity_ids:
        return "platform"
    return None


def _weakness_section(finding: Finding) -> str | None:
    """Fall back to the weakness key's own prefix.

    ``android.network.cleartext-endpoint`` is a network finding even when it is
    attached only to the App node, and the key already says so. This is the
    cheapest correct answer and needs nothing the finding does not carry.
    """
    key = finding.weakness_key or ""
    prefix = key.split(".")[1] if key.count(".") >= 2 else ""
    return {
        "network": "network",
        "ipc": "platform",
        "config": "platform",
        "platform": "platform",
        "integrity": "platform",
        "crypto": "crypto",
        "secrets": "secrets",
        "supply-chain": "dependencies",
        "storage": "storage",
    }.get(prefix)
