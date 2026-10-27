"""The scoring pass: severity in context, and the standards mapping.

Runs after the normalizer, and for the same reason the normalizer runs after the
analyzers. Scoring needs the finished graph, because exposure is a property of
the whole picture: a finding is reachable or not depending on components another
stage discovered, and asking mid-run would give an answer that depends on
ordering.

Two jobs, deliberately in this order:

1. **Fill the standards mapping.** MASVS control, CWE and OWASP Mobile Top 10
   come from the weakness pack, so a report never has to reconstruct them and a
   pack correction reaches old findings on the next run.
2. **Adjust severity for exposure**, once, upward only, with the reason
   recorded.

It refuses to run twice on the same finding without recomputing from the base.
Severity is stored, so a pass that raised MEDIUM to HIGH would raise it again to
CRITICAL on the next run if it treated the stored value as the base. The
weakness pack is the base, always, and the stored value is only an output.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..correlate.graph import build_snapshot
from ..correlate.pivots import Exposure, entry_points, exposure
from ..knowledge import Weakness, catalogue
from ..model.enums import Severity
from ..storage.repositories import Repositories
from .model import Score, score


@dataclass
class ScoringReport:
    """What the pass changed, and what it could not."""

    scored: int = 0
    raised: int = 0
    exposed: int = 0
    mapped: int = 0
    unknown_weakness: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unknown_weakness

    def summary(self) -> str:
        text = f"scored {self.scored} findings"
        if self.exposed:
            text += f", {self.exposed} externally reachable"
        if self.raised:
            text += f", {self.raised} raised a level"
        return text


def run(repos: Repositories, project_id: str) -> ScoringReport:
    """Score one project's findings against its finished graph."""
    report = ScoringReport()
    packs = catalogue()

    snapshot = build_snapshot(repos, project_id)
    entries = entry_points(snapshot)
    cache: dict[str, Exposure] = {}

    for finding in repos.findings.list(project_id):
        weakness = packs.get(finding.weakness_key or "")
        if weakness is None:
            # The normalizer already reports this; recorded here too so the
            # scorer's own report is self-contained.
            report.unknown_weakness.append(finding.fingerprint)
            continue

        reached = _best_exposure(snapshot, finding, entries, cache)
        # The reporter's own rating, not the stored severity: the stored value
        # may already carry a previous run's exposure bump, and raising from it
        # would compound. A CVE keeps the advisory's number, which is more
        # specific than the pack's class default, so base_severity is preferred
        # over the pack wherever it exists.
        base = finding.base_severity or weakness.severity
        result = score(base=base, confidence=finding.confidence,
                       exposed=reached is not None,
                       hops=reached.hops if reached else None)

        _apply(repos, finding, weakness, result)
        report.scored += 1
        report.mapped += 1
        if reached is not None:
            report.exposed += 1
        if result.adjusted:
            report.raised += 1

    return report


def _best_exposure(snapshot, finding, entries, cache) -> Exposure | None:
    """The shortest external route to anything this finding is about."""
    if not entries:
        return None
    best: Exposure | None = None
    for entity_id in finding.entity_ids:
        if entity_id not in cache:
            cache[entity_id] = exposure(snapshot, entity_id, entries)
        reached = cache[entity_id]
        if reached.reachable and (best is None or reached.hops < best.hops):
            best = reached
    return best


def _apply(repos: Repositories, finding, weakness: Weakness,
           result: Score) -> None:
    """Write the score and the standards mapping back.

    The standards mapping is overwritten from the pack rather than filled in
    only when missing, so a correction to the pack reaches findings stored
    before it. The severity comes from the score, which already started from
    the reporter's own rating.
    """
    repos.findings.set_score(
        finding.id,
        severity=result.severity,
        masvs_category=weakness.masvs_category,
        masvs_control=weakness.masvs_control,
        maswe_id=weakness.maswe_id,
        mobile_top10=weakness.mobile_top10,
        cwe=weakness.cwe,
        risk=result.risk,
        rationale=result.reason,
    )
