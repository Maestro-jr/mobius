"""The normalize pass: score every finding once all the analyzers have spoken.

This runs after the pipeline's analyzers, never during. Voting is about
agreement, and agreement is not knowable while reporters are still arriving:
scoring a finding when gitleaks reports it and again when apkleaks confirms it
would make the result depend on the order the stages happened to run in.

What it does, in one sweep per project:

* recomputes confidence from the accumulated ``finding_sources`` rows, using the
  method-aware model in :mod:`themob.normalize.voting`
* reports which findings no weakness pack defines, because that is a bug in an
  adapter that would otherwise surface as an unmapped row in a report weeks
  later

It deliberately does **not** touch severity. Severity is the scorer's job, and
two stages quietly adjusting the same number is how a rating stops being
explainable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import keys as known_weaknesses
from ..storage.repositories import Repositories
from .voting import Vote, combine


@dataclass
class NormalizeReport:
    """What the pass changed, and what it could not account for."""

    scored: int = 0
    corroborated: int = 0
    raised: int = 0
    lowered: int = 0
    unmapped: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether every finding carried a weakness the catalogue defines."""
        return not self.unmapped

    def summary(self) -> str:
        text = (f"scored {self.scored} findings, "
                f"{self.corroborated} corroborated by independent methods")
        if self.unmapped:
            text += f", {len(self.unmapped)} with no weakness key"
        return text


def run(repos: Repositories, project_id: str) -> NormalizeReport:
    """Re-score one project's findings from their accumulated sources."""
    report = NormalizeReport()
    catalogue = known_weaknesses()

    for finding in repos.findings.list(project_id):
        reported = repos.findings.source_votes(finding.id)
        if not reported:
            # Nothing to vote on. The stored confidence is the only opinion
            # anyone offered, so it stands.
            continue

        # A null confidence means the row predates the column. Falling back to
        # the finding's own value keeps such a reporter in the count without
        # inventing a number for it.
        votes = [Vote(tool=tool,
                      confidence=finding.confidence if value is None else value)
                 for tool, value in reported]
        verdict = combine(votes)

        if abs(verdict.confidence - finding.confidence) >= 0.0001:
            repos.findings.set_confidence(finding.id, verdict.confidence)
            if verdict.confidence > finding.confidence:
                report.raised += 1
            else:
                report.lowered += 1
        report.scored += 1
        if verdict.corroborated:
            report.corroborated += 1

        key = finding.weakness_key
        if not key or key not in catalogue:
            report.unmapped.append(finding.fingerprint)

    return report
