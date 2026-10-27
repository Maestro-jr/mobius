"""The dataflow pass: adjust confidence by where a flagged value ends up.

Runs after :mod:`themob.normalize.pass_` and before the scorer, and the order is
the whole design. Normalize recomputes confidence from the accumulated votes
every run, so this pass always starts from a freshly voted number and re-running
the pair converges instead of drifting upward.

**Confidence, never severity.** Reaching a sink says the reporting tool was
right about what it found, which is confidence. How bad it is if the tool was
right is severity, and that belongs to the scorer, which raises for
reachability from an exported entry point. Two stages quietly adjusting the same
number is how a rating stops being explainable.

**Corroboration is a vote; its absence is not.** A sink is independent evidence,
so it enters the existing noisy-or model as a vote from a ``dataflow`` method.
An identifier that is never referenced is the absence of evidence, which is not
a negative vote and cannot be modelled as one, so it applies a bounded discount
with a floor. A secret nothing references is still compiled into the package and
still extractable: the detector may have been over-confident about it being live,
but the finding does not go away.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..model.findings import Finding
from ..normalize.voting import MAX_CONFIDENCE, Vote, combine
from ..storage.repositories import Repositories
from ..storage.workspace import Workspace
from . import sinks
from .trace import (REACHES_SINK, UNDETERMINED, UNUSED, USED, Flow,
                    java_sources, trace)

logger = logging.getLogger(__name__)

# A wall-clock ceiling for the whole pass. The cross-file search is bounded per
# finding, but a project with dozens of traceable secrets over a huge decompiled
# tree still summed to minutes on the engine thread, which read to the operator
# as the app hanging once every analyzer already said "done". Past this, the
# remaining findings keep their voted confidence untraced: this pass only ever
# refines, so skipping it loses no finding. Override with THEMOB_DATAFLOW_BUDGET_S.
def _budget_s() -> float:
    try:
        return max(1.0, float(os.environ.get("THEMOB_DATAFLOW_BUDGET_S", "20")))
    except ValueError:
        return 20.0

# What an unreferenced value keeps. Not zero, and not close to it: the scanner
# still found a real string in a real package, and only its claim about the
# string being live is weakened.
UNUSED_DISCOUNT = 0.75
UNUSED_FLOOR = 0.3

# Only these weaknesses are worth tracing. A debuggable manifest flag has no
# value to follow, and running the tracer over it would waste the pass and
# invite a meaningless "unused" discount on a fact read out of the manifest.
TRACEABLE_PREFIXES = ("android.secrets.", "android.crypto.")


@dataclass
class DataflowReport:
    """What the pass established, and what it could not."""

    examined: int = 0
    reached_sink: int = 0
    used: int = 0
    unused: int = 0
    undetermined: int = 0
    raised: int = 0
    lowered: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        return (f"{self.examined} traced: {self.reached_sink} reach a sink, "
                f"{self.used} used elsewhere, {self.unused} never referenced, "
                f"{self.undetermined} undetermined "
                f"({self.raised} raised, {self.lowered} lowered)")


def traceable(finding: Finding) -> bool:
    """Whether following this finding's value could mean anything."""
    key = finding.weakness_key or ""
    return key.startswith(TRACEABLE_PREFIXES)


def confidence_for(flow: Flow, voted: float, votes: list[Vote]) -> float:
    """The confidence this flow implies, given what the tools already said."""
    if flow.verdict == REACHES_SINK:
        strength = sinks.weight(flow.best_category)
        # A vote, combined the same way every other reporter's is, so one model
        # decides confidence and this pass does not grow a second one.
        return combine(votes + [Vote("dataflow", strength)]).confidence
    if flow.verdict == UNUSED:
        return max(round(voted * UNUSED_DISCOUNT, 4), UNUSED_FLOOR)
    return voted


def run(repos: Repositories, project_id: str,
        workspace: Workspace) -> DataflowReport:
    """Trace every traceable finding in one project and adjust its confidence."""
    report = DataflowReport()
    root = Path(workspace.path)
    search_root = workspace.artifacts_root / "jadx" / "sources"
    sources = java_sources(search_root)     # walk the tree once, not per finding
    deadline = time.monotonic() + _budget_s()
    skipped = 0

    for finding in repos.findings.list(project_id, limit=10_000):
        if not traceable(finding):
            continue
        # Stop refining once the budget is spent. The untraced findings keep the
        # confidence normalize already voted; the pass only ever refines, so this
        # drops no finding, it just declines to spend minutes blocking the engine.
        if time.monotonic() > deadline:
            skipped += 1
            continue
        report.examined += 1

        flow = trace(finding, root, search_root,
                     sources=sources, deadline=deadline)
        report.reasons[flow.reason or flow.verdict] = (
            report.reasons.get(flow.reason or flow.verdict, 0) + 1)

        if flow.verdict == REACHES_SINK:
            report.reached_sink += 1
        elif flow.verdict == USED:
            report.used += 1
        elif flow.verdict == UNUSED:
            report.unused += 1
        else:
            report.undetermined += 1

        votes = [Vote(tool, confidence if confidence is not None else 0.5)
                 for tool, confidence in repos.findings.source_votes(finding.id)]
        voted = combine(votes).confidence if votes else finding.confidence
        adjusted = min(confidence_for(flow, voted, votes), MAX_CONFIDENCE)

        steps = flow.steps()
        if steps:
            repos.findings.set_data_flow(finding.id, steps)

        if abs(adjusted - finding.confidence) < 1e-9:
            continue
        if adjusted > finding.confidence:
            report.raised += 1
        else:
            report.lowered += 1
        repos.findings.set_confidence(finding.id, adjusted)

    if skipped:
        logger.info("dataflow: budget of %.0fs reached, %d traceable finding(s) "
                    "left at their voted confidence", _budget_s(), skipped)
    logger.info("dataflow: %s", report.summary)
    return report
