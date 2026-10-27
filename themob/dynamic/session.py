"""The dynamic run: turning a device session into findings on the graph.

Phases 1 and 2 run inside :class:`~themob.orchestrator.pipeline.Pipeline`,
automatically, one stage after another. Dynamic analysis does not belong there.
It needs a device, it needs a second attestation, and it is driven by an
operator deciding what to exercise, not by a stage order. So it has its own
coordinator, the way Phase 2's service mode had its own module before the MobSF
adapter used it.

What this owns, and what the pipeline owns for the static side:

* **the execution gate**, re-checked here at the top: a plan is a value that can
  be held, and the attestation it was built under must still hold when its
  results are being written, not only when it was prepared;
* **entity identity**: a runtime finding references the App node or an endpoint,
  and this resolves those to real ids from the current graph so the finding
  attaches rather than dangling;
* **the merge**: findings are upserted by fingerprint, so "we watched it happen"
  lands on the same row as "a static tool suspected it" and the two become one
  finding with two sources;
* **the re-vote**: after the merge, the normalizer and scorer run again, because
  a runtime source is new corroboration and confidence is exactly what new
  corroboration should change. This is the whole reason dynamic analysis feeds
  the same graph instead of a separate report.

Nothing here starts a process or touches a device. It takes the evidence a run
already produced, Frida's tagged output and mitmproxy's capture, the same way
the static adapters take a container's output. Driving the device is the tools'
job (adb, instrument, capture); making what they saw matter is this one's.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence

from .. import normalize, scoring
from ..audit.attestation import Action, AuditTrail
from ..correlate.graph import build_snapshot
from ..model.enums import EntityType, JobStatus, Stage
from ..model.findings import Finding
from ..storage.repositories import Repositories
from .capture import CaptureResult
from .findings import Observation, from_capture, from_frida, parse_frida_events
from .gate import require_execution

logger = logging.getLogger(__name__)


@dataclass
class DynamicOutcome:
    """What one dynamic run added, after persistence and the re-vote."""

    source: str                           # "frida" | "mitmproxy"
    findings: int = 0
    merged: int = 0                       # of those, how many joined a static one
    new: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class DynamicSummary:
    """The result of a dynamic session over one project."""

    project_id: str
    outcomes: list[DynamicOutcome] = field(default_factory=list)
    revoted: bool = False

    @property
    def findings(self) -> int:
        return sum(o.findings for o in self.outcomes)

    @property
    def merged(self) -> int:
        return sum(o.merged for o in self.outcomes)

    @property
    def summary(self) -> str:
        if not self.outcomes:
            return "no dynamic findings"
        return (f"{self.findings} runtime finding(s), {self.merged} merged with "
                f"a static finding")


class DynamicSession:
    """Coordinates a dynamic run's results onto one project's graph."""

    def __init__(self, repos: Repositories, audit: AuditTrail) -> None:
        self._repos = repos
        self._audit = audit

    # ------------------------------------------------------------------ public

    def record_frida(self, project_id: str, output: Sequence[str] | str, *,
                     raw_ref: str = "") -> DynamicOutcome:
        """Merge what a Frida agent observed into the graph.

        *output* is the agent's stdout, whole or split into lines. Only the
        ``themob-observe`` lines are read; the rest is Frida's own chatter.
        """
        lines = output.splitlines() if isinstance(output, str) else list(output)
        observations = parse_frida_events(lines)
        return self._ingest("frida", project_id, observations, None,
                            raw_ref=raw_ref)

    def record_capture(self, project_id: str, result: CaptureResult, *,
                       raw_ref: str = "") -> DynamicOutcome:
        """Merge intercepted traffic into the graph."""
        return self._ingest("mitmproxy", project_id, None, result,
                            raw_ref=raw_ref)

    def finalize(self, project_id: str) -> DynamicSummary:
        """Re-vote and re-score after a run, so runtime corroboration counts.

        Called once when the operator finishes exercising the app, not after
        every observation: confidence is about the accumulated agreement, and
        recomputing it mid-run would make the number depend on the order the
        operator happened to click things.
        """
        summary = DynamicSummary(project_id=project_id)
        summary.revoted = self._revote(project_id)
        return summary

    # ----------------------------------------------------------------- ingest

    def _ingest(self, source: str, project_id: str,
                observations: Sequence[Observation] | None,
                capture: CaptureResult | None, *,
                raw_ref: str) -> DynamicOutcome:
        # The gate is re-checked at write time, not only when the plan was made.
        require_execution(self._repos, project_id)

        stage = Stage.DYNAMIC
        job = self._repos.jobs.create(project_id, stage, source)
        self._repos.jobs.start(job.id)

        try:
            snapshot = build_snapshot(self._repos, project_id)
            existing = {f.fingerprint for f in
                        self._repos.findings.list(project_id, limit=100_000)}

            if observations is not None:
                app = next(iter(snapshot.of_type(EntityType.APP)), None)
                findings = from_frida(observations,
                                      app_entity_id=app.id if app else "",
                                      raw_ref=raw_ref)
            else:
                findings = from_capture(capture,
                                        endpoint_ids=self._endpoint_ids(snapshot),
                                        raw_ref=raw_ref)

            outcome = DynamicOutcome(source=source, findings=len(findings))
            for finding in findings:
                if finding.fingerprint in existing:
                    outcome.merged += 1
                else:
                    outcome.new += 1
                self._repos.findings.upsert(project_id, finding)

            self._repos.jobs.finish(job.id, JobStatus.SUCCEEDED)
            self._audit.record(
                Action.ANALYZER_FINISHED, project_id=project_id,
                analyzer=source, stage=stage.value,
                findings=outcome.findings, merged=outcome.merged,
                new=outcome.new)
            return outcome
        except Exception as exc:                       # noqa: BLE001
            logger.exception("dynamic ingest failed for %s", source)
            self._repos.jobs.finish(job.id, JobStatus.FAILED, str(exc))
            self._audit.record(Action.ANALYZER_FAILED, project_id=project_id,
                               analyzer=source, stage=stage.value,
                               error=str(exc))
            return DynamicOutcome(source=source, error=str(exc))

    def run(self, project_id: str, *, frida_output: Sequence[str] | str = "",
            capture: CaptureResult | None = None,
            frida_raw: str = "", capture_raw: str = "") -> DynamicSummary:
        """Ingest whatever a run produced, then finalize. The one-call form."""
        summary = DynamicSummary(project_id=project_id)
        if frida_output:
            summary.outcomes.append(
                self.record_frida(project_id, frida_output, raw_ref=frida_raw))
        if capture is not None:
            summary.outcomes.append(
                self.record_capture(project_id, capture, raw_ref=capture_raw))
        if summary.outcomes:
            summary.revoted = self._revote(project_id)
        return summary

    # ---------------------------------------------------------------- internal

    def _endpoint_ids(self, snapshot) -> dict[str, str]:
        """host -> entity id, so a captured flow attaches to the graph's node."""
        ids: dict[str, str] = {}
        for entity in snapshot.of_type(EntityType.ENDPOINT):
            host = str(entity.attributes.get("host") or "").strip().lower()
            if host and host not in ids:
                ids[host] = entity.id
        return ids

    def _revote(self, project_id: str) -> bool:
        """Recompute confidence and risk. A failure here does not lose findings.

        Same trade the pipeline makes: the runtime findings are already stored
        and correct, and only their confidence would be stale. Dataflow is not
        re-run, because it reads decompiled sources for a static source-to-sink
        and a runtime observation is not one of its inputs.
        """
        ok = True
        for name, pass_run in (("normalize", normalize.run),
                               ("scoring", scoring.run)):
            try:
                pass_run(self._repos, project_id)
            except Exception as exc:                   # noqa: BLE001
                logger.exception("%s re-vote failed", name)
                ok = False
        return ok
