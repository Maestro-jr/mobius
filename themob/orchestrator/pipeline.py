"""The pipeline: runs analyzers, persists what they find, audits every step.

One stage at a time, one analyzer at a time, each independently re-runnable
(the pentester requirement from build plan Sec 5). The orchestrator owns three
things no adapter should:

* **the authorization gate**: :func:`require_authorization` runs before any
  analyzer does, and the run aborts if the project has no attestation;
* **entity identity**: adapters emit entities with no database id and edges
  that reference endpoints by ``(type, key)``; the orchestrator upserts the
  entities and resolves those references, which is what makes two analyzers
  converge on one node instead of duplicating it;
* **the audit trail**: every analyzer start, finish and failure is appended.

No Qt here. The engine emits plain :class:`Event` objects; ``app/signals.py``
adapts them to Qt signals on the UI thread.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Sequence

from ..adapters.base import (AnalysisContext, Analyzer, AnalyzerRegistry,
                             AnalyzerResult, Availability, EntityRef,
                             RawResult, Target)
from ..correlate.graph import build_snapshot
from .. import dataflow, normalize, scoring
from ..audit.attestation import (Action, AuditTrail, AuthorizationError,
                                 require_authorization)
from ..model.entities import Edge, Entity
from ..model.enums import EntityType, JobStatus, Stage
from ..model.findings import Finding
from ..sandbox.runner import SandboxRunner
from ..storage.repositories import Project, Repositories
from ..storage.workspace import Workspace
from .events import Event, EventType, LogLevel, PipelineState, noop_emit

# Markers of an out-of-disk-space failure, however the OS and the adapter phrase
# it: ENOSPC on POSIX, WinError 112 on Windows. By the time the run loop sees it,
# it is the analyzer's error string.
_OUT_OF_SPACE_MARKERS = (
    "not enough space on the disk",      # Windows, WinError 112
    "no space left on device",           # POSIX, ENOSPC
    "winerror 112",
    "errno 28",
)


def is_out_of_space(message: str | None) -> bool:
    """Whether an analyzer's failure is really the disk being full."""
    low = (message or "").lower()
    return any(marker in low for marker in _OUT_OF_SPACE_MARKERS)

logger = logging.getLogger(__name__)


class PipelineError(RuntimeError):
    """The run could not proceed (as distinct from an analyzer failing)."""


@dataclass
class AnalyzerOutcome:
    """What one analyzer produced, after persistence."""
    analyzer: str
    stage: Stage
    status: JobStatus
    entities: int = 0
    edges: int = 0
    findings: int = 0
    duration_s: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is JobStatus.SUCCEEDED


@dataclass
class RunSummary:
    """The result of one pipeline run."""
    project_id: str
    state: str = PipelineState.IDLE
    outcomes: list[AnalyzerOutcome] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None
    # What the dataflow pass established about where flagged values end up.
    traced: "dataflow.DataflowReport | None" = None
    # What the normalize pass did once every analyzer had reported. None when
    # the pass did not run, which is not the same as it having found nothing.
    normalized: "normalize.NormalizeReport | None" = None
    # What the scorer decided, once the graph was final. None when the pass did
    # not run, which is not the same as it having changed nothing.
    scored: "scoring.ScoringReport | None" = None

    @property
    def entities(self) -> int:
        return sum(o.entities for o in self.outcomes)

    @property
    def findings(self) -> int:
        return sum(o.findings for o in self.outcomes)

    @property
    def failed(self) -> list[AnalyzerOutcome]:
        return [o for o in self.outcomes if o.status is JobStatus.FAILED]

    @property
    def ok(self) -> bool:
        return self.state == PipelineState.DONE and not self.failed


class Pipeline:
    """Runs a project's analyzers and folds their output into the graph."""

    def __init__(self, registry: AnalyzerRegistry, repos: Repositories,
                 sandbox: SandboxRunner, audit: AuditTrail,
                 emit: Callable[[Event], None] = noop_emit) -> None:
        self._registry = registry
        self._repos = repos
        self._sandbox = sandbox
        self._audit = audit
        self._emit = emit
        self._stop = threading.Event()
        self.state = PipelineState.IDLE

    # ------------------------------------------------------------------ control

    def stop(self) -> None:
        """Ask the run to stop after the analyzer in flight finishes."""
        if self.state == PipelineState.RUNNING:
            self.state = PipelineState.STOPPING
            self._stop.set()
            self._log("Stop requested: finishing the current analyzer.",
                      LogLevel.WARN)

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # --------------------------------------------------------------------- run

    def run(self, project: Project, target: Target, workspace: Workspace,
            stages: Sequence[Stage] | None = None,
            analyzers: Sequence[str] | None = None) -> RunSummary:
        """Run the applicable analyzers for *project*.

        ``stages`` / ``analyzers`` narrow the run. That is the re-run control:
        a tester can re-run one analyzer without redoing the pipeline.

        Raises :class:`AuthorizationError` before anything executes if the
        project carries no attestation.
        """
        require_authorization(project)
        if target.project_id != project.id:
            raise PipelineError("target does not belong to this project")

        selected = self._select(target, stages, analyzers)
        summary = RunSummary(project_id=project.id, state=PipelineState.RUNNING)
        started = time.monotonic()

        self._stop.clear()
        self.state = PipelineState.RUNNING
        self._audit.record(Action.PIPELINE_STARTED, project_id=project.id,
                           target_sha256=project.source_sha256,
                           analyzers=[a.name for a in selected])
        self._emit(Event(EventType.PIPELINE_STARTED, project_id=project.id,
                         payload={"analyzers": [a.name for a in selected]}))
        self._set_state(PipelineState.RUNNING, project.id)
        self._log(f"Pipeline start: {len(selected)} analyzer(s) on "
                  f"{project.name}", LogLevel.INFO)

        out_of_space = False
        try:
            for stage in _ordered_stages(selected):
                if self.stopping or out_of_space:
                    break
                stage_analyzers = [a for a in selected if a.stage is stage]
                self._emit(Event(EventType.STAGE_STARTED, project_id=project.id,
                                 stage=stage))
                for analyzer in stage_analyzers:
                    if self.stopping or out_of_space:
                        break
                    # Re-resolve the App node between analyzers: a later stage
                    # needs to attach to the node an earlier one created, and
                    # cannot always work out its key by itself (jadx reads DEX,
                    # never the manifest).
                    outcome = self._run_analyzer(
                        analyzer, project, self._resolve_app(target), workspace)
                    summary.outcomes.append(outcome)
                    # A full disk fails every analyzer the same way, each only
                    # after its own long timeout. Stop at the first one rather
                    # than burning half an hour proving the disk is still full.
                    if (outcome.status is JobStatus.FAILED
                            and is_out_of_space(outcome.error)):
                        out_of_space = True
                        summary.error = ("stopped early: the disk is full. Free "
                                         "up space and re-run.")
                        self._log(
                            "The disk is full: an analyzer could not write its "
                            "output. Stopping the run so the rest do not fail the "
                            "same way. Free up disk space and re-run.",
                            LogLevel.ERROR)
                        break
                self._emit(Event(EventType.STAGE_FINISHED, project_id=project.id,
                                 stage=stage))
        except AuthorizationError:
            raise
        except Exception as exc:                       # noqa: BLE001
            # A bug in the orchestrator must still leave an auditable record.
            logger.exception("pipeline aborted")
            summary.state = PipelineState.FAILED
            summary.error = str(exc)
            self._finish(project, summary, started)
            raise PipelineError(str(exc)) from exc

        summary.state = (PipelineState.DONE if not self.stopping
                         else PipelineState.STOPPING)
        self._normalize(project, summary, workspace)
        self._finish(project, summary, started)
        return summary

    def _normalize(self, project: Project, summary: RunSummary,
                   workspace: Workspace) -> None:
        """Score agreement, once every analyzer in this run has reported.

        After the analyzers, never between them: voting is about corroboration,
        and corroboration is not knowable while reporters are still arriving.
        Scoring a finding when gitleaks reports it and again when apkleaks
        confirms it would make the answer depend on stage ordering.

        A failure here must not fail the run. The findings are already stored
        and correct; only their confidence would be stale, and losing a whole
        assessment over a scoring pass would be a poor trade.
        """
        try:
            report = normalize.run(self._repos, project.id)
        except Exception as exc:                       # noqa: BLE001
            logger.exception("normalize pass failed")
            self._log(f"Confidence scoring failed: {exc}", LogLevel.WARN)
            return

        summary.normalized = report
        if report.scored:
            self._log(report.summary(), LogLevel.INFO)
        if report.unmapped:
            # An adapter emitted a weakness no pack defines. That is a bug, and
            # it would otherwise reach a report as a finding with no severity
            # and no standards reference.
            self._log(f"{len(report.unmapped)} finding(s) carry no known "
                      "weakness key, which is an adapter bug", LogLevel.WARN)

        self._trace(project, summary, workspace)

    def _trace(self, project: Project, summary: RunSummary,
               workspace: Workspace) -> None:
        """Adjust confidence by where a flagged value actually ends up.

        Between the normalizer and the scorer, and the order is the design.
        Normalize recomputes confidence from the accumulated votes every run,
        so this always starts from a freshly voted number and re-running the
        pair converges rather than drifting upward. The scorer then reads the
        adjusted confidence into its risk figure.

        Needs the workspace, because it reads the decompiled sources jadx left
        there. A run with no reverse-engineering stage has nothing to read and
        reports every finding undetermined, which is the honest answer.
        """
        try:
            report = dataflow.run(self._repos, project.id, workspace)
        except Exception as exc:                       # noqa: BLE001
            logger.exception("dataflow pass failed")
            self._log(f"Dataflow tracing failed: {exc}", LogLevel.WARN)
            return

        summary.traced = report
        if report.examined:
            self._log(report.summary, LogLevel.INFO)

        self._score(project, summary)

    def _score(self, project: Project, summary: RunSummary) -> None:
        """Rate the findings against the finished graph.

        After the normalizer, because confidence feeds the risk figure, and
        after every analyzer, because exposure depends on components a later
        stage may have discovered. Asking earlier would give an answer that
        depends on the order the stages happened to run in.

        Like the normalize pass, a failure here does not fail the run: the
        findings are stored and correct, and losing an assessment over a
        ranking pass would be a poor trade.
        """
        try:
            report = scoring.run(self._repos, project.id)
        except Exception as exc:                       # noqa: BLE001
            logger.exception("scoring pass failed")
            self._log(f"Scoring failed: {exc}", LogLevel.WARN)
            return

        summary.scored = report
        if report.scored:
            self._log(report.summary(), LogLevel.INFO)

    def _finish(self, project: Project, summary: RunSummary,
                started: float) -> None:
        summary.duration_s = time.monotonic() - started
        self.state = summary.state
        self._audit.record(Action.PIPELINE_FINISHED, project_id=project.id,
                           target_sha256=project.source_sha256,
                           state=summary.state, entities=summary.entities,
                           findings=summary.findings,
                           failed=[o.analyzer for o in summary.failed],
                           duration_s=round(summary.duration_s, 2))
        self._emit(Event(EventType.PIPELINE_FINISHED, project_id=project.id,
                         payload={"state": summary.state,
                                  "entities": summary.entities,
                                  "findings": summary.findings,
                                  "duration_s": summary.duration_s}))
        self._set_state(summary.state, project.id)
        self._log(f"Pipeline {summary.state.lower()}: {summary.entities} entities, "
                  f"{summary.findings} findings in {summary.duration_s:.1f}s",
                  LogLevel.ERROR if summary.failed else LogLevel.INFO)

    # -------------------------------------------------------------- one analyzer

    def _run_analyzer(self, analyzer: Analyzer, project: Project, target: Target,
                      workspace: Workspace) -> AnalyzerOutcome:
        outcome = AnalyzerOutcome(analyzer=analyzer.name, stage=analyzer.stage,
                                  status=JobStatus.PENDING)
        availability = analyzer.availability(self._sandbox)
        if availability != Availability.READY:
            outcome.status = JobStatus.SKIPPED
            outcome.error = availability
            self._emit(Event(EventType.ANALYZER_SKIPPED, project_id=project.id,
                             stage=analyzer.stage, analyzer=analyzer.name,
                             text=availability, level=LogLevel.WARN))
            self._log(f"{analyzer.display} skipped: {availability}", LogLevel.WARN)
            return outcome

        job = self._repos.jobs.create(project.id, analyzer.stage, analyzer.name)
        self._repos.jobs.start(job.id)
        self._audit.record(Action.ANALYZER_STARTED, project_id=project.id,
                           target_sha256=project.source_sha256,
                           analyzer=analyzer.name, stage=analyzer.stage.value,
                           job_id=job.id)
        self._emit(Event(EventType.ANALYZER_STARTED, project_id=project.id,
                         stage=analyzer.stage, analyzer=analyzer.name))
        self._log(f"{analyzer.display} running...", LogLevel.INFO)

        started = time.monotonic()
        try:
            # Built per analyzer, and only on request: it is a full graph read,
            # and it has to be current: the auditor judges what the analyzers
            # *before it in this run* established, not a snapshot from the top.
            context = self._context(project.id) if analyzer.wants_graph else None
            raw = analyzer.run(target, workspace, self._sandbox, context)
        except Exception as exc:                       # noqa: BLE001
            # An adapter must never take the pipeline down with it.
            logger.exception("%s raised during run", analyzer.name)
            raw = RawResult(analyzer=analyzer.name, ok=False,
                            error=f"{type(exc).__name__}: {exc}")

        if raw.ok:
            try:
                result = analyzer.normalize(raw, target)
            except Exception as exc:                   # noqa: BLE001
                logger.exception("%s raised during normalize", analyzer.name)
                raw.ok = False
                raw.error = f"normalize failed: {type(exc).__name__}: {exc}"
                result = AnalyzerResult()
        else:
            result = AnalyzerResult()

        if raw.ok:
            try:
                counts = self.persist(project.id, result)
            except Exception as exc:                   # noqa: BLE001
                logger.exception("%s output could not be persisted", analyzer.name)
                raw.ok = False
                raw.error = f"could not persist results: {exc}"
                counts = (0, 0, 0)
        else:
            counts = (0, 0, 0)

        outcome.entities, outcome.edges, outcome.findings = counts
        outcome.duration_s = time.monotonic() - started
        outcome.status = JobStatus.SUCCEEDED if raw.ok else JobStatus.FAILED
        outcome.error = raw.error

        self._repos.jobs.finish(job.id, outcome.status, outcome.error)
        self._audit.record(
            Action.ANALYZER_FINISHED if raw.ok else Action.ANALYZER_FAILED,
            project_id=project.id, target_sha256=project.source_sha256,
            analyzer=analyzer.name, stage=analyzer.stage.value, job_id=job.id,
            status=outcome.status.value, entities=outcome.entities,
            findings=outcome.findings, error=outcome.error,
            duration_s=round(outcome.duration_s, 2))

        self._emit(Event(EventType.ANALYZER_FINISHED, project_id=project.id,
                         stage=analyzer.stage, analyzer=analyzer.name,
                         level=LogLevel.INFO if raw.ok else LogLevel.ERROR,
                         text=outcome.error or "",
                         payload={"status": outcome.status.value,
                                  "entities": outcome.entities,
                                  "edges": outcome.edges,
                                  "findings": outcome.findings,
                                  "duration_s": outcome.duration_s}))
        if outcome.entities or outcome.findings:
            self._emit(Event(EventType.GRAPH_CHANGED, project_id=project.id,
                             analyzer=analyzer.name))
        if raw.ok:
            self._log(f"{analyzer.display} -> {outcome.entities} entities, "
                      f"{outcome.findings} findings "
                      f"({outcome.duration_s:.1f}s)", LogLevel.DISCOVERY)
        else:
            self._log(f"{analyzer.display} failed: {outcome.error}", LogLevel.ERROR)
        return outcome

    def _context(self, project_id: str) -> AnalysisContext:
        """The read model handed to analyzers that judge the graph."""
        return AnalysisContext(snapshot=build_snapshot(self._repos, project_id))

    # ---------------------------------------------------------------- persistence

    def persist(self, project_id: str, result: AnalyzerResult) -> tuple[int, int, int]:
        """Fold one analyzer's output into the graph.

        Entities are upserted first so edges can be resolved against real row
        ids. An edge whose endpoint does not exist, the adapter referenced
        something no analyzer has discovered, is dropped with a warning rather
        than failing the run; a dangling foreign key is not worth losing a
        stage's work over.
        """
        index: dict[tuple, Entity] = {}
        entities = 0
        for entity in result.entities:
            stored = self._repos.entities.upsert(project_id, entity)
            index[(stored.type, stored.key)] = stored
            entities += 1

        edges = 0
        for spec in result.edges:
            src = self._resolve(project_id, spec.src, index)
            dst = self._resolve(project_id, spec.dst, index)
            if src is None or dst is None:
                missing = spec.src if src is None else spec.dst
                logger.warning("dropping edge %s: unknown %s %r",
                               spec.type.value, missing.type.value, missing.key)
                continue
            self._repos.edges.upsert(project_id, Edge(
                src_id=src.id, dst_id=dst.id, type=spec.type,
                attributes=spec.attributes))
            edges += 1

        findings = 0
        for finding in result.findings:
            self._repos.findings.upsert(project_id, self._link(finding, index))
            findings += 1

        if entities or edges or findings:
            self._emit(Event(EventType.ENTITIES_ADDED, project_id=project_id,
                             payload={"entities": entities, "edges": edges,
                                      "findings": findings}))
        return entities, edges, findings

    def _resolve(self, project_id: str, ref: EntityRef,
                 index: dict[tuple, Entity]) -> Entity | None:
        """An entity id for a ``(type, key)`` reference.

        Checks this run's batch first, then the database, a later analyzer
        routinely links to a node an earlier stage created.
        """
        hit = index.get((ref.type, ref.key))
        if hit is not None:
            return hit
        stored = self._repos.entities.get_by_key(project_id, ref.type, ref.key)
        if stored is not None:
            index[(ref.type, ref.key)] = stored
        return stored

    @staticmethod
    def _link(finding: Finding, index: dict[tuple, Entity]) -> Finding:
        """Map any ``type:key`` placeholders in ``entity_ids`` to real ids."""
        resolved: list[str] = []
        by_key = {f"{e.type.value}:{e.key}": e.id for e in index.values()}
        for ref in finding.entity_ids:
            resolved.append(by_key.get(ref, ref))
        finding.entity_ids = resolved
        return finding

    def _resolve_app(self, target: Target) -> Target:
        """Stamp the current App node's key onto the target.

        Cheap (one indexed lookup per analyzer) and it is what keeps every
        adapter upserting onto a single App node instead of forking one per
        tool.
        """
        apps = self._repos.entities.list(target.project_id, EntityType.APP)
        if not apps:
            return target
        app = apps[0]
        package = app.attributes.get("package")
        if target.app_key == app.key and target.package == package:
            return target
        return replace(target, app_key=app.key,
                       package=package if isinstance(package, str) else None)

    # -------------------------------------------------------------------- helpers

    def _select(self, target: Target, stages: Sequence[Stage] | None,
                analyzers: Sequence[str] | None) -> list[Analyzer]:
        selected = self._registry.applicable(target, stages)
        if analyzers:
            wanted = set(analyzers)
            unknown = wanted - {a.name for a in self._registry.all()}
            if unknown:
                raise PipelineError(f"unknown analyzer(s): {sorted(unknown)}")
            selected = [a for a in selected if a.name in wanted]
        if not selected:
            raise PipelineError(
                "no analyzer applies to this target, check the platform and "
                "file type, or that the requested stage has an analyzer")
        return selected

    def _log(self, text: str, level: str = LogLevel.INFO) -> None:
        self._emit(Event(EventType.LOG, text=text, level=level))

    def _set_state(self, state: str, project_id: str) -> None:
        self._emit(Event(EventType.STATE, project_id=project_id, text=state))


def _ordered_stages(analyzers: Sequence[Analyzer]) -> list[Stage]:
    """The stages present in *analyzers*, in pipeline order."""
    present = {a.stage for a in analyzers}
    return [s for s in Stage if s in present]
