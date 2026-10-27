"""Intake, the authorization gate in front of the pipeline, and persistence.

The pipeline runs with a stub analyzer here, the real one needs Docker. What
matters at this layer is that authorization is enforced, entity identity is
resolved correctly, an adapter cannot take the run down, and every step is
audited.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.adapters.base import (Analyzer, AnalyzerRegistry, AnalyzerResult,
                                  Availability, EdgeSpec, EntityRef, RawResult,
                                  Target)
from themob.audit.attestation import (Action, Attestation, AuditTrail,
                                      AuthorizationError)
from themob.model.entities import Entity
from themob.model.enums import (EdgeType, EntityType, JobStatus, Platform,
                                Severity, Stage)
from themob.model.findings import Finding, FindingSource
from themob.orchestrator import (Event, EventType, IntakeError, Pipeline,
                                 PipelineError, PipelineState, detect_platform,
                                 intake, target_for, validate_sample)
from themob.sandbox.runner import SandboxRunner
from themob.storage.repositories import Repositories
from themob.storage.workspace import Workspace


# --------------------------------------------------------------------- stubs

class _StubAnalyzer(Analyzer):
    name = "stub"
    display = "Stub analyzer"
    stage = Stage.UNPACK
    tool = "stubtool"
    image = ""                       # no container needed, so always READY

    def __init__(self, result: AnalyzerResult | None = None,
                 raw_ok: bool = True, raises: Exception | None = None) -> None:
        self._result = result or AnalyzerResult()
        self._raw_ok = raw_ok
        self._raises = raises
        self.runs = 0
        self.context = None

    def run(self, target, workspace, sandbox, context=None) -> RawResult:
        self.runs += 1
        self.context = context
        if self._raises is not None:
            raise self._raises
        return RawResult(analyzer=self.name, ok=self._raw_ok,
                         payload={"x": 1}, error=None if self._raw_ok else "tool died")

    def normalize(self, raw, target) -> AnalyzerResult:
        return self._result


class _SecondStage(_StubAnalyzer):
    name = "stub2"
    display = "Second stage"
    stage = Stage.CONFIG_AUDIT


class _OfflineSandbox(SandboxRunner):
    def is_available(self) -> bool:
        return False


def _entity(key: str, etype: EntityType = EntityType.APP) -> Entity:
    return Entity(type=etype, platform=Platform.ANDROID, key=key, label=key)


@pytest.fixture()
def audit(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


@pytest.fixture()
def sandbox() -> SandboxRunner:
    return SandboxRunner()


def _authorized(repos: Repositories, audit: AuditTrail, sample_apk: Path,
                tmp_path: Path):
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name=result.project.name, target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-7", attested=True),
        repos.projects)
    return repos.projects.get(result.project.id), result


def _pipeline(registry, repos, audit, sandbox, events=None) -> Pipeline:
    emit = events.append if events is not None else (lambda _e: None)
    return Pipeline(registry, repos, sandbox, audit, emit)


def _registry(*analyzers) -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    registry.register_all(analyzers)
    return registry


# -------------------------------------------------------------------- intake

def test_intake_creates_an_unauthorized_project(repos, audit, sample_apk,
                                                tmp_path: Path) -> None:
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    assert result.project.target_platform is Platform.ANDROID
    assert not result.project.is_authorized, "intake must not authorize"
    assert result.workspace.resolve(result.project.source_path).is_file()
    assert repos.audit.list(result.project.id)[0].action == Action.PROJECT_CREATED


def test_intake_rejects_non_packages(repos, audit, tmp_path: Path) -> None:
    text = tmp_path / "notes.txt"
    text.write_text("hello", encoding="utf-8")
    with pytest.raises(IntakeError, match="not a zip"):
        intake(text, repos, audit, root=tmp_path / "home")

    with pytest.raises(IntakeError, match="not found"):
        validate_sample(tmp_path / "ghost.apk")

    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")
    with pytest.raises(IntakeError, match="empty"):
        validate_sample(empty)


def test_platform_detected_from_layout_when_extension_is_unknown(
        tmp_path: Path) -> None:
    import zipfile

    android = tmp_path / "mystery.bin"
    with zipfile.ZipFile(android, "w") as zf:
        zf.writestr("AndroidManifest.xml", "x")
    assert detect_platform(android) is Platform.ANDROID

    ios = tmp_path / "mystery2.bin"
    with zipfile.ZipFile(ios, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", "x")
    assert detect_platform(ios) is Platform.IOS

    unknown = tmp_path / "mystery3.bin"
    with zipfile.ZipFile(unknown, "w") as zf:
        zf.writestr("readme.txt", "x")
    with pytest.raises(IntakeError):
        detect_platform(unknown)


def test_failed_project_creation_leaves_no_workspace(repos, audit, sample_apk,
                                                     tmp_path: Path,
                                                     monkeypatch) -> None:
    def boom(_project):
        raise RuntimeError("db down")

    monkeypatch.setattr(repos.projects, "create", boom)
    with pytest.raises(RuntimeError):
        intake(sample_apk, repos, audit, root=tmp_path / "home")
    projects_dir = tmp_path / "home" / "projects"
    assert not projects_dir.exists() or not any(projects_dir.iterdir())


def test_target_for_rebuilds_an_existing_project(repos, audit, sample_apk,
                                                 tmp_path: Path) -> None:
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    rebuilt = target_for(result.project, result.workspace)
    assert rebuilt.sha256 == result.sha256
    assert rebuilt.sample_path.is_file()


# ------------------------------------------------------------- the gate

def test_pipeline_refuses_an_unauthorized_project(repos, audit, sandbox,
                                                  sample_apk, tmp_path) -> None:
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    stub = _StubAnalyzer()
    pipeline = _pipeline(_registry(stub), repos, audit, sandbox)

    with pytest.raises(AuthorizationError):
        pipeline.run(result.project, result.target, result.workspace)
    assert stub.runs == 0, "no analyzer may run before the gate"
    assert repos.jobs.list(result.project.id) == []


def test_authorized_project_runs(repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    stub = _StubAnalyzer(AnalyzerResult(entities=[_entity("com.example")]))
    summary = _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert summary.ok and summary.entities == 1
    assert stub.runs == 1
    assert repos.entities.count(project.id) == 1


def test_is_out_of_space_detects_enospc_and_winerror() -> None:
    from themob.orchestrator.pipeline import is_out_of_space

    assert is_out_of_space("OSError: [Errno 28] No space left on device")
    assert is_out_of_space("[WinError 112] There is not enough space on the disk")
    assert is_out_of_space("could not persist results: No space left on device")
    assert not is_out_of_space("timed out after 900s")
    assert not is_out_of_space(None)
    assert not is_out_of_space("")


def test_the_run_stops_early_when_the_disk_is_full(repos, audit, sandbox,
                                                   sample_apk, tmp_path) -> None:
    """A full disk fails every analyzer, each only after its own long timeout.
    The run must stop at the first out-of-space failure, not burn through the
    rest proving the disk is still full."""
    import errno

    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    first = _StubAnalyzer(raises=OSError(errno.ENOSPC, "No space left on device"))
    second = _SecondStage()           # a later stage; it must never run
    summary = _pipeline(_registry(first, second), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert first.runs == 1
    assert second.runs == 0, "the run should have stopped at the full disk"
    assert any(o.status is JobStatus.FAILED for o in summary.outcomes)
    assert "disk is full" in (summary.error or "")


def test_target_must_belong_to_the_project(repos, audit, sandbox, sample_apk,
                                           tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    foreign = Target(project_id="someone-else", platform=Platform.ANDROID,
                     sample_path=result.target.sample_path, sha256=result.sha256)
    with pytest.raises(PipelineError, match="does not belong"):
        _pipeline(_registry(_StubAnalyzer()), repos, audit, sandbox).run(
            project, foreign, result.workspace)


# ---------------------------------------------------------------- persistence

def test_edges_resolve_entities_emitted_in_the_same_batch(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    app, comp = _entity("com.example"), _entity("com.example.Main", EntityType.COMPONENT)
    stub = _StubAnalyzer(AnalyzerResult(
        entities=[app, comp],
        edges=[EdgeSpec(EntityRef.of(app), EntityRef.of(comp), EdgeType.DECLARES)]))

    _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    edges = repos.edges.list(project.id)
    assert len(edges) == 1
    stored_app = repos.entities.get_by_key(project.id, EntityType.APP, "com.example")
    assert edges[0].src_id == stored_app.id


def test_edges_resolve_entities_from_an_earlier_stage(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    app = _entity("com.example")
    later = _entity("android.permission.INTERNET", EntityType.PERMISSION)

    first = _StubAnalyzer(AnalyzerResult(entities=[app]))
    second = _SecondStage(AnalyzerResult(
        entities=[later],
        # References the App the first stage created, by key alone.
        edges=[EdgeSpec(EntityRef(EntityType.APP, "com.example"),
                        EntityRef.of(later), EdgeType.REQUESTS_PERMISSION)]))

    summary = _pipeline(_registry(first, second), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert summary.ok
    assert repos.edges.count(project.id) == 1


def test_edge_to_an_unknown_entity_is_dropped_not_fatal(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    app = _entity("com.example")
    stub = _StubAnalyzer(AnalyzerResult(
        entities=[app],
        edges=[EdgeSpec(EntityRef.of(app),
                        EntityRef(EntityType.SECRET, "never-discovered"),
                        EdgeType.EVIDENCES)]))

    summary = _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert summary.ok, "a dangling edge must not fail the stage"
    assert repos.edges.count(project.id) == 0
    assert repos.entities.count(project.id) == 1


def test_findings_are_persisted_with_their_sources(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    finding = Finding(fingerprint="f" * 64, title="Debuggable build",
                      severity=Severity.HIGH,
                      sources=[FindingSource(tool="stubtool", rule="dbg")])
    stub = _StubAnalyzer(AnalyzerResult(findings=[finding]))

    summary = _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert summary.findings == 1
    stored = repos.findings.list(project.id)[0]
    assert stored.sources[0].tool == "stubtool"


def test_finding_entity_placeholders_resolve_to_real_ids(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    app = _entity("com.example")
    finding = Finding(fingerprint="a" * 64, title="X", severity=Severity.LOW,
                      entity_ids=["app:com.example"])
    stub = _StubAnalyzer(AnalyzerResult(entities=[app], findings=[finding]))

    _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    stored_app = repos.entities.get_by_key(project.id, EntityType.APP, "com.example")
    assert repos.findings.list(project.id)[0].entity_ids == [stored_app.id]


# ------------------------------------------------------------------ failure

def test_an_adapter_that_raises_fails_only_its_own_job(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    exploding = _StubAnalyzer(raises=RuntimeError("parser blew up"))
    survivor = _SecondStage(AnalyzerResult(entities=[_entity("com.example")]))

    summary = _pipeline(_registry(exploding, survivor), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    assert summary.state == PipelineState.DONE
    statuses = {o.analyzer: o.status for o in summary.outcomes}
    assert statuses == {"stub": JobStatus.FAILED, "stub2": JobStatus.SUCCEEDED}
    assert "parser blew up" in summary.failed[0].error
    assert repos.entities.count(project.id) == 1


def test_failed_analyzer_is_recorded_on_its_job_and_in_the_audit(
        repos, audit, sandbox, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    stub = _StubAnalyzer(raw_ok=False)
    _pipeline(_registry(stub), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    job = repos.jobs.list(project.id)[0]
    assert job.status is JobStatus.FAILED and job.error == "tool died"
    actions = [e.action for e in repos.audit.list(project.id)]
    assert Action.ANALYZER_FAILED in actions


def test_unavailable_analyzer_is_skipped_not_failed(
        repos, audit, sample_apk, tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)

    class _Containerized(_StubAnalyzer):
        name = "needs-docker"
        image = "themob/whatever:1"

    summary = _pipeline(_registry(_Containerized()), repos, audit,
                        _OfflineSandbox()).run(project, result.target,
                                               result.workspace)
    outcome = summary.outcomes[0]
    assert outcome.status is JobStatus.SKIPPED
    assert outcome.error == Availability.NO_SANDBOX
    assert repos.jobs.list(project.id) == [], "a skip is not a job"


def test_no_applicable_analyzer_is_an_error(repos, audit, sandbox, sample_apk,
                                            tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)

    class _IosOnly(_StubAnalyzer):
        name = "ios-only"
        platforms = (Platform.IOS,)

    with pytest.raises(PipelineError, match="no analyzer applies"):
        _pipeline(_registry(_IosOnly()), repos, audit, sandbox).run(
            project, result.target, result.workspace)


def test_rerunning_one_analyzer_is_supported(repos, audit, sandbox, sample_apk,
                                             tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    first, second = _StubAnalyzer(), _SecondStage()
    pipeline = _pipeline(_registry(first, second), repos, audit, sandbox)

    pipeline.run(project, result.target, result.workspace, analyzers=["stub2"])
    assert (first.runs, second.runs) == (0, 1)

    with pytest.raises(PipelineError, match="unknown analyzer"):
        pipeline.run(project, result.target, result.workspace,
                     analyzers=["does-not-exist"])


# ------------------------------------------------------------------- events

def test_run_emits_a_complete_event_stream(repos, audit, sandbox, sample_apk,
                                           tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    events: list[Event] = []
    stub = _StubAnalyzer(AnalyzerResult(entities=[_entity("com.example")]))

    _pipeline(_registry(stub), repos, audit, sandbox, events).run(
        project, result.target, result.workspace)

    kinds = [e.kind for e in events]
    for expected in (EventType.PIPELINE_STARTED, EventType.STAGE_STARTED,
                     EventType.ANALYZER_STARTED, EventType.ANALYZER_FINISHED,
                     EventType.GRAPH_CHANGED, EventType.STAGE_FINISHED,
                     EventType.PIPELINE_FINISHED):
        assert expected in kinds, f"missing {expected}"
    assert kinds.index(EventType.PIPELINE_STARTED) < kinds.index(
        EventType.ANALYZER_STARTED)


def test_audit_chain_survives_a_full_run(repos, audit, sandbox, sample_apk,
                                         tmp_path) -> None:
    project, result = _authorized(repos, audit, sample_apk, tmp_path)
    _pipeline(_registry(_StubAnalyzer()), repos, audit, sandbox).run(
        project, result.target, result.workspace)

    ok, message = audit.verify_chain()
    assert ok, message
    actions = [e.action for e in repos.audit.list(project.id)]
    assert Action.PIPELINE_STARTED in actions
    assert Action.PIPELINE_FINISHED in actions
