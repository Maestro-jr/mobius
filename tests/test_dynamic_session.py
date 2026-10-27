"""The dynamic session, where Phase 3 finally reaches the graph.

Everything Phase 3 built was islands until this. The test that matters is the
same one that justified the phase: a thing themob watched happen merges with the
thing a static tool suspected, into one finding with two sources and a higher
confidence, and the merge survives a re-vote. No device is involved: the session
takes the evidence a run produced, which is exactly what makes it testable.
"""
from __future__ import annotations

import pytest

from themob.audit.attestation import Action, AuditTrail
from themob.dynamic import gate
from themob.dynamic.capture import CaptureResult, Flow
from themob.dynamic.gate import (DeviceAttestation, ExecutionAttestation,
                                 ExecutionNotAuthorized)
from themob.dynamic.session import DynamicSession
from themob.model.entities import Entity
from themob.model.enums import (EntityType, JobStatus, Platform, Severity,
                                Stage)
from themob.model.findings import Finding, FindingSource
from themob.storage.repositories import Project, Repositories

SERIAL = "emulator-5554"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-42", by="tester@lab")
    return repos.projects.get(stored.id)


@pytest.fixture()
def app(repos: Repositories, project: Project) -> Entity:
    return repos.entities.upsert(project.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID,
        key="com.example.shop", label="shop",
        attributes={"package": "com.example.shop"}))


@pytest.fixture()
def authorized(repos: Repositories, project: Project) -> Project:
    gate.authorize(ExecutionAttestation(
        operator="tester@lab", engagement_ref="ENG-42",
        device=DeviceAttestation(identifier=SERIAL, dedicated_test_device=True,
                                 is_emulator=True),
        traffic_authorized=True, interception_scope=[".example.com"]),
        project.id, AuditTrail(repos.audit))
    return project


def _session(repos) -> DynamicSession:
    return DynamicSession(repos, AuditTrail(repos.audit))


# ------------------------------------------------------------------ the gate

def test_a_dynamic_run_needs_the_execution_gate(repos, project, app) -> None:
    with pytest.raises(ExecutionNotAuthorized):
        _session(repos).record_frida(
            project.id, 'themob-observe {"kind":"digest","algorithm":"MD5"}')


# ------------------------------------------------------- the merge, on the graph

def test_a_runtime_finding_merges_with_a_stored_static_one(
        repos, authorized, app) -> None:
    """The whole justification for the phase, now actually wired to storage."""
    fingerprint = Finding.compute_fingerprint(
        "android.crypto.weak-hash", None, "md5")
    repos.findings.upsert(authorized.id, Finding(
        fingerprint=fingerprint, weakness_key="android.crypto.weak-hash",
        title="Broken hash", severity=Severity.MEDIUM, confidence=0.6,
        entity_ids=[app.id],
        sources=[FindingSource(tool="semgrep", rule="weak-hash")]))

    session = _session(repos)
    outcome = session.record_frida(
        authorized.id, 'themob-observe {"kind":"digest","algorithm":"MD5"}')
    session.finalize(authorized.id)

    assert outcome.findings == 1
    assert outcome.merged == 1

    findings = repos.findings.list(authorized.id)
    assert len(findings) == 1, "the runtime finding should merge, not duplicate"
    merged = findings[0]
    assert {s.tool for s in merged.sources} == {"semgrep", "frida"}


def test_the_merge_raises_confidence(repos, authorized, app) -> None:
    """Runtime and semantic are independent methods, so agreement lifts it."""
    fingerprint = Finding.compute_fingerprint(
        "android.crypto.weak-hash", None, "md5")
    repos.findings.upsert(authorized.id, Finding(
        fingerprint=fingerprint, weakness_key="android.crypto.weak-hash",
        title="Broken hash", severity=Severity.MEDIUM, confidence=0.6,
        entity_ids=[app.id],
        sources=[FindingSource(tool="semgrep", rule="weak-hash")]))

    session = _session(repos)
    session.record_frida(
        authorized.id, 'themob-observe {"kind":"digest","algorithm":"MD5"}')
    summary = session.finalize(authorized.id)

    assert summary.revoted
    after = repos.findings.list(authorized.id)[0]
    assert after.confidence > 0.6


def test_a_runtime_finding_with_no_static_match_is_new(repos, authorized,
                                                       app) -> None:
    session = _session(repos)
    outcome = session.record_frida(
        authorized.id,
        'themob-observe {"kind":"cipher","transformation":"DES/CBC/PKCS5Padding"}')

    assert outcome.new == 1
    assert outcome.merged == 0
    findings = repos.findings.list(authorized.id)
    assert len(findings) == 1
    assert findings[0].sources[0].tool == "frida"
    assert app.id in findings[0].entity_ids


# ------------------------------------------------------------------- capture

def test_captured_cleartext_attaches_to_the_endpoint_node(repos, authorized,
                                                          app) -> None:
    endpoint = repos.entities.upsert(authorized.id, Entity(
        type=EntityType.ENDPOINT, platform=Platform.ANDROID,
        key="http://api.example.com/login", label="api.example.com",
        attributes={"host": "api.example.com"}))

    result = CaptureResult(flows=[
        Flow(host="api.example.com", method="POST", scheme="http",
             path="/login")])
    outcome = _session(repos).record_capture(authorized.id, result)

    assert outcome.findings == 1
    finding = repos.findings.list(authorized.id)[0]
    assert finding.weakness_key == "android.network.cleartext-endpoint"
    assert endpoint.id in finding.entity_ids


# ------------------------------------------------------------------ recording

def test_a_dynamic_run_is_a_stage_in_the_record(repos, authorized, app) -> None:
    """So the report's provenance names it, like every other stage."""
    _session(repos).record_frida(
        authorized.id, 'themob-observe {"kind":"digest","algorithm":"MD5"}')

    jobs = repos.jobs.list(authorized.id)
    dynamic = [j for j in jobs if j.stage is Stage.DYNAMIC]
    assert dynamic
    assert dynamic[0].status is JobStatus.SUCCEEDED
    assert dynamic[0].analyzer == "frida"


def test_the_run_is_audited_and_the_chain_holds(repos, authorized, app) -> None:
    audit = AuditTrail(repos.audit)
    DynamicSession(repos, audit).record_frida(
        authorized.id, 'themob-observe {"kind":"digest","algorithm":"MD5"}')

    actions = [e.action for e in repos.audit.list(authorized.id)]
    assert Action.ANALYZER_FINISHED in actions
    ok, message = audit.verify_chain()
    assert ok, message


def test_the_one_call_form_ingests_both_sources(repos, authorized, app) -> None:
    result = CaptureResult(flows=[
        Flow(host="api.example.com", scheme="http", path="/x")])
    summary = _session(repos).run(
        authorized.id,
        frida_output='themob-observe {"kind":"digest","algorithm":"MD5"}',
        capture=result)

    assert summary.findings == 2
    assert summary.revoted
    assert len(summary.outcomes) == 2
