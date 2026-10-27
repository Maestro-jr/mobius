"""Credential validation: gated, opt-in, and prepared not performed.

The two properties that keep this from being a foot-gun are tested first: it
refuses to do anything without its own attestation, and it never contains the
secret value, because themob does not hold it. The rest is classification, that
the right provider probe is prepared, and result recording, that a live or dead
verdict lands in the manual-validation workflow like any other.
"""
from __future__ import annotations

import pytest

from themob.audit.attestation import Action, AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.storage.repositories import Project, Repositories
from themob.validate import (Probe, ValidationAttestation,
                             ValidationNotAuthorized, classify, gate, plan,
                             probe_for, record_result)


@pytest.fixture()
def audit(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Shop", target_platform=Platform.ANDROID,
        source_path="in/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-1", by="tester@lab")
    return repos.projects.get(stored.id)


def _secret(repos, project, *, rule="aws-access-token", preview="AKIA****",
            tags=("aws",), key="android.secrets.cloud-credential"):
    entity = repos.entities.upsert(project.id, Entity(
        type=EntityType.SECRET, platform=Platform.ANDROID, key="sha256:abcd",
        label="k", attributes={"rule": rule, "preview": preview,
                               "tags": list(tags)}))
    finding = repos.findings.upsert(project.id, Finding(
        fingerprint="a" * 64, weakness_key=key, title="Secret",
        severity=Severity.CRITICAL, confidence=0.9, entity_ids=[entity.id],
        sources=[FindingSource(tool="gitleaks", rule=rule)]))
    return entity, finding


def _authorize(repos, project):
    gate.authorize(ValidationAttestation(
        operator="tester@lab", engagement_ref="ENG-1", acknowledged=True),
        project.id, AuditTrail(repos.audit))


# --------------------------------------------------------------------- the gate

def test_planning_is_refused_without_an_attestation(repos, project) -> None:
    _secret(repos, project)
    with pytest.raises(ValidationNotAuthorized):
        plan(repos, project.id)


def test_an_unacknowledged_attestation_is_refused(repos, project) -> None:
    """Validating contacts the provider, so it is not default-on."""
    with pytest.raises(ValidationNotAuthorized, match="Acknowledge"):
        ValidationAttestation(operator="tester@lab", acknowledged=False).validate()


def test_an_unattributed_attestation_is_refused() -> None:
    with pytest.raises(ValidationNotAuthorized, match="operator identity"):
        ValidationAttestation(operator="  ", acknowledged=True).validate()


def test_authorizing_is_audited_and_the_chain_holds(repos, project) -> None:
    audit = AuditTrail(repos.audit)
    gate.authorize(ValidationAttestation(
        operator="tester@lab", acknowledged=True), project.id, audit)

    actions = [e.action for e in repos.audit.list(project.id)]
    assert Action.VALIDATION_AUTHORIZED in actions
    ok, message = audit.verify_chain()
    assert ok, message


# ---------------------------------------------------------------- the provider

@pytest.mark.parametrize("rule,preview,expected", [
    ("aws-access-token", "AKIAABCD", "aws"),
    ("github-pat", "ghp_abc", "github"),
    ("gitlab-token", "glpat-abc", "gitlab"),
    ("slack-token", "xoxb-abc", "slack"),
    ("stripe-key", "sk_live_abc", "stripe"),
    ("google-api-key", "AIzaSyabc", "google"),
    ("generic-high-entropy", "d0ntkn0w", None),
])
def test_the_provider_is_classified_from_what_the_detector_reported(
        rule, preview, expected) -> None:
    assert classify(rule=rule, preview=preview) == expected


def test_a_provider_with_no_safe_probe_is_not_given_one() -> None:
    """Google keys authorise one specific API; no generic read-only check."""
    assert probe_for("google") is None
    assert probe_for(None) is None
    assert isinstance(probe_for("aws"), Probe)


# --------------------------------------------------------------------- planning

def test_a_secret_finding_gets_its_provider_probe(repos, project) -> None:
    _secret(repos, project, rule="aws-access-token", preview="AKIA****")
    _authorize(repos, project)

    tasks = plan(repos, project.id)
    assert len(tasks) == 1
    assert tasks[0].provider == "aws"
    assert tasks[0].runnable


def test_the_prepared_command_never_holds_the_secret(repos, project) -> None:
    """themob has a digest and a preview, not the value, so it cannot fill one."""
    _secret(repos, project)
    _authorize(repos, project)

    task = plan(repos, project.id)[0]
    assert "<SECRET>" in task.probe.command
    assert "AKIA****" not in task.probe.command


def test_a_non_secret_finding_is_not_planned(repos, project) -> None:
    repos.findings.upsert(project.id, Finding(
        fingerprint="b" * 64, weakness_key="android.config.debuggable",
        title="Debuggable", severity=Severity.HIGH, confidence=0.9,
        sources=[FindingSource(tool="config-audit", rule="x")]))
    _authorize(repos, project)

    assert plan(repos, project.id) == []


def test_an_unrecognised_provider_is_flagged_for_manual_review(repos,
                                                               project) -> None:
    _secret(repos, project, rule="generic-secret", preview="just-entropy",
            tags=())
    _authorize(repos, project)

    task = plan(repos, project.id)[0]
    assert task.provider is None
    assert not task.runnable
    assert "by hand" in task.note


# ----------------------------------------------------------------- the result

def test_a_live_result_confirms_the_finding(repos, project) -> None:
    _entity, finding = _secret(repos, project)
    audit = AuditTrail(repos.audit)
    _authorize(repos, project)

    record_result(repos, audit, finding.id, live=True, operator="tester@lab")

    after = repos.findings.get(finding.id)
    assert after.status is FindingStatus.CONFIRMED
    notes = repos.findings.notes(finding.id)
    assert any("validation" in n.text and "live" in n.text for n in notes)


def test_a_revoked_result_accepts_the_risk_with_a_reason(repos, project) -> None:
    _entity, finding = _secret(repos, project)
    audit = AuditTrail(repos.audit)
    _authorize(repos, project)

    record_result(repos, audit, finding.id, live=False, operator="tester@lab")

    after = repos.findings.get(finding.id)
    assert after.status is FindingStatus.ACCEPTED_RISK


def test_recording_a_result_is_gated_too(repos, project) -> None:
    _entity, finding = _secret(repos, project)
    audit = AuditTrail(repos.audit)
    with pytest.raises(ValidationNotAuthorized):
        record_result(repos, audit, finding.id, live=True, operator="tester@lab")


def test_the_result_keeps_the_audit_chain_intact(repos, project) -> None:
    _entity, finding = _secret(repos, project)
    audit = AuditTrail(repos.audit)
    _authorize(repos, project)
    record_result(repos, audit, finding.id, live=True, operator="tester@lab")

    ok, message = audit.verify_chain()
    assert ok, message
