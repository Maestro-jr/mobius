"""The authorization gate and the tamper-evident audit chain."""
from __future__ import annotations

import pytest

from themob.audit.attestation import (Action, Attestation, AuditTrail,
                                      AuthorizationError, require_authorization)
from themob.model.enums import Platform
from themob.storage.db import Database
from themob.storage.repositories import Project, Repositories

_SHA = "b" * 64


@pytest.fixture()
def project(repos: Repositories) -> Project:
    return repos.projects.create(Project(
        name="Sample App", target_platform=Platform.ANDROID,
        source_path="input/sample.apk", source_sha256=_SHA))


@pytest.fixture()
def trail(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


def _attestation(**kw) -> Attestation:
    return Attestation(
        target_name=kw.pop("target_name", "sample.apk"),
        target_sha256=kw.pop("target_sha256", _SHA),
        operator=kw.pop("operator", "tester@lab"),
        engagement_ref=kw.pop("engagement_ref", "ENG-42"),
        attested=kw.pop("attested", True), **kw)


# ------------------------------------------------------------ the gate

def test_unauthorized_project_is_refused(project: Project) -> None:
    with pytest.raises(AuthorizationError):
        require_authorization(project)
    with pytest.raises(AuthorizationError):
        require_authorization(None)


def test_attestation_authorizes_the_project(project: Project, trail: AuditTrail,
                                            repos: Repositories) -> None:
    trail.record_attestation(project, _attestation(), repos.projects)
    reloaded = repos.projects.get(project.id)
    assert require_authorization(reloaded) is reloaded
    assert reloaded.authorization_ref == "ENG-42"
    assert reloaded.authorized_by == "tester@lab"


def test_unattested_checkbox_blocks_everything(project: Project, trail: AuditTrail,
                                               repos: Repositories) -> None:
    with pytest.raises(AuthorizationError):
        trail.record_attestation(project, _attestation(attested=False), repos.projects)
    # Nothing was written: the gate fails closed.
    assert repos.projects.get(project.id).authorized_at is None
    assert repos.audit.list(project.id) == []


def test_attestation_hash_must_match_the_sample(project: Project, trail: AuditTrail,
                                                repos: Repositories) -> None:
    with pytest.raises(AuthorizationError, match="does not match"):
        trail.record_attestation(project, _attestation(target_sha256="c" * 64),
                                 repos.projects)


def test_attestation_requires_an_operator(project: Project, trail: AuditTrail,
                                          repos: Repositories) -> None:
    with pytest.raises(AuthorizationError):
        trail.record_attestation(project, _attestation(operator="  "), repos.projects)


def test_reference_falls_back_when_no_engagement_ref() -> None:
    assert _attestation(engagement_ref="").reference.startswith("attested:")


# ------------------------------------------------------------ the chain

def test_chain_is_intact_across_many_entries(project: Project,
                                             trail: AuditTrail,
                                             repos: Repositories) -> None:
    trail.record_attestation(project, _attestation(), repos.projects)
    for stage in ("unpack", "secrets", "sast"):
        trail.record(Action.STAGE_STARTED, project_id=project.id, stage=stage)
        trail.record(Action.STAGE_FINISHED, project_id=project.id, stage=stage)

    ok, message = trail.verify_chain()
    assert ok, message
    assert len(trail.entries(project.id)) == 7


def test_out_of_band_edit_breaks_the_chain(db: Database, project: Project,
                                           trail: AuditTrail,
                                           repos: Repositories) -> None:
    trail.record_attestation(project, _attestation(), repos.projects)
    trail.record(Action.PIPELINE_STARTED, project_id=project.id)
    assert trail.verify_chain()[0]

    # Simulate tampering that bypasses the application: drop the triggers and
    # rewrite an entry the way an attacker with sqlite3 access would.
    db.execute("DROP TRIGGER audit_log_no_update")
    db.execute("UPDATE audit_log SET actor = 'someone-else' "
               "WHERE action = ?", (Action.PROJECT_AUTHORIZED,))

    ok, message = trail.verify_chain()
    assert not ok
    assert "modified" in message or "chain break" in message


def test_entry_without_chain_fields_is_rejected(repos: Repositories,
                                                trail: AuditTrail,
                                                project: Project) -> None:
    from themob.storage.repositories import AuditEntry

    repos.audit.append(AuditEntry(project_id=project.id, actor="raw",
                                  action="hand.written"))
    ok, message = trail.verify_chain()
    assert not ok and "not chained" in message


def test_record_requires_an_action(trail: AuditTrail) -> None:
    with pytest.raises(ValueError):
        trail.record("")


# ------------------------------- the audit trail outlives its project (0002)

def test_project_with_audit_entries_can_be_deleted(project: Project,
                                                   trail: AuditTrail,
                                                   repos: Repositories) -> None:
    """Regression: audit_log.project_id used to carry ON DELETE SET NULL.

    That cascade is an UPDATE, which the append-only trigger aborts, so a
    project became undeletable the moment anything was audited about it, which
    is immediately. Migration 0002 dropped the foreign key.
    """
    trail.record_attestation(project, _attestation(), repos.projects)
    trail.record(Action.PIPELINE_STARTED, project_id=project.id)

    repos.projects.delete(project.id)

    assert repos.projects.get(project.id) is None
    surviving = repos.audit.list(project.id)
    assert len(surviving) == 2, "the record must outlive the project it describes"
    assert trail.verify_chain()[0], "deletion must not disturb the hash chain"


def test_audit_rows_still_reject_updates_after_the_rebuild(
        db: Database, project: Project, trail: AuditTrail,
        repos: Repositories) -> None:
    entry = trail.record(Action.PIPELINE_STARTED, project_id=project.id)
    with pytest.raises(Exception):
        db.execute("UPDATE audit_log SET actor = 'x' WHERE id = ?", (entry.id,))
    with pytest.raises(Exception):
        db.execute("DELETE FROM audit_log WHERE id = ?", (entry.id,))
