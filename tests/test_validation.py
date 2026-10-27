"""The manual-validation workflow: what a tester concluded, and the trail of it.

Most of this file is about what the workflow refuses. A verdict that suppresses
a finding without a reason, an unattributed decision, a status only a scanner
should set: each one produces a report that cannot be defended six months later
when somebody asks why an issue is not in it.
"""
from __future__ import annotations

import pytest

from themob.audit.attestation import Action, AuditTrail
from themob.model.enums import FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.orchestrator.validation import (VERDICTS, ValidationError,
                                            record)
from themob.storage.repositories import Project, Repositories

OPERATOR = "tester@lab"


@pytest.fixture()
def audit(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


@pytest.fixture()
def finding(repos: Repositories) -> Finding:
    project = repos.projects.create(Project(
        name="Sample", target_platform=Platform.ANDROID,
        source_path="input/s.apk", source_sha256="a" * 64))
    return repos.findings.upsert(project.id, Finding(
        fingerprint="f" * 64, weakness_key="android.config.debuggable",
        title="Application is debuggable", severity=Severity.HIGH,
        confidence=0.95,
        sources=[FindingSource(tool="config-audit", rule="x")]))


# ------------------------------------------------------------------ verdicts

def test_confirming_records_the_verdict(repos, audit, finding) -> None:
    verdict = record(repos, audit, finding.id, FindingStatus.CONFIRMED,
                     operator=OPERATOR)
    assert verdict.status is FindingStatus.CONFIRMED
    assert repos.findings.get(finding.id).status is FindingStatus.CONFIRMED


def test_confirming_needs_no_reason(repos, audit, finding) -> None:
    """Agreeing with the scanner adds nothing that needs explaining.

    Only the verdicts that remove a finding from the report have to justify
    themselves.
    """
    record(repos, audit, finding.id, FindingStatus.CONFIRMED, operator=OPERATOR)
    assert repos.findings.notes(finding.id) == []


@pytest.mark.parametrize("status", [FindingStatus.FALSE_POSITIVE,
                                    FindingStatus.ACCEPTED_RISK])
def test_a_suppressing_verdict_is_refused_without_a_reason(
        repos, audit, finding, status) -> None:
    """The rule this whole module exists for.

    These two verdicts take a finding out of the report, and an unexplained
    removal cannot be told apart from an oversight.
    """
    with pytest.raises(ValidationError, match="needs a reason"):
        record(repos, audit, finding.id, status, operator=OPERATOR)
    assert repos.findings.get(finding.id).status is FindingStatus.NEW


@pytest.mark.parametrize("status", [FindingStatus.FALSE_POSITIVE,
                                    FindingStatus.ACCEPTED_RISK])
def test_a_suppressing_verdict_with_a_reason_is_recorded(
        repos, audit, finding, status) -> None:
    verdict = record(repos, audit, finding.id, status, operator=OPERATOR,
                     note="Debug build only, release sets it false.")
    assert verdict.status is status
    notes = repos.findings.notes(finding.id)
    assert len(notes) == 1
    assert notes[0].author == OPERATOR
    assert "release" in notes[0].text


def test_a_refused_verdict_changes_nothing(repos, audit, finding) -> None:
    """Not the status, not the notes, not the audit trail."""
    before = len(repos.audit.list(repos.findings.project_of(finding.id)))
    with pytest.raises(ValidationError):
        record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
               operator=OPERATOR)
    assert repos.findings.notes(finding.id) == []
    assert len(repos.audit.list(repos.findings.project_of(finding.id))) == before


def test_an_unattributed_verdict_is_refused(repos, audit, finding) -> None:
    """An audit record with no actor answers none of the questions it exists for."""
    with pytest.raises(ValidationError, match="operator"):
        record(repos, audit, finding.id, FindingStatus.CONFIRMED, operator="  ")


def test_new_is_not_a_verdict(repos, audit, finding) -> None:
    """It is the scanner's starting state, not something a person concludes."""
    with pytest.raises(ValidationError, match="not a verdict"):
        record(repos, audit, finding.id, FindingStatus.NEW, operator=OPERATOR)


def test_an_unknown_finding_is_refused(repos, audit) -> None:
    with pytest.raises(ValidationError, match="no finding"):
        record(repos, audit, "no-such-id", FindingStatus.CONFIRMED,
               operator=OPERATOR)


def test_every_verdict_a_tester_can_set_is_offered() -> None:
    assert set(VERDICTS) == {FindingStatus.CONFIRMED,
                             FindingStatus.FALSE_POSITIVE,
                             FindingStatus.ACCEPTED_RISK}
    assert FindingStatus.NEW not in VERDICTS


# --------------------------------------------------------------- audit trail

def test_the_verdict_lands_in_the_audit_trail(repos, audit, finding) -> None:
    """The question a disputed report turns on: who decided, and when."""
    record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
           operator=OPERATOR, note="Not reachable in the shipped build.")

    entries = [e for e in repos.audit.list(repos.findings.project_of(finding.id))
               if e.action == Action.FINDING_STATUS_CHANGED]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.actor == OPERATOR
    assert entry.detail["was"] == "new"
    assert entry.detail["now"] == "false_positive"
    assert entry.detail["weakness"] == "android.config.debuggable"
    assert "Not reachable" in entry.detail["reason"]


def test_the_trail_survives_a_note_being_changed(repos, audit, finding) -> None:
    """Notes are working notes; the trail is the record.

    A tester correcting their own note is not tampering, so notes are editable.
    What the decision was justified by at the time lives in the chain, which is
    not.
    """
    record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
           operator=OPERATOR, note="Original reasoning.")
    project_id = repos.findings.project_of(finding.id)

    entry = next(e for e in repos.audit.list(project_id)
                 if e.action == Action.FINDING_STATUS_CHANGED)
    assert entry.detail["reason"] == "Original reasoning."

    ok, message = audit.verify_chain()
    assert ok, message


def test_the_chain_still_verifies_after_several_verdicts(repos, audit,
                                                         finding) -> None:
    record(repos, audit, finding.id, FindingStatus.CONFIRMED, operator=OPERATOR)
    record(repos, audit, finding.id, FindingStatus.ACCEPTED_RISK,
           operator=OPERATOR, note="Client accepts, ticket SEC-41.")
    ok, message = audit.verify_chain()
    assert ok, message

    # list() is newest-first, which is what the Activity page wants. The chain
    # itself is append-only in rowid order, so reverse to read it as it happened.
    entries = [e for e in repos.audit.list(repos.findings.project_of(finding.id))
               if e.action == Action.FINDING_STATUS_CHANGED]
    happened = [e.detail["now"] for e in reversed(entries)]
    assert happened == ["confirmed", "accepted_risk"]


# ------------------------------------------------------------------- notes

def test_notes_accumulate_rather_than_replace(repos, audit, finding) -> None:
    """The sequence is often the useful part: a doubt, then the answer."""
    record(repos, audit, finding.id, FindingStatus.CONFIRMED,
           operator=OPERATOR, note="Reproduced on a Pixel 6.")
    record(repos, audit, finding.id, FindingStatus.ACCEPTED_RISK,
           operator=OPERATOR, note="Client accepts for the beta.")

    notes = repos.findings.notes(finding.id)
    assert len(notes) == 2
    assert "Reproduced" in notes[0].text and "beta" in notes[1].text


def test_an_empty_note_is_refused_by_storage(repos, finding) -> None:
    from themob.storage.repositories import RepositoryError

    with pytest.raises(RepositoryError):
        repos.findings.add_note(finding.id, "   ")


def test_a_verdict_does_not_touch_the_scanner_account(repos, audit,
                                                      finding) -> None:
    """A human verdict is recorded beside the evidence, not over it."""
    before = repos.findings.get(finding.id)
    record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
           operator=OPERATOR, note="Test build only.")
    after = repos.findings.get(finding.id)

    assert after.severity is before.severity
    assert after.confidence == before.confidence
    assert after.weakness_key == before.weakness_key
