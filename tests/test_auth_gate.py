"""The authorization gate: the one control the whole tool rests on.

themob decompiles other people's software. Every other safeguard here assumes
this gate held, so the tests are about what it refuses: a sample with no
attestation, an attestation that is not ticked, and a rejected attestation that
must leave nothing on disk.

The engine-level half of this lives in `test_audit.py`. These cover the dialog
and the `authorize` call that binds it to intake, which nothing else exercised.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication                       # noqa: E402

from themob.app.auth_gate import AuthorizationGate, GateResult, authorize
from themob.audit.attestation import (Action, AuditTrail,       # noqa: E402
                                      AuthorizationError)
from themob.orchestrator.intake import IntakeError             # noqa: E402
from themob.storage.repositories import Repositories           # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def gate(qapp) -> AuthorizationGate:
    return AuthorizationGate()


# ------------------------------------------------------------------ the dialog

def test_the_gate_opens_refusing_to_proceed(gate) -> None:
    """Nothing selected, nothing attested: there is nothing to authorize."""
    assert not gate._go.isEnabled()
    assert gate.result() is None


def test_a_sample_alone_is_not_enough(gate, sample_apk: Path) -> None:
    """The file is valid, but nobody has said they are allowed to assess it."""
    gate._path.setText(str(sample_apk))
    assert not gate._go.isEnabled()
    assert "attest" in gate._hint.text().lower()


def test_an_attestation_alone_is_not_enough(gate) -> None:
    gate._attest.setChecked(True)
    assert not gate._go.isEnabled()


def test_both_together_unlock_it(gate, sample_apk: Path) -> None:
    gate._path.setText(str(sample_apk))
    gate._attest.setChecked(True)
    assert gate._go.isEnabled()
    assert not gate._hint.text()


def test_unticking_the_attestation_locks_it_again(gate, sample_apk: Path) -> None:
    """A tester who changes their mind must not be left with a live button."""
    gate._path.setText(str(sample_apk))
    gate._attest.setChecked(True)
    gate._attest.setChecked(False)
    assert not gate._go.isEnabled()


def test_a_file_that_is_not_a_package_is_named_as_the_problem(
        gate, tmp_path: Path) -> None:
    """The check is structural: nothing here opens the file to find out."""
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not a package", encoding="utf-8")

    gate._path.setText(str(bogus))
    gate._attest.setChecked(True)

    assert not gate._go.isEnabled()
    assert gate._hint.text(), "the operator was not told why"


def test_a_missing_file_is_refused(gate, tmp_path: Path) -> None:
    gate._path.setText(str(tmp_path / "absent.apk"))
    gate._attest.setChecked(True)
    assert not gate._go.isEnabled()


def test_a_quoted_path_is_accepted(gate, sample_apk: Path) -> None:
    """Copying a path from Explorer brings the quotes with it."""
    gate._path.setText(f'"{sample_apk}"')
    gate._attest.setChecked(True)
    assert gate._go.isEnabled()


def test_authorizing_captures_what_was_attested(gate, sample_apk: Path) -> None:
    gate._path.setText(str(sample_apk))
    gate._name.setText("Example Shop")
    gate._ref.setText("ENG-42")
    gate._scope.setText("static analysis only")
    gate._attest.setChecked(True)
    gate._on_authorize()

    result = gate.result()
    assert result is not None
    assert result.sample_path == sample_apk
    assert result.engagement_ref == "ENG-42"
    assert result.scope_note == "static analysis only"
    assert result.attested


def test_authorizing_without_the_tick_records_nothing(gate,
                                                      sample_apk: Path) -> None:
    """The click is refused even if it somehow reaches the handler."""
    gate._path.setText(str(sample_apk))
    gate._on_authorize()
    assert gate.result() is None


# --------------------------------------------------------------- authorize()

def test_authorize_ingests_and_stamps_the_attestation(
        repos: Repositories, sample_apk: Path, tmp_path: Path) -> None:
    audit = AuditTrail(repos.audit)
    result = authorize(
        GateResult(sample_path=sample_apk, project_name="Example Shop",
                   engagement_ref="ENG-42", scope_note="static only",
                   attested=True),
        repos, audit, root=tmp_path / "home")

    assert result.project.is_authorized
    assert result.project.authorization_ref == "ENG-42"

    actions = [e.action for e in repos.audit.list(result.project.id)]
    assert Action.PROJECT_CREATED in actions
    assert Action.PROJECT_AUTHORIZED in actions

    ok, message = audit.verify_chain()
    assert ok, message


def test_a_rejected_attestation_leaves_nothing_on_disk(
        repos: Repositories, sample_apk: Path, tmp_path: Path) -> None:
    """An unauthorized sample must not linger in a workspace."""
    audit = AuditTrail(repos.audit)
    before = repos.projects.list()

    with pytest.raises(AuthorizationError):
        authorize(
            GateResult(sample_path=sample_apk, project_name="Refused",
                       engagement_ref="", scope_note="", attested=False),
            repos, audit, root=tmp_path / "home")

    assert len(repos.projects.list()) == len(before)
    workspaces = list((tmp_path / "home" / "projects").glob("*")) \
        if (tmp_path / "home" / "projects").is_dir() else []
    assert not workspaces, "the sample was left behind"


def test_the_refusal_stays_in_the_trail_after_the_project_is_gone(
        repos: Repositories, sample_apk: Path, tmp_path: Path) -> None:
    """The audit trail outlives the project it describes (migration 0002)."""
    audit = AuditTrail(repos.audit)
    with pytest.raises(AuthorizationError):
        authorize(
            GateResult(sample_path=sample_apk, project_name="Refused",
                       engagement_ref="", scope_note="", attested=False),
            repos, audit, root=tmp_path / "home")

    actions = [e.action for e in repos.audit.list(limit=100)]
    assert Action.PROJECT_CREATED in actions
    assert Action.PROJECT_DELETED in actions

    ok, message = audit.verify_chain()
    assert ok, message


def test_a_sample_that_is_not_a_package_never_reaches_the_database(
        repos: Repositories, tmp_path: Path) -> None:
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not a package", encoding="utf-8")
    audit = AuditTrail(repos.audit)

    with pytest.raises(IntakeError):
        authorize(
            GateResult(sample_path=bogus, project_name="Bogus",
                       engagement_ref="", scope_note="", attested=True),
            repos, audit, root=tmp_path / "home")

    assert not repos.projects.list()
