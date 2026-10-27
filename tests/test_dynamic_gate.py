"""The execution gate, where the victim of a mistake stops being a report.

Static analysis reads a file and the worst case is a wrong finding. Running an
app puts a hostile package on a device, sends live requests to production, and
terminates TLS. These tests are about the gate refusing each of those
separately, and about it never assuming any of them.
"""
from __future__ import annotations

import pytest

from themob.audit.attestation import Action, AuditTrail
from themob.dynamic import gate
from themob.dynamic.gate import (DeviceAttestation, ExecutionAttestation,
                                 ExecutionNotAuthorized)
from themob.model.enums import Platform
from themob.storage.repositories import Project, Repositories


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    return repos.projects.get(stored.id)


def _good(**overrides) -> ExecutionAttestation:
    base = dict(
        operator="tester@lab",
        engagement_ref="ENG-42",
        device=DeviceAttestation(identifier="emulator-5554",
                                 description="wiped AVD, snapshot 3",
                                 dedicated_test_device=True, is_emulator=True),
        traffic_authorized=True,
        interception_scope=[".example.com"],
    )
    base.update(overrides)
    return ExecutionAttestation(**base)


# ------------------------------------------------------------- the three clauses

def test_a_complete_attestation_is_accepted() -> None:
    _good().validate()


def test_running_on_an_unattested_device_is_refused() -> None:
    """The clause with a person on the other end of it."""
    attestation = _good(device=DeviceAttestation(
        identifier="R58M12345", dedicated_test_device=False))

    with pytest.raises(ExecutionNotAuthorized, match="dedicated test device"):
        attestation.validate()


def test_a_device_with_no_identifier_is_refused() -> None:
    """The record has to say which machine ran the sample."""
    attestation = _good(device=DeviceAttestation(
        identifier="   ", dedicated_test_device=True))

    with pytest.raises(ExecutionNotAuthorized, match="device identifier"):
        attestation.validate()


def test_generating_live_traffic_needs_its_own_permission() -> None:
    """An engagement that covers reading a binary may not cover running it."""
    with pytest.raises(ExecutionNotAuthorized, match="production systems"):
        _good(traffic_authorized=False).validate()


def test_an_unattributed_execution_is_refused() -> None:
    with pytest.raises(ExecutionNotAuthorized, match="operator identity"):
        _good(operator="  ").validate()


# ------------------------------------------------------- the interception scope

def test_nothing_is_intercepted_by_default() -> None:
    """An empty scope decrypts nothing at all, rather than everything."""
    attestation = _good(interception_scope=[])
    attestation.validate()

    for host in ("api.example.com", "example.com", "anything.at.all"):
        assert not attestation.may_intercept(host)


def test_a_leading_dot_covers_the_domain_and_what_is_under_it() -> None:
    attestation = _good(interception_scope=[".example.com"])

    assert attestation.may_intercept("example.com")
    assert attestation.may_intercept("api.example.com")
    assert attestation.may_intercept("a.b.example.com")
    assert attestation.may_intercept("API.EXAMPLE.COM")


def test_a_bare_host_covers_only_that_host() -> None:
    attestation = _good(interception_scope=["api.example.com"])

    assert attestation.may_intercept("api.example.com")
    assert not attestation.may_intercept("example.com")
    assert not attestation.may_intercept("other.example.com")


def test_a_host_nobody_listed_is_never_intercepted() -> None:
    """themob knows what an app talks to and not who owns it."""
    attestation = _good(interception_scope=[".example.com"])

    for host in ("graph.facebook.com", "firebase.googleapis.com",
                 "notexample.com", "example.com.evil.net"):
        assert not attestation.may_intercept(host), host


def test_a_wildcard_scope_is_refused() -> None:
    """It is the one thing this list exists to stop somebody typing."""
    for bad in ("*", "*.*", "all", "any", "0.0.0.0/0", "::/0", "."):
        with pytest.raises(ExecutionNotAuthorized):
            _good(interception_scope=[bad]).validate()


def test_a_star_pattern_points_at_the_leading_dot_instead() -> None:
    with pytest.raises(ExecutionNotAuthorized, match="leading dot"):
        _good(interception_scope=["*.example.com"]).validate()


def test_something_that_is_not_a_hostname_is_refused() -> None:
    for bad in ("not a host", "http://example.com", "example.com/path",
                "-leading.example.com", ""):
        with pytest.raises(ExecutionNotAuthorized):
            _good(interception_scope=[bad]).validate()


# ------------------------------------------------------------------- recording

def test_authorizing_writes_to_the_hash_chained_trail(repos, project) -> None:
    audit = AuditTrail(repos.audit)
    gate.authorize(_good(), project.id, audit)

    entry = next(e for e in repos.audit.list(project.id)
                 if e.action == Action.EXECUTION_AUTHORIZED)
    assert entry.actor == "tester@lab"
    assert entry.detail["device_id"] == "emulator-5554"
    assert entry.detail["dedicated_test_device"] is True
    # Recorded in full: "which hosts did you decrypt" is the question a
    # disputed capture turns on.
    assert entry.detail["interception_scope"] == [".example.com"]

    ok, message = audit.verify_chain()
    assert ok, message


def test_an_invalid_attestation_is_never_recorded(repos, project) -> None:
    """A refusal must not leave a record implying permission was granted."""
    audit = AuditTrail(repos.audit)
    with pytest.raises(ExecutionNotAuthorized):
        gate.authorize(_good(traffic_authorized=False), project.id, audit)

    assert not [e for e in repos.audit.list(project.id)
                if e.action == Action.EXECUTION_AUTHORIZED]


# ---------------------------------------------------------------- the gate call

def test_the_gate_refuses_a_project_that_never_attested(repos, project) -> None:
    with pytest.raises(ExecutionNotAuthorized, match="no execution attestation"):
        gate.require_execution(repos, project.id)


def test_the_gate_passes_once_the_attestation_is_recorded(repos,
                                                          project) -> None:
    audit = AuditTrail(repos.audit)
    gate.authorize(_good(), project.id, audit)

    detail = gate.require_execution(repos, project.id)
    assert detail["device_id"] == "emulator-5554"


def test_the_static_attestation_does_not_unlock_execution(repos,
                                                          project) -> None:
    """The whole point: assessing a binary and running it are different acts."""
    from themob.audit.attestation import Attestation

    audit = AuditTrail(repos.audit)
    audit.record_attestation(project, Attestation(
        target_name="shop.apk", target_sha256="a" * 64, operator="tester@lab",
        engagement_ref="ENG-42", attested=True), repos.projects)

    with pytest.raises(ExecutionNotAuthorized):
        gate.require_execution(repos, project.id)


def test_a_record_missing_a_clause_does_not_pass_the_gate(repos,
                                                          project) -> None:
    """Fails closed on anything unexpected, including a hand-written row."""
    audit = AuditTrail(repos.audit)
    audit.record(Action.EXECUTION_AUTHORIZED, project_id=project.id,
                 actor="someone", device_id="emulator-5554",
                 dedicated_test_device=True)          # no traffic_authorized

    with pytest.raises(ExecutionNotAuthorized):
        gate.require_execution(repos, project.id)


def test_another_projects_attestation_does_not_carry_over(repos,
                                                          project) -> None:
    other = repos.projects.create(Project(
        name="Other", target_platform=Platform.ANDROID,
        source_path="input/other.apk", source_sha256="b" * 64))
    audit = AuditTrail(repos.audit)
    gate.authorize(_good(), project.id, audit)

    with pytest.raises(ExecutionNotAuthorized):
        gate.require_execution(repos, other.id)
