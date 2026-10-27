"""Instrumentation: the stage where a mistake runs code inside the target.

No device is involved, and that is the point of the split under test: the parts
that can be checked without one, the gate, the agent path, the argv, are checked
here in full, and the one thing that genuinely needs an emulator is isolated
behind FridaSession._launch, which these tests never call.

The agent-path tests are the security core. An instrumentation script runs
inside the app, so "load this script" resolving to anything outside the
repository is an arbitrary-code-execution primitive, and the traversal cases are
the ones that must never regress.
"""
from __future__ import annotations

import pytest

from themob.audit.attestation import AuditTrail
from themob.dynamic import gate
from themob.dynamic.adb import Adb
from themob.dynamic.gate import (DeviceAttestation, ExecutionAttestation,
                                 ExecutionNotAuthorized)
from themob.dynamic.instrument import (AGENTS_DIR, Instrumentation,
                                       InstrumentationError, OBJECTION_JOBS,
                                       available_agents, resolve_agent)
from themob.model.enums import Platform
from themob.storage.repositories import Project, Repositories

SERIAL = "emulator-5554"
PKG = "com.example.shop"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    return repos.projects.get(stored.id)


@pytest.fixture()
def authorized(repos: Repositories, project: Project) -> Project:
    gate.authorize(ExecutionAttestation(
        operator="tester@lab", engagement_ref="ENG-42",
        device=DeviceAttestation(identifier=SERIAL, dedicated_test_device=True,
                                 is_emulator=True),
        traffic_authorized=True), project.id, AuditTrail(repos.audit))
    return project


class _BoundAdb(Adb):
    """An adb whose gate check passes and whose device is always the attested one."""

    def bind(self, repos, project_id):
        from themob.dynamic.gate import require_execution
        require_execution(repos, project_id)          # still exercises the gate
        return SERIAL


# ------------------------------------------------------------- the agent path

def test_the_shipped_agents_are_discoverable() -> None:
    agents = available_agents()
    assert "observe-crypto.js" in agents
    assert "observe-tls.js" in agents


def test_a_shipped_agent_resolves_inside_the_repository() -> None:
    path = resolve_agent("observe-crypto.js")
    assert path.is_file()
    assert path.parent == AGENTS_DIR.resolve()


def test_an_agent_from_outside_the_repository_is_refused() -> None:
    """The security core: a loaded script runs inside the target."""
    for bad in ("../gate.py", "../../etc/passwd", "/etc/passwd",
                "..\\gate.py", "http://evil/x.js", "agents/../gate.py"):
        with pytest.raises(InstrumentationError):
            resolve_agent(bad)


def test_a_name_that_is_not_a_js_file_is_refused() -> None:
    for bad in ("observe-crypto.py", "observe-crypto", "", "  ", "a.js.exe"):
        with pytest.raises(InstrumentationError):
            resolve_agent(bad)


def test_a_js_name_that_does_not_exist_lists_what_does() -> None:
    with pytest.raises(InstrumentationError, match="observe-crypto"):
        resolve_agent("not-shipped.js")


# ----------------------------------------------------------------- the gate

def test_no_instrumentation_without_an_execution_attestation(repos,
                                                             project) -> None:
    instr = Instrumentation(adb=Adb())
    with pytest.raises(ExecutionNotAuthorized):
        instr.objection_job(repos, project.id, PKG, "ssl-pin-bypass")
    with pytest.raises(ExecutionNotAuthorized):
        instr.frida_script(repos, project.id, PKG, "observe-crypto.js")


# ------------------------------------------------------------------ objection

def test_a_named_job_becomes_the_right_objection_command(repos,
                                                         authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    plan = instr.objection_job(repos, authorized.id, PKG, "ssl-pin-bypass")

    assert plan.kind == "objection-job"
    assert plan.serial == SERIAL
    assert "-S" in plan.command and SERIAL in plan.command
    assert "-g" in plan.command and PKG in plan.command
    assert OBJECTION_JOBS["ssl-pin-bypass"] in plan.command


def test_an_unknown_job_is_refused_and_lists_the_known_ones(repos,
                                                            authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    with pytest.raises(InstrumentationError, match="ssl-pin-bypass"):
        instr.objection_job(repos, authorized.id, PKG, "rm -rf /")


# --------------------------------------------------------------- frida script

def test_a_frida_run_loads_only_a_shipped_agent(repos, authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    plan = instr.frida_script(repos, authorized.id, PKG, "observe-crypto.js")

    assert plan.kind == "frida-script"
    assert plan.agent_path.name == "observe-crypto.js"
    assert str(plan.agent_path) in plan.command
    # Spawn form, which starts the app under instrumentation.
    assert "-f" in plan.command and PKG in plan.command


def test_a_frida_run_will_not_load_a_script_from_outside(repos,
                                                         authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    with pytest.raises(InstrumentationError):
        instr.frida_script(repos, authorized.id, PKG, "../gate.py")


def test_attach_form_is_available_for_a_running_app(repos, authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    plan = instr.frida_script(repos, authorized.id, PKG, "observe-tls.js",
                              spawn=False)
    assert "-n" in plan.command and "-f" not in plan.command


def test_a_hostile_package_name_is_refused(repos, authorized) -> None:
    instr = Instrumentation(adb=_BoundAdb())
    for bad in ("com.example; rm -rf /", "no-dots", "../x"):
        with pytest.raises(InstrumentationError, match="invalid package name"):
            instr.frida_script(repos, authorized.id, bad, "observe-crypto.js")


# ------------------------------------------------------------------ recording

def test_a_plan_records_what_it_will_do() -> None:
    from themob.dynamic.instrument import InstrumentationPlan

    plan = InstrumentationPlan(serial=SERIAL, package=PKG, kind="objection-job",
                              job="ssl-pin-bypass",
                              description="objection: ssl-pin-bypass")
    detail = plan.to_detail()
    assert detail["serial"] == SERIAL
    assert detail["job"] == "ssl-pin-bypass"
    assert detail["package"] == PKG


def test_running_rechecks_the_gate_before_launching(repos, project) -> None:
    """A plan is a value that can be held; the attestation must still hold."""
    from themob.dynamic.instrument import FridaSession, InstrumentationPlan

    # A plan built as if authorized, but the project never attested.
    plan = InstrumentationPlan(serial=SERIAL, package=PKG, kind="frida-script")
    session = FridaSession(plan)

    with pytest.raises(ExecutionNotAuthorized):
        session.run(repos, project.id)


# ------------------------------------------------------------------- agents

def test_the_observe_agents_never_emit_key_or_certificate_bytes() -> None:
    """An assessment tool, not a key logger.

    The agents are shipped source; this asserts they stay observational. A
    future edit that starts sending raw key material would trip it.
    """
    crypto = (AGENTS_DIR / "observe-crypto.js").read_text(encoding="utf-8")
    assert "key_length" in crypto
    # The key bytes are measured, never sent.
    assert "bytes.length" in crypto
    assert "JSON.stringify(bytes" not in crypto


def test_the_agents_only_observe_they_do_not_disable() -> None:
    """Bypassing pinning is a named objection job, not something an agent does."""
    tls = (AGENTS_DIR / "observe-tls.js").read_text(encoding="utf-8")
    # It reads the trust managers and reports; it does not replace them.
    assert "return managers" in tls
    assert "return this.check" in tls
