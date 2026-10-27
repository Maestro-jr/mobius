"""Preflight tests: the check that tells an operator whether this install works.

The thing worth testing is not that the checks pass on this machine, which
proves only that this machine is set up. It is that a missing prerequisite is
reported as missing, loudly, with the command that fixes it: a preflight that
returns "ready" on a broken install is worse than no preflight at all.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from themob import preflight
from themob.preflight import FAIL, OK, WARN, Check


def test_every_check_reports_a_known_state() -> None:
    checks = preflight.run()
    assert checks
    for check in checks:
        assert check.state in (OK, WARN, FAIL), check
        assert check.name and check.detail, check


def test_a_healthy_install_is_ready() -> None:
    """The checkout the tests run in is, by definition, a working install.

    Docker is excluded from the claim. Whether a daemon is up and its images
    are built is a property of the machine, not of this checkout, and asserting
    it here would fail the suite on any box that simply has Docker stopped.
    """
    docker_names = {c.name for c in (Check("docker", OK), Check("worker images", OK),
                                     Check("worker sources", OK))}
    failed = [c for c in preflight.run()
              if c.state == FAIL and c.name not in docker_names]
    assert not failed, [(c.name, c.detail) for c in failed]


def test_the_preflight_leads_with_the_version() -> None:
    """The first question on any bug report is which build this was."""
    checks = preflight.run()
    assert checks[0].name == "themob"
    assert checks[0].state in (OK, WARN)


def test_an_uninstalled_checkout_says_so_rather_than_guessing(monkeypatch) -> None:
    import themob

    monkeypatch.setattr(themob, "__version__", "0.0.0+unknown")
    check = preflight.themob_version()
    assert check.state == WARN
    assert "no package metadata" in check.detail


# ------------------------------------------------------------------ reporting

def test_a_failure_is_reported_and_exits_non_zero() -> None:
    out = io.StringIO()
    code = preflight.report([
        Check("python", OK, "3.12.3"),
        Check("worker images", FAIL, "0/7 built",
              "python -m themob.sandbox.build"),
    ], stream=out)

    text = out.getvalue()
    assert code == 1
    assert "0/7 built" in text
    # The fix is printed, because "it failed" without "do this" is a dead end.
    assert "python -m themob.sandbox.build" in text
    assert "will not analyze anything" in text


def test_a_warning_alone_still_reports_ready() -> None:
    out = io.StringIO()
    code = preflight.report([
        Check("python", OK, "3.12.3"),
        Check("weakness packs", WARN, "19 weaknesses", "fill maswe_id"),
    ], stream=out)

    assert code == 0
    assert "Ready, with 1 warning" in out.getvalue()


def test_a_clean_run_says_so_without_qualification() -> None:
    out = io.StringIO()
    code = preflight.report([Check("python", OK, "3.12.3")], stream=out)
    assert code == 0
    assert out.getvalue().rstrip().endswith("Ready.")


def test_the_fix_is_not_printed_for_a_passing_check() -> None:
    out = io.StringIO()
    preflight.report([Check("python", OK, "3.12.3", "do not show me")],
                     stream=out)
    assert "do not show me" not in out.getvalue()


# ------------------------------------------------------------- the checks

def test_the_missing_maswe_ids_are_surfaced_not_hidden() -> None:
    """The gap is real, so the operator learns it here rather than from a client."""
    check = preflight.knowledge_packs()
    assert check.state == WARN
    assert "MASWE" in check.detail
    assert "mas.owasp.org" in check.fix


def test_adb_is_a_warning_not_a_failure() -> None:
    """Phases 1 and 2 never need it, and a preflight that cries wolf is ignored."""
    check = preflight.android_tools()
    assert check.state in (OK, WARN)
    if check.state == WARN:
        assert "dynamic" in check.fix


def test_migrations_are_applied_to_a_fresh_database() -> None:
    check = preflight.migrations()
    assert check.state == OK
    assert "applied" in check.detail and "tables" in check.detail


def test_the_image_check_asks_the_registry_not_the_workers_directory(
        monkeypatch) -> None:
    """An installed copy has no workers/ and still runs on built images.

    Checking the directory instead of the registry would fail every install
    that was not a git checkout, which is exactly the wrong answer.
    """
    from themob.sandbox import build as build_module

    monkeypatch.setattr(build_module, "discover", lambda *a, **k: [])
    checks = {c.name: c for c in preflight.docker()}

    if "docker" in checks and checks["docker"].state == FAIL:
        pytest.skip("no docker daemon on this machine")

    # Asserted on meaning, not wording: this failed once because the
    # message was reworded from "missing" to "not ready" while the check
    # itself was correct. A test that breaks on a rephrasing tests phrasing.
    images = checks["worker images"]
    assert images.state in (OK, FAIL)
    assert "ready" in images.detail
    if images.state == FAIL:
        assert images.fix, "a failure must name the command that fixes it"
    # Not being able to build is a warning, not a failure.
    assert checks["worker sources"].state == WARN


def test_a_missing_image_fails_rather_than_warns(monkeypatch) -> None:
    """A skipped stage reads like a clean one, so this cannot be a warning."""
    from themob.sandbox.runner import SandboxRunner

    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: True)
    monkeypatch.setattr(SandboxRunner, "has_image", lambda self, image: False)

    checks = {c.name: c for c in preflight.docker()}
    assert checks["worker images"].state == FAIL
    # Named, so the operator knows which stage will silently report nothing.
    assert "not ready:" in checks["worker images"].detail
    assert "mobsf-scan" in checks["worker images"].detail


def test_an_unreachable_daemon_stops_at_the_daemon(monkeypatch) -> None:
    from themob.sandbox.runner import SandboxRunner

    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: False)
    checks = preflight.docker()
    assert len(checks) == 1
    assert checks[0].state == FAIL
    assert "Docker Desktop" in checks[0].fix


def test_an_unwritable_workspace_is_a_failure(monkeypatch, tmp_path) -> None:
    from themob.storage import workspace as workspace_module

    target = tmp_path / "nope"

    def refuse(*_a, **_k):
        raise OSError("read-only file system")

    monkeypatch.setattr(workspace_module, "default_root", lambda: target)
    monkeypatch.setattr(Path, "mkdir", refuse)

    check = preflight.workspace()
    assert check.state == FAIL
    assert "THEMOB_HOME" in check.fix


# ------------------------------------------------------------------ the entry

def test_the_check_flag_runs_the_preflight(monkeypatch, capsys) -> None:
    """`python -m themob --check` must not need a display or a container."""
    from themob.__main__ import main

    called = {}

    def fake_report():
        called["ran"] = True
        return 0

    monkeypatch.setattr(preflight, "report", fake_report)
    assert main(["--check"]) == 0
    assert called.get("ran")


def test_the_console_script_and_the_module_are_one_entry_point() -> None:
    """`themob --check` and `python -m themob --check` must not diverge.

    The script used to point straight at the GUI entry, which ignored the flag
    and opened a window instead.
    """
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["scripts"]["themob"] == "themob.__main__:main"


def test_no_argument_launches_the_console(monkeypatch) -> None:
    from themob.__main__ import main

    called = {}
    import themob.app.main as app_main

    def fake_launch():
        called["launched"] = True
        return 7

    monkeypatch.setattr(app_main, "main", fake_launch)

    assert main([]) == 7
    assert called.get("launched")
