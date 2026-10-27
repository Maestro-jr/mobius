"""The full console CLI: routing, the project-scoped commands, and the gate.

The headless ``scan``/``diff``/``verify``/``sign-pack`` contract is covered in
test_cli.py. This covers the rest of the surface the window exposes, driven the
way a user or a script drives it, through ``python -m themob`` into the one
dispatcher: that every capability has a command, that the commands read and
write a real project store, that the authorization gate is still enforced in a
terminal, and that colour turns itself off when it should.

No Docker and no Qt: the commands that need a container (``analyze``) are checked
for the refusal they give without one, which is the behaviour a build box hits.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from themob import cli
from themob.__main__ import main
from themob.model.entities import Entity
from themob.model.enums import EntityType, FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource

_FP = "a" * 64


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-manifest")
        zf.writestr("classes.dex", b"dex\n035\x00")
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00")
    return path


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    return tmp_path / "home"


def _authorize(apk: Path, home: Path) -> str:
    """Run the authorize command; return the created project's id."""
    rc = main(["authorize", str(apk), "--engagement", "ENG-1", "--yes",
               "--home", str(home)])
    assert rc == 0
    return _first_project(home).id


def _open(home: Path):
    from themob.storage.db import open_database
    from themob.storage.repositories import Repositories

    database = open_database(home / "themob.db")
    return database, Repositories(database)


def _first_project(home: Path):
    database, repos = _open(home)
    try:
        return repos.projects.list(limit=1)[0]
    finally:
        database.close_all()


def _seed_finding(home: Path, project_id: str, *,
                  severity: Severity = Severity.HIGH) -> None:
    database, repos = _open(home)
    try:
        secret = repos.entities.upsert(project_id, Entity(
            type=EntityType.SECRET, platform=Platform.ANDROID, key="secret:aws",
            label="AWS key", attributes={"rule": "aws-access-key",
                                         "tags": ["aws"]}))
        repos.findings.upsert(project_id, Finding(
            fingerprint=_FP, weakness_key="android.secrets.hardcoded",
            title="Hardcoded AWS access key", severity=severity, confidence=0.9,
            sources=[FindingSource(tool="gitleaks", rule="aws")],
            entity_ids=[secret.id]))
    finally:
        database.close_all()


# ------------------------------------------------------------------- routing

def test_help_lists_every_capability(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    printed = capsys.readouterr().out
    for command in ("doctor", "projects", "authorize", "scan", "analyze",
                    "report", "overview", "section", "findings", "finding",
                    "verdict", "graph", "entity", "code", "query", "audit",
                    "analyzers", "dynamic", "handoff", "validate", "sign-pack",
                    "diff", "verify", "build-workers", "gui"):
        assert command in printed, f"{command} is missing from the top-level help"


def test_an_unknown_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["no-such-command"])
    assert exc.value.code == 2


def test_new_subcommands_route_through_the_dispatcher(monkeypatch) -> None:
    seen = {}

    def fake_run(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("themob.cli.run", fake_run)
    assert main(["overview", "--project", "x"]) == 0
    assert seen["argv"] == ["overview", "--project", "x"]


# ---------------------------------------------------------- the read commands

def test_authorize_then_overview_report_and_verify(apk, home, capsys) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)

    assert main(["overview", "--home", str(home)]) == 0
    assert "Hardcoded AWS access key" in capsys.readouterr().out

    out = home / "bundle"
    assert main(["report", "--home", str(home), "--out", str(out)]) == 0
    assert (out / "themob-report.json").is_file()
    assert (out / "manifest.json").is_file()

    assert main(["verify", str(out)]) == 0             # verify takes a path, not --home


def test_findings_json_is_machine_readable(apk, home, capsys) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)
    capsys.readouterr()                         # discard the authorize output
    assert main(["findings", "--home", str(home), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload and payload[0]["fingerprint"] == _FP


def test_project_defaults_to_the_most_recent(apk, home) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)
    # No --project given: the one just authorized is used.
    assert main(["overview", "--home", str(home)]) == 0


def test_an_unknown_project_is_a_usage_error(home) -> None:
    assert main(["overview", "--home", str(home), "--project", "nope"]) == 2


# ------------------------------------------------------------- the verdict loop

def test_a_verdict_is_recorded_and_a_suppression_needs_a_reason(
        apk, home) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)

    assert main(["verdict", _FP, "--status", "confirmed", "--operator", "t@lab",
                 "--home", str(home)]) == 0
    database, repos = _open(home)
    try:
        finding = repos.findings.get_by_fingerprint(project_id, _FP)
        assert finding.status is FindingStatus.CONFIRMED
    finally:
        database.close_all()

    # A false-positive removes the finding from the report, so it is refused
    # without a reason, the same rule the GUI and the engine enforce.
    assert main(["verdict", _FP, "--status", "false-positive",
                 "--home", str(home)]) == 2


# ------------------------------------------------------------------- the gates

def test_authorize_refuses_without_a_tick_when_non_interactive(
        apk, home, monkeypatch) -> None:
    """No --yes and no terminal to ask at: nothing may be ingested."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = main(["authorize", str(apk), "--engagement", "ENG-1",
               "--home", str(home)])
    assert rc == 2
    # And the refusal left nothing behind.
    database, repos = _open(home)
    try:
        assert not repos.projects.list()
    finally:
        database.close_all()


def test_analyze_refuses_an_unauthorized_project(apk, home, monkeypatch) -> None:
    """The pipeline gate is not softened for the CLI: no attestation, no run."""
    from themob.audit.attestation import AuditTrail
    from themob.orchestrator.intake import intake

    database, repos = _open(home)
    try:
        # Ingest without attesting: intake creates the project, the gate does not
        # pass, so require_authorization must refuse before Docker is even asked.
        intake(apk, repos, AuditTrail(repos.audit), root=home)
        project_id = repos.projects.list(limit=1)[0].id
    finally:
        database.close_all()

    rc = main(["analyze", "--home", str(home), "--project", project_id])
    assert rc == 2


def test_validate_is_gated_before_it_will_plan(apk, home, capsys) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)
    # Planning a probe is refused until the separate validation gate is attested.
    assert main(["validate", "plan", "--home", str(home)]) == 0
    assert "no validation attestation" in capsys.readouterr().out
    assert main(["validate", "authorize", "--yes", "--home", str(home)]) == 0
    assert main(["validate", "plan", "--home", str(home)]) == 0
    assert "aws" in capsys.readouterr().out.lower()


# -------------------------------------------------------------------- colour

def test_colour_is_off_when_not_a_terminal(apk, home, capsys) -> None:
    """Piped output carries no ANSI escapes, so a log or a file stays clean."""
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)
    main(["overview", "--home", str(home)])
    assert "\033[" not in capsys.readouterr().out


def test_no_color_flag_works_in_either_position(apk, home) -> None:
    project_id = _authorize(apk, home)
    _seed_finding(home, project_id)
    assert main(["--no-color", "overview", "--home", str(home)]) == 0
    assert main(["overview", "--no-color", "--home", str(home)]) == 0


def test_ink_paints_only_when_enabled() -> None:
    assert cli.Ink(False).accent("x") == "x"
    painted = cli.Ink(True).accent("x")
    assert painted != "x" and painted.startswith("\033[")
