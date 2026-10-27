"""Report export: the assessment as a document somebody has to defend.

The tests that matter are about what the report must not do. It must not carry
a secret value, must not silently drop a dismissed finding, must not claim
coverage an analyzer failed to provide, and must not stay quiet when its own
audit chain no longer verifies. Each of those turns a report into something
that misleads its reader rather than informing them.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.audit.attestation import Action, AuditTrail
from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, FindingStatus, JobStatus,
                                Platform, Severity, Stage)
from themob.model.findings import Evidence, Finding, FindingSource, Remediation
from themob.model.enums import EvidenceKind
from themob.report import build, export, html_report, json_report
from themob.storage.repositories import Project, Repositories

PKG = "com.example.shop"
SECRET_VALUE = "AKIAZZ7NLQK4PRODXYZQ"


@pytest.fixture()
def audit(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-42", by="tester@lab")
    return repos.projects.get(stored.id)


def _entity(repos, project, etype, key, **attrs) -> Entity:
    return repos.entities.upsert(project.id, Entity(
        type=etype, platform=Platform.ANDROID, key=key,
        label=key.rsplit(".", 1)[-1], attributes=attrs))


@pytest.fixture()
def populated(repos: Repositories, project: Project):
    """A small assessment: one reachable finding, one buried, one dismissed."""
    app = _entity(repos, project, EntityType.APP, PKG, package=PKG,
                  version_name="3.2.1", version_code="3021",
                  analyzer_version="4.1.2")
    door = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Public",
                   kind="activity", exported=True)
    secret = _entity(repos, project, EntityType.SECRET, "sha256:abcd",
                     preview="AKIA************XYZQ")
    repos.edges.upsert(project.id, Edge(src_id=app.id, dst_id=door.id,
                                        type=EdgeType.EXPORTS))
    repos.edges.upsert(project.id, Edge(src_id=door.id, dst_id=secret.id,
                                        type=EdgeType.USES))

    reachable = repos.findings.upsert(project.id, Finding(
        fingerprint="a" * 64, weakness_key="android.secrets.cloud-credential",
        title="Cloud credential in the package", severity=Severity.CRITICAL,
        confidence=0.94, risk=88.0, masvs_control="MASVS-STORAGE-1",
        mobile_top10="M1", cwe="CWE-798",
        score_rationale="raised from high because an exported entry point reaches it",
        entity_ids=[secret.id],
        evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                           value="AKIA************XYZQ",
                           artifact_path="raw/gitleaks/gitleaks.json")],
        remediation=Remediation(summary="Rotate the key and move it server side."),
        sources=[FindingSource(tool="gitleaks", rule="aws-access-token")]))

    repos.findings.upsert(project.id, Finding(
        fingerprint="b" * 64, weakness_key="android.config.debuggable",
        title="Application is debuggable", severity=Severity.HIGH,
        confidence=0.95, risk=66.0, entity_ids=[app.id],
        sources=[FindingSource(tool="config-audit", rule="x")]))

    dismissed = repos.findings.upsert(project.id, Finding(
        fingerprint="c" * 64, weakness_key="android.config.backup-allowed",
        title="Application data can be backed up", severity=Severity.MEDIUM,
        confidence=0.9, risk=40.0, entity_ids=[app.id],
        sources=[FindingSource(tool="config-audit", rule="y")]))
    return {"app": app, "reachable": reachable, "dismissed": dismissed}


# --------------------------------------------------------------- provenance

def test_the_provenance_header_says_what_was_assessed(repos, audit, project,
                                                      populated) -> None:
    report = build(repos, project.id, audit)
    p = report.provenance

    assert p.package == PKG
    assert p.sha256 == "a" * 64
    assert p.authorization_ref == "ENG-42"
    assert p.authorized_by == "tester@lab"
    assert p.authorized and p.generated_at


def test_tool_versions_travel_with_the_report(repos, audit, project,
                                              populated) -> None:
    """A finding is only reproducible against the tool that produced it."""
    report = build(repos, project.id, audit)
    assert report.provenance.tools.get("androguard") == "4.1.2"


def test_an_unauthorized_project_is_called_out(repos, audit) -> None:
    """A report of work that should not have happened has to say so."""
    stored = repos.projects.create(Project(
        name="No attestation", target_platform=Platform.ANDROID,
        source_path="input/x.apk", source_sha256="b" * 64))
    report = build(repos, stored.id, audit)
    assert not report.provenance.authorized

    html = html_report.render(report)
    assert "no authorization attestation" in html


def test_the_trail_cannot_be_edited_in_the_first_place(repos, audit,
                                                       project) -> None:
    """The database refuses it, which is why the chain is worth checking."""
    import sqlite3

    audit.record(Action.PIPELINE_STARTED, project_id=project.id)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repos.db.execute(
            "UPDATE audit_log SET actor = 'someone else' WHERE project_id = ?",
            (project.id,))


def test_a_broken_audit_chain_is_reported_on_the_page(repos, project,
                                                      populated,
                                                      monkeypatch) -> None:
    """A report whose own trail does not verify must not read as normal.

    Tampering is refused by the schema, so the chain is broken here with a
    stub. What is under test is the report's reaction, not the trail's
    resistance, which :func:`test_the_trail_cannot_be_edited_in_the_first_place`
    covers.
    """
    trail = AuditTrail(repos.audit)
    monkeypatch.setattr(trail, "verify_chain",
                        lambda *a, **k: (False, "entry 4 hash mismatch"))

    report = build(repos, project.id, trail)
    assert report.provenance.audit_chain_ok is False

    html = html_report.render(report)
    assert "does NOT verify" in html
    assert "entry 4 hash mismatch" in html


def test_a_failed_analyzer_is_reported_as_missing_coverage(
        repos, audit, project, populated) -> None:
    """Omitting the analyzer that crashed would claim coverage themob lacks."""
    job = repos.jobs.create(project.id, Stage.SECRETS, "gitleaks-scan")
    repos.jobs.finish(job.id, JobStatus.FAILED, "the worker produced no output")

    report = build(repos, project.id, audit)
    html = html_report.render(report)
    assert "Incomplete coverage" in html
    assert "gitleaks-scan" in html


def test_the_report_names_the_themob_that_made_it(repos, audit, project,
                                                  populated) -> None:
    """Tool versions say what found a finding; this says what wrote it up."""
    from themob import __version__

    report = build(repos, project.id, audit)
    assert report.provenance.themob_version == __version__

    assert __version__ in html_report.render(report)
    document = json_report.to_dict(report)
    assert document["provenance"]["themob_version"] == __version__


# ------------------------------------------------------------------ secrets

def test_no_secret_value_reaches_either_export(repos, audit, project,
                                               populated) -> None:
    """The one thing a report can never contain.

    The workers redact before anything leaves the container, so themob holds no
    plaintext to leak. This asserts the export end of that, because "we do not
    store it" and "it cannot appear here" are different claims.
    """
    report = build(repos, project.id, audit)
    html = html_report.render(report)
    payload = json.dumps(json_report.to_dict(report))

    assert SECRET_VALUE not in html
    assert SECRET_VALUE not in payload
    # The masked preview is what a reader gets, and it is enough to recognise.
    assert "AKIA************XYZQ" in html


# --------------------------------------------------------------- suppression

def test_a_dismissed_finding_leaves_the_body(repos, audit, project, populated,
                                             ) -> None:
    from themob.orchestrator.validation import record

    record(repos, audit, populated["dismissed"].id,
           FindingStatus.FALSE_POSITIVE, operator="tester@lab",
           note="Debug build only.")

    report = build(repos, project.id, audit)
    titles = [r.finding.title for r in report.reported]
    assert "Application data can be backed up" not in titles
    assert report.total == 2


def test_a_dismissed_finding_is_still_in_the_report(repos, audit, project,
                                                    populated) -> None:
    """Dropping it would make the report unauditable.

    A reader has to be able to see what was decided not to matter, and why.
    """
    from themob.orchestrator.validation import record

    record(repos, audit, populated["dismissed"].id,
           FindingStatus.FALSE_POSITIVE, operator="tester@lab",
           note="Debug build only, release sets it false.")

    report = build(repos, project.id, audit)
    assert len(report.suppressed) == 1

    html = html_report.render(report)
    assert "Dismissed after review" in html
    assert "Debug build only" in html
    assert "tester@lab" in html


def test_a_confirmed_finding_stays_in_the_body(repos, audit, project,
                                               populated) -> None:
    from themob.orchestrator.validation import record

    record(repos, audit, populated["reachable"].id, FindingStatus.CONFIRMED,
           operator="tester@lab")
    report = build(repos, project.id, audit)
    assert any(r.finding.fingerprint == "a" * 64 for r in report.reported)


# ------------------------------------------------------------------ content

def test_findings_are_ordered_worst_first(repos, audit, project,
                                          populated) -> None:
    report = build(repos, project.id, audit)
    severities = [r.finding.severity for r in report.reported]
    assert severities[0] is Severity.CRITICAL
    assert report.worst is Severity.CRITICAL


def test_exposure_and_its_route_are_shown(repos, audit, project,
                                          populated) -> None:
    """The reader should not have to take reachability on trust."""
    report = build(repos, project.id, audit)
    reachable = next(r for r in report.reported
                     if r.finding.fingerprint == "a" * 64)
    assert reachable.exposed is True
    assert "Public" in " ".join(reachable.exposure_path)

    html = html_report.render(report)
    assert "Externally reachable" in html
    assert "Reachable via" in html


def test_the_score_rationale_is_carried_into_the_report(repos, audit, project,
                                                        populated) -> None:
    """A rating a report cannot explain is one nobody trusts."""
    assert "raised from high" in html_report.render(build(repos, project.id, audit))


def test_findings_are_grouped_by_the_consoles_own_sections(repos, audit,
                                                           project,
                                                           populated) -> None:
    report = build(repos, project.id, audit)
    by_key = {s.key: s for s in report.sections}
    assert "secrets" in by_key and "platform" in by_key
    assert sum(len(s.findings) for s in report.sections) == report.total


def test_an_empty_assessment_does_not_claim_the_app_is_safe(repos, audit,
                                                            project) -> None:
    """No findings is not the same as nothing to find."""
    html = html_report.render(build(repos, project.id, audit))
    assert "not the same as the app being safe" in html


# --------------------------------------------------------------------- html

def test_the_html_is_self_contained(repos, audit, project, populated) -> None:
    """A report is opened later on a machine that never heard of themob."""
    html = html_report.render(build(repos, project.id, audit))
    assert "<script" not in html.lower()
    assert "http://" not in html.replace("http://schemas", "")
    assert "src=" not in html and "@import" not in html


def test_hostile_content_cannot_inject_markup(repos, audit, project) -> None:
    """Every string in a report came out of an untrusted package."""
    repos.findings.upsert(project.id, Finding(
        fingerprint="d" * 64, weakness_key="android.config.debuggable",
        title="<script>alert('x')</script>", severity=Severity.HIGH,
        description="<img src=x onerror=alert(1)>",
        sources=[FindingSource(tool="config-audit", rule="x")]))

    html = html_report.render(build(repos, project.id, audit))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    # The attribute text survives, escaped, which is the point: it is inert
    # because the angle brackets around it are entities, so no tag is formed.
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


# --------------------------------------------------------------------- json

def test_the_json_export_is_stable(repos, audit, project, populated) -> None:
    """Two exports of one project must diff cleanly, or nobody diffs them."""
    first = json.dumps(json_report.to_dict(build(repos, project.id, audit)),
                       sort_keys=True)
    second = json.dumps(json_report.to_dict(build(repos, project.id, audit)),
                        sort_keys=True)
    # generated_at is the one field that legitimately moves.
    assert _without_timestamp(first) == _without_timestamp(second)


def _without_timestamp(payload: str) -> str:
    document = json.loads(payload)
    document["provenance"]["generated_at"] = ""
    return json.dumps(document, sort_keys=True)


def test_the_json_carries_the_full_schema(repos, audit, project,
                                          populated) -> None:
    document = json_report.to_dict(build(repos, project.id, audit))
    finding = next(f for section in document["sections"]
                   for f in section["findings"]
                   if f["fingerprint"] == "a" * 64)

    assert finding["weakness"] == "android.secrets.cloud-credential"
    assert finding["standards"]["mobile_top10"] == "M1"
    assert finding["standards"]["maswe_id"] is None, "absent, not invented"
    assert finding["externally_reachable"] is True
    assert finding["reported_by"] == ["gitleaks"]
    assert finding["remediation"]


def test_the_prose_agrees_with_its_numbers(repos, audit, project,
                                           populated) -> None:
    """"1 endpoints" is the kind of thing a reader stops reading at."""
    html = html_report.render(build(repos, project.id, audit))

    assert "1 app, 1 component, 1 secret." in html
    assert "1 secrets" not in html and "1 components" not in html
    assert "3 findings reported" in html


def test_a_single_audit_entry_is_not_reported_as_entries(repos, audit, project,
                                                         populated) -> None:
    audit.record(Action.PIPELINE_STARTED, project_id=project.id)
    html = html_report.render(build(repos, project.id, audit))
    assert "1 entry," in html and "1 entries" not in html


def test_one_failed_analyzer_is_described_in_the_singular(repos, audit, project,
                                                          populated) -> None:
    job = repos.jobs.create(project.id, Stage.SECRETS, "gitleaks-scan")
    repos.jobs.finish(job.id, JobStatus.FAILED, "no output")

    html = html_report.render(build(repos, project.id, audit))
    assert "so anything it would have found" in html


# ------------------------------------------------------------------- export

def test_export_writes_both_formats(repos, audit, project, populated,
                                    tmp_path: Path) -> None:
    written = export(repos, audit, project.id, tmp_path / "out",
                     operator="tester@lab")
    assert written.files["html"].is_file() and written.files["json"].is_file()
    assert json.loads(
        written.files["json"].read_text(encoding="utf-8"))["format"]
    # The document comes back with the paths, so a caller can describe what it
    # wrote without building it again.
    assert written.report is not None and written.report.total == 3


def test_exporting_is_itself_audited(repos, audit, project, populated,
                                     tmp_path: Path) -> None:
    """A report leaving the tool is the moment findings become forwardable."""
    export(repos, audit, project.id, tmp_path / "out", operator="tester@lab")

    entry = next(e for e in repos.audit.list(project.id)
                 if e.action == Action.REPORT_EXPORTED)
    assert entry.actor == "tester@lab"
    assert entry.detail["findings"] == 3
    # html, json, sarif and the manifest: the audit names every file that left
    # the tool.
    assert len(entry.detail["files"]) == 4

    ok, message = audit.verify_chain()
    assert ok, message


def test_the_report_builds_without_a_gui_toolkit() -> None:
    """A report has to be exportable from a machine with no Qt on it.

    Run in a subprocess with PyQt6 blocked at import time, because once this
    process has imported it, an assertion here would prove nothing.
    """
    import subprocess
    import sys
    import textwrap

    program = textwrap.dedent("""
    import sys

    class NoQt:
        def find_module(self, name, path=None):
            return None

        def find_spec(self, name, path=None, target=None):
            if name == "PyQt6" or name.startswith("PyQt6."):
                raise ImportError("PyQt6 is not installed on this machine")
            return None

    sys.meta_path.insert(0, NoQt())

    from themob.report import build, export, html_report, json_report  # noqa: F401
    from themob.report.model import Report  # noqa: F401

    assert not [m for m in sys.modules if m.startswith("PyQt6")]
    print("ok")
""")
    result = subprocess.run([sys.executable, "-c", program],
                            capture_output=True, text=True,
                            cwd=str(Path(__file__).resolve().parents[1]))
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
