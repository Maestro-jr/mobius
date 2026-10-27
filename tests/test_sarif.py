"""SARIF export: themob findings in the format a build pipeline gates on.

The properties that matter are the ones a consumer relies on: a stable level and
security-severity so GitHub ranks correctly, a partial fingerprint so a triaged
finding is not re-reported as new, and, as everywhere, no secret value in the
file.
"""
from __future__ import annotations

import json

import pytest

from themob.audit.attestation import AuditTrail
from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, EvidenceKind, Platform,
                                Severity)
from themob.model.findings import (Evidence, Finding, FindingSource, Location,
                                   Remediation)
from themob.report import build, sarif
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


@pytest.fixture()
def populated(repos: Repositories, project: Project):
    app = repos.entities.upsert(project.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key=PKG,
        label="shop", attributes={"package": PKG}))
    secret = repos.entities.upsert(project.id, Entity(
        type=EntityType.SECRET, platform=Platform.ANDROID, key="sha256:abcd",
        label="key", attributes={"preview": "AKIA****"}))
    repos.edges.upsert(project.id, Edge(src_id=app.id, dst_id=secret.id,
                                        type=EdgeType.USES))

    repos.findings.upsert(project.id, Finding(
        fingerprint="a" * 64, weakness_key="android.secrets.cloud-credential",
        title="Cloud credential in the package", severity=Severity.CRITICAL,
        confidence=0.94, risk=88.0, masvs_control="MASVS-STORAGE-1",
        cwe="CWE-798", mobile_top10="M1", entity_ids=[secret.id],
        location=Location(file="res/values/strings.xml", line=48),
        evidence=[Evidence(kind=EvidenceKind.SNIPPET, value="AKIA************XYZQ",
                           artifact_path="raw/gitleaks/gitleaks.json")],
        remediation=Remediation(summary="Rotate the key and move it server side."),
        sources=[FindingSource(tool="gitleaks", rule="aws")]))
    repos.findings.upsert(project.id, Finding(
        fingerprint="b" * 64, weakness_key="android.config.debuggable",
        title="Application is debuggable", severity=Severity.MEDIUM,
        confidence=0.95, entity_ids=[app.id],
        sources=[FindingSource(tool="config-audit", rule="x")]))
    return project


def _sarif(repos, project_id, audit) -> dict:
    return sarif.to_sarif(build(repos, project_id, audit))


# --------------------------------------------------------------------- shape

def test_it_is_a_2_1_0_log_with_one_run(repos, project, populated, audit) -> None:
    doc = _sarif(repos, project.id, audit)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "themob"


def test_a_rule_per_weakness_not_per_finding(repos, project, populated,
                                             audit) -> None:
    rules = _sarif(repos, project.id, audit)["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert "android.secrets.cloud-credential" in ids
    assert "android.config.debuggable" in ids
    assert len(ids) == len(set(ids)), "a weakness must define one rule"


# --------------------------------------------------------------- the ranking

def test_severity_becomes_a_level_and_a_number(repos, project, populated,
                                               audit) -> None:
    """GitHub ranks by security-severity, not by the level word, so both ship."""
    run = _sarif(repos, project.id, audit)["runs"][0]
    by_rule = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["ruleId"]: r for r in run["results"]}

    critical = results["android.secrets.cloud-credential"]
    assert critical["level"] == "error"
    assert by_rule["android.secrets.cloud-credential"][
        "properties"]["security-severity"] == "9.5"

    medium = results["android.config.debuggable"]
    assert medium["level"] == "warning"
    assert by_rule["android.config.debuggable"][
        "properties"]["security-severity"] == "5.0"


def test_a_result_carries_the_stable_fingerprint(repos, project, populated,
                                                 audit) -> None:
    """So a triaged finding is tracked across runs, not re-reported as new."""
    results = _sarif(repos, project.id, audit)["runs"][0]["results"]
    fps = {r["ruleId"]: r["partialFingerprints"]["themob/v1"] for r in results}
    assert fps["android.secrets.cloud-credential"] == "a" * 64


# ------------------------------------------------------------------ locations

def test_a_finding_with_a_file_gets_a_physical_location(repos, project,
                                                        populated, audit) -> None:
    results = {r["ruleId"]: r for r in
               _sarif(repos, project.id, audit)["runs"][0]["results"]}
    loc = results["android.secrets.cloud-credential"]["locations"][0]
    physical = loc["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "res/values/strings.xml"
    assert physical["region"]["startLine"] == 48


def test_a_finding_with_no_file_gets_a_logical_location(repos, project,
                                                        populated, audit) -> None:
    results = {r["ruleId"]: r for r in
               _sarif(repos, project.id, audit)["runs"][0]["results"]}
    loc = results["android.config.debuggable"]["locations"][0]
    assert "logicalLocations" in loc


# --------------------------------------------------------------------- safety

def test_no_secret_value_reaches_the_sarif(repos, project, populated,
                                           audit) -> None:
    """The same thing the other exports promise, asserted for this one too."""
    payload = json.dumps(_sarif(repos, project.id, audit))
    assert SECRET_VALUE not in payload


def test_standards_become_tags_and_a_help_uri(repos, project, populated,
                                              audit) -> None:
    rules = {r["id"]: r for r in
             _sarif(repos, project.id, audit)["runs"][0]["tool"]["driver"]["rules"]}
    rule = rules["android.secrets.cloud-credential"]
    assert "MASVS-STORAGE-1" in rule["properties"]["tags"]
    assert "CWE-798" in rule["properties"]["tags"]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/798.html"


# ------------------------------------------------------------------- writing

def test_export_writes_a_sarif_file(repos, project, populated, audit,
                                    tmp_path) -> None:
    from themob.report import export

    written = export(repos, audit, project.id, tmp_path / "out",
                     operator="tester@lab")
    assert "sarif" in written.files
    doc = json.loads(written.files["sarif"].read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_export_can_omit_sarif(repos, project, populated, audit,
                               tmp_path) -> None:
    from themob.report import export

    written = export(repos, audit, project.id, tmp_path / "out",
                     operator="tester@lab", sarif_report=False)
    assert "sarif" not in written.files
