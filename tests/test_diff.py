"""Version diffing: what changed since the last release.

The property that makes this cheap and correct is the stable fingerprint, so the
tests are about set logic on fingerprints: a finding present in both scans is not
new, a finding gone from the current scan is resolved, and a baseline that
already dismissed something keeps it from counting as new. The surface diff is
the same idea over entity keys.
"""
from __future__ import annotations

import json

import pytest

from themob.audit.attestation import AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.report import build, diff, json_report
from themob.storage.repositories import Project, Repositories


def _project(repos, name, sha) -> Project:
    stored = repos.projects.create(Project(
        name=name, target_platform=Platform.ANDROID,
        source_path=f"in/{name}.apk", source_sha256=sha))
    repos.projects.set_authorization(stored.id, ref="ENG-1", by="tester@lab")
    repos.entities.upsert(stored.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
        label="shop", attributes={"package": "com.example.shop"}))
    return repos.projects.get(stored.id)


def _finding(repos, project, fp, key, severity, entity_id=None):
    repos.findings.upsert(project.id, Finding(
        fingerprint=fp, weakness_key=key, title=key.split(".")[-1],
        severity=severity, confidence=0.9,
        entity_ids=[entity_id] if entity_id else [],
        sources=[FindingSource(tool="config-audit", rule="x")]))


# --------------------------------------------------------------- the finding set

def test_new_resolved_and_persisting_are_a_set_operation(repos) -> None:
    audit = AuditTrail(repos.audit)
    base = _project(repos, "v1", "a" * 64)
    _finding(repos, base, "a" * 64, "android.config.debuggable", Severity.HIGH)
    _finding(repos, base, "b" * 64, "android.config.backup-allowed", Severity.LOW)

    curr = _project(repos, "v2", "b" * 64)
    _finding(repos, curr, "b" * 64, "android.config.backup-allowed", Severity.LOW)
    _finding(repos, curr, "c" * 64, "android.secrets.cloud-credential",
             Severity.CRITICAL)

    delta = diff.compare_projects(repos, base.id, curr.id, audit)

    assert {d.fingerprint for d in delta.new} == {"c" * 64}
    assert {d.fingerprint for d in delta.resolved} == {"a" * 64}
    assert {d.fingerprint for d in delta.persisting} == {"b" * 64}
    assert not delta.clean
    assert "1 new, 1 resolved, 1 unchanged" == delta.summary


def test_new_is_worst_first_and_gates_by_severity(repos) -> None:
    audit = AuditTrail(repos.audit)
    base = _project(repos, "v1", "a" * 64)
    curr = _project(repos, "v2", "b" * 64)
    _finding(repos, curr, "c" * 64, "android.config.debuggable", Severity.MEDIUM)
    _finding(repos, curr, "d" * 64, "android.secrets.cloud-credential",
             Severity.CRITICAL)

    delta = diff.compare_projects(repos, base.id, curr.id, audit)
    assert delta.new[0].severity == "critical"
    assert len(delta.new_at_or_above(Severity.HIGH)) == 1


# --------------------------------------------------------------- the surface

def test_the_attack_surface_delta_is_reported(repos) -> None:
    audit = AuditTrail(repos.audit)
    base = _project(repos, "v1", "a" * 64)
    curr = _project(repos, "v2", "b" * 64)
    repos.entities.upsert(curr.id, Entity(
        type=EntityType.ENDPOINT, platform=Platform.ANDROID,
        key="https://new.example.com/x", label="new.example.com",
        attributes={"host": "new.example.com"}))

    delta = diff.compare_projects(repos, base.id, curr.id, audit)
    assert any("new.example.com" in k for k in delta.surface.added)
    assert not delta.surface.removed


# ----------------------------------------------------------- file-based baseline

def _report_file(tmp_path, name, findings):
    """A minimal themob JSON report shape with the given (fp, sev) findings."""
    doc = {"sections": [{"findings": [
        {"fingerprint": fp, "title": f"F {fp[:4]}", "severity": sev,
         "weakness": "k"} for fp, sev in findings]}],
        "suppressed": []}
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_baseline_fingerprints_include_suppressed(tmp_path) -> None:
    """A dismissed finding that returns is not new; it was already judged."""
    doc = {"sections": [{"findings": [{"fingerprint": "a" * 64}]}],
           "suppressed": [{"fingerprint": "b" * 64}]}
    path = tmp_path / "r.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    fps = diff.read_baseline_fingerprints(path)
    assert fps == {"a" * 64, "b" * 64}


def test_new_against_a_baseline_file(repos, tmp_path) -> None:
    audit = AuditTrail(repos.audit)
    curr = _project(repos, "v2", "b" * 64)
    _finding(repos, curr, "a" * 64, "android.config.debuggable", Severity.HIGH)
    _finding(repos, curr, "c" * 64, "android.secrets.cloud-credential",
             Severity.CRITICAL)
    report = build(repos, curr.id, audit)

    baseline = {"a" * 64}                                # the high one is known
    new = diff.new_against_baseline(report, baseline)
    assert {d.fingerprint for d in new} == {"c" * 64}


def test_compare_two_report_files(tmp_path) -> None:
    a = _report_file(tmp_path, "a.json",
                     [("a" * 64, "high"), ("b" * 64, "medium")])
    b = _report_file(tmp_path, "b.json",
                     [("b" * 64, "medium"), ("c" * 64, "critical")])

    delta = diff.compare_files(a, b)
    assert {d.fingerprint for d in delta.new} == {"c" * 64}
    assert {d.fingerprint for d in delta.resolved} == {"a" * 64}


def test_a_file_that_is_not_a_report_is_refused(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"nope": True}), encoding="utf-8")
    with pytest.raises(ValueError):
        diff.read_report_deltas(bad)


# ------------------------------------------------------------------- rendering

def test_the_text_render_names_new_and_resolved(repos) -> None:
    audit = AuditTrail(repos.audit)
    base = _project(repos, "v1", "a" * 64)
    _finding(repos, base, "a" * 64, "android.config.debuggable", Severity.HIGH)
    curr = _project(repos, "v2", "b" * 64)
    _finding(repos, curr, "c" * 64, "android.secrets.cloud-credential",
             Severity.CRITICAL)

    text = diff.render_text(diff.compare_projects(repos, base.id, curr.id, audit))
    assert "New:" in text and "Resolved:" in text


def test_no_change_reads_as_no_change(repos) -> None:
    audit = AuditTrail(repos.audit)
    base = _project(repos, "v1", "a" * 64)
    _finding(repos, base, "a" * 64, "android.config.debuggable", Severity.HIGH)
    curr = _project(repos, "v2", "b" * 64)
    _finding(repos, curr, "a" * 64, "android.config.debuggable", Severity.HIGH)

    delta = diff.compare_projects(repos, base.id, curr.id, audit)
    assert delta.clean
    assert "No change." in diff.render_text(delta)
