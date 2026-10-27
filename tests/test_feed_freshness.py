"""Vulnerability-feed freshness: a clean result is only as current as its data.

grype matches an SBOM against a database baked into the worker image. If that
database is old, a real CVE is simply invisible, and "no vulnerable
dependencies" reads as reassurance when it is really ignorance. So the build
date travels from grype through the adapter into the report, and the report says
how old it was and warns when it is stale.
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from themob.audit.attestation import AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform
from themob.report import build, html_report
from themob.report.model import (VULN_DB_STALE_AFTER_DAYS, vuln_db_age_days)
from themob.storage.repositories import Project, Repositories

_WORKER = (Path(__file__).resolve().parent.parent
           / "workers" / "sbom" / "analyze.py")


# --------------------------------------------------------------- the age math

def test_age_reads_the_shapes_grype_emits() -> None:
    now = datetime(2026, 9, 23, tzinfo=timezone.utc)
    assert vuln_db_age_days("2026-09-16T00:00:00Z", now) == 7
    assert vuln_db_age_days("2026-09-16T00:00:00+00:00", now) == 7
    assert vuln_db_age_days("2026-09-16", now) == 7          # naive, assumed UTC


def test_an_unparseable_date_is_none_not_a_wrong_number() -> None:
    """A made-up age is worse than a missing one on a page about staleness."""
    for bad in ("", "yesterday", "not-a-date", None):
        assert vuln_db_age_days(bad) is None


def test_a_future_build_date_is_zero_not_negative() -> None:
    now = datetime(2026, 9, 23, tzinfo=timezone.utc)
    assert vuln_db_age_days("2026-12-01T00:00:00Z", now) == 0


# --------------------------------------------------------------- the worker

@pytest.fixture(scope="module")
def worker():
    spec = importlib.util.spec_from_file_location("themob_sbom_worker_f", _WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_worker_reads_the_db_date_from_either_schema(worker) -> None:
    newer = worker.grype_db_info(
        {"descriptor": {"db": {"status": {"built": "2026-09-20T01:02:03Z",
                                          "schemaVersion": "5.0.2"}}}})
    assert newer["built"] == "2026-09-20T01:02:03Z"

    older = worker.grype_db_info(
        {"descriptor": {"db": {"built": "2026-08-01T00:00:00Z",
                               "schemaVersion": 5}}})
    assert older["built"] == "2026-08-01T00:00:00Z"

    assert worker.grype_db_info({"matches": []}) is None


# ------------------------------------------------------------- in the report

def _project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Shop", target_platform=Platform.ANDROID,
        source_path="in/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-1", by="tester@lab")
    return repos.projects.get(stored.id)


def _app_with_db(repos, project, built: str | None) -> None:
    scan = {"libraries": 3, "vulnerabilities": 0}
    if built is not None:
        scan["vuln_db"] = {"built": built, "schema_version": "5"}
    repos.entities.upsert(project.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
        label="shop", attributes={"package": "com.example.shop",
                                   "dependency_scan": scan}))


def _built(days_ago: int) -> str:
    return (datetime.now(timezone.utc)
            - timedelta(days=days_ago)).isoformat(timespec="seconds")


def test_a_fresh_feed_is_reported_and_not_flagged(repos) -> None:
    project = _project(repos)
    _app_with_db(repos, project, _built(1))
    report = build(repos, project.id, AuditTrail(repos.audit))

    assert report.provenance.vuln_db_built is not None
    assert report.provenance.vuln_db_age_days <= 2
    assert not report.provenance.vuln_db_stale

    html = html_report.render(report)
    assert "Vulnerability data" in html
    assert "days old at scan time" not in html


def test_a_stale_feed_warns_in_the_report(repos) -> None:
    """The false-negative the whole feature exists to catch."""
    project = _project(repos)
    _app_with_db(repos, project, _built(VULN_DB_STALE_AFTER_DAYS + 30))
    report = build(repos, project.id, AuditTrail(repos.audit))

    assert report.provenance.vuln_db_stale
    html = html_report.render(report)
    assert "days old at scan time" in html


def test_no_dependency_scan_means_no_freshness_claim(repos) -> None:
    """Absent, not fabricated: the honest 'we do not know'."""
    project = _project(repos)
    _app_with_db(repos, project, None)
    report = build(repos, project.id, AuditTrail(repos.audit))

    assert report.provenance.vuln_db_built is None
    assert report.provenance.vuln_db_age_days is None
    assert not report.provenance.vuln_db_stale
    assert "Vulnerability data" not in html_report.render(report)


def test_the_freshness_reaches_json_and_sarif(repos) -> None:
    from themob.report import json_report, sarif

    project = _project(repos)
    built = _built(VULN_DB_STALE_AFTER_DAYS + 5)
    _app_with_db(repos, project, built)
    report = build(repos, project.id, AuditTrail(repos.audit))

    document = json_report.to_dict(report)
    assert document["provenance"]["vuln_db_built"] == built

    run = sarif.to_sarif(report)["runs"][0]
    assert run["properties"]["vulnerability_db_stale"] is True
