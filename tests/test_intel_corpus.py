"""The local corpus: aggregating the operator's own scans, naming no app.

These seed a project store directly (no sample needed) and check the figures:
prevalence by weakness and by app, the verdict mix, platform and severity
distributions, and co-occurrence. Everything is descriptive and local.
"""
from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from themob.intel import corpus
from themob.model.enums import FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.storage.db import open_database
from themob.storage.repositories import Project, Repositories

_CLEARTEXT = "android.network.cleartext-endpoint"
_DEBUGGABLE = "android.config.debuggable"


@pytest.fixture()
def repos(tmp_path: Path):
    database = open_database(tmp_path / "themob.db")
    try:
        yield Repositories(database)
    finally:
        database.close_all()


def _finding(fp: str, key: str, severity: Severity,
             status: FindingStatus = FindingStatus.NEW) -> Finding:
    return Finding(fingerprint=fp, weakness_key=key, title=key, severity=severity,
                   status=status, sources=[FindingSource(tool="t", rule=key)])


_sha_seq = itertools.count(1)


def _project(repos: Repositories, name: str, platform: Platform) -> Project:
    project = Project(name=name, target_platform=platform,
                      source_path=f"{name}.apk",
                      source_sha256=f"{next(_sha_seq):064x}")
    repos.projects.create(project)
    return project


def test_empty_store_is_an_empty_corpus(repos) -> None:
    result = corpus.build(repos)
    assert result.is_empty and result.projects == 0 and result.findings == 0


def test_prevalence_counts_occurrences_and_apps(repos) -> None:
    p1 = _project(repos, "a", Platform.ANDROID)
    p2 = _project(repos, "b", Platform.IOS)
    # cleartext appears in both apps (twice in p1), debuggable in one.
    repos.findings.upsert(p1.id, _finding("a" * 64, _CLEARTEXT, Severity.HIGH,
                                          FindingStatus.CONFIRMED))
    repos.findings.upsert(p1.id, _finding("b" * 64, _CLEARTEXT, Severity.HIGH,
                                          FindingStatus.NEW))
    repos.findings.upsert(p1.id, _finding("c" * 64, _DEBUGGABLE, Severity.MEDIUM,
                                          FindingStatus.FALSE_POSITIVE))
    repos.findings.upsert(p2.id, _finding("d" * 64, _CLEARTEXT, Severity.HIGH,
                                          FindingStatus.CONFIRMED))

    result = corpus.build(repos)
    assert result.projects == 2 and result.findings == 4
    assert result.by_platform == {"android": 1, "ios": 1}

    cleartext = next(w for w in result.weaknesses if w.key == _CLEARTEXT)
    assert cleartext.occurrences == 3        # three findings
    assert cleartext.apps == 2               # in two distinct apps
    assert cleartext.confirmed == 2 and cleartext.new == 1


def test_severity_distribution_counts_every_finding(repos) -> None:
    p = _project(repos, "a", Platform.ANDROID)
    repos.findings.upsert(p.id, _finding("a" * 64, _CLEARTEXT, Severity.HIGH))
    repos.findings.upsert(p.id, _finding("b" * 64, _DEBUGGABLE, Severity.MEDIUM))
    result = corpus.build(repos)
    assert result.by_severity.get("high") == 1
    assert result.by_severity.get("medium") == 1


def test_false_positive_rate_reflects_the_operator_verdicts(repos) -> None:
    p = _project(repos, "a", Platform.ANDROID)
    # Same weakness: one confirmed, three dismissed -> 75% dismissed.
    repos.findings.upsert(p.id, _finding("a" * 64, _DEBUGGABLE, Severity.MEDIUM,
                                         FindingStatus.CONFIRMED))
    for i, fp in enumerate(("b", "c", "d")):
        repos.findings.upsert(_project(repos, f"p{i}", Platform.ANDROID).id,
                              _finding(fp * 64, _DEBUGGABLE, Severity.MEDIUM,
                                       FindingStatus.FALSE_POSITIVE))
    stat = next(w for w in corpus.build(repos).weaknesses if w.key == _DEBUGGABLE)
    assert stat.triaged == 4
    assert stat.false_positive_rate == 0.75


def test_co_occurrence_needs_more_than_one_app(repos) -> None:
    # A pair seen in a single app is not reported; the same pair in two is.
    p1 = _project(repos, "a", Platform.ANDROID)
    repos.findings.upsert(p1.id, _finding("a" * 64, _CLEARTEXT, Severity.HIGH))
    repos.findings.upsert(p1.id, _finding("b" * 64, _DEBUGGABLE, Severity.MEDIUM))
    assert corpus.build(repos).co_occurrence == []

    p2 = _project(repos, "b", Platform.ANDROID)
    repos.findings.upsert(p2.id, _finding("c" * 64, _CLEARTEXT, Severity.HIGH))
    repos.findings.upsert(p2.id, _finding("d" * 64, _DEBUGGABLE, Severity.MEDIUM))
    pairs = corpus.build(repos).co_occurrence
    assert len(pairs) == 1
    a, b, n = pairs[0]
    assert {a, b} == {_CLEARTEXT, _DEBUGGABLE} and n == 2


def test_summarize_reads_the_store_at_home(repos, tmp_path) -> None:
    # repos is backed by tmp_path/themob.db, so home=tmp_path reaches it.
    p = _project(repos, "a", Platform.ANDROID)
    repos.findings.upsert(p.id, _finding("a" * 64, _CLEARTEXT, Severity.HIGH))
    result = corpus.summarize(home=tmp_path)
    assert result.findings == 1 and result.weaknesses[0].key == _CLEARTEXT
