"""Severity in context, and the number the report ranks by.

The tests that matter here are the ones about what the scorer refuses to do.
It never lowers a severity, never raises one twice, and never lets confidence
touch severity. Each of those is a way a rating stops being defensible, and a
rating nobody can defend is worse than no rating.
"""
from __future__ import annotations

import pytest

from themob.knowledge import get as weakness
from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, FindingStatus, Platform,
                                Severity)
from themob.model.findings import Finding, FindingSource
from themob.scoring import rank, run as score_run, score
from themob.storage.repositories import Project, Repositories

PKG = "com.example.shop"


# -------------------------------------------------------------------- model

def test_an_unreachable_finding_keeps_its_severity() -> None:
    result = score(Severity.MEDIUM, confidence=0.9, exposed=False)
    assert result.severity is Severity.MEDIUM
    assert result.adjusted is False
    assert result.reason == ""


def test_exposure_raises_one_level_and_says_why() -> None:
    """A rating a report cannot explain in one sentence is one nobody trusts."""
    result = score(Severity.MEDIUM, confidence=0.9, exposed=True, hops=1)
    assert result.severity is Severity.HIGH
    assert result.base_severity is Severity.MEDIUM
    assert "raised from medium" in result.reason
    assert "1 hop" in result.reason


def test_exposure_raises_by_one_level_only() -> None:
    """Never two. Reachability is context, not a different finding."""
    result = score(Severity.LOW, confidence=1.0, exposed=True, hops=0)
    assert result.severity is Severity.MEDIUM


def test_critical_cannot_be_raised_further() -> None:
    result = score(Severity.CRITICAL, confidence=1.0, exposed=True, hops=0)
    assert result.severity is Severity.CRITICAL
    assert "top of the scale" in result.reason


def test_the_scorer_never_lowers_a_severity() -> None:
    """Silence is not absence.

    themob failing to find a path to something is not evidence that no path
    exists; it may simply not have looked in the right place. Downgrading on
    that would turn a gap in the analysis into a reassurance.
    """
    for severity in Severity:
        for confidence in (0.0, 0.3, 1.0):
            result = score(severity, confidence=confidence, exposed=False)
            assert rank(result.severity) >= rank(severity)


def test_confidence_does_not_touch_severity() -> None:
    """Two different axes.

    How likely a finding is to be real and how bad it would be are separate
    questions, and multiplying them into one number destroys both.
    """
    low = score(Severity.HIGH, confidence=0.1, exposed=False)
    high = score(Severity.HIGH, confidence=1.0, exposed=False)
    assert low.severity is high.severity is Severity.HIGH
    assert low.risk < high.risk, "confidence belongs in the ranking, not the level"


def test_risk_orders_a_certain_low_below_an_uncertain_high() -> None:
    """The severity gap has to outweigh a confidence gap, or the list inverts."""
    certain_low = score(Severity.LOW, confidence=1.0, exposed=False)
    uncertain_high = score(Severity.HIGH, confidence=0.5, exposed=False)
    assert uncertain_high.risk > certain_low.risk


def test_exposure_breaks_a_tie_between_equal_findings() -> None:
    """Same weakness, same confidence: the reachable one sorts first."""
    reachable = score(Severity.HIGH, confidence=0.8, exposed=True, hops=2)
    buried = score(Severity.HIGH, confidence=0.8, exposed=False)
    assert reachable.risk > buried.risk


def test_a_reachable_finding_outranks_an_unreachable_one_a_level_above() -> None:
    """And that is the intended answer, not a rounding accident.

    A HIGH something can walk to is raised to CRITICAL and carries the exposure
    bonus on top, so it sorts above a CRITICAL nothing can reach. That is the
    whole argument for scoring in context: the ladder position alone was never
    the ordering a tester wanted.
    """
    reachable_high = score(Severity.HIGH, confidence=0.8, exposed=True, hops=2)
    buried_critical = score(Severity.CRITICAL, confidence=0.8, exposed=False)
    assert reachable_high.severity is buried_critical.severity is Severity.CRITICAL
    assert reachable_high.risk > buried_critical.risk


@pytest.mark.parametrize("confidence", [-1.0, 2.0, float("nan")])
def test_a_nonsense_confidence_cannot_break_the_score(confidence) -> None:
    result = score(Severity.HIGH, confidence=confidence, exposed=False)
    assert 0.0 <= result.risk <= 100.0


# --------------------------------------------------------------------- pass

def _project(repos: Repositories) -> Project:
    return repos.projects.create(Project(
        name="Sample", target_platform=Platform.ANDROID,
        source_path="input/s.apk", source_sha256="a" * 64))


def _entity(repos, project, etype, key, **attrs) -> Entity:
    return repos.entities.upsert(project.id, Entity(
        type=etype, platform=Platform.ANDROID, key=key,
        label=key.rsplit(".", 1)[-1], attributes=attrs))


def _graph(repos, project):
    """An app with one exported door, and a secret behind it."""
    app = _entity(repos, project, EntityType.APP, PKG, package=PKG)
    door = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Public",
                   kind="activity", exported=True)
    reached = _entity(repos, project, EntityType.SECRET, "sha256:reached")
    buried = _entity(repos, project, EntityType.SECRET, "sha256:buried")
    inner = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Inner",
                    kind="service", exported=False)
    for src, dst, etype in ((app, door, EdgeType.EXPORTS),
                            (app, inner, EdgeType.DECLARES),
                            (door, reached, EdgeType.USES),
                            (inner, buried, EdgeType.USES)):
        repos.edges.upsert(project.id, Edge(src_id=src.id, dst_id=dst.id,
                                            type=etype))
    return {"app": app, "door": door, "reached": reached, "buried": buried}


def _finding(repos, project, key, *entity_ids, tool="config-audit",
             severity=None) -> Finding:
    spec = weakness(key)
    return repos.findings.upsert(project.id, Finding(
        fingerprint=key + ":" + ":".join(entity_ids), weakness_key=key,
        title=spec.title, severity=severity or spec.severity, confidence=0.9,
        entity_ids=list(entity_ids),
        sources=[FindingSource(tool=tool, rule=key)]))


def test_the_pass_raises_a_reachable_finding(repos: Repositories) -> None:
    project = _project(repos)
    nodes = _graph(repos, project)
    _finding(repos, project, "android.secrets.service-api-key",
             nodes["reached"].id)

    report = score_run(repos, project.id)
    assert report.exposed == 1 and report.raised == 1

    stored = repos.findings.list(project.id)[0]
    assert stored.severity is Severity.CRITICAL      # HIGH, raised once
    assert "raised from high" in stored.score_rationale


def test_the_pass_leaves_an_unreachable_finding_alone(repos: Repositories) -> None:
    project = _project(repos)
    nodes = _graph(repos, project)
    _finding(repos, project, "android.secrets.service-api-key",
             nodes["buried"].id)

    report = score_run(repos, project.id)
    assert report.exposed == 0 and report.raised == 0
    assert repos.findings.list(project.id)[0].severity is Severity.HIGH


def test_running_twice_does_not_compound(repos: Repositories) -> None:
    """The bug a stored severity invites.

    The scorer raises for exposure and writes the result back, so a second run
    that treated the stored value as its starting point would raise it again,
    and a third would raise it once more. The reporter's own rating is kept as
    the base so the pass is idempotent by construction.
    """
    project = _project(repos)
    nodes = _graph(repos, project)
    _finding(repos, project, "android.secrets.service-api-key",
             nodes["reached"].id)

    score_run(repos, project.id)
    first = repos.findings.list(project.id)[0].severity
    score_run(repos, project.id)
    score_run(repos, project.id)
    assert repos.findings.list(project.id)[0].severity is first


def test_a_cve_keeps_the_advisory_severity_as_its_base(
        repos: Repositories) -> None:
    """The advisory rated that specific vulnerability; the pack rates the class.

    Overriding the specific with the general would throw away the better
    number, so the scorer starts from what grype said.
    """
    project = _project(repos)
    _graph(repos, project)
    # The pack's default for this weakness is high; the advisory said low.
    _finding(repos, project, "android.supply-chain.vulnerable-dependency",
             tool="grype", severity=Severity.LOW)

    score_run(repos, project.id)
    assert repos.findings.list(project.id)[0].severity is Severity.LOW


def test_the_pass_fills_the_standards_mapping(repos: Repositories) -> None:
    project = _project(repos)
    _graph(repos, project)
    _finding(repos, project, "android.config.debuggable")

    score_run(repos, project.id)
    stored = repos.findings.list(project.id)[0]
    spec = weakness("android.config.debuggable")

    assert stored.masvs_control == spec.masvs_control
    assert stored.cwe == spec.cwe
    assert stored.mobile_top10 == spec.mobile_top10 == "M8"


def test_a_pack_correction_reaches_stored_findings(repos: Repositories) -> None:
    """The mapping is overwritten, not filled in only when missing."""
    project = _project(repos)
    _graph(repos, project)
    stored = _finding(repos, project, "android.config.debuggable")
    repos.findings.set_score(
        stored.id, severity=Severity.HIGH, masvs_category=None,
        masvs_control="MASVS-WRONG-9", maswe_id=None, mobile_top10="M99",
        cwe="CWE-0", risk=1.0, rationale="")

    score_run(repos, project.id)
    fixed = repos.findings.list(project.id)[0]
    assert fixed.masvs_control == weakness("android.config.debuggable").masvs_control
    assert fixed.mobile_top10 == "M8"


def test_the_pass_records_a_risk_for_ranking(repos: Repositories) -> None:
    project = _project(repos)
    nodes = _graph(repos, project)
    _finding(repos, project, "android.secrets.service-api-key",
             nodes["reached"].id)
    _finding(repos, project, "android.config.backup-allowed", nodes["app"].id)

    score_run(repos, project.id)
    risks = [f.risk for f in repos.findings.list(project.id)]
    assert all(r is not None for r in risks)
    assert len(set(risks)) > 1, "every finding scored the same, so ranking is flat"


def test_scoring_never_overwrites_a_human_verdict(repos: Repositories) -> None:
    project = _project(repos)
    nodes = _graph(repos, project)
    stored = _finding(repos, project, "android.secrets.service-api-key",
                      nodes["reached"].id)
    repos.findings.set_status(stored.id, FindingStatus.FALSE_POSITIVE)

    score_run(repos, project.id)
    assert repos.findings.list(project.id)[0].status is FindingStatus.FALSE_POSITIVE


def test_an_unknown_weakness_is_reported_not_scored(repos: Repositories) -> None:
    project = _project(repos)
    _graph(repos, project)
    repos.findings.upsert(project.id, Finding(
        fingerprint="z" * 64, weakness_key="android.invented.nonsense",
        title="?", severity=Severity.LOW,
        sources=[FindingSource(tool="test", rule="x")]))

    report = score_run(repos, project.id)
    assert not report.ok
    assert report.scored == 0


def test_an_app_with_no_exported_surface_raises_nothing(
        repos: Repositories) -> None:
    project = _project(repos)
    app = _entity(repos, project, EntityType.APP, PKG)
    secret = _entity(repos, project, EntityType.SECRET, "sha256:x")
    repos.edges.upsert(project.id, Edge(src_id=app.id, dst_id=secret.id,
                                        type=EdgeType.USES))
    _finding(repos, project, "android.secrets.service-api-key", secret.id)

    report = score_run(repos, project.id)
    assert report.exposed == 0
    assert repos.findings.list(project.id)[0].severity is Severity.HIGH
