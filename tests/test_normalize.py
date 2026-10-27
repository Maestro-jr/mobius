"""Cross-tool voting: what agreement is worth, and when it is worth nothing.

The load-bearing test in this file is
:func:`test_two_pattern_matchers_agreeing_is_not_corroboration`. Every other
property here is arithmetic; that one is the judgement call, and getting it
wrong would inflate confidence on exactly the findings most likely to be a
shared false positive.
"""
from __future__ import annotations

import pytest

from themob.model.enums import EntityType, FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.normalize import MAX_CONFIDENCE, Vote, combine
from themob.normalize import run as normalize_run
from themob.storage.repositories import Project, Repositories


# ---------------------------------------------------------------- the model

def test_a_lone_reporter_is_not_inflated() -> None:
    """One tool saying so is exactly as good as one tool saying so."""
    assert combine([Vote("gitleaks", 0.8)]).confidence == pytest.approx(0.8)


def test_two_pattern_matchers_agreeing_is_not_corroboration() -> None:
    """The judgement this whole module exists to encode.

    gitleaks and apkleaks both run regular expressions over the same decompiled
    text. They share their blind spots almost exactly, so both firing is close
    to one detector reporting twice. Counting that as two independent votes
    would raise confidence most on the findings most likely to be a shared
    false positive, which is precisely backwards.
    """
    verdict = combine([Vote("gitleaks", 0.8), Vote("apkleaks", 0.7)])
    assert verdict.confidence == pytest.approx(0.8), "same method, so no lift"
    assert verdict.corroborated is False
    assert verdict.methods == ["pattern"]


def test_different_methods_do_corroborate() -> None:
    """Nothing about how a regex fails makes an AST matcher fail too."""
    verdict = combine([Vote("gitleaks", 0.8), Vote("semgrep", 0.8)])
    assert verdict.confidence == pytest.approx(0.96)
    assert verdict.corroborated is True
    assert verdict.methods == ["pattern", "semantic"]


def test_agreement_has_diminishing_returns() -> None:
    """Each extra method adds less than the last, and none of them adds 1."""
    one = combine([Vote("gitleaks", 0.5)]).confidence
    two = combine([Vote("gitleaks", 0.5), Vote("semgrep", 0.5)]).confidence
    three = combine([Vote("gitleaks", 0.5), Vote("semgrep", 0.5),
                     Vote("config-audit", 0.5)]).confidence
    assert one < two < three < 1.0
    assert (two - one) > (three - two)


def test_confidence_never_reaches_certainty() -> None:
    """Static analysis of a package nobody ran does not produce certainty.

    A report claiming 100% invites the reader to skip the validation step.
    """
    verdict = combine([Vote("gitleaks", 0.99), Vote("semgrep", 0.99),
                       Vote("config-audit", 0.99), Vote("grype", 0.99)])
    assert verdict.confidence <= MAX_CONFIDENCE < 1.0


def test_the_strongest_vote_within_a_method_wins() -> None:
    """A weak second opinion from the same method must not drag it down."""
    assert combine([Vote("gitleaks", 0.9), Vote("apkleaks", 0.2)]).confidence \
        == pytest.approx(0.9)


def test_an_unknown_tool_stands_on_its_own() -> None:
    """A tool with no declared method is assumed independent, not discounted.

    Assuming independence risks over-counting; assuming a shared method would
    silently suppress a real second opinion. Over-counting is visible in the
    number, suppression is not.
    """
    verdict = combine([Vote("gitleaks", 0.8), Vote("mystery-tool", 0.8)])
    assert verdict.corroborated is True


def test_no_votes_returns_a_neutral_confidence() -> None:
    assert 0.0 < combine([]).confidence < 1.0


@pytest.mark.parametrize("value", [-1.0, 1.5, float("nan")])
def test_a_nonsense_confidence_cannot_break_the_model(value) -> None:
    """Tool output is untrusted, and that includes its numbers."""
    verdict = combine([Vote("gitleaks", value)])
    assert 0.0 <= verdict.confidence <= MAX_CONFIDENCE


def test_the_trail_is_stable() -> None:
    """The same inputs explain themselves the same way every run."""
    votes = [Vote("semgrep", 0.8), Vote("gitleaks", 0.7)]
    assert combine(votes).tools == combine(list(reversed(votes))).tools


# ------------------------------------------------------------------ the pass

def _project(repos: Repositories) -> Project:
    return repos.projects.create(Project(
        name="Sample", target_platform=Platform.ANDROID,
        source_path="input/s.apk", source_sha256="a" * 64))


def _finding(fingerprint: str, tool: str, confidence: float,
             weakness: str = "android.config.debuggable") -> Finding:
    return Finding(
        fingerprint=fingerprint, weakness_key=weakness,
        title="Application is debuggable", severity=Severity.HIGH,
        confidence=confidence,
        sources=[FindingSource(tool=tool, rule=weakness)])


def test_the_pass_scores_agreement_across_methods(repos: Repositories) -> None:
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    repos.findings.upsert(project.id, _finding("f" * 64, "semgrep", 0.8))

    report = normalize_run(repos, project.id)
    assert report.scored == 1
    assert report.corroborated == 1
    assert report.raised == 1

    stored = repos.findings.list(project.id)[0]
    assert stored.confidence == pytest.approx(0.96)


def test_the_pass_leaves_same_method_agreement_alone(repos: Repositories) -> None:
    """The storage merge already kept the higher of the two."""
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    repos.findings.upsert(project.id, _finding("f" * 64, "apkleaks", 0.7))

    report = normalize_run(repos, project.id)
    assert report.corroborated == 0
    assert repos.findings.list(project.id)[0].confidence == pytest.approx(0.8)


def test_each_reporter_keeps_its_own_confidence(repos: Repositories) -> None:
    """The merge collapses the finding's number; the source rows must not.

    Voting asks how likely it is that every reporter is wrong, which cannot be
    answered from a value that already discarded all but the surest opinion.
    """
    project = _project(repos)
    stored = repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    repos.findings.upsert(project.id, _finding("f" * 64, "semgrep", 0.55))

    votes = dict(repos.findings.source_votes(stored.id))
    assert votes["gitleaks"] == pytest.approx(0.8)
    assert votes["semgrep"] == pytest.approx(0.55)


def test_a_single_reporter_is_left_untouched(repos: Repositories) -> None:
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))

    report = normalize_run(repos, project.id)
    assert report.raised == 0 and report.lowered == 0
    assert repos.findings.list(project.id)[0].confidence == pytest.approx(0.8)


def test_the_pass_reports_a_weakness_no_pack_defines(repos: Repositories) -> None:
    """An adapter bug that would otherwise reach a report unmapped."""
    project = _project(repos)
    repos.findings.upsert(project.id, _finding(
        "f" * 64, "gitleaks", 0.8, weakness="android.invented.nonsense"))

    report = normalize_run(repos, project.id)
    assert not report.ok
    assert report.unmapped == ["f" * 64]


def test_a_finding_with_no_weakness_key_is_reported(repos: Repositories) -> None:
    project = _project(repos)
    finding = _finding("f" * 64, "gitleaks", 0.8)
    finding.weakness_key = None
    repos.findings.upsert(project.id, finding)

    report = normalize_run(repos, project.id)
    assert not report.ok


def test_a_clean_project_is_ok(repos: Repositories) -> None:
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    report = normalize_run(repos, project.id)
    assert report.ok and report.scored == 1


def test_scoring_is_idempotent(repos: Repositories) -> None:
    """Running twice must not compound the confidence."""
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    repos.findings.upsert(project.id, _finding("f" * 64, "semgrep", 0.8))

    normalize_run(repos, project.id)
    first = repos.findings.list(project.id)[0].confidence
    second_report = normalize_run(repos, project.id)
    assert repos.findings.list(project.id)[0].confidence == pytest.approx(first)
    assert second_report.raised == 0 and second_report.lowered == 0


def test_scoring_never_overwrites_a_human_verdict(repos: Repositories) -> None:
    """A tester's decision outranks arithmetic.

    Confidence and status are separate axes, so raising one must not disturb
    the other.
    """
    project = _project(repos)
    stored = repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    repos.findings.set_status(stored.id, FindingStatus.FALSE_POSITIVE)
    repos.findings.upsert(project.id, _finding("f" * 64, "semgrep", 0.8))

    normalize_run(repos, project.id)
    assert repos.findings.list(project.id)[0].status is FindingStatus.FALSE_POSITIVE


def test_the_weakness_key_survives_storage(repos: Repositories) -> None:
    """The gap this stage had to close first.

    The key only fed the fingerprint, which is a hash, so a stored finding could
    not say what class of issue it was. Everything downstream needs it.
    """
    project = _project(repos)
    repos.findings.upsert(project.id, _finding("f" * 64, "gitleaks", 0.8))
    assert repos.findings.list(project.id)[0].weakness_key == \
        "android.config.debuggable"


def test_every_shipped_adapter_sets_a_weakness_key() -> None:
    """A finding with no key is an adapter bug, so catch it here.

    Read from the source rather than by running them, so an adapter whose
    finding path no test happens to exercise is still covered.
    """
    import ast
    from pathlib import Path

    from themob import adapters

    missing = []
    for path in sorted(Path(adapters.__file__).parent.glob("*_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constructs = [n for n in ast.walk(tree)
                      if isinstance(n, ast.Call)
                      and getattr(n.func, "id", "") == "Finding"]
        for call in constructs:
            names = {kw.arg for kw in call.keywords}
            if "fingerprint" in names and "weakness_key" not in names:
                missing.append(f"{path.name}:{call.lineno}")
    assert not missing, f"Finding built without a weakness key: {missing}"
