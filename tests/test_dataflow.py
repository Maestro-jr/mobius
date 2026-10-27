"""Dataflow: the tests are mostly about what it refuses to claim.

The pass exists to separate two findings a scanner reports identically, a
hardcoded string that goes nowhere from one that is sent as an auth header. It
does that by reading decompiled text, which is a heuristic, so the tests pin
both what it establishes and where it stops: an identifier it cannot resolve,
a file outside the workspace, a value it can see but not follow.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.dataflow import (REACHES_SINK, UNDETERMINED, UNUSED, USED,
                             confidence_for, trace, traceable)
from themob.dataflow import pass_ as dataflow_pass
from themob.dataflow import sinks
from themob.model.enums import Severity
from themob.model.findings import Finding, Location
from themob.normalize.voting import Vote, combine


SOURCES = "artifacts/jadx/sources/com/example"


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A small decompiled tree covering each outcome."""
    root = tmp_path / SOURCES
    root.mkdir(parents=True)

    (root / "Live.java").write_text(
        "package com.example;\n"
        "public class Live {\n"
        '    private static final String API_KEY = "AKIAZZ7NLQK4PRODXYZQ";\n'
        "    public void sync() {\n"
        "        HttpURLConnection c = open();\n"
        '        c.setRequestProperty("Authorization", API_KEY);\n'
        "    }\n"
        "}\n", encoding="utf-8")

    (root / "Dead.java").write_text(
        "package com.example;\n"
        "public class Dead {\n"
        '    private static final String OLD_TOKEN = "AKIAZZ7NLQK4STALEXYZ";\n'
        "}\n", encoding="utf-8")

    (root / "Local.java").write_text(
        "package com.example;\n"
        "public class Local {\n"
        '    private static final String SOME_VALUE = "AKIAZZ7NLQK4LOCALXYZ";\n'
        '    public String describe() { return "v=" + SOME_VALUE; }\n'
        "}\n", encoding="utf-8")

    (root / "Logged.java").write_text(
        "package com.example;\n"
        "public class Logged {\n"
        '    private static final String TRACE_TOKEN = "AKIAZZ7NLQK4LOGGEDXY";\n'
        '    public void dump() { Log.d("tag", TRACE_TOKEN); }\n'
        "}\n", encoding="utf-8")

    # The value is copied through two locals before it is sent. The single-hop
    # tracer saw only "SECRET is used" and missed the sink.
    (root / "Chained.java").write_text(
        "package com.example;\n"
        "public class Chained {\n"
        '    private static final String SECRET = "AKIAZZ7NLQK4CHAINXYZ";\n'
        "    public void sync() {\n"
        "        String token = SECRET;\n"
        '        String header = "Bearer " + token;\n'
        "        HttpURLConnection c = open();\n"
        '        c.setRequestProperty("Authorization", header);\n'
        "    }\n"
        "}\n", encoding="utf-8")

    return tmp_path


def _finding(file: str, line: int | None = 3,
             key: str = "android.secrets.cloud-credential") -> Finding:
    return Finding(fingerprint="a" * 64, weakness_key=key, title="Secret",
                   severity=Severity.HIGH, confidence=0.5,
                   location=Location(file=f"{SOURCES}/{file}", line=line))


# ------------------------------------------------------------------ verdicts

def test_a_value_sent_as_a_header_reaches_a_sink(tree: Path) -> None:
    flow = trace(_finding("Live.java"), tree)
    assert flow.verdict == REACHES_SINK
    assert flow.identifier == "API_KEY"
    assert flow.best_category == "network"


def test_a_value_nothing_references_is_unused(tree: Path) -> None:
    flow = trace(_finding("Dead.java"), tree)
    assert flow.verdict == UNUSED
    assert flow.identifier == "OLD_TOKEN"


def test_a_value_used_away_from_any_sink_is_only_used(tree: Path) -> None:
    """Referenced is not the same as consequential."""
    flow = trace(_finding("Local.java"), tree)
    assert flow.verdict == USED
    assert not flow.sink_uses


def test_a_logged_value_reaches_a_weaker_sink(tree: Path) -> None:
    flow = trace(_finding("Logged.java"), tree)
    assert flow.verdict == REACHES_SINK
    assert flow.best_category == "log"
    assert sinks.weight("log") < sinks.weight("network")


# --------------------------------------------------------------- what it wont

def test_a_finding_with_no_file_is_undetermined() -> None:
    finding = Finding(fingerprint="a" * 64, title="x", severity=Severity.LOW)
    assert trace(finding, Path(".")).verdict == UNDETERMINED


def test_a_path_outside_the_workspace_is_refused(tree: Path) -> None:
    """The path came from a tool that parsed a hostile package."""
    finding = _finding("Live.java")
    finding.location.file = "../../../../etc/passwd"
    flow = trace(finding, tree)
    assert flow.verdict == UNDETERMINED
    assert "workspace" in flow.reason


def test_a_line_that_assigns_nothing_yields_no_identifier(tree: Path) -> None:
    flow = trace(_finding("Live.java", line=2), tree)
    assert flow.verdict == UNDETERMINED
    assert "identifier" in flow.reason


def test_a_line_past_the_end_of_the_file_is_undetermined(tree: Path) -> None:
    assert trace(_finding("Live.java", line=9999), tree).verdict == UNDETERMINED


def test_a_noisy_identifier_is_not_followed(tmp_path: Path) -> None:
    """jadx names locals aggressively; "value" appearing somewhere means nothing."""
    root = tmp_path / SOURCES
    root.mkdir(parents=True)
    (root / "Noisy.java").write_text(
        "package com.example;\n"
        "public class Noisy {\n"
        '    String value = "AKIAZZ7NLQK4NOISYXYZ";\n'
        "    void f() { g(value); }\n"
        "}\n", encoding="utf-8")

    assert trace(_finding("Noisy.java"), tmp_path).verdict == UNDETERMINED


def test_a_missing_file_is_undetermined_not_unused(tree: Path) -> None:
    """"I could not look" must never be reported as "I looked and found none"."""
    flow = trace(_finding("Absent.java"), tree)
    assert flow.verdict == UNDETERMINED
    assert flow.verdict != UNUSED


# --------------------------------------------------------------- multi-hop

def test_a_value_laundered_through_locals_still_reaches_the_sink(tree: Path) -> None:
    """The false negative the single-hop tracer left on the table.

    SECRET is copied into token, token into header, and header is sent. Only a
    multi-hop trace connects the source literal to the sink.
    """
    flow = trace(_finding("Chained.java"), tree)
    assert flow.verdict == REACHES_SINK
    assert flow.hops, "the assignment chain should be recorded"


def test_the_hops_appear_in_the_recorded_flow(tree: Path) -> None:
    steps = trace(_finding("Chained.java"), tree).steps()
    kinds = [s.kind for s in steps]
    assert kinds[0] == "source"
    assert "propagation" in kinds
    assert kinds[-1] == "sink"


def test_an_unrelated_assignment_does_not_taint(tmp_path: Path) -> None:
    """A local that never touches the secret must not carry the taint to a sink."""
    root = tmp_path / SOURCES
    root.mkdir(parents=True)
    (root / "Unrelated.java").write_text(
        "package com.example;\n"
        "public class Unrelated {\n"
        '    private static final String SECRET = "AKIAZZ7NLQK4UNRELXYZ";\n'
        "    public void sync() {\n"
        '        String other = "not the secret";\n'
        '        HttpURLConnection c = open();\n'
        '        c.setRequestProperty("X", other);\n'
        "    }\n"
        "}\n", encoding="utf-8")
    flow = trace(_finding("Unrelated.java"), tmp_path)
    assert flow.verdict != REACHES_SINK


# ------------------------------------------------------------------- the flow

def test_the_flow_is_recorded_as_a_source_then_a_sink(tree: Path) -> None:
    steps = trace(_finding("Live.java"), tree).steps()
    assert [s.kind for s in steps] == ["source", "sink"]
    assert steps[0].location.line == 3
    assert steps[1].location.line == 6


def test_the_note_says_appears_not_flows(tree: Path) -> None:
    """It reads text. The report must not imply it proved a path."""
    steps = trace(_finding("Live.java"), tree).steps()
    sink_note = steps[1].note or ""
    assert "appears" in sink_note
    assert "flows" not in sink_note


# ------------------------------------------------------------------ confidence

def test_reaching_a_sink_is_a_vote_not_a_bonus(tree: Path) -> None:
    """It enters the same noisy-or model every other reporter uses."""
    votes = [Vote("gitleaks", 0.5)]
    voted = combine(votes).confidence
    flow = trace(_finding("Live.java"), tree)

    adjusted = confidence_for(flow, voted, votes)
    expected = combine(votes + [Vote("dataflow", sinks.weight("network"))]).confidence
    assert adjusted == expected
    assert adjusted > voted


def test_a_stronger_sink_category_counts_for_more(tree: Path) -> None:
    votes = [Vote("gitleaks", 0.5)]
    voted = combine(votes).confidence
    network = confidence_for(trace(_finding("Live.java"), tree), voted, votes)
    logged = confidence_for(trace(_finding("Logged.java"), tree), voted, votes)
    assert network > logged > voted


def test_an_unused_value_is_discounted_but_never_erased(tree: Path) -> None:
    """A secret nothing references is still compiled into the package."""
    votes = [Vote("gitleaks", 0.9)]
    voted = combine(votes).confidence
    adjusted = confidence_for(trace(_finding("Dead.java"), tree), voted, votes)

    assert adjusted < voted
    assert adjusted >= dataflow_pass.UNUSED_FLOOR


def test_the_discount_has_a_floor(tree: Path) -> None:
    votes = [Vote("gitleaks", 0.1)]
    adjusted = confidence_for(trace(_finding("Dead.java"), tree), 0.1, votes)
    assert adjusted == dataflow_pass.UNUSED_FLOOR


def test_used_and_undetermined_leave_confidence_alone(tree: Path) -> None:
    votes = [Vote("gitleaks", 0.62)]
    for file in ("Local.java", "Absent.java"):
        flow = trace(_finding(file), tree)
        assert confidence_for(flow, 0.62, votes) == 0.62


# -------------------------------------------------------------- what it traces

def test_only_findings_with_a_value_to_follow_are_traced() -> None:
    """A debuggable flag has no value to follow, so tracing it means nothing."""
    assert traceable(_finding("x.java", key="android.secrets.cloud-credential"))
    assert traceable(_finding("x.java", key="android.crypto.weak-cipher-mode"))
    assert not traceable(_finding("x.java", key="android.config.debuggable"))
    assert not traceable(_finding("x.java", key="android.ipc.provider-exported-unprotected"))


# ------------------------------------------------------------------- the pass

def test_the_pass_writes_the_flow_and_moves_confidence(repos, tree: Path,
                                                       tmp_path: Path) -> None:
    from themob.model.enums import Platform
    from themob.model.findings import FindingSource
    from themob.storage.repositories import Project
    from themob.storage.workspace import Workspace

    project = repos.projects.create(Project(
        name="Flow", target_platform=Platform.ANDROID,
        source_path="input/x.apk", source_sha256="a" * 64))

    stored = repos.findings.upsert(project.id, Finding(
        fingerprint="b" * 64, weakness_key="android.secrets.cloud-credential",
        title="Cloud credential", severity=Severity.HIGH, confidence=0.5,
        location=Location(file=f"{SOURCES}/Live.java", line=3),
        sources=[FindingSource(tool="gitleaks", rule="aws-access-token")]))

    workspace = Workspace(tmp_path.parent, tree.name)
    workspace.path = tree
    report = dataflow_pass.run(repos, project.id, workspace)

    assert report.examined == 1
    assert report.reached_sink == 1
    after = repos.findings.get(stored.id)
    assert after.confidence > 0.5
    assert [s.kind for s in after.data_flow] == ["source", "sink"]


def test_the_pass_is_idempotent(repos, tree: Path, tmp_path: Path) -> None:
    """Re-running must converge, not drift upward one vote at a time."""
    from themob.model.enums import Platform
    from themob.model.findings import FindingSource
    from themob.storage.repositories import Project
    from themob.storage.workspace import Workspace

    project = repos.projects.create(Project(
        name="Flow", target_platform=Platform.ANDROID,
        source_path="input/x.apk", source_sha256="a" * 64))
    stored = repos.findings.upsert(project.id, Finding(
        fingerprint="c" * 64, weakness_key="android.secrets.cloud-credential",
        title="Cloud credential", severity=Severity.HIGH, confidence=0.5,
        location=Location(file=f"{SOURCES}/Live.java", line=3),
        sources=[FindingSource(tool="gitleaks", rule="aws-access-token")]))

    workspace = Workspace(tmp_path.parent, tree.name)
    workspace.path = tree

    dataflow_pass.run(repos, project.id, workspace)
    first = repos.findings.get(stored.id)
    dataflow_pass.run(repos, project.id, workspace)
    second = repos.findings.get(stored.id)

    assert first.confidence == second.confidence
    assert len(first.data_flow) == len(second.data_flow)


def test_a_project_with_no_sources_reports_undetermined(repos,
                                                        tmp_path: Path) -> None:
    """No reverse-engineering stage means nothing to read, and it says so."""
    from themob.model.enums import Platform
    from themob.model.findings import FindingSource
    from themob.storage.repositories import Project
    from themob.storage.workspace import Workspace

    project = repos.projects.create(Project(
        name="Bare", target_platform=Platform.ANDROID,
        source_path="input/x.apk", source_sha256="a" * 64))
    repos.findings.upsert(project.id, Finding(
        fingerprint="d" * 64, weakness_key="android.secrets.private-key",
        title="Key", severity=Severity.HIGH, confidence=0.7,
        location=Location(file=f"{SOURCES}/Nothing.java", line=3),
        sources=[FindingSource(tool="gitleaks", rule="private-key")]))

    workspace = Workspace(tmp_path.parent, "bare")
    workspace.path = tmp_path / "bare"
    report = dataflow_pass.run(repos, project.id, workspace)

    assert report.examined == 1
    assert report.undetermined == 1
    assert report.raised == 0 and report.lowered == 0
