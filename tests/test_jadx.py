"""The jadx adapter: invocation, the class index, and App-node convergence.

jadx decompiles DEX and never reads the manifest, so it cannot name the
package. The tests that matter here are the ones proving it still attaches to
the App node the unpack stage created instead of forking a second one, and that
the class index it hands the code browser is validated rather than trusted.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.adapters import build_registry
from themob.adapters.base import RawResult, Target
from themob.adapters.jadx_decompile import JadxDecompileAnalyzer, read_class_index
from themob.model.enums import EntityType, Platform, Stage
from themob.sandbox.runner import SandboxResult, SandboxRunner
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"


@pytest.fixture()
def analyzer() -> JadxDecompileAnalyzer:
    return JadxDecompileAnalyzer()


@pytest.fixture()
def target(sample_apk: Path) -> Target:
    return Target(project_id="p1", platform=Platform.ANDROID,
                  sample_path=sample_apk, sha256="a" * 64, name="sample.apk")


@pytest.fixture()
def resolved_target(target: Target) -> Target:
    """What the orchestrator hands jadx once the App node exists."""
    from dataclasses import replace
    return replace(target, app_key=PACKAGE, package=PACKAGE)


def _payload(**overrides) -> dict:
    doc = {
        "ok": True,
        "error": None,
        "tool": "jadx",
        "tool_version": "jadx 1.5.3",
        "sources_dir": "sources",
        "index_path": "classes.json",
        "stats": {"class_count": 1204, "package_count": 87,
                  "source_bytes": 18_400_000, "decompile_errors": 3,
                  "truncated": False},
        "packages": [{"name": PACKAGE, "classes": 40},
                     {"name": "okhttp3", "classes": 210}],
        "partial": True,
        "stderr_tail": "finished with errors, count: 3",
    }
    doc.update(overrides)
    return doc


def _normalize(analyzer, target, payload, raw_path="raw/jadx-decompile/jadx.json"):
    return analyzer.normalize(
        RawResult(analyzer=analyzer.name, ok=True, payload=payload,
                  raw_path=raw_path), target)


def _app(result):
    return next(e for e in result.entities if e.type is EntityType.APP)


# ------------------------------------------------------------------- registry

def test_registered_in_the_reverse_engineering_stage() -> None:
    registry = build_registry()
    jadx = registry.get("jadx-decompile")
    assert jadx is not None and jadx.stage is Stage.REVERSE_ENGINEERING
    # Unpack must come first: jadx needs the App node to already exist.
    stages = registry.stages()
    assert stages.index(Stage.UNPACK) < stages.index(Stage.REVERSE_ENGINEERING)


def test_headroom_reflects_that_decompiling_is_the_expensive_stage(analyzer) -> None:
    assert analyzer.tool == "jadx"
    assert analyzer.memory == "4g"
    assert analyzer.timeout >= 1200


# -------------------------------------------------------- App-node convergence

def test_attaches_to_the_resolved_app_node(analyzer, resolved_target) -> None:
    """The whole point of Target.app_key: one App node, not one per tool."""
    app = _app(_normalize(analyzer, resolved_target, _payload()))
    assert app.key == PACKAGE
    assert app.label == PACKAGE


def test_falls_back_to_the_shared_hash_key(analyzer, target) -> None:
    """With no unpack stage, jadx still lands on the key the other adapters
    fall back to, so they converge even when the manifest is unreadable."""
    from themob.adapters.androguard_unpack import AndroguardUnpackAnalyzer

    app = _app(_normalize(analyzer, target, _payload()))
    assert app.key == f"sha256:{target.sha256[:16]}"
    assert app.key == target.fallback_app_key
    # androguard's fallback for an unnamed package is the same string.
    other = AndroguardUnpackAnalyzer().normalize(
        RawResult(analyzer="androguard-unpack", ok=True,
                  payload={"ok": True, "app": {"package": None}}), target)
    assert other.entities[0].key == app.key


# ------------------------------------------------------------------ artifacts

def test_records_the_sources_tree_and_index(analyzer, resolved_target) -> None:
    result = _normalize(analyzer, resolved_target, _payload())
    assert "artifacts/jadx/sources" in result.artifacts
    assert "artifacts/jadx/classes.json" in result.artifacts
    assert "raw/jadx-decompile/jadx.json" in result.artifacts

    attributes = _app(result).attributes
    assert attributes["sources_dir"] == "artifacts/jadx/sources"
    assert attributes["class_index"] == "artifacts/jadx/classes.json"


def test_carries_the_decompilation_stats(analyzer, resolved_target) -> None:
    attributes = _app(_normalize(analyzer, resolved_target, _payload())).attributes
    assert attributes["class_count"] == 1204
    assert attributes["package_count"] == 87
    assert attributes["decompile_errors"] == 3
    # A half-decompiled app must not look like a small one.
    assert attributes["decompilation_partial"] is True
    assert attributes["top_packages"][1] == {"name": "okhttp3", "classes": 210}


def test_a_missing_index_is_not_fatal(analyzer, resolved_target) -> None:
    attributes = _app(_normalize(analyzer, resolved_target,
                                 _payload(index_path=None))).attributes
    assert attributes["class_index"] is None
    assert attributes["sources_dir"] == "artifacts/jadx/sources"


def test_emits_no_findings_and_no_edges(analyzer, resolved_target) -> None:
    # Decompiling is inventory. Turning code into findings is semgrep's job.
    result = _normalize(analyzer, resolved_target, _payload())
    assert result.findings == [] and result.edges == []


# ------------------------------------------------- hostile / malformed payloads

@pytest.mark.parametrize("junk", [
    {"stats": "not-a-dict"},
    {"packages": "nope"},
    {"packages": [None, 7, "x"]},
    {"sources_dir": None},
    {"index_path": 12345},
    {"tool_version": {"a": 1}},
])
def test_malformed_sections_are_dropped_not_fatal(analyzer, resolved_target,
                                                  junk) -> None:
    result = _normalize(analyzer, resolved_target, _payload(**junk))
    assert _app(result).key == PACKAGE
    assert result.findings == []


def test_failed_raw_result_normalizes_to_nothing(analyzer, target) -> None:
    raw = RawResult(analyzer=analyzer.name, ok=False, error="jadx died")
    assert analyzer.normalize(raw, target).is_empty


# ---------------------------------------------------------------- class index

def _write_index(workspace: Workspace, entries: list[dict]) -> str:
    directory = workspace.artifact_dir("jadx")
    (directory / "classes.json").write_text(
        json.dumps({"classes": entries}), encoding="utf-8")
    return "artifacts/jadx/classes.json"


def test_index_round_trips(workspace: Workspace) -> None:
    path = _write_index(workspace, [
        {"fqcn": f"{PACKAGE}.MainActivity", "package": PACKAGE,
         "name": "MainActivity", "path": "artifacts/jadx/sources/a.java",
         "size": 4096},
    ])
    index = read_class_index(workspace, path)
    assert len(index) == 1
    assert index[0]["fqcn"] == f"{PACKAGE}.MainActivity"
    assert index[0]["size"] == 4096


def test_index_entries_that_escape_the_workspace_are_dropped(
        workspace: Workspace) -> None:
    """The index came out of a container that parsed a hostile binary; a path
    pointing outside the project must never reach the file reader."""
    path = _write_index(workspace, [
        {"fqcn": "a.Good", "package": "a", "name": "Good",
         "path": "artifacts/jadx/sources/good.java", "size": 1},
        {"fqcn": "a.Escape", "package": "a", "name": "Escape",
         "path": "../../../../etc/passwd", "size": 1},
        {"fqcn": "a.Absolute", "package": "a", "name": "Absolute",
         "path": "/etc/shadow", "size": 1},
    ])
    index = read_class_index(workspace, path)
    assert [e["fqcn"] for e in index] == ["a.Good"]


def test_index_entries_with_bogus_class_names_are_dropped(
        workspace: Workspace) -> None:
    path = _write_index(workspace, [
        {"fqcn": "a.Good", "package": "a", "name": "Good",
         "path": "artifacts/jadx/sources/good.java", "size": 1},
        {"fqcn": "not a class name", "package": "a", "name": "x",
         "path": "artifacts/jadx/sources/x.java", "size": 1},
        {"fqcn": "", "package": "", "name": "", "path": "", "size": 0},
        {"package": "a", "name": "NoFqcn", "path": "artifacts/jadx/x.java"},
        "not-a-dict",
    ])
    assert [e["fqcn"] for e in read_class_index(workspace, path)] == ["a.Good"]


def test_missing_or_malformed_index_reads_as_empty(workspace: Workspace) -> None:
    assert read_class_index(workspace, "") == []
    assert read_class_index(workspace, "artifacts/jadx/nope.json") == []
    assert read_class_index(workspace, "../../etc/passwd") == []

    directory = workspace.artifact_dir("jadx")
    (directory / "classes.json").write_text("{{{ not json", encoding="utf-8")
    assert read_class_index(workspace, "artifacts/jadx/classes.json") == []
    (directory / "classes.json").write_text("[1,2,3]", encoding="utf-8")
    assert read_class_index(workspace, "artifacts/jadx/classes.json") == []


def test_index_is_capped(workspace: Workspace) -> None:
    path = _write_index(workspace, [
        {"fqcn": f"p.C{i}", "package": "p", "name": f"C{i}",
         "path": f"artifacts/jadx/sources/C{i}.java", "size": 1}
        for i in range(50_000)
    ])
    assert len(read_class_index(workspace, path)) <= 40_000


# ------------------------------------------------------------------ sandboxing

class _StubSandbox(SandboxRunner):
    def __init__(self, result: SandboxResult) -> None:
        super().__init__()
        self._result = result
        self._available = True
        self.calls: list[tuple] = []

    def is_available(self) -> bool:
        return True

    def has_image(self, image: str) -> bool:
        return True

    def run(self, image, args, **kw):                  # type: ignore[override]
        self.calls.append((image, args, kw))
        return self._result


def test_sources_are_written_to_artifacts(analyzer, resolved_target,
                                          workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(
        ok=True, exit_code=0, stdout=json.dumps(_payload()).encode()))

    raw = analyzer.run(resolved_target, workspace, sandbox)

    assert raw.ok
    _image, args, kw = sandbox.calls[0]
    assert args == ["/input/sample.apk"]
    assert kw["output_dir"] == workspace.artifacts_root / "jadx"
    assert kw["limits"].memory == "4g"
    # Decompiling is CPU-bound; the worker asks for four threads.
    assert kw["limits"].cpus >= 4.0
    assert raw.raw_path == "raw/jadx-decompile/jadx.json"


def test_worker_failure_is_surfaced(analyzer, resolved_target,
                                    workspace: Workspace) -> None:
    stdout = json.dumps({"ok": False, "error": "no classes.dex found"}).encode()
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=1, stdout=stdout))
    raw = analyzer.run(resolved_target, workspace, sandbox)
    assert not raw.ok and "classes.dex" in raw.error


def test_sandbox_failure_wins_over_worker_output(analyzer, resolved_target,
                                                 workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(
        ok=False, exit_code=137, stdout=json.dumps(_payload()).encode(),
        timed_out=True, error="timed out after 1800s"))
    raw = analyzer.run(resolved_target, workspace, sandbox)
    assert not raw.ok and "timed out" in raw.error


def test_non_json_output_is_reported_not_raised(analyzer, resolved_target,
                                                workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(
        ok=True, exit_code=0, stdout=b"Exception in thread main"))
    raw = analyzer.run(resolved_target, workspace, sandbox)
    assert not raw.ok and "not valid JSON" in raw.error
    assert raw.raw_path is not None


def test_worker_diagnosis_beats_a_bare_exit_code(analyzer, resolved_target,
                                                 workspace: Workspace) -> None:
    """Regression: the sandbox's generic message used to mask the worker's.

    "exited with code 1" tells an operator nothing; "Failed to read zip entry:
    classes.dex" tells them what to do next.
    """
    stdout = json.dumps({"ok": False,
                         "error": "Failed to read zip entry: classes.dex"}).encode()
    sandbox = _StubSandbox(SandboxResult(
        ok=False, exit_code=1, stdout=stdout, error="exited with code 1"))

    raw = analyzer.run(resolved_target, workspace, sandbox)

    assert not raw.ok
    assert raw.error == "Failed to read zip entry: classes.dex"


def test_a_timeout_still_outranks_the_worker(analyzer, resolved_target,
                                             workspace: Workspace) -> None:
    """A sandbox-level failure is the sandbox's to report: the worker's own
    output is whatever it managed to emit before being killed."""
    sandbox = _StubSandbox(SandboxResult(
        ok=False, exit_code=137, stdout=json.dumps({"ok": False,
                                                    "error": "partial"}).encode(),
        timed_out=True, error="timed out after 1800s"))
    raw = analyzer.run(resolved_target, workspace, sandbox)
    assert raw.error == "timed out after 1800s"
