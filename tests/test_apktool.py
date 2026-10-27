"""The apktool adapter: invocation, path handling, and normalization.

apktool's contribution is mostly the decoded tree that four later analyzers
read, so the tests that matter are the ones about *paths* and *convergence*:
the artifacts must be findable, and the App node it enriches must be the same
node androguard created, not a second one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.adapters import build_registry
from themob.adapters.apktool_decode import ApktoolDecodeAnalyzer
from themob.adapters.base import RawResult, Target
from themob.model.enums import EntityType, Platform, Stage
from themob.sandbox.runner import SandboxResult, SandboxRunner
from themob.storage.workspace import Workspace


@pytest.fixture()
def analyzer() -> ApktoolDecodeAnalyzer:
    return ApktoolDecodeAnalyzer()


@pytest.fixture()
def target(sample_apk: Path) -> Target:
    return Target(project_id="p1", platform=Platform.ANDROID,
                  sample_path=sample_apk, sha256="a" * 64, name="sample.apk")


def _payload(**overrides) -> dict:
    doc = {
        "ok": True,
        "error": None,
        "tool": "apktool",
        "tool_version": "Apktool v2.11.1",
        "decoded_dir": "decoded",
        "package": "com.example.shop",
        "manifest_path": "decoded/AndroidManifest.xml",
        "manifest_parsed": True,
        "meta": {
            "apktool_version": "2.11.1",
            "apk_file_name": "shop.apk",
            "is_framework_apk": False,
            "shared_library": False,
            "sparse_resources": True,
            "min_sdk_version": "24",
            "target_sdk_version": "34",
            "version_code": "3021",
            "version_name": "3.2.1",
            "do_not_compress": ["resources.arsc", "png"],
        },
        "network_security_config": {
            "path": "decoded/res/xml/network_security_config.xml",
            "configs": [
                {"scope": "base", "domains": [], "cleartext_permitted": False,
                 "pins": [], "trust_anchors": ["system"]},
                {"scope": "domain", "domains": ["legacy.example.com"],
                 "cleartext_permitted": True, "pins": [], "trust_anchors": []},
                {"scope": "domain", "domains": ["api.example.com"],
                 "cleartext_permitted": False, "pins": ["abc=", "def="],
                 "trust_anchors": ["system"]},
            ],
        },
        "inventory": {"file_count": 1841, "decoded_bytes": 24_000_000,
                      "extensions": {"xml": 900, "png": 700}},
        "resources": {"directories": {"values": 300, "drawable": 500},
                      "locales": ["en", "fr", "de"], "locale_count": 3},
        "assets": ["assets/config.json", "assets/fonts/x.ttf"],
        "stderr_tail": "",
    }
    doc.update(overrides)
    return doc


def _normalize(analyzer, target, payload, raw_path="raw/apktool-decode/apktool.json"):
    return analyzer.normalize(
        RawResult(analyzer=analyzer.name, ok=True, payload=payload,
                  raw_path=raw_path), target)


def _app(result):
    return next(e for e in result.entities if e.type is EntityType.APP)


# ------------------------------------------------------------------- registry

def test_registered_in_the_unpack_stage() -> None:
    registry = build_registry()
    apktool = registry.get("apktool-decode")
    assert apktool is not None and apktool.stage is Stage.UNPACK
    # androguard runs first: it is the cheap one, and it establishes the App node.
    names = [a.name for a in registry.for_stage(Stage.UNPACK)]
    assert names[0] == "androguard-unpack"
    # ios-unpack is the iOS counterpart; it only applies to .ipa targets.
    assert set(names) == {"androguard-unpack", "apktool-decode", "ios-unpack"}


def test_tool_identity_and_headroom(analyzer) -> None:
    assert analyzer.tool == "apktool"
    # A JVM rewriting a resource table needs more than the 2g default.
    assert analyzer.memory == "3g" and analyzer.timeout >= 600


def test_applies_only_to_android_packages(analyzer, target, tmp_path: Path) -> None:
    assert analyzer.applies_to(target)
    ipa = Target(project_id="p1", platform=Platform.IOS,
                 sample_path=tmp_path / "a.ipa", sha256="a" * 64)
    assert not analyzer.applies_to(ipa)


# ------------------------------------------------------------------ artifacts

def test_decoded_tree_is_recorded_as_an_artifact(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    assert "artifacts/apktool/decoded" in result.artifacts
    assert "raw/apktool-decode/apktool.json" in result.artifacts


def test_manifest_path_is_workspace_relative(analyzer, target) -> None:
    """The worker reports paths relative to /output; the engine stores them
    relative to the project workspace, or later stages cannot open them."""
    app = _app(_normalize(analyzer, target, _payload()))
    assert app.attributes["decoded_manifest"] == \
        "artifacts/apktool/decoded/AndroidManifest.xml"
    assert app.attributes["manifest_decoded"] is True


def test_recorded_paths_resolve_inside_the_workspace(analyzer, target,
                                                     workspace: Workspace) -> None:
    app = _app(_normalize(analyzer, target, _payload()))
    for key in ("decoded_dir", "decoded_manifest"):
        # resolve() rejects traversal, so this also proves the path is contained.
        assert workspace.resolve(app.attributes[key]).is_relative_to(workspace.path)


# --------------------------------------------------------------- the App node

def test_enriches_the_app_on_the_package_key(analyzer, target) -> None:
    """Same key as androguard's App entity, so the upsert merges them."""
    app = _app(_normalize(analyzer, target, _payload()))
    assert app.key == "com.example.shop"
    assert app.type is EntityType.APP


def test_app_carries_the_apktool_metadata(analyzer, target) -> None:
    app = _app(_normalize(analyzer, target, _payload()))
    attributes = app.attributes
    assert attributes["sparse_resources"] is True
    assert attributes["is_framework_apk"] is False
    assert attributes["decoded_file_count"] == 1841
    assert attributes["locales"] == ["en", "fr", "de"]
    assert attributes["asset_count"] == 2
    assert attributes["resource_directories"]["drawable"] == 500


def test_no_findings_are_emitted(analyzer, target) -> None:
    # Decoding is inventory. "Cleartext is permitted here" is the auditor's call.
    assert _normalize(analyzer, target, _payload()).findings == []


def test_no_edges_are_invented(analyzer, target) -> None:
    assert _normalize(analyzer, target, _payload()).edges == []


# ------------------------------------------------------- network security config

def test_network_security_config_is_recorded_verbatim(analyzer, target) -> None:
    nsc = _app(_normalize(analyzer, target, _payload())).attributes[
        "network_security_config"]
    assert nsc["path"] == "decoded/res/xml/network_security_config.xml"
    scopes = {c["scope"] for c in nsc["configs"]}
    assert scopes == {"base", "domain"}

    cleartext = [c for c in nsc["configs"] if c["cleartext_permitted"]]
    assert len(cleartext) == 1
    assert cleartext[0]["domains"] == ["legacy.example.com"]

    pinned = [c for c in nsc["configs"] if c["pin_count"]]
    assert pinned[0]["pin_count"] == 2, "pin count, not the pins themselves"


def test_unresolved_config_reference_is_preserved(analyzer, target) -> None:
    """A manifest can name a config that is not in the decoded tree; say so
    rather than silently reporting no policy at all."""
    nsc = _app(_normalize(analyzer, target, _payload(
        network_security_config={"reference": "@xml/nsc", "unresolved": True}
    ))).attributes["network_security_config"]
    assert nsc == {"reference": "@xml/nsc", "unresolved": True}


def test_absent_config_is_none_not_empty(analyzer, target) -> None:
    app = _app(_normalize(analyzer, target,
                          _payload(network_security_config=None)))
    assert app.attributes["network_security_config"] is None


# ------------------------------------------------- hostile / malformed payloads

def test_missing_package_falls_back_to_the_sample_hash(analyzer, target) -> None:
    app = _app(_normalize(analyzer, target, _payload(package=None)))
    assert app.key == f"sha256:{target.sha256[:16]}"


def test_bogus_package_is_rejected(analyzer, target) -> None:
    app = _app(_normalize(analyzer, target, _payload(package="../../etc/passwd")))
    assert app.key.startswith("sha256:")
    assert app.attributes["package"] is None


@pytest.mark.parametrize("junk", [
    {"meta": "not-a-dict"},
    {"inventory": []},
    {"resources": None},
    {"assets": "nope"},
    {"assets": [None, 3, {"x": 1}]},
    {"network_security_config": "nope"},
    {"network_security_config": {"configs": ["junk", 7, None]}},
    {"manifest_path": None},
    {"decoded_dir": None},
])
def test_malformed_sections_are_dropped_not_fatal(analyzer, target, junk) -> None:
    result = _normalize(analyzer, target, _payload(**junk))
    app = _app(result)
    assert app.key and "\n" not in app.key
    assert result.findings == []


def test_oversized_lists_are_capped(analyzer, target) -> None:
    doc = _payload()
    doc["assets"] = [f"assets/f{i}" for i in range(20_000)]
    doc["resources"] = {"locales": [f"l{i}" for i in range(5_000)],
                        "locale_count": 5_000, "directories": {}}
    app = _app(_normalize(analyzer, target, doc))
    assert len(app.attributes["assets"]) <= 4000
    assert len(app.attributes["locales"]) <= 400


def test_failed_raw_result_normalizes_to_nothing(analyzer, target) -> None:
    raw = RawResult(analyzer=analyzer.name, ok=False, error="apktool died")
    assert analyzer.normalize(raw, target).is_empty


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


def test_decoded_tree_is_written_to_artifacts_not_raw(analyzer, target,
                                                      workspace: Workspace) -> None:
    """The writable mount must be artifacts/apktool/, pointing it at raw/
    would bury a decompiled tree in the provenance directory."""
    sandbox = _StubSandbox(SandboxResult(
        ok=True, exit_code=0, stdout=json.dumps(_payload()).encode()))

    raw = analyzer.run(target, workspace, sandbox)

    assert raw.ok
    _image, args, kw = sandbox.calls[0]
    assert args == ["/input/sample.apk"]
    assert kw["output_dir"] == workspace.artifacts_root / "apktool"
    assert kw["limits"].memory == "3g"
    # The JSON summary still lands under raw/ for provenance.
    assert raw.raw_path == "raw/apktool-decode/apktool.json"


def test_worker_failure_is_surfaced(analyzer, target, workspace: Workspace) -> None:
    stdout = json.dumps({"ok": False, "error": "brut.androlib.AndrolibException"}).encode()
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=1, stdout=stdout))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and "AndrolibException" in raw.error


def test_sandbox_failure_wins_over_worker_output(analyzer, target,
                                                 workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(
        ok=False, exit_code=137, stdout=json.dumps(_payload()).encode(),
        timed_out=True, error="timed out after 900s"))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and "timed out" in raw.error


def test_non_json_output_is_reported_not_raised(analyzer, target,
                                                workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=0, stdout=b"Exception!"))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and "not valid JSON" in raw.error
    assert raw.raw_path is not None
