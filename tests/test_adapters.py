"""The androguard adapter: sandbox invocation and normalization.

``normalize`` runs in the engine process on JSON produced by a container that
just parsed a hostile file, so most of these tests feed it malformed input and
assert it degrades rather than raising.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.adapters import build_registry
from themob.adapters.androguard_unpack import AndroguardUnpackAnalyzer
from themob.adapters.base import AnalyzerResult, RawResult, Target
from themob.model.enums import EdgeType, EntityType, Platform, Stage
from themob.sandbox.runner import SandboxResult, SandboxRunner
from themob.storage.workspace import Workspace


@pytest.fixture()
def analyzer() -> AndroguardUnpackAnalyzer:
    return AndroguardUnpackAnalyzer()


@pytest.fixture()
def target(sample_apk: Path) -> Target:
    return Target(project_id="p1", platform=Platform.ANDROID,
                  sample_path=sample_apk, sha256="a" * 64, name="sample.apk")


def _payload(**overrides) -> dict:
    doc = {
        "ok": True,
        "error": None,
        "tool": "androguard",
        "tool_version": "4.1.4",
        "app": {
            "package": "com.example.shop",
            "version_name": "3.2.1",
            "version_code": "3021",
            "min_sdk": 24,
            "target_sdk": 34,
            "app_name": "Example Shop",
            "main_activity": "com.example.shop.MainActivity",
            "debuggable": True,
            "allow_backup": True,
            "uses_cleartext_traffic": False,
            "signing": {"v1": True, "v2": True, "v3": False},
        },
        "permissions": [
            {"name": "android.permission.INTERNET", "max_sdk": None},
            {"name": "android.permission.READ_CONTACTS", "max_sdk": 28},
        ],
        "declared_permissions": [
            {"name": "com.example.shop.permission.SYNC",
             "protection_level": "signature"},
        ],
        "components": [
            {"kind": "activity", "tag": "activity", "name": ".MainActivity",
             "exported": True, "exported_declared": True,
             "intent_filters": [{"actions": ["android.intent.action.MAIN"],
                                 "categories": ["android.intent.category.LAUNCHER"],
                                 "auto_verify": None}]},
            {"kind": "provider", "tag": "provider",
             "name": "com.example.shop.data.ShopProvider",
             "exported": True, "exported_declared": None,
             "authorities": "com.example.shop.provider",
             "read_permission": "com.example.shop.permission.SYNC"},
            {"kind": "service", "tag": "service", "name": "com.example.shop.SyncService",
             "exported": False, "exported_declared": False},
        ],
        "deep_links": [
            {"scheme": "https", "host": "shop.example.com", "path": "/order",
             "auto_verify": True, "browsable": True,
             "component": "com.example.shop.MainActivity"},
            {"scheme": "exampleshop", "host": "open", "path": "/pay",
             "auto_verify": False, "browsable": True, "component": ".MainActivity"},
        ],
        "certificates": [{"sha256": "c" * 64, "subject": "CN=Example",
                          "self_signed": True}],
        "native_libs": [
            {"path": "lib/arm64-v8a/libshop.so", "name": "libshop.so",
             "arch": "arm64-v8a", "size": 204800},
        ],
        "dex": [{"path": "classes.dex", "size": 1024, "sha256": "d" * 64}],
        "inventory": {"file_count": 412, "uncompressed_bytes": 9_000_000},
    }
    doc.update(overrides)
    return doc


def _normalize(analyzer, target, payload) -> "AnalyzerResult":
    return analyzer.normalize(
        RawResult(analyzer=analyzer.name, ok=True, payload=payload), target)


def _by_type(result, etype: EntityType):
    return [e for e in result.entities if e.type is etype]


# ------------------------------------------------------------------- registry

def test_registry_exposes_the_unpack_stage() -> None:
    registry = build_registry()
    assert Stage.UNPACK in registry.stages()
    assert registry.get("androguard-unpack") is not None
    # Stages come back in pipeline order, whichever ones are populated.
    assert registry.stages() == [s for s in Stage if s in set(registry.stages())]


def test_registry_rejects_duplicate_registration() -> None:
    registry = build_registry()
    with pytest.raises(ValueError):
        registry.register(AndroguardUnpackAnalyzer())


def test_applies_only_to_android_packages(analyzer, target, tmp_path: Path) -> None:
    assert analyzer.applies_to(target)
    ipa = Target(project_id="p1", platform=Platform.IOS,
                 sample_path=tmp_path / "a.ipa", sha256="a" * 64)
    assert not analyzer.applies_to(ipa)
    zipped = Target(project_id="p1", platform=Platform.ANDROID,
                    sample_path=tmp_path / "a.zip", sha256="a" * 64)
    assert not analyzer.applies_to(zipped)


def test_tool_name_is_the_tool_not_the_adapter(analyzer) -> None:
    # Cross-tool voting is only meaningful if `sources` names the real tool.
    assert analyzer.tool == "androguard"


# ------------------------------------------------------------------ entities

def test_app_entity_carries_the_manifest_facts(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    app = _by_type(result, EntityType.APP)[0]
    assert app.key == "com.example.shop"
    assert app.label == "Example Shop"
    assert app.attributes["version_name"] == "3.2.1"
    assert app.attributes["target_sdk"] == 34
    assert app.attributes["debuggable"] is True
    assert app.attributes["sample_sha256"] == target.sha256
    assert app.attributes["certificates"][0]["self_signed"] is True


def test_relative_component_names_are_qualified(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    keys = {e.key for e in _by_type(result, EntityType.COMPONENT)}
    assert "com.example.shop.MainActivity" in keys, "'.MainActivity' must resolve"
    assert ".MainActivity" not in keys


def test_exported_components_get_an_exports_edge(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    exported = {e.dst.key for e in result.edges if e.type is EdgeType.EXPORTS}
    assert exported == {"com.example.shop.MainActivity",
                        "com.example.shop.data.ShopProvider"}
    # Every component is declared, exported or not.
    declared = {e.dst.key for e in result.edges
                if e.type is EdgeType.DECLARES
                and e.dst.type is EntityType.COMPONENT}
    assert "com.example.shop.SyncService" in declared


def test_absent_exported_attribute_is_preserved(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    provider = next(e for e in _by_type(result, EntityType.COMPONENT)
                    if e.attributes["kind"] == "provider")
    # Exported by inference, but the manifest never said so, the distinction the
    # config auditor needs to flag a missing android:exported on SDK 31+.
    assert provider.attributes["exported"] is True
    assert provider.attributes["exported_declared"] is None


def test_permissions_split_requested_from_declared(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    perms = {e.key: e.attributes for e in _by_type(result, EntityType.PERMISSION)}
    assert perms["android.permission.INTERNET"]["requested"] is True
    assert perms["android.permission.INTERNET"]["custom"] is False
    custom = perms["com.example.shop.permission.SYNC"]
    assert custom["declared_by_app"] is True and custom["custom"] is True
    assert custom["protection_level"] == "signature"


def test_component_permission_becomes_a_graph_edge(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    scoped = [e for e in result.edges
              if e.type is EdgeType.REQUESTS_PERMISSION
              and e.attributes.get("scope") == "component"]
    assert len(scoped) == 1
    assert scoped[0].src.key == "com.example.shop.data.ShopProvider"
    assert scoped[0].dst.key == "com.example.shop.permission.SYNC"


def test_deep_links_are_canonicalised_and_owned(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    links = {e.key: e.attributes for e in _by_type(result, EntityType.DEEP_LINK)}
    assert "https://shop.example.com/order" in links
    assert "exampleshop://open/pay" in links
    assert links["https://shop.example.com/order"]["web_scheme"] is True
    assert links["exampleshop://open/pay"]["web_scheme"] is False
    owners = {e.src.key for e in result.edges if e.dst.type is EntityType.DEEP_LINK}
    assert owners == {"com.example.shop.MainActivity"}


def test_native_libs_are_embedded_in_the_app(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload())
    lib = _by_type(result, EntityType.NATIVE_LIB)[0]
    assert lib.key == "lib/arm64-v8a/libshop.so"
    assert lib.attributes["arch"] == "arm64-v8a"
    assert any(e.type is EdgeType.EMBEDS and e.dst.key == lib.key
               for e in result.edges)


def test_unpack_emits_no_findings(analyzer, target) -> None:
    # Inventory is not judgement: findings are the config auditor's job.
    assert _normalize(analyzer, target, _payload()).findings == []


# ------------------------------------------------- hostile / malformed payloads

def test_missing_package_falls_back_to_the_sample_hash(analyzer, target) -> None:
    result = _normalize(analyzer, target, _payload(app={"package": None}))
    assert _by_type(result, EntityType.APP)[0].key == f"sha256:{target.sha256[:16]}"


def test_bogus_package_name_is_rejected(analyzer, target) -> None:
    result = _normalize(analyzer, target,
                        _payload(app={"package": "../../etc/passwd"}))
    app = _by_type(result, EntityType.APP)[0]
    assert app.key.startswith("sha256:")
    assert app.attributes["package"] is None


@pytest.mark.parametrize("junk", [
    {"components": "not-a-list"},
    {"components": [None, 42, "x"]},
    {"components": [{"kind": "activity", "name": "has spaces & ;rm -rf"}]},
    {"components": [{"kind": "wormhole", "name": "com.example.X"}]},
    {"permissions": [{"name": "bad name;$(id)"}]},
    {"deep_links": [{"scheme": "not a scheme"}]},
    {"native_libs": [{"path": None}]},
    {"app": "not-a-dict"},
])
def test_malformed_sections_are_dropped_not_fatal(analyzer, target, junk) -> None:
    result = _normalize(analyzer, target, _payload(**junk))
    # The App entity always survives; the junk never becomes a node.
    assert len(_by_type(result, EntityType.APP)) == 1
    for entity in result.entities:
        assert entity.key and "\n" not in entity.key


def test_duplicate_entries_collapse(analyzer, target) -> None:
    doc = _payload()
    doc["components"] = doc["components"] + doc["components"]
    doc["native_libs"] = doc["native_libs"] * 3
    result = _normalize(analyzer, target, doc)
    assert len(_by_type(result, EntityType.COMPONENT)) == 3
    assert len(_by_type(result, EntityType.NATIVE_LIB)) == 1


def test_oversized_payload_is_capped(analyzer, target) -> None:
    doc = _payload()
    doc["components"] = [
        {"kind": "activity", "name": f"com.example.A{i}"} for i in range(20_000)]
    result = _normalize(analyzer, target, doc)
    assert len(_by_type(result, EntityType.COMPONENT)) <= 5000


def test_overlong_strings_are_truncated(analyzer, target) -> None:
    doc = _payload()
    doc["app"]["version_name"] = "v" * 100_000
    result = _normalize(analyzer, target, doc)
    assert len(_by_type(result, EntityType.APP)[0].attributes["version_name"]) <= 128


def test_failed_raw_result_normalizes_to_nothing(analyzer, target) -> None:
    raw = RawResult(analyzer=analyzer.name, ok=False, error="worker died")
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


def test_run_persists_raw_output_and_parses_it(analyzer, target,
                                               workspace: Workspace) -> None:
    stdout = json.dumps(_payload()).encode()
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=0, stdout=stdout))

    raw = analyzer.run(target, workspace, sandbox)

    assert raw.ok and raw.payload["app"]["package"] == "com.example.shop"
    assert raw.raw_path == "raw/androguard-unpack/androguard.json"
    # The provenance copy on disk is byte-identical to what the tool emitted.
    assert workspace.resolve(raw.raw_path).read_bytes() == stdout
    # The sample is passed by its sanitised container path, not the host path.
    _image, args, kw = sandbox.calls[0]
    assert args == ["/input/sample.apk"]
    assert kw["sample"] == target.sample_path


def test_worker_reported_failure_is_surfaced(analyzer, target,
                                             workspace: Workspace) -> None:
    stdout = json.dumps({"ok": False, "error": "not a zip"}).encode()
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=1, stdout=stdout))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and raw.error == "not a zip"


def test_sandbox_failure_wins_over_worker_output(analyzer, target,
                                                 workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(
        ok=False, exit_code=137, stdout=json.dumps(_payload()).encode(),
        timed_out=True, error="timed out after 300s"))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and "timed out" in raw.error


def test_non_json_output_is_reported_not_raised(analyzer, target,
                                                workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(ok=True, exit_code=0,
                                         stdout=b"\x00\xffnot json"))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and "not valid JSON" in raw.error
    # Even unparseable output is kept for provenance.
    assert raw.raw_path is not None


def test_empty_output_is_reported(analyzer, target, workspace: Workspace) -> None:
    sandbox = _StubSandbox(SandboxResult(ok=False, exit_code=125, stdout=b"",
                                         error="image missing"))
    raw = analyzer.run(target, workspace, sandbox)
    assert not raw.ok and raw.error == "image missing"
