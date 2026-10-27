"""iOS unpack (M1): the fixture, the worker's structural parsing, and the adapter.

The worker's lief Mach-O read runs only in the container, so the hermetic tests
here cover what does not need lief: the fixture is a readable bundle, the worker
parses the Info.plist and frameworks, intake detects the .ipa, and the adapter's
normalize and run turn a worker document into App, LIBRARY and NATIVE_LIB nodes.
"""
from __future__ import annotations

import importlib.util
import json
import plistlib
import zipfile
from pathlib import Path

import pytest

from themob.adapters.base import RawResult, Target
from themob.adapters.ios_unpack import IosUnpackAnalyzer
from themob.model.enums import EntityType, Platform
from themob.orchestrator.intake import detect_platform
from themob.sandbox.runner import SandboxLimits, SandboxResult
from themob.storage.workspace import Workspace
from tests.fixtures.ipa import build_ipa

_WORKER = (Path(__file__).resolve().parent.parent / "workers" / "ios-unpack"
           / "analyze.py")


def _worker():
    """Load the worker module by path (its directory name has a hyphen)."""
    spec = importlib.util.spec_from_file_location("ios_unpack_worker", _WORKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def ipa(tmp_path) -> Path:
    return build_ipa(tmp_path / "demo.ipa", url_schemes=("demo", "demopay"),
                     arbitrary_loads=True, file_sharing=True)


def _target(ipa: Path) -> Target:
    return Target(project_id="p1", platform=Platform.IOS, sample_path=ipa,
                  sha256="e" * 64, name="demo.ipa")


def _worker_payload() -> dict:
    """What the worker would emit for the fixture (the lief fields canned)."""
    return {
        "ok": True, "error": None, "tool": "ios-unpack", "tool_version": "0.16.6",
        "app": {"bundle_id": "com.example.demo", "name": "Demo", "version": "1.0",
                "build": "1", "min_os": "14.0", "executable": "Demo",
                "platform": "iphoneos", "url_schemes": ["demo", "demopay"],
                "ats": {"arbitrary_loads": True}, "file_sharing": True},
        "frameworks": [
            {"path": "Payload/Demo.app/Frameworks/Thing.framework",
             "name": "Thing.framework", "kind": "framework"},
            {"path": "Payload/Demo.app/libextra.dylib",
             "name": "libextra.dylib", "kind": "dylib"}],
        "macho": {"path": "Payload/Demo.app/Demo", "name": "Demo",
                  "archs": ["ARM64"], "pie": True, "encrypted": False,
                  "signed": True, "stack_canary": False, "arc": True, "nx": True,
                  "size": 70},
        "inventory": {"file_count": 6, "uncompressed_bytes": 100},
    }


# ----------------------------------------------------------------- the fixture

def test_the_fixture_is_a_readable_ipa(ipa) -> None:
    with zipfile.ZipFile(ipa) as zf:
        names = zf.namelist()
        assert any(n.startswith("Payload/Demo.app/") for n in names)
        info = plistlib.loads(zf.read("Payload/Demo.app/Info.plist"))
        assert info["CFBundleIdentifier"] == "com.example.demo"


def test_intake_detects_the_ipa_as_ios(ipa) -> None:
    assert detect_platform(ipa) is Platform.IOS


# ------------------------------------------------- the worker's structural half

def test_worker_reads_plist_and_frameworks(ipa) -> None:
    worker = _worker()
    with zipfile.ZipFile(ipa) as zf:
        prefix = worker._app_prefix(zf.namelist())
        assert prefix == "Payload/Demo.app/"
        info = plistlib.loads(zf.read(f"{prefix}Info.plist"))
        facts = worker._plist_facts(info)
        assert facts["bundle_id"] == "com.example.demo"
        assert facts["executable"] == "Demo"
        assert set(facts["url_schemes"]) == {"demo", "demopay"}
        assert facts["ats"]["arbitrary_loads"] is True
        assert facts["file_sharing"] is True

        kinds = {f["name"]: f["kind"] for f in worker._frameworks(zf, prefix)}
        assert kinds.get("Thing.framework") == "framework"
        assert kinds.get("libextra.dylib") == "dylib"


def test_worker_reads_entitlements_and_insecure_domains(tmp_path) -> None:
    """The mobileprovision plist is sliced out and its entitlements read, and an
    NSExceptionDomains entry that permits cleartext is surfaced."""
    ipa = build_ipa(tmp_path / "prof.ipa", with_profile=True, get_task_allow=True,
                    keychain_wildcard=True, insecure_domains=("legacy.example.com",))
    worker = _worker()
    with zipfile.ZipFile(ipa) as zf:
        prefix = worker._app_prefix(zf.namelist())
        facts = worker._plist_facts(plistlib.loads(zf.read(f"{prefix}Info.plist")))
        ents = worker._entitlements(zf, prefix)
    assert facts["ats"]["insecure_domains"] == ["legacy.example.com"]
    assert ents["get_task_allow"] is True
    assert ents["provisions_devices"] is True
    assert ents["entitlements"]["keychain-access-groups"] == ["*"]


def test_worker_without_a_profile_reports_no_entitlements(ipa) -> None:
    """A bundle with no embedded.mobileprovision is not an error, just empty."""
    worker = _worker()
    with zipfile.ZipFile(ipa) as zf:
        ents = worker._entitlements(zf, worker._app_prefix(zf.namelist()))
    assert ents["get_task_allow"] is None
    assert ents["entitlements"] == {}


def test_worker_scans_urls_and_decodes_the_bundle(tmp_path) -> None:
    """URLs come out of both the resources and the main binary, and the bundle
    is decoded to disk so the secrets and dependency scanners have a tree."""
    ipa = tmp_path / "urls.ipa"
    app = "Payload/Demo.app"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr(f"{app}/Info.plist",
                    plistlib.dumps({"CFBundleExecutable": "Demo",
                                    "CFBundleIdentifier": "com.example.demo"},
                                   fmt=plistlib.FMT_BINARY))
        zf.writestr(f"{app}/Demo", b"MACHO https://api.example.com/v1/login\x00")
        zf.writestr(f"{app}/config.json", b'{"u":"http://legacy.example.com/ping"}')
    worker = _worker()
    dest = tmp_path / "out"
    dest.mkdir()
    with zipfile.ZipFile(ipa) as zf:
        prefix = worker._app_prefix(zf.namelist())
        urls = worker._scan_urls(zf, prefix, "Demo")
        written = worker._safe_extract(zf, str(dest))
    assert "https://api.example.com/v1/login" in urls      # from the binary
    assert "http://legacy.example.com/ping" in urls         # from a resource
    assert written == 3
    assert (dest / "Payload/Demo.app/Info.plist").is_file()


def test_worker_extraction_rejects_zip_slip(tmp_path) -> None:
    """A traversal entry must never land outside the output directory."""
    evil = tmp_path / "evil.ipa"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("Payload/Demo.app/Info.plist", b"ok")
        zf.writestr("../../escape.txt", b"nope")
    worker = _worker()
    dest = tmp_path / "out"
    dest.mkdir()
    with zipfile.ZipFile(evil) as zf:
        worker._safe_extract(zf, str(dest))
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path.parent / "escape.txt").exists()


# -------------------------------------------------------------- the adapter

def test_normalize_builds_app_frameworks_and_macho(ipa) -> None:
    out = IosUnpackAnalyzer().normalize(
        RawResult(analyzer="ios-unpack", ok=True, payload=_worker_payload()),
        _target(ipa))

    by_type: dict = {}
    for entity in out.entities:
        by_type.setdefault(entity.type, []).append(entity)

    app = by_type[EntityType.APP][0]
    assert app.key == "com.example.demo"
    assert app.attributes["url_schemes"] == ["demo", "demopay"]
    assert app.attributes["ats"]["arbitrary_loads"] is True
    assert app.attributes["file_sharing"] is True

    assert len(by_type[EntityType.LIBRARY]) == 2
    macho = by_type[EntityType.NATIVE_LIB][0]
    assert macho.attributes["hardening"]["encrypted"] is False
    assert macho.attributes["hardening"]["pie"] is True
    assert macho.attributes["archs"] == ["ARM64"]

    # Each custom URL scheme becomes a DEEP_LINK node (androguard does the same
    # on Android, in the unpack stage, for the auditor to judge).
    deep_links = {e.attributes["scheme"] for e in by_type[EntityType.DEEP_LINK]}
    assert deep_links == {"demo", "demopay"}

    # The App embeds the two frameworks and the Mach-O, and declares two schemes.
    assert len(out.edges) == 5


def test_normalize_carries_entitlements_and_ats_detail(ipa) -> None:
    """The App node carries the entitlement and ATS facts M3 will judge."""
    payload = _worker_payload()
    payload["app"]["ats"]["insecure_domains"] = ["legacy.example.com"]
    payload["app"]["file_sharing"] = True
    payload["app"]["get_task_allow"] = True
    payload["app"]["entitlements"] = {"keychain-access-groups": ["*"],
                                      "get-task-allow": True}
    out = IosUnpackAnalyzer().normalize(
        RawResult(analyzer="ios-unpack", ok=True, payload=payload), _target(ipa))
    app = next(e for e in out.entities if e.type is EntityType.APP)
    assert app.attributes["get_task_allow"] is True
    assert app.attributes["file_sharing"] is True
    assert app.attributes["ats"]["insecure_domains"] == ["legacy.example.com"]
    assert app.attributes["entitlements"]["keychain-access-groups"] == ["*"]


def test_normalize_falls_back_to_the_hash_without_a_bundle_id(ipa) -> None:
    payload = _worker_payload()
    payload["app"]["bundle_id"] = "not a valid id!!"
    out = IosUnpackAnalyzer().normalize(
        RawResult(analyzer="ios-unpack", ok=True, payload=payload), _target(ipa))
    app = next(e for e in out.entities if e.type is EntityType.APP)
    assert app.key.startswith("sha256:")
    assert app.attributes["bundle_id"] is None


def test_run_persists_the_raw_output_with_a_stub_sandbox(ipa, tmp_path) -> None:
    class _StubSandbox:
        limits = SandboxLimits()

        def run(self, *args, **kwargs) -> SandboxResult:
            return SandboxResult(ok=True, exit_code=0,
                                 stdout=json.dumps(_worker_payload()).encode())

    workspace = Workspace(tmp_path, "p1").create()
    raw = IosUnpackAnalyzer().run(_target(ipa), workspace, _StubSandbox())
    assert raw.ok
    assert raw.raw_path and workspace.resolve(raw.raw_path).is_file()
    normalized = IosUnpackAnalyzer().normalize(raw, _target(ipa))
    assert any(e.type is EntityType.APP for e in normalized.entities)


def test_run_decodes_the_bundle_into_the_artifacts_tree(ipa, tmp_path) -> None:
    """The writable mount is artifacts/ios, so gitleaks and syft, which scan the
    artifacts tree, find the decoded bundle there. The JSON stays under raw/."""
    calls: dict = {}

    class _StubSandbox:
        limits = SandboxLimits()

        def run(self, image, args, **kwargs) -> SandboxResult:
            calls.update(kwargs)
            return SandboxResult(ok=True, exit_code=0,
                                 stdout=json.dumps(_worker_payload()).encode())

    workspace = Workspace(tmp_path, "p1").create()
    raw = IosUnpackAnalyzer().run(_target(ipa), workspace, _StubSandbox())
    assert calls["output_dir"] == workspace.artifacts_root / "ios"
    assert raw.raw_path.startswith("raw/")


def test_only_the_ios_adapter_applies_to_an_ipa() -> None:
    from themob.adapters import build_registry

    registry = build_registry()
    ios_target = Target(project_id="p", platform=Platform.IOS,
                        sample_path=Path("x.ipa"), sha256="f" * 64, name="x.ipa")
    names = {a.name for a in registry.applicable(ios_target)}
    assert "ios-unpack" in names
    assert "androguard-unpack" not in names, "Android analyzers must not run on iOS"
