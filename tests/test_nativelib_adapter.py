"""The nativelib adapter: ELF facts become findings on the library node.

The worker reports what it saw; this decides what it means and attaches it to
the graph. The tests are about that mapping, that an executable stack is a
finding and a hardened library is not, and about the finding landing on the same
NativeLib node androguard keys by the in-APK path so the two do not fork.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.adapters.base import RawResult, Target
from themob.adapters.nativelib_scan import NativeLibScanAnalyzer, _canonical_path
from themob.model.enums import EntityType, Platform
from themob.model.findings import Finding

PACKAGE = "com.example.shop"


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


def _lib(path, **hardening) -> dict:
    base = {"nx": True, "relro": "full", "stack_canary": True,
            "fortify": True, "executable_stack": False}
    base.update(hardening)
    return {"path": path, "name": path.rsplit("/", 1)[-1],
            "arch": "arm64-v8a", "bits": 64, "hardening": base}


def _normalize(libraries, target):
    analyzer = NativeLibScanAnalyzer()
    payload = {"ok": True, "error": None, "tool": "nativelib",
               "libraries": libraries}
    raw = RawResult(analyzer=analyzer.name, ok=True, payload=payload,
                    raw_path="raw/nativelib-scan/nativelib.json")
    return analyzer.normalize(raw, target)


# ------------------------------------------------------------------ the key

def test_the_path_is_canonicalised_to_the_in_apk_form() -> None:
    assert _canonical_path("apktool/shop/lib/arm64-v8a/libfoo.so") \
        == "lib/arm64-v8a/libfoo.so"
    assert _canonical_path("weird/place/libbar.so") == "weird/place/libbar.so"


def test_a_finding_lands_on_the_native_lib_node(target) -> None:
    result = _normalize([_lib("apktool/shop/lib/arm64-v8a/libfoo.so",
                              executable_stack=True, nx=False)], target)
    lib = next(e for e in result.entities if e.type is EntityType.NATIVE_LIB)
    assert lib.key == "lib/arm64-v8a/libfoo.so"
    finding = result.findings[0]
    assert "native_lib:lib/arm64-v8a/libfoo.so" in finding.entity_ids


# --------------------------------------------------------------- the mapping

def test_an_executable_stack_is_a_medium_finding(target) -> None:
    result = _normalize([_lib("lib/arm64-v8a/libfoo.so",
                              executable_stack=True, nx=False)], target)
    keys = {f.weakness_key for f in result.findings}
    assert "android.native.executable-stack" in keys
    finding = next(f for f in result.findings
                   if f.weakness_key == "android.native.executable-stack")
    assert finding.severity.value == "medium"


def test_no_relro_is_a_finding(target) -> None:
    result = _normalize([_lib("lib/arm64-v8a/libfoo.so", relro="none")], target)
    assert "android.native.no-relro" in {f.weakness_key for f in result.findings}


def test_a_missing_canary_is_info(target) -> None:
    result = _normalize([_lib("lib/arm64-v8a/libfoo.so", stack_canary=False)],
                        target)
    finding = next(f for f in result.findings
                   if f.weakness_key == "android.native.no-stack-canary")
    assert finding.severity.value == "info"


def test_a_fully_hardened_library_has_no_findings(target) -> None:
    """RELRO full, non-exec stack, canary present: nothing to report."""
    result = _normalize([_lib("lib/arm64-v8a/libfoo.so")], target)
    assert result.findings == []
    # The node is still recorded, so the graph knows the library was examined.
    assert any(e.type is EntityType.NATIVE_LIB for e in result.entities)


def test_partial_relro_is_not_flagged(target) -> None:
    """Partial RELRO is the common, acceptable case; only 'none' is a finding."""
    result = _normalize([_lib("lib/arm64-v8a/libfoo.so", relro="partial")],
                        target)
    assert "android.native.no-relro" not in {f.weakness_key
                                             for f in result.findings}


# --------------------------------------------------------------- convergence

def test_a_finding_is_keyed_so_re_running_converges(target) -> None:
    """Same weakness, same library, same fingerprint across runs."""
    a = _normalize([_lib("lib/arm64-v8a/libfoo.so", relro="none")], target)
    b = _normalize([_lib("lib/arm64-v8a/libfoo.so", relro="none")], target)
    fa = next(f for f in a.findings if f.weakness_key == "android.native.no-relro")
    fb = next(f for f in b.findings if f.weakness_key == "android.native.no-relro")
    assert fa.fingerprint == fb.fingerprint


def test_two_libraries_get_distinct_findings(target) -> None:
    result = _normalize([
        _lib("lib/arm64-v8a/libfoo.so", relro="none"),
        _lib("lib/armeabi-v7a/libfoo.so", relro="none")], target)
    no_relro = [f for f in result.findings
                if f.weakness_key == "android.native.no-relro"]
    assert len({f.fingerprint for f in no_relro}) == 2


# ------------------------------------------------------------------ robustness

def test_a_failed_worker_yields_nothing(target) -> None:
    analyzer = NativeLibScanAnalyzer()
    raw = RawResult(analyzer=analyzer.name, ok=False,
                    payload={"ok": False, "error": "boom", "libraries": []})
    assert analyzer.normalize(raw, target).findings == []


def test_a_malformed_library_entry_is_skipped(target) -> None:
    result = _normalize(["not a dict", {"path": "x"}, 42,
                         _lib("lib/arm64-v8a/ok.so", relro="none")], target)
    assert len([f for f in result.findings
                if f.weakness_key == "android.native.no-relro"]) == 1
