"""Analyzer registry assembly.

``build_registry()`` instantiates and registers every adapter. Adding a tool is
a one-line append here: the orchestrator discovers stages and per-stage
analyzers from the registry, exactly as TOPRECON's ``build_registry()`` feeds
its pivot engine.

Import order in this file is the order analyzers run *within* a stage; the
stage order itself comes from ``Stage``.
"""
from __future__ import annotations

from .base import (AnalysisContext, Analyzer, AnalyzerError, AnalyzerRegistry,
                   AnalyzerResult, Availability, EdgeSpec, EntityRef,
                   RawResult, Target)

__all__ = [
    "AnalysisContext", "Analyzer", "AnalyzerError", "AnalyzerRegistry",
    "AnalyzerResult", "Availability", "EdgeSpec", "EntityRef", "RawResult",
    "Target", "build_registry",
]


def build_registry() -> AnalyzerRegistry:
    """Every analyzer themob ships, wired into one registry."""
    registry = AnalyzerRegistry()

    # --- Stage 1: unpack & inventory ---
    # androguard first: it establishes the App node the rest hang off, and it is
    # the fast one, so a broken sample fails before a JVM is ever started.
    from .androguard_unpack import AndroguardUnpackAnalyzer
    from .apktool_decode import ApktoolDecodeAnalyzer
    from .ios_unpack import IosUnpackAnalyzer
    registry.register(AndroguardUnpackAnalyzer())
    registry.register(ApktoolDecodeAnalyzer())
    # iOS unpack runs only for iOS targets (platforms = (Platform.IOS,)), so it
    # sits beside the Android unpackers without ever competing with them.
    registry.register(IosUnpackAnalyzer())

    # --- Stage 2: reverse engineering ---
    from .ios_macho_audit import IosMachoAuditAnalyzer
    from .jadx_decompile import JadxDecompileAnalyzer
    from .nativelib_scan import NativeLibScanAnalyzer
    registry.register(JadxDecompileAnalyzer())
    # Native hardening: reads the ELF headers of the .so files apktool extracted,
    # so it belongs beside the other code-level analysis rather than a stage of
    # its own.
    registry.register(NativeLibScanAnalyzer())
    # iOS Mach-O hardening: the iOS counterpart of nativelib. No container, it
    # judges the hardening flags ios-unpack put on the NATIVE_LIB node, and it
    # runs only for iOS targets (platforms = (Platform.IOS,)).
    registry.register(IosMachoAuditAnalyzer())

    # --- Stage 6: config & platform audit ---
    # Runs no container: it judges the graph the unpackers built rather than
    # re-opening the package, so it is registered without an image and is the
    # first analyzer that emits findings.
    from .config_audit import ConfigAuditAnalyzer
    from .ios_config_audit import IosConfigAuditAnalyzer
    registry.register(ConfigAuditAnalyzer())
    # iOS Info.plist & entitlements auditor: the iOS counterpart. Also no
    # container, and iOS-only (platforms = (Platform.IOS,)), so it judges the
    # App and DEEP_LINK nodes ios-unpack built without touching Android runs.
    registry.register(IosConfigAuditAnalyzer())

    # --- Stage 3: secrets ---
    # Runs after unpack and reverse engineering because it scans what they
    # produced, the decoded resources and the decompiled Java, not the package.
    from .apkleaks_scan import ApkleaksScanAnalyzer
    from .gitleaks_scan import GitleaksScanAnalyzer
    registry.register(GitleaksScanAnalyzer())
    # apkleaks second: it runs its own jadx pass, so it is the slow one, and a
    # broken package should fail on the fast scanner first.
    registry.register(ApkleaksScanAnalyzer())

    # --- Stage 4: insecure patterns ---
    # Runs after jadx: it matches call sites in the decompiled Java, so a
    # package with no reverse-engineering stage gives it nothing to read.
    from .semgrep_scan import SemgrepScanAnalyzer
    registry.register(SemgrepScanAnalyzer())

    # MobSF last in this stage: it is by far the slowest, and it is a second
    # opinion rather than new coverage, so everything it corroborates should
    # already be in the graph when it arrives. Skipped cleanly when either of
    # its two images is missing, which is the usual case: it is a large pull.
    from .mobsf_scan import MobSFScanAnalyzer
    registry.register(MobSFScanAnalyzer())

    # --- Stage 5: dependencies and SBOM ---
    # Runs after unpack so apktool has laid the package out. syft alone finds
    # nothing in an APK, so the worker catalogs Android's own dependency
    # evidence and hands grype an SBOM built from it.
    from .sbom_scan import SbomScanAnalyzer
    registry.register(SbomScanAnalyzer())

    # --- Stage 7: API and endpoint recon ---
    # No container: it reads the JSON apkleaks already produced in one, so the
    # package is never opened a second time. Registered after the secrets stage
    # because that output is its input.
    from .endpoint_extract import EndpointExtractAnalyzer
    registry.register(EndpointExtractAnalyzer())

    return registry
