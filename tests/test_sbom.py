"""The SBOM adapter: bundled libraries become nodes, advisories become findings.

Two things this file is really guarding. First, that a library is a graph node
even when nothing is wrong with it, because "what shipped" is worth recording on
its own and a later stage needs the node to pivot from. Second, that the
severity on a CVE finding comes from the advisory rather than from themob's
house default: the advisory already carries a considered rating, and replacing
it with a blanket "high" throws away the better number.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.adapters.base import RawResult, Target
from themob.adapters.sbom_scan import SbomScanAnalyzer
from themob.knowledge import get as weakness
from themob.model.enums import EdgeType, EntityType, Platform, Severity, Stage
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"
GSON = "pkg:maven/com.google.code.gson/gson@2.8.5"
CORE = "pkg:maven/androidx.core/core@1.12.0"


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


def _library(purl=CORE, **overrides) -> dict:
    group, _, rest = purl[len("pkg:maven/"):].partition("/")
    name, _, version = rest.partition("@")
    doc = {"group": group, "name": name, "version": version, "purl": purl,
           "evidence": "META-INF/marker.version",
           "cataloger": "android-version-marker"}
    doc.update(overrides)
    return doc


def _vuln(**overrides) -> dict:
    doc = {
        "id": "GHSA-4jrv-ppp4-jm57",
        "severity": "High",
        "purl": GSON,
        "package": "gson",
        "version": "2.8.5",
        "fixed_in": "2.8.9",
        "description": "Deserialization of untrusted data.",
        "cvss": 7.7,
        "urls": ["https://example.invalid/advisory"],
    }
    doc.update(overrides)
    return doc


def _raw(libraries=None, vulnerabilities=None, ok=True, **extra) -> RawResult:
    payload = {
        "ok": True,
        "error": None,
        "tool": "syft+grype",
        "tool_version": {"syft": "1.51.1", "grype": "0.118.0"},
        "libraries": libraries if libraries is not None else [_library()],
        "vulnerabilities": vulnerabilities or [],
        "scanned": {"files": 42, "libraries": 1},
        "truncated": False,
    }
    payload.update(extra)
    return RawResult(analyzer="sbom-scan", ok=ok, payload=payload,
                     raw_path="raw/sbom-scan/sbom.json")


def _normalize(target, **kwargs):
    return SbomScanAnalyzer().normalize(_raw(**kwargs), target)


# -------------------------------------------------------------------- shape

def test_the_adapter_declares_itself_correctly() -> None:
    analyzer = SbomScanAnalyzer()
    assert analyzer.stage is Stage.DEPENDENCIES
    assert analyzer.image == "themob/sbom:1"
    assert analyzer.tool == "grype"


def test_a_failed_run_produces_nothing(target) -> None:
    result = SbomScanAnalyzer().normalize(
        RawResult(analyzer="sbom-scan", ok=False, error="boom"), target)
    assert result.entities == [] and result.findings == []


# ---------------------------------------------------------------- libraries

def test_a_library_becomes_a_node_even_when_it_is_clean(target) -> None:
    """Knowing what shipped is worth recording on its own."""
    result = _normalize(target, libraries=[_library(CORE)])
    libraries = [e for e in result.entities if e.type is EntityType.LIBRARY]

    assert len(libraries) == 1
    library = libraries[0]
    assert library.key == CORE
    assert library.attributes["package_name"] == "core"
    assert library.attributes["version"] == "1.12.0"
    assert library.attributes["group"] == "androidx.core"
    assert library.attributes["cataloger"] == "android-version-marker"
    assert result.findings == []


def test_the_app_embeds_every_library(target) -> None:
    """The edge is what lets a later stage ask what reaches a bad dependency."""
    result = _normalize(target, libraries=[_library(CORE), _library(GSON)])
    embeds = [e for e in result.edges if e.type is EdgeType.EMBEDS]
    assert len(embeds) == 2
    assert all(e.src.type is EntityType.APP for e in embeds)
    assert {e.dst.key for e in embeds} == {CORE, GSON}


def test_a_library_without_a_purl_is_dropped(target) -> None:
    """The purl is the identity; without one the node cannot be merged later."""
    result = _normalize(target, libraries=[_library(CORE), {"name": "mystery"}])
    assert len([e for e in result.entities if e.type is EntityType.LIBRARY]) == 1


def test_the_scan_records_that_it_ran(target) -> None:
    """A scan that found nothing and a scan that never happened differ."""
    result = _normalize(target, libraries=[], vulnerabilities=[])
    app = next(e for e in result.entities if e.type is EntityType.APP)
    summary = app.attributes["dependency_scan"]
    assert summary["files"] == 42
    assert summary["vulnerabilities"] == 0
    assert summary["tool_version"]["grype"] == "0.118.0"


# ------------------------------------------------------------- advisories

def test_an_advisory_becomes_a_finding(target) -> None:
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln()])
    assert len(result.findings) == 1
    finding = result.findings[0]
    spec = weakness("android.supply-chain.vulnerable-dependency")

    assert "GHSA-4jrv-ppp4-jm57" in finding.title
    assert "gson" in finding.title
    assert finding.masvs_control == spec.masvs_control
    assert finding.cwe == spec.cwe
    assert finding.sources[0].tool == "grype"
    assert finding.sources[0].rule == "GHSA-4jrv-ppp4-jm57"


@pytest.mark.parametrize("reported,expected", [
    ("Critical", Severity.CRITICAL),
    ("High", Severity.HIGH),
    ("Medium", Severity.MEDIUM),
    ("Low", Severity.LOW),
    ("Negligible", Severity.INFO),
    ("Unknown", Severity.INFO),
])
def test_severity_comes_from_the_advisory(target, reported, expected) -> None:
    """Not from the catalogue default.

    The advisory already carries a considered rating. Overriding every one of
    them with a house default would throw away the better number and make a
    negligible issue look like a critical one.
    """
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln(severity=reported)])
    assert result.findings[0].severity is expected


def test_an_unrecognised_severity_falls_back_to_the_catalogue(target) -> None:
    spec = weakness("android.supply-chain.vulnerable-dependency")
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln(severity="spicy")])
    assert result.findings[0].severity is spec.severity


def test_the_fix_version_reaches_the_remediation(target) -> None:
    """The one thing a developer reading this actually needs."""
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln(fixed_in="2.8.9")])
    assert "2.8.9" in result.findings[0].remediation.summary


def test_two_advisories_on_one_library_are_two_findings(target) -> None:
    """Same package, same version, different CVEs. Not one issue seen twice."""
    result = _normalize(target, libraries=[_library(GSON)], vulnerabilities=[
        _vuln(id="CVE-2022-25647"), _vuln(id="GHSA-4jrv-ppp4-jm57")])
    assert len(result.findings) == 2
    assert len({f.fingerprint for f in result.findings}) == 2


def test_rerunning_produces_the_same_fingerprint(target) -> None:
    """Otherwise every re-run duplicates every advisory."""
    first = _normalize(target, libraries=[_library(GSON)],
                       vulnerabilities=[_vuln()])
    second = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln()])
    assert first.findings[0].fingerprint == second.findings[0].fingerprint


def test_the_finding_points_at_the_library_it_is_about(target) -> None:
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln()])
    finding = result.findings[0]
    assert finding.location is not None and finding.location.file == GSON
    assert GSON in finding.evidence[0].value


def test_the_finding_is_wired_to_its_library_node(target) -> None:
    """So the graph can answer "what reaches this vulnerable dependency".

    The Library has no row id yet at this point, so the adapter emits the
    ``type:key`` placeholder the pipeline swaps for a real one after the upsert.
    """
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln()])
    assert result.findings[0].entity_ids == [f"library:{GSON}"]


def test_an_advisory_against_an_uncatalogued_library_links_nothing(target) -> None:
    """Better an unlinked finding than one pointing at a node that is not there."""
    result = _normalize(target, libraries=[_library(CORE)],
                        vulnerabilities=[_vuln(purl="pkg:maven/ghost/ghost@1.0")])
    assert result.findings[0].entity_ids == []


def test_an_advisory_without_an_id_is_dropped(target) -> None:
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln(id=None)])
    assert result.findings == []


def test_findings_require_manual_validation(target) -> None:
    """Bundled is not reachable, and deciding that is the tester's job."""
    result = _normalize(target, libraries=[_library(GSON)],
                        vulnerabilities=[_vuln()])
    assert result.findings[0].requires_manual_validation is True


# ---------------------------------------------------------- error handling

def test_a_worker_failure_outranks_the_exit_code(target, workspace) -> None:
    """The worker's own diagnosis is the useful one."""
    from themob.sandbox.runner import SandboxResult

    payload = json.dumps({"ok": False, "tool": "syft+grype",
                          "error": "grype database is missing"}).encode()
    raw = SbomScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=payload, exit_code=1, error="exited with code 1"),
        workspace)
    assert not raw.ok
    assert raw.error == "grype database is missing"


def test_a_timeout_outranks_the_worker(target, workspace) -> None:
    from themob.sandbox.runner import SandboxResult

    payload = json.dumps({"ok": False, "error": "something"}).encode()
    raw = SbomScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=payload, exit_code=124, timed_out=True,
                      error="timed out after 1200s"),
        workspace)
    assert raw.error == "timed out after 1200s"


def test_unparseable_output_is_reported_clearly(target, workspace) -> None:
    from themob.sandbox.runner import SandboxResult

    raw = SbomScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=b"not json", exit_code=0), workspace)
    assert not raw.ok and "not valid JSON" in raw.error
