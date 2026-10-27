"""iOS Mach-O hardening (M2): the in-process auditor over the NATIVE_LIB node.

ios-unpack puts a ``hardening`` dict on the Mach-O node; this adapter turns an
absent mitigation into a finding. The tests feed it a graph built by hand (the
config-audit pattern), with no container and no sample, and check the three
things that matter: a flag that is False becomes a finding, a flag that is True
does not, and a flag that is None (undetermined) never does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.adapters.base import AnalysisContext, Availability, Target
from themob.adapters.ios_macho_audit import IosMachoAuditAnalyzer
from themob.correlate.graph import GraphSnapshot
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity, Stage

_MACHO = "Payload/Demo.app/Demo"

# Every mitigation present: a well-built binary, which must yield no findings.
_ALL_ON = {"pie": True, "nx": True, "arc": True, "stack_canary": True,
           "signed": True, "encrypted": True}
# Every mitigation absent: one finding per rule.
_ALL_OFF = {"pie": False, "nx": False, "arc": False, "stack_canary": False,
            "signed": False, "encrypted": False}


# ------------------------------------------------------------------- helpers

def _macho(path: str = _MACHO, **hardening) -> Entity:
    return Entity(type=EntityType.NATIVE_LIB, platform=Platform.IOS, key=path,
                  label=path.rsplit("/", 1)[-1],
                  attributes={"hardening": dict(hardening)} if hardening else {})


def _ctx(*entities: Entity) -> AnalysisContext:
    root = entities[0].id if entities else None
    return AnalysisContext(snapshot=GraphSnapshot(
        project_id="p", entities=list(entities), edges=[], root_id=root))


@pytest.fixture()
def analyzer() -> IosMachoAuditAnalyzer:
    return IosMachoAuditAnalyzer()


@pytest.fixture()
def workspace(tmp_path: Path):
    from themob.storage.workspace import Workspace
    return Workspace(tmp_path / "home", "project-1").create()


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "demo.ipa"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.IOS, sample_path=sample,
                  sha256="e" * 64, name="demo.ipa")


def _run(analyzer, workspace, target, context):
    raw = analyzer.run(target, workspace, None, context)
    return raw, analyzer.normalize(raw, target)


def _keys(result) -> set[str]:
    return {f.weakness_key for f in result.findings}


# ------------------------------------------------------------------- the shape

def test_the_auditor_needs_no_container(analyzer) -> None:
    assert analyzer.image == ""
    assert analyzer.wants_graph is True
    assert analyzer.stage is Stage.REVERSE_ENGINEERING
    assert analyzer.availability(None) == Availability.READY


def test_only_applies_to_ios(analyzer, tmp_path: Path) -> None:
    ipa = Target(project_id="p", platform=Platform.IOS,
                 sample_path=tmp_path / "a.ipa", sha256="e" * 64, name="a.ipa")
    apk = Target(project_id="p", platform=Platform.ANDROID,
                 sample_path=tmp_path / "a.apk", sha256="a" * 64, name="a.apk")
    assert analyzer.applies_to(ipa) and not analyzer.applies_to(apk)


def test_empty_graph_is_honest(analyzer, workspace, target) -> None:
    """No graph means nothing to judge, not a silent clean bill."""
    raw, result = _run(analyzer, workspace, target, AnalysisContext())
    assert not raw.ok and "unpack" in raw.error
    assert result.findings == []


# ------------------------------------------------------------------- judgement

def test_all_flags_off_produce_one_finding_each(analyzer, workspace, target) -> None:
    raw, result = _run(analyzer, workspace, target, _ctx(_macho(**_ALL_OFF)))
    assert raw.ok
    assert _keys(result) == {
        "ios.macho.no-pie", "ios.macho.no-nx", "ios.macho.no-arc",
        "ios.macho.no-stack-canary", "ios.macho.no-code-signature",
        "ios.macho.not-encrypted"}


def test_all_flags_on_produce_nothing(analyzer, workspace, target) -> None:
    raw, result = _run(analyzer, workspace, target, _ctx(_macho(**_ALL_ON)))
    assert raw.ok
    assert result.findings == []


def test_undetermined_flag_is_never_a_finding(analyzer, workspace, target) -> None:
    """A flag lief could not read comes through as None; that is not 'absent'."""
    hardening = dict(_ALL_ON)
    hardening["pie"] = False       # genuinely absent -> a finding
    hardening["stack_canary"] = None   # undetermined -> no finding
    raw, result = _run(analyzer, workspace, target, _ctx(_macho(**hardening)))
    assert _keys(result) == {"ios.macho.no-pie"}


def test_a_node_without_hardening_is_skipped(analyzer, workspace, target) -> None:
    """A NATIVE_LIB with no hardening dict (an Android .so, say) is left alone."""
    raw, result = _run(analyzer, workspace, target, _ctx(_macho()))
    assert raw.ok
    assert result.findings == []


def test_finding_cites_the_node_and_carries_the_pack_metadata(
        analyzer, workspace, target) -> None:
    node = _macho(pie=False)
    _raw, result = _run(analyzer, workspace, target, _ctx(node))
    finding = result.findings[0]
    assert finding.weakness_key == "ios.macho.no-pie"
    assert finding.severity is Severity.MEDIUM
    assert finding.entity_ids == [node.id]
    assert finding.masvs_category.value == "MASVS-CODE"
    assert finding.mobile_top10 == "M7"
    assert finding.cwe == "CWE-693"
    assert finding.sources[0].rule == "ios.macho.no-pie"
    assert "Payload/Demo.app/Demo" in finding.location.file


def test_not_encrypted_is_informational(analyzer, workspace, target) -> None:
    """Unencrypted is expected off the App Store, so it must not raise alarm."""
    _raw, result = _run(analyzer, workspace, target,
                        _ctx(_macho(**{**_ALL_ON, "encrypted": False})))
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.INFO


def test_fingerprints_converge_across_runs(analyzer, workspace, target) -> None:
    ctx = _ctx(_macho(**_ALL_OFF))
    first = {f.fingerprint for f in _run(analyzer, workspace, target, ctx)[1].findings}
    second = {f.fingerprint for f in _run(analyzer, workspace, target, ctx)[1].findings}
    assert first == second and len(first) == 6


def test_two_machos_each_get_their_own_row(analyzer, workspace, target) -> None:
    a = _macho("Payload/Demo.app/Demo", pie=False)
    b = _macho("Payload/Demo.app/Frameworks/Thing.framework/Thing", pie=False)
    _raw, result = _run(analyzer, workspace, target, _ctx(a, b))
    assert len(result.findings) == 2
    assert {f.fingerprint for f in result.findings} == {
        result.findings[0].fingerprint, result.findings[1].fingerprint}
    assert len({f.location.file for f in result.findings}) == 2


def test_the_payload_is_persisted_for_citation(analyzer, workspace, target) -> None:
    raw, _result = _run(analyzer, workspace, target, _ctx(_macho(pie=False)))
    assert raw.raw_path and workspace.resolve(raw.raw_path).is_file()
