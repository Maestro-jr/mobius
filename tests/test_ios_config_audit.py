"""iOS Info.plist and entitlements audit (M3): the in-process judge of the graph.

ios-unpack puts the Info.plist facts and entitlements on the App node and founds
a DEEP_LINK node per custom scheme; this adapter judges them. The tests build the
graph by hand (the config-audit pattern), with no container and no sample, and
check both halves of every rule: the signal fires a finding, and the benign or
undetermined case does not.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.adapters.base import AnalysisContext, Availability, Target
from themob.adapters.ios_config_audit import IosConfigAuditAnalyzer
from themob.correlate.graph import GraphSnapshot
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity, Stage
from themob.storage.workspace import Workspace

BUNDLE = "com.example.demo"


# ------------------------------------------------------------------- helpers

def _ats(**kw) -> dict:
    base = {"arbitrary_loads": False, "arbitrary_loads_web": False,
            "arbitrary_loads_media": False, "exception_domains": [],
            "insecure_domains": []}
    base.update(kw)
    return base


def _app(**attrs) -> Entity:
    base = {"ats": _ats(), "file_sharing": None, "get_task_allow": None,
            "entitlements": {}}
    base.update(attrs)
    return Entity(type=EntityType.APP, platform=Platform.IOS, key=BUNDLE,
                  label="Demo", attributes=base)


def _deep_link(scheme: str, *, web: bool = False) -> Entity:
    return Entity(type=EntityType.DEEP_LINK, platform=Platform.IOS,
                  key=f"{scheme}://", label=f"{scheme}://",
                  attributes={"scheme": scheme, "web_scheme": web})


def _ctx(app: Entity, *others: Entity) -> AnalysisContext:
    entities = [app, *others]
    return AnalysisContext(snapshot=GraphSnapshot(
        project_id="p", entities=entities, edges=[], root_id=app.id))


@pytest.fixture()
def analyzer() -> IosConfigAuditAnalyzer:
    return IosConfigAuditAnalyzer()


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "demo.ipa"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.IOS, sample_path=sample,
                  sha256="e" * 64, name="demo.ipa", app_key=BUNDLE)


def _run(analyzer, workspace, target, context):
    raw = analyzer.run(target, workspace, None, context)
    return raw, analyzer.normalize(raw, target)


def _keys(result) -> set[str]:
    return {f.weakness_key for f in result.findings}


# ------------------------------------------------------------------- the shape

def test_the_auditor_needs_no_container(analyzer) -> None:
    assert analyzer.image == ""
    assert analyzer.wants_graph is True
    assert analyzer.stage is Stage.CONFIG_AUDIT
    assert analyzer.availability(None) == Availability.READY


def test_only_applies_to_ios(analyzer, tmp_path: Path) -> None:
    ipa = Target(project_id="p", platform=Platform.IOS,
                 sample_path=tmp_path / "a.ipa", sha256="e" * 64, name="a.ipa")
    apk = Target(project_id="p", platform=Platform.ANDROID,
                 sample_path=tmp_path / "a.apk", sha256="a" * 64, name="a.apk")
    assert analyzer.applies_to(ipa) and not analyzer.applies_to(apk)


def test_empty_graph_is_honest(analyzer, workspace, target) -> None:
    raw, result = _run(analyzer, workspace, target, AnalysisContext())
    assert not raw.ok and "unpack" in raw.error
    assert result.findings == []


def test_a_clean_app_has_no_findings(analyzer, workspace, target) -> None:
    """ATS on, no file sharing, no dev entitlements, no custom schemes."""
    raw, result = _run(analyzer, workspace, target, _ctx(_app()))
    assert raw.ok
    assert result.findings == []


# ------------------------------------------------------------- transport security

def test_arbitrary_loads_is_flagged(analyzer, workspace, target) -> None:
    app = _app(ats=_ats(arbitrary_loads=True))
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert _keys(result) == {"ios.ats.arbitrary-loads"}


def test_arbitrary_loads_web_is_flagged(analyzer, workspace, target) -> None:
    app = _app(ats=_ats(arbitrary_loads_web=True))
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert _keys(result) == {"ios.ats.arbitrary-loads-web"}


def test_each_insecure_exception_domain_is_its_own_finding(
        analyzer, workspace, target) -> None:
    app = _app(ats=_ats(exception_domains=["a.example.com", "b.example.com"],
                        insecure_domains=["a.example.com", "b.example.com"]))
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    insecure = [f for f in result.findings
                if f.weakness_key == "ios.ats.insecure-exception-domain"]
    assert len(insecure) == 2
    assert len({f.fingerprint for f in insecure}) == 2       # not collapsed


def test_a_secure_exception_domain_is_not_flagged(analyzer, workspace, target) -> None:
    """A domain listed under NSExceptionDomains that does NOT permit cleartext."""
    app = _app(ats=_ats(exception_domains=["pinned.example.com"], insecure_domains=[]))
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert result.findings == []


# --------------------------------------------------------------- url schemes

def test_each_custom_scheme_is_flagged_on_its_deep_link_node(
        analyzer, workspace, target) -> None:
    app = _app()
    demo, pay = _deep_link("demo"), _deep_link("demopay")
    _raw, result = _run(analyzer, workspace, target, _ctx(app, demo, pay))
    schemes = [f for f in result.findings
               if f.weakness_key == "ios.scheme.hijackable-url-scheme"]
    assert len(schemes) == 2
    # The finding cites the DEEP_LINK node, not the App.
    cited = {eid for f in schemes for eid in f.entity_ids}
    assert cited == {demo.id, pay.id}


def test_a_web_scheme_deep_link_is_not_flagged(analyzer, workspace, target) -> None:
    app = _app()
    _raw, result = _run(analyzer, workspace, target,
                        _ctx(app, _deep_link("https", web=True)))
    assert result.findings == []


# --------------------------------------------------------------- storage / sharing

def test_file_sharing_is_flagged(analyzer, workspace, target) -> None:
    _raw, result = _run(analyzer, workspace, target, _ctx(_app(file_sharing=True)))
    assert _keys(result) == {"ios.sharing.itunes-file-sharing"}


def test_file_sharing_absent_is_not_flagged(analyzer, workspace, target) -> None:
    for value in (None, False):
        _raw, result = _run(analyzer, workspace, target,
                            _ctx(_app(file_sharing=value)))
        assert result.findings == []


# --------------------------------------------------------------- entitlements

def test_get_task_allow_is_flagged(analyzer, workspace, target) -> None:
    _raw, result = _run(analyzer, workspace, target, _ctx(_app(get_task_allow=True)))
    assert _keys(result) == {"ios.entitlement.get-task-allow"}


def test_get_task_allow_absent_is_not_flagged(analyzer, workspace, target) -> None:
    """None (no profile) and False (release signing) must stay silent."""
    for value in (None, False):
        _raw, result = _run(analyzer, workspace, target,
                            _ctx(_app(get_task_allow=value)))
        assert result.findings == []


def test_keychain_wildcard_is_flagged(analyzer, workspace, target) -> None:
    app = _app(entitlements={"keychain-access-groups": ["ABCDE.com.example", "*"]})
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert "ios.entitlement.wildcard-keychain" in _keys(result)


def test_scoped_keychain_group_is_not_flagged(analyzer, workspace, target) -> None:
    app = _app(entitlements={"keychain-access-groups": ["ABCDE.com.example.shared"]})
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert result.findings == []


def test_associated_domains_wildcard_is_flagged(analyzer, workspace, target) -> None:
    app = _app(entitlements={"com.apple.developer.associated-domains": ["applinks:*"]})
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert "ios.entitlement.wildcard-associated-domains" in _keys(result)


def test_scoped_associated_subdomain_is_not_flagged(analyzer, workspace, target) -> None:
    """A named-domain subdomain wildcard is normal, not over-broad."""
    app = _app(entitlements={
        "com.apple.developer.associated-domains": ["applinks:*.example.com"]})
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    assert result.findings == []


# --------------------------------------------------------------- finding shape

def test_finding_carries_the_pack_metadata(analyzer, workspace, target) -> None:
    app = _app(ats=_ats(arbitrary_loads=True))
    _raw, result = _run(analyzer, workspace, target, _ctx(app))
    finding = result.findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.masvs_category.value == "MASVS-NETWORK"
    assert finding.cwe == "CWE-319"
    assert finding.mobile_top10 == "M5"
    assert finding.entity_ids == [app.id]
    assert finding.sources[0].rule == "ios.ats.arbitrary-loads"


def test_fingerprints_converge_across_runs(analyzer, workspace, target) -> None:
    app = _app(ats=_ats(arbitrary_loads=True, insecure_domains=["x.example.com"]),
               file_sharing=True, get_task_allow=True)
    ctx = _ctx(app, _deep_link("demo"))
    first = {f.fingerprint for f in _run(analyzer, workspace, target, ctx)[1].findings}
    second = {f.fingerprint for f in _run(analyzer, workspace, target, ctx)[1].findings}
    assert first == second and len(first) == 5
