"""The config auditor: the first analyzer that makes a judgement.

These tests are mostly about *not* crying wolf. An auditor that reports every
exported launcher activity, or claims an app has no network security config
because the tool that resolves it did not run, trains its reader to skim, which
is worse than reporting nothing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.adapters.base import AnalysisContext, Target
from themob.adapters.config_audit import ConfigAuditAnalyzer
from themob.correlate.graph import GraphSnapshot
from themob.knowledge import get as weakness
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity, Stage
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"


# ------------------------------------------------------------------- helpers

def _entity(etype: EntityType, key: str, **attributes) -> Entity:
    return Entity(type=etype, platform=Platform.ANDROID, key=key,
                  label=key.rsplit(".", 1)[-1], attributes=attributes)


def _app(**attributes) -> Entity:
    base = {"package": PACKAGE, "debuggable": False, "allow_backup": False,
            "target_sdk": 34, "min_sdk": 30}
    base.update(attributes)
    return _entity(EntityType.APP, PACKAGE, **base)


def _context(app: Entity, *others: Entity) -> AnalysisContext:
    entities = [app, *others]
    return AnalysisContext(snapshot=GraphSnapshot(
        project_id="p", entities=entities, edges=[], root_id=app.id))


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


def _run(workspace: Workspace, target: Target, context: AnalysisContext):
    analyzer = ConfigAuditAnalyzer()
    raw = analyzer.run(target, workspace, None, context)
    return raw, analyzer.normalize(raw, target)


def _keys(result) -> set[str]:
    return {source.rule for f in result.findings for source in f.sources}


# ------------------------------------------------------------------ the shape

def test_the_auditor_needs_no_container() -> None:
    """It judges the graph, so Docker being down must not stop it."""
    analyzer = ConfigAuditAnalyzer()
    assert analyzer.image == ""
    assert analyzer.wants_graph is True
    assert analyzer.stage is Stage.CONFIG_AUDIT
    assert analyzer.availability(None) == "Ready"


def test_an_empty_graph_is_an_error_not_a_crash(workspace, target) -> None:
    raw, result = _run(workspace, target, AnalysisContext())
    assert not raw.ok
    assert "unpack" in (raw.error or "")
    assert result.findings == []


def test_the_verdict_document_is_persisted(workspace, target) -> None:
    """Findings themob produced itself still cite a tool-output artifact."""
    raw, result = _run(workspace, target, _context(_app(debuggable=True)))
    assert raw.ok and raw.raw_path
    assert workspace.resolve(raw.raw_path).is_file()
    assert raw.raw_path in result.artifacts
    assert result.findings[0].sources[0].raw_ref == raw.raw_path


# --------------------------------------------------------------- app settings

def test_debuggable_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(debuggable=True)))
    assert "android.config.debuggable" in _keys(result)


def test_debuggable_false_is_not_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(debuggable=False)))
    assert "android.config.debuggable" not in _keys(result)


@pytest.mark.parametrize("value,expected_evidence", [
    (True, 'android:allowBackup="true"'),
    (None, "not declared"),
])
def test_backup_is_reported_whether_declared_or_defaulted(
        workspace, target, value, expected_evidence) -> None:
    """allowBackup defaults to true, so silence is still permission."""
    _raw, result = _run(workspace, target, _context(_app(allow_backup=value)))
    finding = next(f for f in result.findings
                   if f.sources[0].rule == "android.config.backup-allowed")
    assert expected_evidence in finding.evidence[0].value


def test_backup_explicitly_disabled_is_not_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(allow_backup=False)))
    assert "android.config.backup-allowed" not in _keys(result)


def test_an_old_min_sdk_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(min_sdk=19)))
    assert "android.platform.min-sdk-unsupported" in _keys(result)


def test_a_current_min_sdk_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(min_sdk=34)))
    assert "android.platform.min-sdk-unsupported" not in _keys(result)


def test_v1_only_signing_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(signing={"v1": True, "v2": False, "v3": None})))
    assert "android.integrity.v1-signature-only" in _keys(result)


def test_v1_plus_v2_signing_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(signing={"v1": True, "v2": True, "v3": None})))
    assert "android.integrity.v1-signature-only" not in _keys(result)


# -------------------------------------------------------------------- network

def test_global_cleartext_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(uses_cleartext_traffic=True)))
    assert "android.network.cleartext-permitted" in _keys(result)


def test_a_missing_config_below_api_28_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(target_sdk=26)))
    assert "android.network.no-network-security-config" in _keys(result)


def test_a_missing_config_at_api_28_is_not(workspace, target) -> None:
    """From API 28 the platform default is already no-cleartext."""
    _raw, result = _run(workspace, target, _context(_app(target_sdk=28)))
    assert "android.network.no-network-security-config" not in _keys(result)


def test_an_unresolved_config_reference_is_not_reported_either_way(
        workspace, target) -> None:
    """androguard saw the declaration; apktool never resolved the file.

    The declaration exists, so "no config" is false. Its contents are unknown,
    so "permits cleartext" would be a guess. Saying nothing is the honest answer.
    """
    _raw, result = _run(workspace, target, _context(
        _app(target_sdk=26, network_security_config="res/xml/nsc.xml")))
    reported = _keys(result)
    assert "android.network.no-network-security-config" not in reported
    assert "android.network.cleartext-permitted" not in reported
    assert "android.network.cleartext-permitted-for-domain" not in reported


def test_apktools_unresolved_marker_is_also_silent(workspace, target) -> None:
    """The other shape of "we could not resolve it".

    androguard reports the reference as a string; apktool reports
    ``{"reference": ..., "unresolved": True}``. Both mean the same thing, and
    both must produce nothing rather than a guess in either direction.
    """
    _raw, result = _run(workspace, target, _context(_app(
        target_sdk=26,
        network_security_config={"reference": "@xml/nsc", "unresolved": True})))
    reported = _keys(result)
    assert "android.network.no-network-security-config" not in reported
    assert "android.network.cleartext-permitted" not in reported
    assert "android.network.user-ca-trusted" not in reported


def test_base_config_cleartext_is_app_wide(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "base", "domains": [], "cleartext_permitted": True}]})))
    assert "android.network.cleartext-permitted" in _keys(result)


def test_domain_config_cleartext_is_scoped_and_names_the_hosts(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "domain", "domains": ["legacy.example.com"],
             "cleartext_permitted": True}]})))
    finding = next(f for f in result.findings
                   if f.sources[0].rule ==
                   "android.network.cleartext-permitted-for-domain")
    assert "legacy.example.com" in finding.evidence[0].value
    # Narrower exposure than an app-wide opt-in, and scored that way.
    assert finding.severity is Severity.MEDIUM


def test_trusting_user_cas_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "base", "domains": [], "trust_anchors": ["system", "user"]}]})))
    assert "android.network.user-ca-trusted" in _keys(result)


def test_trusting_only_system_cas_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "base", "domains": [], "trust_anchors": ["system"]}]})))
    assert "android.network.user-ca-trusted" not in _keys(result)


def test_two_config_entries_do_not_collapse_into_one_finding(
        workspace, target) -> None:
    """Both are on the App node, so location alone cannot separate them."""
    _raw, result = _run(workspace, target, _context(_app(
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "domain", "domains": ["a.example.com"],
             "cleartext_permitted": True},
            {"scope": "domain", "domains": ["b.example.com"],
             "cleartext_permitted": True}]})))
    cleartext = [f for f in result.findings
                 if f.sources[0].rule ==
                 "android.network.cleartext-permitted-for-domain"]
    assert len(cleartext) == 2
    assert len({f.fingerprint for f in cleartext}) == 2


# ------------------------------------------------------------------------ IPC

def test_an_exported_component_without_a_permission_is_reported(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.SyncService",
                        kind="service", exported=True)))
    assert "android.ipc.component-exported-unprotected" in _keys(result)


def test_an_exported_component_with_a_permission_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.SyncService",
                        kind="service", exported=True,
                        permission=f"{PACKAGE}.permission.SYNC")))
    assert "android.ipc.component-exported-unprotected" not in _keys(result)


def test_the_launcher_activity_is_not_reported(workspace, target) -> None:
    """Every app has one, and it must be exported to be launchable.

    Reporting it is how an auditor teaches its reader to skim past the exported
    components that actually matter.
    """
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.MainActivity",
                        kind="activity", exported=True,
                        intent_filters=[{
                            "actions": ["android.intent.action.MAIN"],
                            "categories": ["android.intent.category.LAUNCHER"],
                            "auto_verify": None}])))
    assert "android.ipc.component-exported-unprotected" not in _keys(result)


def test_a_non_launcher_activity_with_filters_is_still_reported(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.DeepLinkActivity",
                        kind="activity", exported=True,
                        intent_filters=[{
                            "actions": ["android.intent.action.VIEW"],
                            "categories": ["android.intent.category.BROWSABLE"],
                            "auto_verify": True}])))
    assert "android.ipc.component-exported-unprotected" in _keys(result)


def test_an_exported_provider_is_its_own_higher_severity_weakness(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.data.ShopProvider",
                        kind="provider", exported=True,
                        authorities=f"{PACKAGE}.provider")))
    finding = next(f for f in result.findings
                   if f.sources[0].rule ==
                   "android.ipc.provider-exported-unprotected")
    assert finding.severity is Severity.HIGH
    assert f"{PACKAGE}.provider" in finding.evidence[0].value


def test_a_provider_guarded_on_only_one_side_is_still_reported(
        workspace, target) -> None:
    """readPermission alone leaves writes open, and vice versa."""
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.data.ShopProvider",
                        kind="provider", exported=True,
                        read_permission=f"{PACKAGE}.permission.READ")))
    assert "android.ipc.provider-exported-unprotected" in _keys(result)


def test_a_fully_guarded_provider_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.data.ShopProvider",
                        kind="provider", exported=True,
                        read_permission=f"{PACKAGE}.permission.READ",
                        write_permission=f"{PACKAGE}.permission.WRITE")))
    assert "android.ipc.provider-exported-unprotected" not in _keys(result)


def test_an_undeclared_exported_flag_is_called_out(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.COMPONENT, f"{PACKAGE}.Receiver",
                        kind="receiver", exported=True, exported_declared=None)))
    finding = next(f for f in result.findings
                   if f.sources[0].rule ==
                   "android.ipc.component-exported-unprotected")
    assert "not declared" in finding.evidence[0].value


def test_a_weak_custom_permission_is_reported(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.PERMISSION, f"{PACKAGE}.permission.SYNC",
                        custom=True, declared_by_app=True,
                        protection_level="normal")))
    assert "android.ipc.custom-permission-weak-protection" in _keys(result)


@pytest.mark.parametrize("level", ["signature", "signatureOrSystem",
                                   "signature|privileged"])
def test_compound_signature_levels_are_accepted(workspace, target, level) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.PERMISSION, f"{PACKAGE}.permission.SYNC",
                        custom=True, declared_by_app=True,
                        protection_level=level)))
    assert "android.ipc.custom-permission-weak-protection" not in _keys(result)


def test_the_declared_protection_level_is_quoted_verbatim(workspace, target) -> None:
    """A reader checking the report against the app has to be able to find it."""
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.PERMISSION, f"{PACKAGE}.permission.SYNC",
                        custom=True, declared_by_app=True,
                        protection_level="dangerous")))
    finding = next(f for f in result.findings
                   if f.sources[0].rule ==
                   "android.ipc.custom-permission-weak-protection")
    assert 'android:protectionLevel="dangerous"' == finding.evidence[0].value


def test_a_signature_custom_permission_is_not(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.PERMISSION, f"{PACKAGE}.permission.SYNC",
                        custom=True, declared_by_app=True,
                        protection_level="signature")))
    assert "android.ipc.custom-permission-weak-protection" not in _keys(result)


def test_a_platform_permission_the_app_merely_requests_is_not(
        workspace, target) -> None:
    """The app does not define android.permission.INTERNET; it cannot fix it."""
    _raw, result = _run(workspace, target, _context(
        _app(), _entity(EntityType.PERMISSION, "android.permission.INTERNET",
                        custom=False, declared_by_app=False, requested=True)))
    assert "android.ipc.custom-permission-weak-protection" not in _keys(result)


# ----------------------------------------------------------- finding contents

def test_findings_carry_their_standards_mapping_and_remediation(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(_app(debuggable=True)))
    finding = next(f for f in result.findings
                   if f.sources[0].rule == "android.config.debuggable")
    spec = weakness("android.config.debuggable")

    assert finding.severity is spec.severity
    assert finding.masvs_control == spec.masvs_control
    assert finding.masvs_category is spec.masvs_category
    assert finding.cwe == spec.cwe
    assert finding.remediation is not None and finding.remediation.summary
    assert finding.requires_manual_validation is True


def test_findings_link_back_to_the_entity_they_are_about(workspace, target) -> None:
    provider = _entity(EntityType.COMPONENT, f"{PACKAGE}.data.ShopProvider",
                       kind="provider", exported=True)
    _raw, result = _run(workspace, target, _context(_app(), provider))
    finding = next(f for f in result.findings
                   if f.sources[0].rule ==
                   "android.ipc.provider-exported-unprotected")
    assert finding.entity_ids == [provider.id]
    assert finding.location is not None
    assert finding.location.component == provider.key


def test_rerunning_produces_identical_fingerprints(workspace, target) -> None:
    """Otherwise every re-run duplicates every finding."""
    context = _context(_app(debuggable=True, allow_backup=True),
                       _entity(EntityType.COMPONENT, f"{PACKAGE}.SyncService",
                               kind="service", exported=True))
    _raw_a, first = _run(workspace, target, context)
    _raw_b, second = _run(workspace, target, context)

    assert first.findings, "expected findings to compare"
    assert ([f.fingerprint for f in first.findings]
            == [f.fingerprint for f in second.findings])


def test_distinct_weaknesses_never_share_a_fingerprint(workspace, target) -> None:
    _raw, result = _run(workspace, target, _context(
        _app(debuggable=True, allow_backup=True, min_sdk=19)))
    fingerprints = [f.fingerprint for f in result.findings]
    assert len(fingerprints) == len(set(fingerprints))


def test_a_clean_app_produces_nothing(workspace, target) -> None:
    """The auditor must be able to say "no"."""
    _raw, result = _run(workspace, target, _context(_app(
        debuggable=False, allow_backup=False, uses_cleartext_traffic=False,
        min_sdk=34, target_sdk=34, signing={"v1": True, "v2": True},
        network_security_config={"path": "res/xml/nsc.xml", "configs": [
            {"scope": "base", "domains": [], "cleartext_permitted": False,
             "trust_anchors": ["system"]}]})))
    assert result.findings == []


def test_an_unknown_weakness_key_fails_loudly() -> None:
    """A typo must not reach a report as an unmapped finding."""
    with pytest.raises(KeyError, match="unknown weakness key"):
        ConfigAuditAnalyzer._check("android.config.typo", _app(),
                                   evidence="x")
