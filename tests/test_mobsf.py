"""MobSF: the tests are about what the overlap is worth, not about coverage.

MobSF finds much of what themob already finds, so the interesting questions are
whether the two merge into one finding, whether the agreement is counted
honestly, and whether a rule themob has no key for is dropped loudly rather than
given an invented identity.
"""
from __future__ import annotations

import pytest

from themob.adapters.base import Availability, RawResult
from themob.adapters.mobsf_scan import (CLIENT_IMAGE, SERVICE_IMAGE,
                                        MobSFScanAnalyzer, known_reporters,
                                        mapped_keys)
from themob.knowledge import catalogue
from themob.model.enums import Platform, Severity
from themob.model.findings import Finding, Location
from themob.normalize.voting import METHODS, Vote, combine
from themob.orchestrator.intake import Target


@pytest.fixture()
def analyzer() -> MobSFScanAnalyzer:
    return MobSFScanAnalyzer()


def _app_entity():
    """The App node the auditor hangs an app-level check on."""
    from themob.model.entities import Entity
    from themob.model.enums import EntityType

    return Entity(type=EntityType.APP, platform=Platform.ANDROID,
                  key="com.example.shop", label="shop")


@pytest.fixture()
def target(tmp_path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p1", platform=Platform.ANDROID,
                  sample_path=sample, sha256="a" * 64, name="shop.apk")


def _raw(sections: dict, **kw) -> RawResult:
    payload = {"ok": True, "error": None, "tool": "mobsf",
               "tool_version": "4.3.2", "app": {}, "sections": sections,
               "truncated": False}
    payload.update(kw)
    return RawResult(analyzer="mobsf-scan", payload=payload,
                     raw_path="raw/mobsf-scan/mobsf.json")


# ------------------------------------------------------------------ integrity

def test_every_reporter_is_known_to_the_voting_model() -> None:
    """A reporter the model does not know becomes a phantom method.

    That is the one mistake the qualified mobsf/<section> names exist to
    prevent, so it is a tripwire rather than a comment.
    """
    assert not known_reporters() - set(METHODS)


def test_every_mapped_key_exists_in_the_weakness_pack() -> None:
    """A key with no weakness behind it would drop findings silently."""
    assert not mapped_keys() - set(catalogue())


def test_mobsf_manifest_does_not_corroborate_the_config_auditor() -> None:
    """Both read the same manifest, so their agreement is nearly one witness."""
    alone = combine([Vote("config-audit", 0.95)])
    together = combine([Vote("config-audit", 0.95), Vote("mobsf/manifest", 0.8)])

    assert together.confidence == alone.confidence
    assert together.methods == ["manifest"]
    assert not together.corroborated
    # Both names still travel, so the report can say who reported it.
    assert together.tools == ["config-audit", "mobsf/manifest"]


def test_mobsf_code_does_corroborate_the_config_auditor() -> None:
    """Different techniques failing together is real evidence."""
    verdict = combine([Vote("config-audit", 0.95), Vote("mobsf/code", 0.8)])
    assert verdict.confidence > 0.95
    assert verdict.corroborated


# --------------------------------------------------------------- availability

class _Sandbox:
    def __init__(self, present: set[str]) -> None:
        self._present = present

    def is_available(self) -> bool:
        return True

    def has_image(self, image: str) -> bool:
        return image in self._present


def test_both_images_are_required(analyzer) -> None:
    """A ready client with no server would arrive as an empty scan."""
    assert analyzer.availability(
        _Sandbox({CLIENT_IMAGE, SERVICE_IMAGE})) == Availability.READY
    assert analyzer.availability(
        _Sandbox({CLIENT_IMAGE})) == Availability.NO_IMAGE
    assert analyzer.availability(
        _Sandbox({SERVICE_IMAGE})) == Availability.NO_IMAGE


def test_availability_never_raises(analyzer) -> None:
    class Broken:
        def is_available(self) -> bool:
            return True

        def has_image(self, image: str) -> bool:
            raise RuntimeError("the daemon went away")

    assert analyzer.availability(Broken()) == Availability.NO_SANDBOX


# ------------------------------------------------------------------ normalize

def test_a_mapped_manifest_rule_becomes_a_canonical_finding(analyzer,
                                                            target) -> None:
    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "app_is_debuggable", "title": "Debug enabled",
         "severity": "high", "description": "android:debuggable is true",
         "targets": []},
    ]}), target)

    finding = result.findings[0]
    assert finding.weakness_key == "android.config.debuggable"
    assert finding.sources[0].tool == "mobsf/manifest"
    assert finding.sources[0].rule == "app_is_debuggable"
    assert finding.masvs_control


def test_a_mobsf_finding_merges_with_the_config_auditors(analyzer,
                                                         target) -> None:
    """The whole point, checked against the real auditor rather than a copy.

    A fingerprint is the weakness plus the place. MobSF naming the same
    weakness somewhere else does not merge; it becomes a second finding, and
    the report shows one problem twice at half the confidence each. That is
    worse than not running MobSF at all.
    """
    from themob.adapters.config_audit import ConfigAuditAnalyzer

    auditor = ConfigAuditAnalyzer()
    check = auditor._check("android.config.debuggable", _app_entity(),
                           evidence='android:debuggable="true"')
    audited = Finding.compute_fingerprint(
        "android.config.debuggable",
        Location(file=check["file"], component=check["component"]),
        check["discriminator"])

    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "app_is_debuggable", "severity": "high",
         "description": "MobSF has its own prose about this", "targets": []},
    ]}), target)

    assert result.findings[0].fingerprint == audited


def test_a_component_scoped_finding_merges_on_the_component(analyzer,
                                                            target) -> None:
    from themob.adapters.config_audit import ConfigAuditAnalyzer

    component = "com.example.shop.PublicActivity"
    auditor = ConfigAuditAnalyzer()
    check = auditor._check("android.ipc.component-exported-unprotected",
                           _app_entity(), evidence="exported",
                           component=component)
    audited = Finding.compute_fingerprint(
        "android.ipc.component-exported-unprotected",
        Location(file=check["file"], component=check["component"]),
        check["discriminator"])

    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "exported_intent_filter_exists", "severity": "warning",
         "description": "exported without permission",
         "targets": ["Activity", component]},
    ]}), target)

    assert result.findings[0].fingerprint == audited


def test_the_manifest_path_tracks_the_auditors(analyzer) -> None:
    """Two constants that must agree, asserted rather than hoped for."""
    from themob.adapters import config_audit
    from themob.adapters.mobsf_scan import MANIFEST_FILE

    assert MANIFEST_FILE == config_audit._MANIFEST


def test_a_rule_that_cannot_be_placed_is_dropped_not_duplicated(analyzer,
                                                                target) -> None:
    """Better to say nothing than to report the same problem a second time."""
    result = analyzer.normalize(_raw({"code": [
        {"rule": "android_md5", "severity": "warning",
         "description": "MD5 used", "targets": ["com/example/Crypto.java"]},
    ]}), target)

    assert not result.findings
    coverage = result.entities[0].attributes["mobsf_scan"]
    assert coverage["not_mergeable_count"] == 1
    assert "code:android_md5" in coverage["not_mergeable"]


def test_a_component_rule_with_no_component_names_no_place(analyzer,
                                                           target) -> None:
    # The type with no name is exactly what a live scan returns when MobSF
    # cannot resolve the component, and it must not be filed against "Activity".
    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "exported_intent_filter_exists", "severity": "warning",
         "description": "x", "targets": ["Activity"]},
    ]}), target)
    assert not result.findings


def test_an_unmapped_rule_is_counted_not_invented(analyzer, target) -> None:
    """An invented key would poison the fingerprint scheme for everyone."""
    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "some_rule_themob_has_no_key_for", "title": "x",
         "severity": "high", "description": "", "targets": []},
    ]}), target)

    assert not result.findings
    coverage = result.entities[0].attributes["mobsf_scan"]
    assert coverage["unmapped_count"] == 1
    assert "manifest:some_rule_themob_has_no_key_for" in coverage["unmapped"]


def test_an_unknown_section_is_ignored_rather_than_guessed(analyzer,
                                                           target) -> None:
    """A section with no mapping has no reporter, so it has no method either."""
    result = analyzer.normalize(_raw({"a_new_mobsf_section": [
        {"rule": "whatever", "severity": "high"}]}), target)
    assert not result.findings


def test_the_tool_version_travels(analyzer, target) -> None:
    result = analyzer.normalize(_raw({"manifest": []}), target)
    assert result.entities[0].attributes["mobsf_scan"]["tool_version"] == "4.3.2"


def test_severity_arrives_unescalated(analyzer, target) -> None:
    """A scanner that never ran the app does not get to say CRITICAL."""
    result = analyzer.normalize(_raw({"manifest": [
        {"rule": "app_is_debuggable", "severity": "high", "description": "x",
         "targets": []},
    ]}), target)
    assert result.findings[0].severity is Severity.HIGH


def test_a_failed_run_normalizes_to_nothing(analyzer, target) -> None:
    """A failure must not look like a clean scan."""
    raw = RawResult(analyzer="mobsf-scan", error="MobSF returned HTTP 500")
    assert not analyzer.normalize(raw, target).findings


def test_a_successful_scan_is_marked_ok(analyzer, tmp_path) -> None:
    """Regression: a clean MobSF run must come back ok. Without it the pipeline
    reads ok=False, error=None and reports even a good scan as 'mobsf-scan: None',
    and the findings never persist because normalize is only called when ok."""
    import json

    from themob.sandbox.runner import SandboxResult
    from themob.storage.workspace import Workspace

    workspace = Workspace(tmp_path / "home", "p1").create()
    payload = {"ok": True, "tool": "mobsf", "sections": {"manifest": []}}
    result = SandboxResult(ok=True, exit_code=0,
                           stdout=json.dumps(payload).encode())
    raw = analyzer._to_raw_result(result, workspace)
    assert raw.ok is True and raw.error is None
    assert raw.payload == payload


def test_a_mobsf_reported_failure_keeps_its_message(analyzer, tmp_path) -> None:
    import json

    from themob.sandbox.runner import SandboxResult
    from themob.storage.workspace import Workspace

    workspace = Workspace(tmp_path / "home", "p1").create()
    result = SandboxResult(ok=True, exit_code=1,
                           stdout=json.dumps({"ok": False, "error": "boom"}).encode())
    raw = analyzer._to_raw_result(result, workspace)
    assert not raw.ok and raw.error == "boom"


def test_hostile_section_content_cannot_crash_the_normalizer(analyzer,
                                                             target) -> None:
    """Everything here came from a container that parsed a hostile file."""
    result = analyzer.normalize(_raw({
        "manifest": ["not a dict", 42, None,
                     {"rule": "app_is_debuggable", "severity": {"nested": 1},
                      "description": ["a", "list"], "targets": "a string"}],
        "code": None,
        "network": {"not": "a list"},
    }), target)
    assert isinstance(result.findings, list)


def test_the_licence_note_says_why_this_is_arms_length(analyzer) -> None:
    """Locked decision 11, stated where somebody reading the adapter sees it."""
    note = analyzer.license_note.lower()
    assert "gpl" in note
    assert "rest api" in note
    assert "never imported" in note


# --------------------------------------------------- against a real MobSF

def _images_present() -> bool:
    from themob.sandbox.runner import SandboxRunner

    runner = SandboxRunner()
    return (runner.is_available()
            and runner.has_image(SERVICE_IMAGE)
            and runner.has_image(CLIENT_IMAGE))


@pytest.mark.docker
def test_the_service_starts_and_the_client_reaches_it(tmp_path) -> None:
    """The plumbing, before the findings: can the two containers talk at all.

    Separate from the scan test because a MobSF that starts but rejects the
    fixture is a different problem from one that never starts, and a single
    test would report them identically.
    """
    if not _images_present():
        pytest.skip("the MobSF images are not built")

    import secrets

    from themob.sandbox.runner import SandboxRunner, with_limits
    from themob.sandbox.service import SandboxService

    runner = SandboxRunner()
    service = SandboxService(runner)
    api_key = secrets.token_hex(32)

    # The adapter's own spec, not a copy of it: a copy is how the test and the
    # thing it tests drift apart.
    spec = MobSFScanAnalyzer().service_spec(runner, api_key)

    with service.running(spec) as handle:
        result = service.client_run(
            handle, CLIENT_IMAGE, [],
            env={"THEMOB_MOBSF_URL": handle.url, "THEMOB_MOBSF_KEY": api_key},
            limits=with_limits(runner, timeout_s=300.0))

    # No sample was mounted, so the client must say so rather than crash: the
    # contract is that it always emits parseable JSON.
    import json
    document = json.loads(result.stdout_text() or "{}")
    assert document, result.stderr or result.error
    assert document.get("ok") is False
    assert "no sample" in str(document.get("error", "")).lower()


@pytest.mark.docker
def test_a_real_scan_produces_mergeable_findings(repos, sample_apk,
                                                 tmp_path) -> None:
    """MobSF against a real package, through the real adapter.

    What is asserted is the contract, not MobSF's coverage: the worker returns
    the agreed shape, every rule it reports is either mapped or counted, and
    nothing it emits carries a key themob does not know.
    """
    if not _images_present():
        pytest.skip("the MobSF images are not built")

    from themob.audit.attestation import Attestation, AuditTrail
    from themob.orchestrator.intake import intake
    from themob.sandbox.runner import SandboxRunner

    audit = AuditTrail(repos.audit)
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="sample.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-MOBSF", attested=True),
        repos.projects)

    analyzer = MobSFScanAnalyzer()
    raw = analyzer.run(result.target, result.workspace, SandboxRunner())

    # A synthetic fixture may be rejected by MobSF, and that is a legitimate
    # outcome: what must not happen is a crash or a silent empty success.
    assert raw.payload or raw.error, "the worker said nothing at all"
    if raw.error:
        pytest.skip(f"MobSF did not scan the fixture: {raw.error[:200]}")

    normalized = analyzer.normalize(raw, result.target)
    for finding in normalized.findings:
        assert finding.weakness_key in catalogue()
        assert finding.sources[0].tool in known_reporters()
    coverage = normalized.entities[0].attributes["mobsf_scan"]
    assert "unmapped_count" in coverage and "not_mergeable_count" in coverage
