"""The apkleaks adapter, and its agreement with gitleaks.

The single most important assertion in this file is that both tools reporting
the same credential produce the same fingerprint. That is the whole reason
findings are keyed on a canonical weakness rather than a tool's own rule name:
agreement has to turn into one finding with two sources, not two findings each
carrying half the confidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from themob.adapters.apkleaks_scan import ApkleaksScanAnalyzer, canonical_rule
from themob.adapters.base import RawResult, Target
from themob.adapters.gitleaks_scan import GitleaksScanAnalyzer, classify
from themob.model.enums import EdgeType, EntityType, Platform, Severity, Stage
from themob.sandbox.runner import SandboxResult, SandboxRunner
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"
AWS = "AKIAZZ7NLQK4PRODXYZQ"
AWS_DIGEST = hashlib.sha256(AWS.encode()).hexdigest()


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


def _match(digest: str = AWS_DIGEST, preview: str = "AKIA************XYZQ",
           value=None) -> dict:
    return {"value": value, "preview": preview, "sha256": digest}


def _rule(name: str, *matches, credential: bool = True) -> dict:
    hits = list(matches) or [_match()]
    return {"rule": name, "credential": credential, "count": len(hits),
            "matches": hits}


def _payload(*rules, **extra) -> dict:
    doc = {"ok": True, "error": None, "tool": "apkleaks",
           "tool_version": "2.6.3", "package": PACKAGE,
           "results": list(rules), "truncated": False}
    doc.update(extra)
    return doc


def _normalize(payload, target, raw_path="raw/apkleaks-scan/apkleaks.json"):
    analyzer = ApkleaksScanAnalyzer()
    raw = RawResult(analyzer=analyzer.name, ok=True, payload=payload,
                    raw_path=raw_path)
    return analyzer.normalize(raw, target)


# ---------------------------------------------------------------- the mapping

@pytest.mark.parametrize("rule,expected", [
    ("Amazon_AWS_Access_Key_ID", "android.secrets.cloud-credential"),
    ("AWS_API_Key", "android.secrets.cloud-credential"),
    ("RSA_private_key", "android.secrets.private-key"),
    ("Stripe_API_Key", "android.secrets.service-api-key"),
    ("Slack_Token", "android.secrets.service-api-key"),
    ("Generic_API_Key", "android.secrets.high-entropy-string"),
])
def test_apkleaks_rules_map_through_the_shared_table(rule, expected) -> None:
    """One mapping for both tools, or the two never agree on a weakness."""
    assert classify(canonical_rule(rule)) == expected


def test_a_google_key_is_not_treated_as_a_cloud_credential() -> None:
    """Shipping a Maps key is normal and usually origin-restricted.

    Calling it critical is how an auditor teaches its reader to skim.
    """
    assert classify(canonical_rule("Google_API_Key")) == \
        "android.secrets.service-api-key"


# ------------------------------------------------------------------ the shape

def test_the_analyzer_is_wired_to_the_secrets_stage() -> None:
    analyzer = ApkleaksScanAnalyzer()
    assert analyzer.stage is Stage.SECRETS
    assert analyzer.image == "themob/apkleaks:1"
    assert analyzer.tool == "apkleaks"
    # It runs its own jadx pass, so it needs a longer leash than gitleaks.
    assert analyzer.timeout >= 1200


def test_it_is_given_the_package_not_the_decoded_tree(workspace, target) -> None:
    """apkleaks takes an APK and nothing else; it decompiles for itself."""
    calls = {}

    class _Sandbox(SandboxRunner):
        def run(self, image, args, **kwargs):           # type: ignore[override]
            calls.update(kwargs, image=image)
            return SandboxResult(ok=True, exit_code=0,
                                 stdout=json.dumps(_payload()).encode())

    ApkleaksScanAnalyzer().run(target, workspace, _Sandbox())
    assert calls["sample"] == target.sample_path
    assert calls.get("scan_dir") is None


# ------------------------------------------------------------------- entities

def test_a_credential_becomes_a_secret_node(target) -> None:
    result = _normalize(_payload(_rule("AWS_API_Key")), target)
    secret = next(e for e in result.entities if e.type is EntityType.SECRET)
    assert secret.key == f"sha256:{AWS_DIGEST}"
    assert result.edges[0].type is EdgeType.USES


def test_two_rules_matching_one_string_is_one_secret(target) -> None:
    """Amazon_AWS_Access_Key_ID and AWS_API_Key both fire on one key."""
    result = _normalize(_payload(
        _rule("Amazon_AWS_Access_Key_ID"), _rule("AWS_API_Key")), target)

    secrets = [e for e in result.entities if e.type is EntityType.SECRET]
    assert len(secrets) == 1
    assert secrets[0].attributes["matched_rules"] == \
        ["AWS_API_Key", "Amazon_AWS_Access_Key_ID"]
    assert len(result.findings) == 1
    assert "2 apkleaks rules" in result.findings[0].description


def test_links_and_buckets_are_left_for_the_endpoint_stage(target) -> None:
    """They are not secrets, and claiming they are would be a false positive."""
    result = _normalize(_payload(
        _rule("LinkFinder",
              _match("b" * 64, "https://api.example.com/v2",
                     value="https://api.example.com/v2"),
              credential=False),
        _rule("AWS_API_Key")), target)

    secrets = [e for e in result.entities if e.type is EntityType.SECRET]
    assert len(secrets) == 1
    app = next(e for e in result.entities if e.type is EntityType.APP)
    assert app.attributes["apkleaks_scan"]["links"] == 1
    assert app.attributes["apkleaks_scan"]["secrets"] == 1


def test_the_credential_value_is_never_stored(target) -> None:
    result = _normalize(_payload(_rule("AWS_API_Key")), target)
    blob = json.dumps([e.model_dump(mode="json") for e in result.entities]
                      + [f.model_dump(mode="json") for f in result.findings])
    assert AWS not in blob
    assert AWS_DIGEST in blob


def test_capture_off_flags_evidence_as_redacted(target) -> None:
    """Default: value is None, so the finding evidence is the redacted preview
    and carries redacted=True (no fuller value exists to reveal)."""
    ev = _normalize(_payload(_rule("AWS_API_Key")), target).findings[0].evidence[0]
    assert ev.redacted is True
    assert "AKIA************XYZQ" in ev.value
    assert AWS not in ev.value


def test_capture_on_keeps_the_full_value_but_not_in_the_node(target) -> None:
    """With the opt-in the worker sends the full value; the adapter stores it as
    evidence (marked not-redacted, for the gated reveal) while the secret node
    keeps only the redacted preview."""
    result = _normalize(
        _payload(_rule("AWS_API_Key", _match(value=AWS))), target)
    ev = result.findings[0].evidence[0]
    assert ev.redacted is False
    assert AWS in ev.value
    secret = next(e for e in result.entities if e.type is EntityType.SECRET)
    assert AWS not in secret.attributes["preview"]


def test_a_match_without_a_usable_digest_is_dropped(target) -> None:
    result = _normalize(_payload(
        _rule("AWS_API_Key", _match(digest="nope"), _match(digest="")),
    ), target)
    assert [e for e in result.entities if e.type is EntityType.SECRET] == []


# ------------------------------------------------- agreement with gitleaks

def test_both_tools_produce_the_same_fingerprint_for_one_secret(target) -> None:
    """The point of the whole canonical-weakness design.

    gitleaks reports the key with a file and a line; apkleaks reports it with
    neither. If either detail reached the fingerprint the two would never
    collide, and agreement between tools could never become confidence.
    """
    apkleaks = _normalize(_payload(_rule("AWS_API_Key")), target)

    gitleaks_payload = {
        "ok": True, "tool": "gitleaks", "tool_version": "8.30.1",
        "findings": [{"rule": "aws-access-token", "description": "",
                      "file": "jadx/sources/com/example/shop/SyncService.java",
                      "line": 12, "match": "AKIA************XYZQ",
                      "secret_sha256": AWS_DIGEST, "entropy": 3.7, "tags": []}],
        "scanned": {"files": 20, "bytes": 9000}, "truncated": False,
    }
    gl = GitleaksScanAnalyzer()
    gitleaks = gl.normalize(
        RawResult(analyzer=gl.name, ok=True, payload=gitleaks_payload,
                  raw_path="raw/gitleaks-scan/gitleaks.json"), target)

    assert apkleaks.findings[0].fingerprint == gitleaks.findings[0].fingerprint
    # And onto the same node, so the graph shows one credential.
    apk_secret = next(e for e in apkleaks.entities
                      if e.type is EntityType.SECRET)
    gl_secret = next(e for e in gitleaks.entities
                     if e.type is EntityType.SECRET)
    assert apk_secret.key == gl_secret.key


def test_apkleaks_alone_is_a_weaker_claim_than_gitleaks(target) -> None:
    """No line numbers and a looser pattern set, so it starts lower."""
    result = _normalize(_payload(_rule("AWS_API_Key")), target)
    assert result.findings[0].confidence == 0.7


# ------------------------------------------------------------------- findings

def test_findings_carry_the_weakness_mapping(target) -> None:
    result = _normalize(_payload(_rule("AWS_API_Key")), target)
    finding = result.findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.masvs_control == "MASVS-STORAGE-1"
    assert finding.cwe == "CWE-798"
    assert finding.entity_ids == [f"secret:sha256:{AWS_DIGEST}"]
    assert finding.remediation is not None


def test_findings_have_no_invented_location(target) -> None:
    """apkleaks does not say where it found the string, so neither do we."""
    result = _normalize(_payload(_rule("AWS_API_Key")), target)
    location = result.findings[0].location
    assert location is not None
    assert location.file is None and location.line is None


def test_rerunning_produces_identical_fingerprints(target) -> None:
    payload = _payload(_rule("AWS_API_Key"), _rule("Stripe_API_Key",
                                                   _match("c" * 64, "sk_l***000")))
    first = _normalize(payload, target)
    second = _normalize(payload, target)
    assert ([f.fingerprint for f in first.findings]
            == [f.fingerprint for f in second.findings])


# --------------------------------------------------------------- failure paths

def test_a_clean_scan_records_the_run(target) -> None:
    result = _normalize(_payload(), target)
    assert [e for e in result.entities if e.type is EntityType.SECRET] == []
    app = next(e for e in result.entities if e.type is EntityType.APP)
    assert app.attributes["apkleaks_scan"]["secrets"] == 0


def test_the_workers_diagnosis_is_not_masked(workspace) -> None:
    analyzer = ApkleaksScanAnalyzer()
    raw = analyzer._to_raw_result(SandboxResult(
        ok=False, exit_code=1, error="container exited with code 1",
        stdout=json.dumps({"ok": False, "tool": "apkleaks",
                           "error": "apkleaks failed with exit code 2"}).encode()),
        workspace)
    assert raw.error == "apkleaks failed with exit code 2"


def test_malformed_output_is_an_error(workspace) -> None:
    analyzer = ApkleaksScanAnalyzer()
    raw = analyzer._to_raw_result(
        SandboxResult(ok=True, exit_code=0, stdout=b"<html>nope"), workspace)
    assert not raw.ok and "not valid JSON" in (raw.error or "")


def test_junk_in_the_results_list_does_not_take_the_run_down(target) -> None:
    result = _normalize(_payload("a string", None, 7, _rule("AWS_API_Key")),
                        target)
    assert len(result.findings) == 1
