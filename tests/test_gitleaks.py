"""The gitleaks adapter: secrets become graph nodes, values never do.

Two things this file is really guarding. First, that a leaked credential is one
node however many files it appears in, because rotating it fixes every copy at
once and a report that lists it eight times is a worse report. Second, that
nothing here ever stores the secret itself: the worker redacts and hashes, and
if this adapter ever started keeping the plaintext, themob would become a second
place to leak it from.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from themob.adapters.base import RawResult, Target
from themob.adapters.gitleaks_scan import GitleaksScanAnalyzer, classify
from themob.knowledge import get as weakness
from themob.model.enums import EdgeType, EntityType, Platform, Severity, Stage
from themob.sandbox.runner import SandboxResult, SandboxRunner
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"
SECRET = "AKIAIOSFODNN7EXAMPLE"
DIGEST = hashlib.sha256(SECRET.encode()).hexdigest()


# ------------------------------------------------------------------- helpers

@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


def _hit(**overrides) -> dict:
    doc = {
        "rule": "aws-access-token",
        "description": "Identified a pattern that may indicate AWS credentials",
        "file": "apktool/res/values/strings.xml",
        "line": 12,
        "match": "AKIA************MPLE",
        "secret_sha256": DIGEST,
        "entropy": 3.5,
        "tags": [],
    }
    doc.update(overrides)
    return doc


def _payload(*hits, ok=True, **extra) -> dict:
    doc = {"ok": ok, "error": None, "tool": "gitleaks", "tool_version": "8.0.0",
           "findings": list(hits), "scanned": {"files": 40, "bytes": 9000},
           "truncated": False}
    doc.update(extra)
    return doc


def _normalize(payload, target, raw_path="raw/gitleaks-scan/gitleaks.json"):
    analyzer = GitleaksScanAnalyzer()
    raw = RawResult(analyzer=analyzer.name, ok=True, payload=payload,
                    raw_path=raw_path)
    return analyzer.normalize(raw, target)


# --------------------------------------------------------------- the mapping

@pytest.mark.parametrize("rule,expected", [
    ("aws-access-token", "android.secrets.cloud-credential"),
    ("gcp-service-account", "android.secrets.cloud-credential"),
    ("azure-storage-key", "android.secrets.cloud-credential"),
    ("private-key", "android.secrets.private-key"),
    ("ssh-key", "android.secrets.private-key"),
    ("generic-api-key", "android.secrets.high-entropy-string"),
    ("slack-bot-token", "android.secrets.service-api-key"),
    ("stripe-access-token", "android.secrets.service-api-key"),
])
def test_rules_map_to_canonical_weaknesses(rule, expected) -> None:
    assert classify(rule) == expected


def test_a_cloud_private_key_is_a_private_key_first() -> None:
    """"gcp-private-key" matches both tables. The key material is the worse half."""
    assert classify("gcp-private-key") == "android.secrets.private-key"


def test_every_key_the_mapping_can_return_is_defined() -> None:
    """A mapping onto a key no pack defines is an unmapped finding in a report."""
    for rule in ("aws-access-token", "private-key", "generic-api-key",
                 "something-nobody-has-seen"):
        weakness(classify(rule))            # raises if the key is unknown


# ------------------------------------------------------------------- the shape

def test_the_analyzer_is_wired_to_the_secrets_stage() -> None:
    analyzer = GitleaksScanAnalyzer()
    assert analyzer.stage is Stage.SECRETS
    assert analyzer.image == "themob/gitleaks:1"
    assert analyzer.tool == "gitleaks"


def test_it_refuses_to_run_before_the_earlier_stages(workspace, target) -> None:
    """There is nothing to scan until the unpackers have written something."""
    raw = GitleaksScanAnalyzer().run(target, workspace, None)
    assert not raw.ok
    assert "nothing to scan" in (raw.error or "")


def test_it_scans_the_artifacts_tree_and_never_the_package(workspace,
                                                           target) -> None:
    """The sample must not be mounted: the decoded tree is what holds the text."""
    (workspace.artifacts_root / "apktool").mkdir(parents=True, exist_ok=True)
    (workspace.artifacts_root / "apktool" / "x.xml").write_text("<a/>",
                                                                encoding="utf-8")
    calls = {}

    class _Sandbox(SandboxRunner):
        def run(self, image, args, **kwargs):           # type: ignore[override]
            calls.update(kwargs, image=image)
            return SandboxResult(ok=True, exit_code=0,
                                 stdout=json.dumps(_payload()).encode())

    GitleaksScanAnalyzer().run(target, workspace, _Sandbox())
    assert calls["scan_dir"] == workspace.artifacts_root
    assert calls.get("sample") is None, "the APK must not be mounted here"


# ------------------------------------------------------------------- entities

def test_a_secret_becomes_a_node_linked_to_the_app(target) -> None:
    result = _normalize(_payload(_hit()), target)

    secret = next(e for e in result.entities if e.type is EntityType.SECRET)
    assert secret.key == f"sha256:{DIGEST}"
    assert result.edges[0].dst.key == secret.key
    assert result.edges[0].type is EdgeType.USES


def test_the_same_secret_in_many_files_is_one_node_and_one_finding(
        target) -> None:
    """Rotating it fixes every copy, so it is one thing to act on.

    The three places still have to be visible, so they become evidence on that
    one finding rather than three findings a tester triages separately.
    """
    result = _normalize(_payload(
        _hit(file="apktool/res/values/strings.xml", line=12),
        _hit(file="jadx/sources/com/example/shop/SyncClient.java", line=44),
        _hit(file="apktool/assets/config.json", line=3)), target)

    secrets = [e for e in result.entities if e.type is EntityType.SECRET]
    assert len(secrets) == 1
    assert secrets[0].attributes["occurrences"] == 3
    assert len(result.edges) == 1
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert len(finding.evidence) == 3
    joined = " ".join(e.value for e in finding.evidence)
    for where in ("strings.xml:12", "SyncClient.java:44", "config.json:3"):
        assert where in joined
    assert "Found in 3 places" in finding.description


def test_distinct_secrets_are_distinct_nodes(target) -> None:
    other = hashlib.sha256(b"a-different-secret").hexdigest()
    result = _normalize(_payload(_hit(), _hit(secret_sha256=other)), target)
    secrets = [e for e in result.entities if e.type is EntityType.SECRET]
    assert len({s.key for s in secrets}) == 2


def test_the_run_records_what_was_scanned(target) -> None:
    """The App node carries the scan summary, so a run is auditable."""
    result = _normalize(_payload(_hit()), target)
    app = next(e for e in result.entities if e.type is EntityType.APP)
    summary = app.attributes["secret_scan"]

    assert summary["tool"] == "gitleaks"
    assert summary["files"] == 40 and summary["bytes"] == 9000
    assert summary["hits"] == 1
    assert summary["truncated"] is False


def test_a_truncated_scan_says_so(target) -> None:
    """"2000 secrets" and "at least 2000" are different statements."""
    result = _normalize(_payload(_hit(), truncated=True), target)
    app = next(e for e in result.entities if e.type is EntityType.APP)
    assert app.attributes["secret_scan"]["truncated"] is True


# ------------------------------------------------------- the value never lands

def test_the_secret_value_is_never_stored(target) -> None:
    """themob must not become a second place to leak the credential from."""
    result = _normalize(_payload(_hit()), target)
    blob = json.dumps(
        [e.model_dump(mode="json") for e in result.entities]
        + [f.model_dump(mode="json") for f in result.findings])

    assert SECRET not in blob, "the plaintext secret reached the graph"
    assert DIGEST in blob, "the digest is what makes it dedupable"


def test_the_redacted_preview_is_kept_for_recognition(target) -> None:
    result = _normalize(_payload(_hit()), target)
    secret = next(e for e in result.entities if e.type is EntityType.SECRET)
    assert secret.attributes["preview"] == "AKIA************MPLE"


def test_capture_off_flags_evidence_as_redacted(target) -> None:
    """Default: no full value leaves the sandbox, so the finding evidence is the
    redacted match and carries redacted=True, so the UI never offers to reveal a
    fuller value that does not exist."""
    ev = _normalize(_payload(_hit()), target).findings[0].evidence[0]
    assert ev.redacted is True
    assert "AKIA************MPLE" in ev.value
    assert SECRET not in ev.value


def test_capture_on_keeps_the_full_value_for_the_gated_reveal(target) -> None:
    """With the opt-in the worker sends the full match; the adapter stores it as
    evidence and marks it not-redacted, so the password gate can reveal it. The
    secret node still carries only the redacted preview."""
    result = _normalize(_payload(_hit(value="AWS_SECRET=" + SECRET)), target)
    ev = result.findings[0].evidence[0]
    assert ev.redacted is False
    assert SECRET in ev.value
    secret = next(e for e in result.entities if e.type is EntityType.SECRET)
    assert SECRET not in secret.attributes["preview"]


def test_a_hit_with_no_usable_digest_is_dropped(target) -> None:
    """Without a digest there is no stable identity, so it cannot dedupe."""
    result = _normalize(_payload(
        _hit(secret_sha256=None),
        _hit(secret_sha256="not-a-digest"),
        _hit(secret_sha256="ABC123"),
    ), target)
    assert [e for e in result.entities if e.type is EntityType.SECRET] == []
    assert result.findings == []


# ------------------------------------------------------------------- findings

def test_findings_carry_the_weakness_mapping(target) -> None:
    result = _normalize(_payload(_hit()), target)
    finding = result.findings[0]
    spec = weakness("android.secrets.cloud-credential")

    assert finding.severity is spec.severity is Severity.CRITICAL
    assert finding.masvs_control == spec.masvs_control
    assert finding.cwe == "CWE-798"
    assert finding.remediation is not None


def test_findings_point_at_the_file_and_line(target) -> None:
    result = _normalize(_payload(_hit()), target)
    location = result.findings[0].location
    assert location.file == "artifacts/apktool/res/values/strings.xml"
    assert location.line == 12


def test_findings_link_to_the_secret_node(target) -> None:
    """The pipeline resolves the placeholder once the entity has a row id."""
    result = _normalize(_payload(_hit()), target)
    assert result.findings[0].entity_ids == [f"secret:sha256:{DIGEST}"]


def test_a_generic_hit_is_a_weaker_claim(target) -> None:
    """A pattern that names no provider is worth less than one that does."""
    named = _normalize(_payload(_hit(rule="aws-access-token")), target).findings[0]
    generic = _normalize(_payload(_hit(rule="generic-api-key")), target).findings[0]

    assert generic.confidence < named.confidence
    assert generic.severity is Severity.MEDIUM
    assert named.severity is Severity.CRITICAL


def test_the_fingerprint_ignores_the_file_so_tools_can_agree(target) -> None:
    """The file is an occurrence detail, not part of the credential's identity.

    apkleaks reports the same secret with no file at all. If the path were in
    the fingerprint the two tools could never collide, and cross-tool voting,
    the entire reason findings are keyed on a canonical weakness, would never
    fire for secrets.
    """
    with_file = _normalize(_payload(_hit(file="a.xml", line=1)), target)
    other_file = _normalize(_payload(_hit(file="b.java", line=99)), target)
    no_file = _normalize(_payload(_hit(file="", line=None)), target)

    prints = {with_file.findings[0].fingerprint,
              other_file.findings[0].fingerprint,
              no_file.findings[0].fingerprint}
    assert len(prints) == 1, "the same secret produced different fingerprints"


def test_rerunning_produces_identical_fingerprints(target) -> None:
    payload = _payload(_hit(), _hit(rule="private-key", file="assets/key.pem"))
    first = _normalize(payload, target)
    second = _normalize(payload, target)
    assert ([f.fingerprint for f in first.findings]
            == [f.fingerprint for f in second.findings])


def test_findings_cite_the_raw_tool_output(target) -> None:
    result = _normalize(_payload(_hit()), target)
    finding = result.findings[0]
    assert finding.sources[0].tool == "gitleaks"
    assert finding.sources[0].rule == "aws-access-token"
    assert finding.sources[0].raw_ref == "raw/gitleaks-scan/gitleaks.json"


# --------------------------------------------------------------- failure paths

def test_a_clean_scan_produces_no_secrets_but_still_records_the_run(
        target) -> None:
    """"We looked and found nothing" has to be distinguishable from "we did
    not look", which is why the scan summary is emitted either way."""
    result = _normalize(_payload(), target)
    assert [e for e in result.entities if e.type is EntityType.SECRET] == []
    assert result.findings == []

    app = next(e for e in result.entities if e.type is EntityType.APP)
    assert app.attributes["secret_scan"]["hits"] == 0


def test_a_worker_failure_is_reported_not_swallowed(workspace) -> None:
    analyzer = GitleaksScanAnalyzer()
    raw = analyzer._to_raw_result(SandboxResult(
        ok=False, exit_code=1,
        stdout=json.dumps({"ok": False, "tool": "gitleaks",
                           "error": "gitleaks could not be started"}).encode()),
        workspace)
    assert not raw.ok
    assert raw.error == "gitleaks could not be started"


def test_the_generic_exit_code_never_masks_the_workers_diagnosis(
        workspace) -> None:
    analyzer = GitleaksScanAnalyzer()
    raw = analyzer._to_raw_result(SandboxResult(
        ok=False, exit_code=1, error="container exited with code 1",
        stdout=json.dumps({"ok": False, "tool": "gitleaks",
                           "error": "permission denied reading /scan"}).encode()),
        workspace)
    assert raw.error == "permission denied reading /scan"


def test_malformed_worker_output_is_an_error(workspace) -> None:
    analyzer = GitleaksScanAnalyzer()
    raw = analyzer._to_raw_result(
        SandboxResult(ok=True, exit_code=0, stdout=b"not json at all"), workspace)
    assert not raw.ok and "not valid JSON" in (raw.error or "")


def test_junk_in_the_findings_list_does_not_take_the_run_down(target) -> None:
    result = _normalize(_payload("a string", None, 42, _hit()), target)
    assert len(result.findings) == 1
