"""The endpoint extractor: turning a noisy link list into a defensible one.

Most of this file is about what does *not* come out. LinkFinder reports every
slash-shaped string it sees, and on themob's own fixture three of its seven hits
are not endpoints: an XML namespace, a bare path, and a cipher transformation.
A recon engine fed that list would scan w3.org on behalf of every app themob
ever looks at, so the filtering is the feature and these tests are the spec.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.adapters.base import RawResult, Target
from themob.adapters.endpoint_extract import (EndpointExtractAnalyzer,
                                              classify_cloud, normalise_url)
from themob.knowledge import get as weakness
from themob.model.enums import EdgeType, EntityType, Platform, Severity, Stage
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"
API = "https://api.shop.example.com/v1/orders"
LEGACY = "http://legacy.shop.example.com/v1/orders"
BUCKET_HOST = "shop-example-uploads.s3.amazonaws.com"


@pytest.fixture()
def target(tmp_path: Path) -> Target:
    sample = tmp_path / "shop.apk"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.ANDROID, sample_path=sample,
                  sha256="a" * 64, name="Example Shop", app_key=PACKAGE)


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "project-1").create()


def _apkleaks(workspace: Workspace, results: list[dict]) -> None:
    """Write the upstream stage's output where this adapter looks for it."""
    path = workspace.raw_dir("apkleaks-scan") / "apkleaks.json"
    path.write_text(json.dumps({"ok": True, "tool": "apkleaks",
                                "results": results}), encoding="utf-8")


def _links(*values: str, rule: str = "LinkFinder") -> dict:
    return {"rule": rule, "credential": False, "count": len(values),
            "matches": [{"value": v, "preview": v, "sha256": "d" * 64}
                        for v in values]}


def _run(workspace: Workspace, target: Target, results: list[dict]):
    _apkleaks(workspace, results)
    analyzer = EndpointExtractAnalyzer()
    raw = analyzer.run(target, workspace, None, None)
    return raw, analyzer.normalize(raw, target)


def _endpoints(result) -> set[str]:
    return {e.key for e in result.entities if e.type is EntityType.ENDPOINT}


def _assets(result) -> set[str]:
    return {e.key for e in result.entities if e.type is EntityType.CLOUD_ASSET}


# ------------------------------------------------------------------- the shape

def test_the_adapter_declares_itself_correctly() -> None:
    analyzer = EndpointExtractAnalyzer()
    assert analyzer.stage is Stage.API_RECON
    assert analyzer.image == "", "this stage opens no package, so it needs no container"
    assert analyzer.wants_graph is True
    assert analyzer.availability(None) == "Ready"


def test_it_says_so_when_the_secrets_stage_has_not_run(workspace, target) -> None:
    raw = EndpointExtractAnalyzer().run(target, workspace, None, None)
    assert not raw.ok
    assert "secrets stage" in (raw.error or "")


def test_malformed_upstream_output_is_an_error_not_an_empty_result(
        workspace, target) -> None:
    path = workspace.raw_dir("apkleaks-scan") / "apkleaks.json"
    path.write_text("{not json", encoding="utf-8")
    raw = EndpointExtractAnalyzer().run(target, workspace, None, None)
    assert not raw.ok and "could not be read" in (raw.error or "")


def test_output_without_results_is_refused(workspace, target) -> None:
    path = workspace.raw_dir("apkleaks-scan") / "apkleaks.json"
    path.write_text(json.dumps({"ok": True}), encoding="utf-8")
    raw = EndpointExtractAnalyzer().run(target, workspace, None, None)
    assert not raw.ok and "shape" in (raw.error or "")


# ------------------------------------------------------------ what comes out

def test_a_real_endpoint_becomes_a_node(workspace, target) -> None:
    _raw, result = _run(workspace, target, [_links(API)])
    assert _endpoints(result) == {API}

    endpoint = next(e for e in result.entities if e.type is EntityType.ENDPOINT)
    assert endpoint.attributes["host"] == "api.shop.example.com"
    assert endpoint.attributes["scheme"] == "https"
    assert endpoint.attributes["path"] == "/v1/orders"
    assert endpoint.attributes["cleartext"] is False
    assert "LinkFinder" in endpoint.attributes["reported_by"]


def test_the_app_talks_to_every_endpoint(workspace, target) -> None:
    """The edge is what makes this a graph rather than a list."""
    _raw, result = _run(workspace, target, [_links(API, LEGACY)])
    talks = [e for e in result.edges if e.type is EdgeType.TALKS_TO]
    assert len(talks) == 2
    assert all(e.src.type is EntityType.APP for e in talks)


def test_the_same_url_from_two_rules_is_one_node(workspace, target) -> None:
    _raw, result = _run(workspace, target, [
        _links(API), _links(API, rule="Other_Rule")])
    assert _endpoints(result) == {API}
    endpoint = next(e for e in result.entities if e.type is EntityType.ENDPOINT)
    assert sorted(endpoint.attributes["reported_by"]) == ["LinkFinder", "Other_Rule"]


def test_the_query_string_is_dropped_so_one_endpoint_is_one_node(
        workspace, target) -> None:
    """Query parameters vary per request; the path is what a tester probes."""
    _raw, result = _run(workspace, target, [_links(
        "https://api.shop.example.com/v1/orders?id=1",
        "https://api.shop.example.com/v1/orders?id=2")])
    assert _endpoints(result) == {API}


# --------------------------------------------------------- what does not

@pytest.mark.parametrize("value,reason", [
    ("http://schemas.android.com/apk/res/android", "namespace"),
    ("https://www.w3.org/2000/svg", "namespace"),
    ("/order", "not an absolute URL"),
    ("AES/ECB/PKCS5Padding", "not an absolute URL"),
    ("", "empty"),
])
def test_noise_never_becomes_an_endpoint(workspace, target, value, reason) -> None:
    """The three real false positives from the fixture, plus their siblings.

    Handing these to a recon engine would have it scanning the W3C on behalf of
    every app, which is how an integration gets switched off.
    """
    _raw, result = _run(workspace, target, [_links(value)] if value else [])
    assert _endpoints(result) == set(), reason


@pytest.mark.parametrize("value", [
    "mailto:security@example.com",
    "content://com.example.shop.provider/orders",
    "file:///data/data/com.example.shop/x",
    "ftp://files.example.com/pub",
])
def test_non_web_schemes_are_left_to_other_stages(workspace, target, value) -> None:
    """A recon engine speaks HTTP. A content:// URI is a different finding."""
    _raw, result = _run(workspace, target, [_links(value)])
    assert _endpoints(result) == set()


def test_a_credential_match_is_never_read(workspace, target) -> None:
    """Credential values never leave the worker, and this must not want them."""
    _raw, result = _run(workspace, target, [
        {"rule": "AWS_API_Key", "credential": True, "count": 1,
         "matches": [{"value": None, "preview": "AKIA****", "sha256": "e" * 64}]}])
    assert _endpoints(result) == set() and _assets(result) == set()


def test_every_rejection_is_recorded_with_a_reason(workspace, target) -> None:
    """A filter nobody can inspect is a black box.

    When a tester finds a URL in the package that is not in the report, this is
    where the answer lives.
    """
    raw, _result = _run(workspace, target, [_links(
        API, "http://schemas.android.com/apk/res/android", "/order")])
    rejected = {r["value"]: r["reason"] for r in raw.payload["rejected"]}
    assert "/order" in rejected
    assert "not an absolute URL" in rejected["/order"]
    assert "namespace" in rejected["http://schemas.android.com/apk/res/android"]


# ------------------------------------------------------------- cloud assets

def test_an_s3_bucket_becomes_a_cloud_asset_not_an_endpoint(
        workspace, target) -> None:
    """A named store that may be world readable is a different question."""
    _raw, result = _run(workspace, target, [_links(f"https://{BUCKET_HOST}")])
    assert _endpoints(result) == set()
    assert _assets(result) == {"aws-s3:shop-example-uploads"}

    asset = next(e for e in result.entities if e.type is EntityType.CLOUD_ASSET)
    assert asset.attributes["provider"] == "aws-s3"
    assert asset.attributes["bucket"] == "shop-example-uploads"


def test_a_bucket_reported_without_a_scheme_is_still_caught(
        workspace, target) -> None:
    """apkleaks reports S3 buckets as a bare hostname."""
    _raw, result = _run(workspace, target, [
        _links(BUCKET_HOST, rule="Amazon_AWS_S3_Bucket")])
    assert _assets(result) == {"aws-s3:shop-example-uploads"}


def test_the_same_bucket_from_two_rules_is_one_node(workspace, target) -> None:
    """apkleaks reports the fixture's bucket twice, by host and by URL."""
    _raw, result = _run(workspace, target, [
        _links(BUCKET_HOST, rule="Amazon_AWS_S3_Bucket"),
        _links(f"https://{BUCKET_HOST}")])
    assert len(_assets(result)) == 1


@pytest.mark.parametrize("host,provider,bucket", [
    ("data.s3.amazonaws.com", "aws-s3", "data"),
    ("assets.storage.googleapis.com", "gcp-gcs", "assets"),
    ("shop.firebaseio.com", "firebase-rtdb", "shop"),
    ("media.blob.core.windows.net", "azure-blob", "media"),
    ("cdn.digitaloceanspaces.com", "do-spaces", "cdn"),
])
def test_the_major_providers_are_recognised(host, provider, bucket) -> None:
    assert classify_cloud(host, "/") == (provider, bucket)


def test_a_bucket_in_the_path_is_recognised() -> None:
    """The other S3 addressing style puts the bucket after the host."""
    assert classify_cloud("s3.amazonaws.com", "/shop-uploads/x.png") == \
        ("aws-s3", "shop-uploads")


def test_an_ordinary_host_is_not_a_cloud_asset() -> None:
    assert classify_cloud("api.shop.example.com", "/v1") is None


# ---------------------------------------------------------------- findings

def test_a_cleartext_endpoint_is_a_finding(workspace, target) -> None:
    _raw, result = _run(workspace, target, [_links(LEGACY)])
    spec = weakness("android.network.cleartext-endpoint")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity is spec.severity is Severity.HIGH
    assert finding.cwe == spec.cwe
    assert "legacy.shop.example.com" in finding.title
    assert finding.remediation is not None


def test_an_https_endpoint_is_not_a_finding(workspace, target) -> None:
    _raw, result = _run(workspace, target, [_links(API)])
    assert result.findings == []


def test_the_cleartext_finding_links_to_its_endpoint_node(
        workspace, target) -> None:
    """So the graph can be asked what talks to the plaintext host."""
    _raw, result = _run(workspace, target, [_links(LEGACY)])
    assert result.findings[0].entity_ids == [f"endpoint:{LEGACY}"]


def test_rerunning_produces_identical_fingerprints(workspace, target) -> None:
    _raw_a, first = _run(workspace, target, [_links(LEGACY)])
    _raw_b, second = _run(workspace, target, [_links(LEGACY)])
    assert [f.fingerprint for f in first.findings] == \
        [f.fingerprint for f in second.findings]


# ------------------------------------------------------------------ scanning

def test_the_scan_records_that_it_ran(workspace, target) -> None:
    """A package with no endpoints and a stage that never ran differ."""
    _raw, result = _run(workspace, target, [_links("/order")])
    app = next(e for e in result.entities if e.type is EntityType.APP)
    summary = app.attributes["endpoint_scan"]
    assert summary["endpoints"] == 0
    assert summary["rejected"] == 1


def test_the_verdict_document_is_persisted(workspace, target) -> None:
    raw, result = _run(workspace, target, [_links(API)])
    assert raw.raw_path and workspace.resolve(raw.raw_path).is_file()
    assert raw.raw_path in result.artifacts


# ------------------------------------------------------------- normalisation

@pytest.mark.parametrize("value,expected", [
    ("https://Api.Example.COM/v1", "https://api.example.com/v1"),
    ("https://api.example.com", "https://api.example.com/"),
    ("https://api.example.com:8443/v1", "https://api.example.com:8443/v1"),
    ("  https://api.example.com/v1  ", "https://api.example.com/v1"),
    ('"https://api.example.com/v1"', "https://api.example.com/v1"),
])
def test_urls_normalise_to_one_form(value, expected) -> None:
    """Two spellings of one endpoint must not become two nodes."""
    parsed = normalise_url(value)
    assert parsed is not None and parsed[0] == expected


def test_localhost_survives_because_a_dev_endpoint_is_a_real_finding() -> None:
    """A hostname with no dot is usually noise. This one is not."""
    parsed = normalise_url("http://localhost:8080/debug")
    assert parsed is not None and parsed[2] == "localhost"


def test_a_private_address_is_flagged_rather_than_dropped(
        workspace, target) -> None:
    _raw, result = _run(workspace, target, [_links("http://192.168.1.10:3000/api")])
    endpoint = next(e for e in result.entities if e.type is EntityType.ENDPOINT)
    assert endpoint.attributes["private"] is True


# ------------------------------------------------------------------- iOS source

IOS_BUNDLE = "com.example.demo"


@pytest.fixture()
def ios_target(tmp_path: Path) -> Target:
    sample = tmp_path / "demo.ipa"
    sample.write_bytes(b"PK\x03\x04")
    return Target(project_id="p", platform=Platform.IOS, sample_path=sample,
                  sha256="e" * 64, name="Demo", app_key=IOS_BUNDLE)


def _ios_source(workspace: Workspace, *urls: str) -> None:
    """Write the ios-unpack worker's output where the extractor looks for it."""
    path = workspace.raw_dir("ios-unpack") / "ios-unpack.json"
    path.write_text(json.dumps({"ok": True, "tool": "ios-unpack",
                                "endpoints": list(urls)}), encoding="utf-8")


def _run_ios(workspace: Workspace, target: Target, *urls: str):
    _ios_source(workspace, *urls)
    analyzer = EndpointExtractAnalyzer()
    raw = analyzer.run(target, workspace, None, None)
    return raw, analyzer.normalize(raw, target)


def test_endpoint_extract_runs_on_ios() -> None:
    assert Platform.IOS in EndpointExtractAnalyzer().platforms


def test_ios_urls_become_the_same_endpoint_and_cloud_nodes(
        workspace, ios_target) -> None:
    """The iOS URL list classifies exactly as the Android one: same node types,
    the namespace host dropped, the bucket split out as a cloud asset."""
    _raw, result = _run_ios(
        workspace, ios_target,
        "https://api.example.com/v1/login",
        "http://schemas.android.com/apk/res/android",   # namespace, dropped
        "https://my-bucket.s3.amazonaws.com/")
    assert _endpoints(result) == {"https://api.example.com/v1/login"}
    assert _assets(result) == {"aws-s3:my-bucket"}


def test_ios_cleartext_endpoint_is_flagged_with_the_ios_key(
        workspace, ios_target) -> None:
    _raw, result = _run_ios(workspace, ios_target, "http://legacy.example.com/ping")
    cleartext = [f for f in result.findings if f.weakness_key.endswith("cleartext-endpoint")]
    assert len(cleartext) == 1
    assert cleartext[0].weakness_key == "ios.network.cleartext-endpoint"
    assert cleartext[0].severity is Severity.HIGH


def test_ios_endpoint_has_the_talks_to_edge(workspace, ios_target) -> None:
    _raw, result = _run_ios(workspace, ios_target, "https://api.example.com/v1")
    assert any(e.type is EdgeType.TALKS_TO for e in result.edges)


def test_ios_without_the_unpack_output_is_honest(workspace, ios_target) -> None:
    analyzer = EndpointExtractAnalyzer()
    raw = analyzer.run(ios_target, workspace, None, None)
    assert not raw.ok and "ios-unpack" in raw.error
