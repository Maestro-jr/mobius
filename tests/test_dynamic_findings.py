"""Dynamic findings, and the one property that makes Phase 3 worth its risk.

A runtime finding is an ordinary Finding: same schema, same graph, same
fingerprint construction. The test that matters is that a thing themob watched
happen merges with the thing a static tool suspected, because that merge is the
whole payoff. "semgrep saw the call and we watched it fire" is the strongest
claim themob can make, and it only works if the two land on one fingerprint and
the voting layer reads them as independent methods.
"""
from __future__ import annotations

import pytest

from themob.dynamic.capture import CaptureResult, Flow
from themob.dynamic.findings import (Observation, from_capture, from_frida,
                                     parse_frida_events)
from themob.model.enums import EvidenceKind
from themob.model.findings import Finding
from themob.normalize.voting import METHODS, Vote, combine


# ------------------------------------------------------------------ parsing

def test_only_tagged_lines_are_read() -> None:
    """The rest of the stream is Frida's own chatter, off a hostile process."""
    obs = parse_frida_events([
        "Spawning `com.example.shop`...",
        'themob-observe {"kind":"cipher","transformation":"DES/CBC"}',
        "not our line at all",
        'themob-observe {"kind":"ready","hooks":["Cipher"]}',
        'themob-observe not-json-after-the-tag',
    ])
    assert len(obs) == 1
    assert obs[0].kind == "cipher"


def test_ready_and_error_events_are_not_observations() -> None:
    obs = parse_frida_events([
        'themob-observe {"kind":"ready"}',
        'themob-observe {"kind":"error","message":"x"}',
    ])
    assert obs == []


# ------------------------------------------------------------------- frida

def test_a_weak_cipher_seen_running_becomes_a_finding() -> None:
    findings = from_frida([
        Observation("cipher", {"transformation": "DES/CBC/PKCS5Padding"})],
        app_entity_id="app-1")

    assert len(findings) == 1
    assert findings[0].weakness_key == "android.crypto.weak-cipher-mode"
    assert findings[0].sources[0].tool == "frida"
    assert "app-1" in findings[0].entity_ids


def test_a_strong_cipher_is_not_a_finding() -> None:
    """Watching AES/GCM is not an accusation."""
    assert from_frida([
        Observation("cipher", {"transformation": "AES/GCM/NoPadding"})]) == []


def test_ecb_is_flagged_whatever_the_cipher() -> None:
    findings = from_frida([
        Observation("cipher", {"transformation": "AES/ECB/PKCS5Padding"})])
    assert findings and findings[0].weakness_key == "android.crypto.weak-cipher-mode"


def test_a_broken_hash_seen_running_becomes_a_finding() -> None:
    findings = from_frida([Observation("digest", {"algorithm": "MD5"})])
    assert findings and findings[0].weakness_key == "android.crypto.weak-hash"


def test_the_same_weakness_seen_repeatedly_is_one_finding() -> None:
    """An app that hashes a hundred times with MD5 has one finding, not a hundred."""
    findings = from_frida([Observation("digest", {"algorithm": "MD5"})] * 100)
    assert len(findings) == 1


def test_a_secret_key_observation_is_not_an_accusation_on_its_own() -> None:
    """Behaviour worth a tester's eye, but not a weakness by itself."""
    assert from_frida([
        Observation("secret-key", {"algorithm": "AES", "key_length": 16})]) == []


# ------------------------------------------------------------------ capture

def test_cleartext_seen_on_the_wire_becomes_a_finding() -> None:
    result = CaptureResult(flows=[
        Flow(host="api.example.com", method="POST", scheme="http", path="/login")])
    findings = from_capture(result, endpoint_ids={"api.example.com": "ep-1"})

    assert len(findings) == 1
    assert findings[0].weakness_key == "android.network.cleartext-endpoint"
    assert findings[0].sources[0].tool == "mitmproxy"
    assert findings[0].entity_ids == ["ep-1"]
    assert findings[0].evidence[0].kind == EvidenceKind.HTTP


def test_https_traffic_is_not_a_finding() -> None:
    result = CaptureResult(flows=[
        Flow(host="api.example.com", scheme="https", path="/x")])
    assert from_capture(result) == []


def test_a_finding_without_a_known_endpoint_still_stands() -> None:
    """The observation is real even if the graph never had that node."""
    result = CaptureResult(flows=[
        Flow(host="new.example.com", scheme="http", path="/y")])
    findings = from_capture(result)
    assert findings and findings[0].entity_ids == []


# --------------------------------------------- the merge that justifies it all

def test_a_runtime_finding_merges_with_the_static_one() -> None:
    """The whole point: watched-it-happen lands on suspected-from-code.

    Both build the fingerprint from the canonical weakness and the same value,
    so they collide. This is what lets the storage upsert merge them into one
    finding with two sources.
    """
    key = "android.crypto.weak-hash"
    value = "md5"

    static = Finding.compute_fingerprint(key, None, value)
    runtime = from_frida([Observation("digest", {"algorithm": "MD5"})])[0]

    assert runtime.fingerprint == static


def test_runtime_and_static_agreement_reads_as_two_methods() -> None:
    """frida is its own method, so agreeing with semgrep raises confidence."""
    assert METHODS["frida"] == "runtime"
    assert METHODS["mitmproxy"] == "runtime"

    # semgrep (semantic) and frida (runtime) are independent methods, so the
    # voting layer treats their agreement as corroboration rather than an echo.
    both = combine([Vote("semgrep", 0.8), Vote("frida", 0.8)])
    only_static = combine([Vote("semgrep", 0.8)])

    assert set(both.methods) == {"semantic", "runtime"}
    assert both.corroborated
    assert both.confidence > only_static.confidence


def test_two_static_pattern_tools_agree_less_than_a_runtime_witness() -> None:
    """A runtime witness is worth more than a second reader of the same code."""
    pattern_pair = combine([Vote("gitleaks", 0.8), Vote("apkleaks", 0.8)])
    with_runtime = combine([Vote("gitleaks", 0.8), Vote("frida", 0.8)])

    # Two pattern tools share a method, so they do not compound at all.
    assert not pattern_pair.corroborated
    assert with_runtime.corroborated
    assert with_runtime.confidence > pattern_pair.confidence
