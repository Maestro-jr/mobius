"""The semgrep rule pack and adapter.

The rule pack is checked here because a rule carrying a weakness key that no
pack defines is silently useless: the adapter refuses it, so the rule matches
code and produces nothing, and the suite stays green while a whole class of
finding quietly stops being reported.

The adapter is checked for one thing above all: that eight matches of the same
weak cipher in one class come out as one finding that says where all eight are,
not eight rows saying the same thing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from themob.adapters.base import RawResult, Target
from themob.adapters.semgrep_scan import SemgrepScanAnalyzer
from themob.knowledge import KNOWLEDGE_DIR, get as weakness, keys
from themob.model.enums import EdgeType, EntityType, Platform, Severity, Stage
from themob.storage.workspace import Workspace

PACKAGE = "com.example.shop"
JAVA = "jadx/sources/com/example/shop/SyncService.java"

_RULES_DIR = KNOWLEDGE_DIR / "semgrep"


# --------------------------------------------------------------- the rules

def _rule_files():
    return sorted(_RULES_DIR.glob("*.yml")) + sorted(_RULES_DIR.glob("*.yaml"))


def test_the_rule_pack_ships() -> None:
    """Section 13 puts rule packs in knowledge/, beside the weakness packs."""
    assert _RULES_DIR.is_dir()
    assert _rule_files(), "no semgrep rules are shipped"


def test_every_rule_names_a_weakness_that_exists() -> None:
    """A rule whose key is not in a pack matches code and produces nothing.

    The adapter refuses unknown keys rather than inventing a finding with no
    severity behind it, so a typo here is a rule that silently stops working.
    """
    known = keys()
    seen = 0
    for path in _rule_files():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in document.get("rules") or []:
            seen += 1
            key = (rule.get("metadata") or {}).get("themob-weakness")
            assert key, f"{rule.get('id')} declares no themob-weakness"
            assert key in known, \
                f"{rule.get('id')} names {key!r}, which no weakness pack defines"
    assert seen >= 2, "the scan found too few rules to prove anything"


def test_every_rule_is_structurally_complete() -> None:
    for path in _rule_files():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in document.get("rules") or []:
            assert rule.get("id"), f"a rule in {path.name} has no id"
            assert rule.get("languages"), f"{rule['id']} declares no language"
            assert rule.get("message"), f"{rule['id']} has no message"
            assert rule.get("severity"), f"{rule['id']} has no severity"


def test_rule_ids_are_unique_across_the_pack() -> None:
    ids = []
    for path in _rule_files():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        ids += [r.get("id") for r in (document.get("rules") or [])]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"


# ------------------------------------------------------------------ helpers

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
        "rule": "themob-weak-cipher-mode",
        "weakness": "android.crypto.weak-cipher-mode",
        "message": "Block cipher requested in ECB mode.",
        "file": JAVA,
        "line": 21,
        "snippet": 'Cipher.getInstance("AES/ECB/PKCS5Padding")',
        "severity": "ERROR",
        "confidence": "HIGH",
    }
    doc.update(overrides)
    return doc


def _raw(*hits, ok=True, **extra) -> RawResult:
    payload = {
        "ok": True, "error": None, "tool": "semgrep",
        "tool_version": "1.90.0",
        "findings": list(hits),
        "scanned": {"files": 12, "rules": 2},
        "truncated": False, "rule_errors": [],
    }
    payload.update(extra)
    return RawResult(analyzer="semgrep-scan", ok=ok, payload=payload,
                     raw_path="raw/semgrep-scan/semgrep.json")


def _normalize(target, *hits, **extra):
    return SemgrepScanAnalyzer().normalize(_raw(*hits, **extra), target)


# ------------------------------------------------------------------- shape

def test_the_adapter_declares_itself_correctly() -> None:
    analyzer = SemgrepScanAnalyzer()
    assert analyzer.stage is Stage.SAST
    assert analyzer.image == "themob/semgrep:1"
    assert analyzer.tool == "semgrep"


def test_a_failed_run_produces_nothing(target) -> None:
    result = SemgrepScanAnalyzer().normalize(
        RawResult(analyzer="semgrep-scan", ok=False, error="boom"), target)
    assert result.findings == [] and result.entities == []


# ---------------------------------------------------------------- findings

def test_a_match_becomes_a_finding_keyed_by_the_weakness(target) -> None:
    result = _normalize(target, _hit())
    assert len(result.findings) == 1
    finding = result.findings[0]
    spec = weakness("android.crypto.weak-cipher-mode")

    assert finding.title == spec.title
    assert finding.severity is spec.severity
    assert finding.masvs_control == spec.masvs_control
    assert finding.cwe == spec.cwe
    assert finding.sources[0].tool == "semgrep"
    assert finding.sources[0].rule == "themob-weak-cipher-mode"


def test_repeated_matches_in_one_file_are_one_finding(target) -> None:
    """Eight rows for the same weak cipher is a worse report than one row.

    The reader needs to know the file uses ECB and where; they do not need the
    same sentence eight times.
    """
    result = _normalize(target, _hit(line=21), _hit(line=44), _hit(line=77))
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert "3 occurrences" in finding.description
    for line in ("21", "44", "77"):
        assert line in finding.description
    # The location points at the first, so a reader has somewhere to start.
    assert finding.location.line == 21


def test_the_same_weakness_in_two_files_is_two_findings(target) -> None:
    other = "jadx/sources/com/example/shop/Other.java"
    result = _normalize(target, _hit(), _hit(file=other))
    assert len(result.findings) == 2
    assert len({f.fingerprint for f in result.findings}) == 2


def test_two_weaknesses_in_one_file_are_two_findings(target) -> None:
    result = _normalize(target, _hit(), _hit(
        rule="themob-weak-hash", weakness="android.crypto.weak-hash",
        snippet='MessageDigest.getInstance("MD5")', line=30))
    assert len(result.findings) == 2
    assert {f.title for f in result.findings} == {
        weakness("android.crypto.weak-cipher-mode").title,
        weakness("android.crypto.weak-hash").title,
    }


def test_the_fingerprint_ignores_the_line_number(target) -> None:
    """A line moves whenever anything above it changes.

    Keying on it would make every re-run report the same issue again as a new
    one, which is how a findings list stops being trustworthy.
    """
    first = _normalize(target, _hit(line=21)).findings[0]
    second = _normalize(target, _hit(line=99)).findings[0]
    assert first.fingerprint == second.fingerprint


def test_an_unknown_weakness_key_is_refused(target) -> None:
    """Better no finding than one with no severity and no standards reference.

    This is what a typo in a rule's metadata looks like, and it must not reach
    a report.
    """
    result = _normalize(target, _hit(weakness="android.crypto.typo"))
    assert result.findings == []


def test_a_hit_with_no_weakness_key_is_refused(target) -> None:
    result = _normalize(target, _hit(weakness=""))
    assert result.findings == []


def test_findings_require_manual_validation(target) -> None:
    """A pattern match on decompiled code is not proof the path matters."""
    result = _normalize(target, _hit())
    assert result.findings[0].requires_manual_validation is True
    assert result.findings[0].confidence < 0.9


# ------------------------------------------------------------ crypto usage

def test_a_crypto_match_becomes_a_graph_node(target) -> None:
    """The plan puts CryptoUsage in the graph so a later stage can pivot."""
    result = _normalize(target, _hit(line=21), _hit(line=44))
    nodes = [e for e in result.entities if e.type is EntityType.CRYPTO_USAGE]

    assert len(nodes) == 1
    node = nodes[0]
    assert node.attributes["weakness"] == "android.crypto.weak-cipher-mode"
    assert node.attributes["file"] == JAVA
    assert node.attributes["occurrences"] == 2
    assert node.attributes["lines"] == [21, 44]


def test_the_app_uses_every_crypto_node(target) -> None:
    result = _normalize(target, _hit())
    uses = [e for e in result.edges if e.type is EdgeType.USES]
    assert len(uses) == 1
    assert uses[0].src.type is EntityType.APP
    assert uses[0].dst.type is EntityType.CRYPTO_USAGE


def test_the_finding_links_to_its_crypto_node(target) -> None:
    result = _normalize(target, _hit())
    node = next(e for e in result.entities
                if e.type is EntityType.CRYPTO_USAGE)
    assert result.findings[0].entity_ids == [f"crypto_usage:{node.key}"]


# ---------------------------------------------------------- error handling

def test_a_worker_failure_outranks_the_exit_code(workspace) -> None:
    from themob.sandbox.runner import SandboxResult

    payload = json.dumps({"ok": False, "tool": "semgrep",
                          "error": "the image was built without its rule pack"
                          }).encode()
    raw = SemgrepScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=payload, exit_code=1, error="exited with code 1"),
        workspace)
    assert not raw.ok
    assert "rule pack" in raw.error


def test_a_timeout_outranks_the_worker(workspace) -> None:
    from themob.sandbox.runner import SandboxResult

    payload = json.dumps({"ok": False, "error": "something"}).encode()
    raw = SemgrepScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=payload, exit_code=124, timed_out=True,
                      error="timed out after 1800s"),
        workspace)
    assert raw.error == "timed out after 1800s"


def test_unparseable_output_is_reported_clearly(workspace) -> None:
    from themob.sandbox.runner import SandboxResult

    raw = SemgrepScanAnalyzer()._to_raw_result(
        SandboxResult(stdout=b"<html>", exit_code=0), workspace)
    assert not raw.ok and "not valid JSON" in raw.error
