"""The semgrep worker's output handling, tested outside the container.

semgrep itself only exists inside the image, so what is exercised here is
everything around it: turning its JSON into themob's bounded shape, and the
refusal that stops an image built without its rules from reporting a clean
result for every app.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_WORKER = (Path(__file__).resolve().parent.parent
           / "workers" / "semgrep" / "analyze.py")


@pytest.fixture(scope="module")
def worker():
    spec = importlib.util.spec_from_file_location("themob_semgrep_worker", _WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _result(**overrides) -> dict:
    doc = {
        "check_id": "themob-weak-cipher-mode",
        "path": "/scan/jadx/sources/com/example/shop/SyncService.java",
        "start": {"line": 21},
        "extra": {
            "message": "Block cipher requested in ECB mode.",
            "severity": "ERROR",
            "lines": '        return Cipher.getInstance("AES/ECB/PKCS5Padding");',
            "metadata": {"themob-weakness": "android.crypto.weak-cipher-mode",
                         "confidence": "HIGH"},
        },
    }
    doc.update(overrides)
    return doc


# ------------------------------------------------------------- normalising

def test_a_result_becomes_the_shape_the_adapter_reads(worker) -> None:
    findings, truncated = worker.normalise({"results": [_result()]})
    assert not truncated
    assert len(findings) == 1

    finding = findings[0]
    assert finding["rule"] == "themob-weak-cipher-mode"
    assert finding["weakness"] == "android.crypto.weak-cipher-mode"
    assert finding["line"] == 21
    assert finding["severity"] == "ERROR"
    assert "AES/ECB" in finding["snippet"]


def test_paths_are_reported_relative_to_the_scan_root(worker) -> None:
    """Never the container's own layout: /scan means nothing to a reader."""
    findings, _ = worker.normalise({"results": [_result()]})
    assert findings[0]["file"] == "jadx/sources/com/example/shop/SyncService.java"
    assert not findings[0]["file"].startswith("/scan")


def test_a_rule_without_the_weakness_metadata_comes_back_empty(worker) -> None:
    """The adapter refuses it; the worker's job is only to pass it through."""
    result = _result()
    result["extra"]["metadata"] = {}
    findings, _ = worker.normalise({"results": [result]})
    assert findings[0]["weakness"] == ""


def test_a_missing_line_number_does_not_crash(worker) -> None:
    findings, _ = worker.normalise({"results": [_result(start={})]})
    assert findings[0]["line"] is None


def test_the_finding_cap_is_reported_rather_than_silent(worker) -> None:
    """"2000 findings" and "at least 2000, stopped counting" are different."""
    many = {"results": [_result() for _ in range(worker.MAX_FINDINGS + 10)]}
    findings, truncated = worker.normalise(many)
    assert len(findings) == worker.MAX_FINDINGS
    assert truncated is True


# -------------------------------------------------------------------- main

def test_main_refuses_to_run_without_rules(worker, tmp_path, monkeypatch,
                                           capsys) -> None:
    """An empty ruleset finds nothing and looks exactly like a clean app.

    Refusing is the only honest answer: the alternative is an image that
    reports every package as clean and never says why.
    """
    (tmp_path / "a.java").write_text("class A {}", encoding="utf-8")
    monkeypatch.setattr(worker, "SCAN_DIR", str(tmp_path))
    monkeypatch.setattr(worker, "RULES_DIR", str(tmp_path / "no-rules-here"))
    monkeypatch.setattr(worker, "tool_version", lambda: "stub")

    assert worker.main() == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is False
    assert "without its rule pack" in document["error"]


def test_main_emits_the_contract(worker, tmp_path, monkeypatch, capsys) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "x.yml").write_text("rules: []", encoding="utf-8")
    (tmp_path / "a.java").write_text("class A {}", encoding="utf-8")

    monkeypatch.setattr(worker, "SCAN_DIR", str(tmp_path))
    monkeypatch.setattr(worker, "RULES_DIR", str(rules))
    monkeypatch.setattr(worker, "tool_version", lambda: "1.90.0")
    monkeypatch.setattr(worker, "run_semgrep",
                        lambda: ({"results": [_result()], "errors": []}, None))

    assert worker.main() == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is True
    assert document["scanned"]["rules"] == 1
    assert document["findings"][0]["weakness"] == "android.crypto.weak-cipher-mode"


def test_main_reports_a_semgrep_failure(worker, tmp_path, monkeypatch,
                                        capsys) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "x.yml").write_text("rules: []", encoding="utf-8")

    monkeypatch.setattr(worker, "SCAN_DIR", str(tmp_path))
    monkeypatch.setattr(worker, "RULES_DIR", str(rules))
    monkeypatch.setattr(worker, "tool_version", lambda: "stub")
    monkeypatch.setattr(worker, "run_semgrep", lambda: (None, "semgrep timed out"))

    assert worker.main() == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is False and document["error"] == "semgrep timed out"


def test_main_survives_an_unmounted_scan_directory(worker, monkeypatch,
                                                   capsys) -> None:
    monkeypatch.setattr(worker, "SCAN_DIR", "/definitely/not/here")
    assert worker.main() == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is False and "not mounted" in document["error"]


# ------------------------------------------------- the crash that looked clean

class _Completed:
    """Just enough of subprocess.CompletedProcess for run_semgrep."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run_with(worker, monkeypatch, completed) -> tuple:
    monkeypatch.setattr(worker.subprocess, "run", lambda *a, **k: completed)
    return worker.run_semgrep()


def test_a_crash_that_prints_nothing_is_a_failure_not_a_clean_scan(
        worker, monkeypatch) -> None:
    """The bug this stage shipped with, and the reason it went unnoticed.

    semgrep could not create its log directory under a home it did not have, so
    it exited 1 with a traceback and no stdout. Exit 1 is also what semgrep
    returns for "findings were found", and the parse read
    ``json.loads(stdout or "{}")``, so empty output became a valid document with
    no results. The stage reported a clean scan of an app carrying two
    weaknesses, and every test passed.
    """
    document, error = _run_with(worker, monkeypatch, _Completed(
        1, stdout="", stderr="PermissionError: [Errno 13] Permission denied: '/.semgrep'"))

    assert document is None, "empty output must never parse as a clean scan"
    assert error and "no output" in error
    assert "PermissionError" in error, "the real cause has to reach the operator"


def test_whitespace_only_output_is_also_a_failure(worker, monkeypatch) -> None:
    document, error = _run_with(worker, monkeypatch, _Completed(1, stdout="   \n"))
    assert document is None and error


def test_json_without_a_results_key_is_a_failure(worker, monkeypatch) -> None:
    """A document that parses but carries no results never ran."""
    document, error = _run_with(worker, monkeypatch, _Completed(
        0, stdout=json.dumps({"errors": [], "paths": {}})))
    assert document is None
    assert error and "did not run" in error


def test_an_empty_results_list_is_a_real_clean_scan(worker, monkeypatch) -> None:
    """The distinction that matters: nothing found, versus nothing ran."""
    document, error = _run_with(worker, monkeypatch, _Completed(
        0, stdout=json.dumps({"results": [], "errors": []})))
    assert error is None
    assert document == {"results": [], "errors": []}


def test_findings_still_come_back_on_exit_one(worker, monkeypatch) -> None:
    """Exit 1 with real output is semgrep saying it found something."""
    payload = {"results": [{"check_id": "themob-weak-hash"}], "errors": []}
    document, error = _run_with(worker, monkeypatch,
                                _Completed(1, stdout=json.dumps(payload)))
    assert error is None and document == payload


# --------------------------------------------------- the id semgrep reports

def test_the_config_path_is_stripped_from_the_rule_id(worker) -> None:
    """semgrep prefixes the rule id with the directory it was loaded from.

    With ``--config /opt/themob/rules`` a rule written as
    ``themob-weak-cipher-mode`` comes back as
    ``opt.themob.rules.themob-weak-cipher-mode``. That prefix is the container's
    filesystem layout, and it must not reach a finding record or a report.
    """
    assert worker.rule_id("opt.themob.rules.themob-weak-cipher-mode") == \
        "themob-weak-cipher-mode"


def test_a_bare_rule_id_is_left_alone(worker) -> None:
    assert worker.rule_id("themob-weak-hash") == "themob-weak-hash"


def test_dotted_rule_ids_are_not_mangled(worker) -> None:
    """Only the known prefix is removed, never the last segment.

    Registry rules are dotted by convention, so taking the final segment would
    turn a real id into a fragment.
    """
    dotted = "java.lang.security.audit.crypto.weak-hash"
    assert worker.rule_id(dotted) == dotted


def test_a_missing_rule_id_becomes_unknown(worker) -> None:
    assert worker.rule_id(None) == "unknown"
