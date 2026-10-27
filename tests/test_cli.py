"""The headless scan CLI, the part a build pipeline runs.

No Docker here: the container-run is replaced by a fake pipeline that seeds a
finding, because what these tests are about is the CLI's contract, that it
refuses without authorization, writes the reports including SARIF, and returns
the exit code a build step gates on, not that androguard works (the docker
suite covers that).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob import cli
from themob.model.enums import Severity
from themob.model.findings import Finding, FindingSource
from themob.orchestrator.events import PipelineState
from themob.orchestrator.pipeline import RunSummary


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """A throwaway THEMOB_HOME so the scan never touches the real one."""
    root = tmp_path / "home"
    monkeypatch.setenv("THEMOB_HOME", str(root))
    return root


def _fake_pipeline(severity: Severity):
    """A pipeline whose run seeds one finding of the given severity."""
    def run(self, project, target, workspace, **kwargs):
        self._repos.findings.upsert(project.id, Finding(
            fingerprint="f" * 64, weakness_key="android.config.debuggable",
            title="Application is debuggable", severity=severity,
            confidence=0.9,
            sources=[FindingSource(tool="config-audit", rule="x")]))
        return RunSummary(project_id=project.id, state=PipelineState.DONE)
    return run


def _args(sample, out, **over):
    ns = cli.build_parser().parse_args(
        [str(sample), "--engagement", "ENG-1", "--out", str(out),
         *[x for k, v in over.items() for x in (f"--{k}", str(v))]])
    return ns


def _patch_engine(monkeypatch, severity=Severity.MEDIUM):
    from themob.sandbox.runner import SandboxRunner
    from themob.orchestrator.pipeline import Pipeline

    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: True)
    monkeypatch.setattr(Pipeline, "run", _fake_pipeline(severity))


# ------------------------------------------------------------------ threshold

def test_gate_exit_is_pure_and_respects_the_threshold() -> None:
    from types import SimpleNamespace

    def report(*severities):
        reported = [SimpleNamespace(finding=SimpleNamespace(severity=s))
                    for s in severities]
        return SimpleNamespace(reported=reported)

    assert cli.gate_exit(report(Severity.HIGH), "none") == 0
    assert cli.gate_exit(report(Severity.HIGH), "high") == 1
    assert cli.gate_exit(report(Severity.MEDIUM), "high") == 0
    assert cli.gate_exit(report(Severity.CRITICAL), "high") == 1
    assert cli.gate_exit(report(), "critical") == 0


# --------------------------------------------------------------------- parsing

def test_engagement_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["app.apk"])


# ------------------------------------------------------------------- refusals

def test_a_missing_file_is_a_usage_error(home, tmp_path) -> None:
    code = cli.scan(_args(tmp_path / "nope.apk", tmp_path / "out"))
    assert code == 2


def test_no_docker_is_a_usage_error(home, sample_apk, tmp_path,
                                    monkeypatch) -> None:
    from themob.sandbox.runner import SandboxRunner
    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: False)

    code = cli.scan(_args(sample_apk, tmp_path / "out"))
    assert code == 2


# ------------------------------------------------------------------- the scan

def test_a_scan_writes_the_reports_including_sarif(home, sample_apk, tmp_path,
                                                   monkeypatch, capsys) -> None:
    _patch_engine(monkeypatch, Severity.MEDIUM)
    out = tmp_path / "out"

    code = cli.scan(_args(sample_apk, out))

    assert code == 0                                     # default fail-on none
    assert (out / "themob-report.html").is_file()
    assert (out / "themob-report.json").is_file()
    sarif_file = out / "themob-report.sarif.json"
    assert sarif_file.is_file()
    doc = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"

    printed = capsys.readouterr().out
    assert "records an authorization attestation" in printed


def test_fail_on_gates_the_build(home, sample_apk, tmp_path, monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.HIGH)
    code = cli.scan(_args(sample_apk, tmp_path / "out", **{"fail-on": "high"}))
    assert code == 1


def test_a_finding_below_the_threshold_does_not_gate(home, sample_apk, tmp_path,
                                                     monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.LOW)
    code = cli.scan(_args(sample_apk, tmp_path / "out", **{"fail-on": "high"}))
    assert code == 0


def test_the_scan_is_authorized_under_the_engagement(home, sample_apk, tmp_path,
                                                     monkeypatch) -> None:
    """The attestation the CLI records is the one the report then carries."""
    _patch_engine(monkeypatch, Severity.MEDIUM)
    out = tmp_path / "out"
    cli.scan(_args(sample_apk, out, operator="ci@lab"))

    doc = json.loads((out / "themob-report.json").read_text(encoding="utf-8"))
    assert doc["provenance"]["authorization_ref"] == "ENG-1"
    assert doc["provenance"]["authorized_by"] == "ci@lab"


def test_scan_routes_from_the_module_entry(monkeypatch) -> None:
    """`python -m themob scan ...` reaches the CLI, not the console."""
    from themob import __main__

    seen = {}

    def fake_scan_main(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("themob.cli.main", fake_scan_main)
    assert __main__.main(["scan", "x.apk", "--engagement", "E"]) == 0
    assert seen["argv"] == ["x.apk", "--engagement", "E"]


# ------------------------------------------------------- baseline gating

def _baseline_file(tmp_path, fingerprints):
    import json as _json
    doc = {"sections": [{"findings": [{"fingerprint": fp} for fp in fingerprints]}],
           "suppressed": []}
    path = tmp_path / "baseline.json"
    path.write_text(_json.dumps(doc), encoding="utf-8")
    return path


def test_baseline_suppresses_inherited_findings_from_the_gate(
        home, sample_apk, tmp_path, monkeypatch) -> None:
    """A high finding already in the baseline must not fail the build."""
    _patch_engine(monkeypatch, Severity.HIGH)          # seeds fingerprint "f"*64
    baseline = _baseline_file(tmp_path, ["f" * 64])

    code = cli.scan(_args(sample_apk, tmp_path / "out",
                          **{"fail-on": "high", "baseline": str(baseline)}))
    assert code == 0, "an inherited finding should not gate the build"


def test_a_new_finding_still_gates_with_a_baseline(
        home, sample_apk, tmp_path, monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.HIGH)          # fingerprint "f"*64
    baseline = _baseline_file(tmp_path, ["different" + "0" * 55])

    code = cli.scan(_args(sample_apk, tmp_path / "out",
                          **{"fail-on": "high", "baseline": str(baseline)}))
    assert code == 1, "a newly introduced finding should gate the build"


def test_an_unreadable_baseline_is_a_usage_error(
        home, sample_apk, tmp_path, monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.HIGH)
    code = cli.scan(_args(sample_apk, tmp_path / "out",
                          **{"baseline": str(tmp_path / "absent.json")}))
    assert code == 2


def test_diff_routes_from_the_module_entry(monkeypatch) -> None:
    from themob import __main__

    seen = {}

    def fake_diff_main(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("themob.cli.diff_main", fake_diff_main)
    assert __main__.main(["diff", "a.json", "b.json"]) == 0
    assert seen["argv"] == ["a.json", "b.json"]


# ------------------------------------------------------- verify + signing

def test_verify_reports_an_intact_bundle(home, sample_apk, tmp_path,
                                         monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.MEDIUM)
    out = tmp_path / "bundle"
    cli.scan(_args(sample_apk, out))

    assert cli.verify_main([str(out)]) == 0


def test_verify_catches_a_tampered_bundle(home, sample_apk, tmp_path,
                                          monkeypatch) -> None:
    _patch_engine(monkeypatch, Severity.MEDIUM)
    out = tmp_path / "bundle"
    cli.scan(_args(sample_apk, out))

    report = out / "themob-report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert cli.verify_main([str(out)]) == 1


def test_verify_without_a_manifest_is_a_usage_error(tmp_path) -> None:
    assert cli.verify_main([str(tmp_path)]) == 2


def test_scan_can_sign_the_deliverable(home, sample_apk, tmp_path,
                                       monkeypatch) -> None:
    from themob.report import signing

    if not signing.available():
        import pytest as _pytest
        _pytest.skip("cryptography is not installed")

    private_pem, _ = signing.generate_keypair()
    key = tmp_path / "key.pem"
    key.write_bytes(private_pem)

    _patch_engine(monkeypatch, Severity.MEDIUM)
    out = tmp_path / "bundle"
    cli.scan(_args(sample_apk, out, sign=str(key)))

    assert (out / "manifest.sig").is_file()
    assert cli.verify_main([str(out)]) == 0


def test_verify_routes_from_the_module_entry(monkeypatch) -> None:
    from themob import __main__

    seen = {}

    def fake_verify_main(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr("themob.cli.verify_main", fake_verify_main)
    assert __main__.main(["verify", "somedir"]) == 0
    assert seen["argv"] == ["somedir"]
