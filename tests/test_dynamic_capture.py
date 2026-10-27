"""Traffic capture, where the hazard is decrypting the wrong person's traffic.

No proxy runs. What is tested is the decision the proxy will make: which hosts
get their TLS terminated, which are relayed untouched, and that the addon making
that decision inside mitmproxy agrees exactly with the gate that authorised it.
The live proxy is the one seam left for an integration test on a device.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from themob.audit.attestation import AuditTrail
from themob.dynamic import capture, gate
from themob.dynamic.capture import CaptureError, CapturePlan
from themob.dynamic.gate import (DeviceAttestation, ExecutionAttestation,
                                 ExecutionNotAuthorized, host_in_scope)
from themob.model.enums import Platform
from themob.storage.repositories import Project, Repositories

SERIAL = "emulator-5554"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    return repos.projects.get(stored.id)


def _authorize(repos, project, scope):
    gate.authorize(ExecutionAttestation(
        operator="tester@lab", engagement_ref="ENG-42",
        device=DeviceAttestation(identifier=SERIAL, dedicated_test_device=True,
                                 is_emulator=True),
        traffic_authorized=True, interception_scope=scope),
        project.id, AuditTrail(repos.audit))


def _load_addon():
    spec = importlib.util.spec_from_file_location(
        "scope_filter", capture.ADDON_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------- the addon cannot drift

def test_the_addon_matches_the_gate_exactly() -> None:
    """The copy is allowed; drifting from the original is not.

    The addon runs in mitmproxy's interpreter and cannot import themob, so it
    carries its own copy of host_in_scope. This is the guard that the copy
    stays a copy.
    """
    addon = _load_addon()
    hosts = ["api.example.com", "example.com", "example.com.evil.net",
             "a.b.example.com", "shop.test", "api.shop.test", "",
             "notexample.com", "EXAMPLE.COM", "sub.api.shop.test"]
    scopes = [[".example.com"], ["api.shop.test"],
              [".example.com", "api.shop.test"], [], [".shop.test"]]

    for scope in scopes:
        for host in hosts:
            assert addon.host_in_scope(host, scope) == host_in_scope(host, scope), \
                (host, scope)


def test_the_addon_fails_closed_when_the_scope_cannot_be_read(tmp_path) -> None:
    """An unreadable scope means intercept nothing, never everything."""
    addon = _load_addon()
    assert addon.load_scope(str(tmp_path / "absent.json")) == []

    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    assert addon.load_scope(str(bad)) == []


def test_the_addon_reads_the_scope_themob_writes(tmp_path) -> None:
    addon = _load_addon()
    path = tmp_path / "scope.json"
    path.write_text(json.dumps([".example.com", "api.shop.test"]),
                    encoding="utf-8")
    assert addon.load_scope(str(path)) == [".example.com", "api.shop.test"]


# --------------------------------------------------------------- preparing

def test_capture_needs_the_execution_gate(repos, project, tmp_path) -> None:
    with pytest.raises(ExecutionNotAuthorized):
        capture.mitmproxy_capture(repos, project.id, tmp_path)


def test_the_scope_is_written_for_the_addon_to_read(repos, project,
                                                    tmp_path) -> None:
    _authorize(repos, project, [".example.com", "api.shop.test"])
    plan = capture.mitmproxy_capture(repos, project.id, tmp_path)

    assert plan.kind == "mitmproxy"
    written = json.loads(plan.scope_file.read_text(encoding="utf-8"))
    assert set(written) == {".example.com", "api.shop.test"}
    # The scope travels as a file, not on the command line.
    assert "-s" in plan.command and str(capture.ADDON_PATH) in plan.command
    assert ".example.com" not in " ".join(plan.command)


def test_an_empty_scope_captures_metadata_and_decrypts_nothing(repos, project,
                                                               tmp_path) -> None:
    """A legitimate mode: see which hosts the app talks to, read none of it."""
    _authorize(repos, project, [])
    plan = capture.mitmproxy_capture(repos, project.id, tmp_path)

    assert not plan.intercepts_anything
    assert any("nothing will be decrypted" in line for line in plan.instructions)


def test_a_scoped_capture_says_a_pinned_app_still_needs_unpinning(
        repos, project, tmp_path) -> None:
    """The seam back to 3.3: a CA is not enough against a pinned release."""
    _authorize(repos, project, [".example.com"])
    plan = capture.mitmproxy_capture(repos, project.id, tmp_path)

    joined = " ".join(plan.instructions)
    assert "CA certificate" in joined
    assert "SSL-unpin" in joined
    assert ".example.com" in joined


def test_the_environment_points_the_addon_at_its_files(repos, project,
                                                       tmp_path) -> None:
    _authorize(repos, project, [".example.com"])
    plan = capture.mitmproxy_capture(repos, project.id, tmp_path)
    env = capture.environment(plan)

    assert env["THEMOB_SCOPE_FILE"] == str(plan.scope_file)
    assert env["THEMOB_CAPTURE_LOG"] == str(plan.log_file)


# ------------------------------------------------------- attach-your-own-Burp

def test_a_delegated_capture_runs_no_proxy(repos, project) -> None:
    _authorize(repos, project, [".example.com"])
    plan = capture.delegated_capture(repos, project.id, "127.0.0.1:8080")

    assert plan.kind == "delegated"
    assert plan.command == []
    assert plan.external_proxy == "127.0.0.1:8080"


def test_a_delegated_capture_needs_the_proxy_address(repos, project) -> None:
    _authorize(repos, project, [".example.com"])
    with pytest.raises(CaptureError, match="proxy address"):
        capture.delegated_capture(repos, project.id, "  ")


def test_a_delegated_capture_is_still_gated(repos, project) -> None:
    with pytest.raises(ExecutionNotAuthorized):
        capture.delegated_capture(repos, project.id, "127.0.0.1:8080")


# ------------------------------------------------------------- reading it back

def _log(path: Path, lines) -> Path:
    path.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    return path


def test_a_capture_reports_what_it_decrypted_and_what_it_did_not(
        tmp_path) -> None:
    """The build plan's requirement: the report says which was which."""
    log = _log(tmp_path / "capture.jsonl", [
        {"event": "intercept", "host": "api.example.com"},
        {"event": "passthrough", "host": "graph.facebook.com"},
        {"event": "passthrough", "host": "firebase.googleapis.com"},
        {"event": "request", "host": "api.example.com", "method": "POST",
         "scheme": "https", "path": "/v1/login"},
        {"event": "response", "host": "api.example.com", "status": 200},
    ])
    result = capture.read_capture(log)

    assert result.intercepted_hosts == ["api.example.com"]
    assert "graph.facebook.com" in result.passed_through_hosts
    assert "firebase.googleapis.com" in result.passed_through_hosts
    assert len(result.flows) == 1
    assert result.flows[0].method == "POST"
    assert result.flows[0].status == 200


def test_a_passed_through_host_yields_no_flow(tmp_path) -> None:
    """It was never decrypted, so there is nothing to have seen."""
    log = _log(tmp_path / "capture.jsonl", [
        {"event": "passthrough", "host": "graph.facebook.com"},
    ])
    result = capture.read_capture(log)

    assert result.passed_through_hosts == ["graph.facebook.com"]
    assert result.flows == []


def test_a_malformed_capture_line_is_skipped_not_trusted(tmp_path) -> None:
    """The log records traffic from a hostile app."""
    path = tmp_path / "capture.jsonl"
    path.write_text("\n".join([
        "not json at all",
        json.dumps(["a", "list"]),
        json.dumps({"event": "intercept", "host": "api.example.com"}),
        "",
    ]), encoding="utf-8")
    result = capture.read_capture(path)

    assert result.intercepted_hosts == ["api.example.com"]


def test_a_missing_capture_log_is_empty_not_an_error(tmp_path) -> None:
    result = capture.read_capture(tmp_path / "never-written.jsonl")
    assert result.flows == []
    assert "0 request" in result.summary


# --------------------------------------------------------------- recording

def test_a_plan_records_only_the_hosts_in_scope(repos, project,
                                                tmp_path) -> None:
    _authorize(repos, project, [".example.com"])
    plan = capture.mitmproxy_capture(repos, project.id, tmp_path)
    detail = plan.to_detail()

    assert detail["kind"] == "mitmproxy"
    assert detail["interception_scope"] == [".example.com"]
