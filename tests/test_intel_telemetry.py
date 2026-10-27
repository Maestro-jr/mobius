"""Opt-in telemetry: the projection that may leave the machine must be safe.

The decisive test is that no identifier (app name, path, hash, evidence) can
reach the payload, only abstract categories and counts. The rest check the
consent gate: nothing is written without it.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from themob.intel import telemetry
from themob.model.enums import EvidenceKind, FindingStatus, Platform, Severity
from themob.model.findings import Evidence, Finding, FindingSource
from themob.storage.db import open_database
from themob.storage.repositories import Project, Repositories

_sha = itertools.count(1)


def _seed(home: Path, *, name: str, path: str) -> None:
    database = open_database(home / "themob.db")
    try:
        repos = Repositories(database)
        project = Project(name=name, target_platform=Platform.ANDROID,
                          source_path=path, source_sha256=f"{next(_sha):064x}")
        repos.projects.create(project)
        repos.findings.upsert(project.id, Finding(
            fingerprint="a" * 64,
            weakness_key="android.network.cleartext-endpoint",
            title="Cleartext endpoint", severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                               value="http://secret-internal.example.com/login")],
            sources=[FindingSource(tool="t", rule="x")]))
    finally:
        database.close_all()


def test_payload_carries_categories_not_identifiers(tmp_path) -> None:
    _seed(tmp_path, name="SECRET_CLIENT_APP", path="/private/client.apk")
    payload = telemetry.preview(home=tmp_path)
    blob = json.dumps(payload)

    # No identifier of the client's app may appear.
    assert "SECRET_CLIENT_APP" not in blob
    assert "client.apk" not in blob
    assert "/private" not in blob
    assert "secret-internal.example.com" not in blob
    # The abstract weakness key may: it is a taxonomy, not app data.
    assert "android.network.cleartext-endpoint" in blob

    # And the shape is locked to the allowed fields, so a future change cannot
    # quietly smuggle an identifier through.
    assert set(payload) <= telemetry._ALLOWED_TOP
    for weakness in payload["weaknesses"]:
        assert set(weakness) <= telemetry._ALLOWED_WEAKNESS


def test_export_refuses_without_consent(tmp_path) -> None:
    out = tmp_path / "telemetry.json"
    result = telemetry.export(home=tmp_path, out=str(out), consent=False)
    assert not result.ok and "consent" in result.error
    assert not out.exists()           # nothing written without opting in


def test_export_writes_only_with_consent(tmp_path) -> None:
    _seed(tmp_path, name="app", path="app.apk")
    out = tmp_path / "sub" / "telemetry.json"
    result = telemetry.export(home=tmp_path, out=str(out), consent=True)
    assert result.ok and out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == telemetry.SCHEMA
    assert data["findings"] == 1
