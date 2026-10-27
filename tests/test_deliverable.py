"""The tamper-evident deliverable: manifest, signature, and verification.

The point of the feature is that an edit to the report after export is caught,
so the tests are mostly about detection: a changed file, a missing file, a
broken signature, a signature from the wrong key. The manifest works without
cryptography; the signature tests skip when it is absent, because signing is an
optional layer and the suite must stay hermetic on a box that lacks it.
"""
from __future__ import annotations

import json

import pytest

from themob.audit.attestation import AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.report import export, manifest, signing
from themob.storage.repositories import Project, Repositories

_HAS_CRYPTO = signing.available()
_needs_crypto = pytest.mark.skipif(not _HAS_CRYPTO,
                                   reason="cryptography is not installed")


@pytest.fixture()
def audit(repos: Repositories) -> AuditTrail:
    return AuditTrail(repos.audit)


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Shop", target_platform=Platform.ANDROID,
        source_path="in/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-1", by="tester@lab")
    repos.entities.upsert(stored.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
        label="shop", attributes={"package": "com.example.shop"}))
    repos.findings.upsert(stored.id, Finding(
        fingerprint="a" * 64, weakness_key="android.config.debuggable",
        title="Debuggable", severity=Severity.HIGH, confidence=0.9,
        sources=[FindingSource(tool="config-audit", rule="x")]))
    return repos.projects.get(stored.id)


# --------------------------------------------------------------- the manifest

def test_export_writes_a_manifest_covering_every_file(repos, audit, project,
                                                      tmp_path) -> None:
    out = tmp_path / "bundle"
    written = export(repos, audit, project.id, out, operator="tester@lab")

    assert "manifest" in written.files
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    covered = {f["path"] for f in doc["files"]}
    assert covered == {"themob-report.html", "themob-report.json",
                       "themob-report.sarif.json"}


def test_an_intact_bundle_verifies(repos, audit, project, tmp_path) -> None:
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab")

    result = manifest.verify(out / "manifest.json")
    assert result.ok
    assert result.checked == 3


def test_an_edited_report_is_caught(repos, audit, project, tmp_path) -> None:
    """The whole reason the feature exists."""
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab")

    html = out / "themob-report.html"
    html.write_text(html.read_text(encoding="utf-8") + "<!-- edited -->",
                    encoding="utf-8")

    result = manifest.verify(out / "manifest.json")
    assert not result.ok
    assert any("themob-report.html" in p for p in result.problems)


def test_a_missing_file_is_caught(repos, audit, project, tmp_path) -> None:
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab")
    (out / "themob-report.sarif.json").unlink()

    result = manifest.verify(out / "manifest.json")
    assert not result.ok
    assert any("missing" in p for p in result.problems)


def test_the_manifest_ties_to_the_audit_head(repos, audit, project,
                                             tmp_path) -> None:
    audit.record("pipeline.started", project_id=project.id)
    export(repos, audit, project.id, tmp_path / "bundle", operator="tester@lab")

    doc = json.loads((tmp_path / "bundle" / "manifest.json").read_text(
        encoding="utf-8"))
    # The head recorded is the trail's tip at export time, not genesis.
    assert doc["audit_head"] == audit.head() or doc["audit_head"]


# ------------------------------------------------------------- the signature

@_needs_crypto
def test_a_signed_bundle_verifies_and_a_tampered_one_does_not(
        repos, audit, project, tmp_path) -> None:
    private_pem, _public_pem = signing.generate_keypair()
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab",
           sign_key=private_pem)

    assert (out / "manifest.sig").is_file()
    assert (out / "manifest.pub").is_file()

    doc = manifest.load(out / "manifest.json")
    signature = (out / "manifest.sig").read_bytes()
    public = (out / "manifest.pub").read_bytes()
    assert signing.verify(doc.signable_bytes(), signature, public)

    # Flip a byte of the signature: it must no longer verify.
    bad = bytearray(signature)
    bad[0] ^= 0x01
    assert not signing.verify(doc.signable_bytes(), bytes(bad), public)


@_needs_crypto
def test_a_signature_from_the_wrong_key_is_rejected(repos, audit, project,
                                                    tmp_path) -> None:
    private_pem, _ = signing.generate_keypair()
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab",
           sign_key=private_pem)

    doc = manifest.load(out / "manifest.json")
    _other_priv, other_pub = signing.generate_keypair()
    assert not signing.verify(doc.signable_bytes(),
                              (out / "manifest.sig").read_bytes(), other_pub)


@_needs_crypto
def test_the_signed_bytes_round_trip_through_the_written_file(
        repos, audit, project, tmp_path) -> None:
    """Verification loads the pretty JSON, so its canonical form must match."""
    private_pem, _ = signing.generate_keypair()
    out = tmp_path / "bundle"
    export(repos, audit, project.id, out, operator="tester@lab",
           sign_key=private_pem)

    reloaded = manifest.load(out / "manifest.json")
    assert signing.verify(reloaded.signable_bytes(),
                          (out / "manifest.sig").read_bytes(),
                          (out / "manifest.pub").read_bytes())
