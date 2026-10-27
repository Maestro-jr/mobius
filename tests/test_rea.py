"""The REA handoff: themob.rea.

prepare resolves a native library or a decompiled class to its file, bundles it
with context, and returns the rea command; import attaches REA's result to a
finding as external evidence. Both are gated and audited, and themob itself
never runs REA. The tests seed a project with a .so, a decompiled class and a
finding, then exercise both halves plus the refusals.
"""
from __future__ import annotations

import json
from pathlib import Path

from themob import rea
from themob.audit.attestation import Attestation, AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.orchestrator.intake import intake
from themob.storage.db import open_database
from themob.storage.repositories import Repositories
from tests.fixtures.ipa import build_ipa

_FP = "c" * 64
_NATIVE_KEY = "lib/arm64-v8a/libfoo.so"
_FQCN = "com.example.MainActivity"
_MACHO_KEY = "Payload/Demo.app/Demo"


def _seed(sample_apk: Path, tmp_path: Path, *, authorized: bool = True) -> str:
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        audit = AuditTrail(repos.audit)
        result = intake(sample_apk, repos, audit, root=tmp_path)
        if authorized:
            audit.record_attestation(result.project, Attestation(
                target_name="sample.apk", target_sha256=result.sha256,
                operator="tester@lab", engagement_ref="ENG-1", attested=True),
                repos.projects)
        pid = result.project.id
        ws = result.workspace

        # A native library deep under the artifacts tree (as apktool would write
        # it), so _find_native_lib has to search for it by its in-APK path.
        so_dir = ws.artifacts_root / "decoded" / "lib" / "arm64-v8a"
        so_dir.mkdir(parents=True, exist_ok=True)
        (so_dir / "libfoo.so").write_bytes(b"\x7fELF not a real native lib")

        # A decompiled class plus the index the app node points at.
        src_dir = ws.artifacts_root / "jadx" / "sources" / "com" / "example"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "MainActivity.java").write_text(
            "package com.example;\npublic class MainActivity {}\n",
            encoding="utf-8")
        index = ws.artifacts_root / "jadx" / "index.json"
        index.write_text(json.dumps({"classes": [{
            "fqcn": _FQCN, "package": "com.example", "name": "MainActivity",
            "path": "sources/com/example/MainActivity.java"}]}), encoding="utf-8")

        repos.entities.upsert(pid, Entity(
            type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
            label="shop", attributes={"package": "com.example.shop",
                                      "class_index": ws.relative(index)}))
        native = repos.entities.upsert(pid, Entity(
            type=EntityType.NATIVE_LIB, platform=Platform.ANDROID,
            key=_NATIVE_KEY, label="libfoo.so"))
        repos.findings.upsert(pid, Finding(
            fingerprint=_FP, title="Native library has no stack canary",
            severity=Severity.LOW, confidence=0.9, masvs_control="MASVS-CODE-2",
            sources=[FindingSource(tool="nativelib", rule="no_canary")],
            entity_ids=[native.id]))
        return pid
    finally:
        database.close_all()


def _seed_ios(tmp_path: Path, *, authorized: bool = True) -> str:
    """Seed an iOS project whose main Mach-O is on disk under artifacts/ios,
    exactly where M4's ios-unpack stage decodes the bundle."""
    ipa = build_ipa(tmp_path / "demo.ipa")
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        audit = AuditTrail(repos.audit)
        result = intake(ipa, repos, audit, root=tmp_path)
        if authorized:
            audit.record_attestation(result.project, Attestation(
                target_name="demo.ipa", target_sha256=result.sha256,
                operator="tester@lab", engagement_ref="ENG-1", attested=True),
                repos.projects)
        pid = result.project.id
        ws = result.workspace

        # The decoded Mach-O, as ios-unpack writes it to artifacts/ios.
        macho = ws.artifacts_root / "ios" / "Payload" / "Demo.app" / "Demo"
        macho.parent.mkdir(parents=True, exist_ok=True)
        macho.write_bytes(b"\xcf\xfa\xed\xfe a placeholder Mach-O")

        repos.entities.upsert(pid, Entity(
            type=EntityType.APP, platform=Platform.IOS, key="com.example.demo",
            label="Demo", attributes={"bundle_id": "com.example.demo"}))
        native = repos.entities.upsert(pid, Entity(
            type=EntityType.NATIVE_LIB, platform=Platform.IOS, key=_MACHO_KEY,
            label="Demo", attributes={"hardening": {"pie": False,
                                                    "encrypted": False}}))
        repos.findings.upsert(pid, Finding(
            fingerprint="d" * 64, title="Mach-O is not position-independent",
            severity=Severity.MEDIUM, confidence=0.9, masvs_control="MASVS-CODE-4",
            weakness_key="ios.macho.no-pie",
            sources=[FindingSource(tool="ios-macho-audit", rule="ios.macho.no-pie")],
            entity_ids=[native.id]))
        return pid
    finally:
        database.close_all()


def _audit_actions(tmp_path: Path, pid: str) -> list[str]:
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        return [e.action for e in AuditTrail(repos.audit).entries(pid)]
    finally:
        database.close_all()


def _notes(tmp_path: Path, pid: str) -> list[str]:
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        f = repos.findings.get_by_fingerprint(pid, _FP)
        return [n.text for n in repos.findings.notes(f.id)]
    finally:
        database.close_all()


# ------------------------------------------------------------------ prepare

def test_prepare_bundles_a_native_library(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    out = rea.prepare(tmp_path, pid, "native", _NATIVE_KEY,
                      out=str(tmp_path / "hand"))
    assert "error" not in out, out
    assert out["command"].startswith("rea ")
    assert Path(out["file"]).is_file() and Path(out["file"]).name == "libfoo.so"
    assert (Path(out["bundle_dir"]) / "context.json").is_file()
    # The handoff is on the trail.
    assert "rea.prepared" in _audit_actions(tmp_path, pid)


def test_prepare_bundles_a_decompiled_class(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    out = rea.prepare(tmp_path, pid, "class", _FQCN, out=str(tmp_path / "hand2"))
    assert "error" not in out, out
    assert out["target"] == _FQCN
    assert Path(out["file"]).read_text(encoding="utf-8").startswith("package com.example")


def test_prepare_rejects_a_bad_kind_or_unknown_target(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    assert "error" in rea.prepare(tmp_path, pid, "bogus", "x")
    assert "error" in rea.prepare(tmp_path, pid, "native", "lib/does/not.so")
    assert "error" in rea.prepare(tmp_path, pid, "class", "com.nope.Missing")


def test_prepare_refuses_an_unauthorized_project(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path, authorized=False)
    assert "error" in rea.prepare(tmp_path, pid, "native", _NATIVE_KEY)


def test_prepare_bundles_an_ios_macho(tmp_path) -> None:
    """M5: the same native handoff resolves and bundles an iOS Mach-O, which is
    the native-binary case REA exists for. No rea.py change: once the bundle is
    decoded to artifacts/ios (M4), the NATIVE_LIB key resolves by path suffix."""
    pid = _seed_ios(tmp_path)
    out = rea.prepare(tmp_path, pid, "native", _MACHO_KEY,
                      out=str(tmp_path / "ios-hand"))
    assert "error" not in out, out
    assert out["kind"] == "native" and out["target"] == _MACHO_KEY
    dest = Path(out["file"])
    assert dest.is_file() and dest.name == "Demo"
    assert out["command"] == f'rea "{dest}"'
    # The context carries the bundle id, the Mach-O hardening, and the finding
    # themob already has on it, so REA starts from what themob knows.
    context = out["context"]
    assert context["app"]["package"] == "com.example.demo"
    assert context["target"]["attributes"]["hardening"]["pie"] is False
    assert any(f["weakness_key"] == "ios.macho.no-pie"
               for f in context["known_findings"])
    assert "rea.prepared" in _audit_actions(tmp_path, pid)


def test_prepare_resolves_an_ios_macho_by_entity_id(tmp_path) -> None:
    """The target may also be the node's entity id, not just its path key."""
    pid = _seed_ios(tmp_path)
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        native = next(e for e in repos.entities.list(pid)
                      if e.type is EntityType.NATIVE_LIB)
    finally:
        database.close_all()
    out = rea.prepare(tmp_path, pid, "native", native.id,
                      out=str(tmp_path / "ios-hand2"))
    assert "error" not in out and Path(out["file"]).name == "Demo"


# ------------------------------------------------------------------- import

def test_import_attaches_evidence_and_audits(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    out = rea.import_summary(tmp_path, pid, _FP,
                             "REA found a custom XOR cipher in JNI_OnLoad.",
                             operator="me@lab")
    assert out["note_added"] is True
    notes = _notes(tmp_path, pid)
    assert any("external: rea" in n and "XOR cipher" in n for n in notes)
    assert "rea.imported" in _audit_actions(tmp_path, pid)


def test_import_refuses_empty_or_unknown(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    assert "error" in rea.import_summary(tmp_path, pid, _FP, "   ")
    assert "error" in rea.import_summary(tmp_path, pid, "nosuchfinding", "x")


def test_import_refuses_an_unauthorized_project(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path, authorized=False)
    assert "error" in rea.import_summary(tmp_path, pid, _FP, "something")


# -------------------------------------------------------------- server tools

def test_the_server_registers_the_rea_tools() -> None:
    import asyncio

    from themob.mcp.server import build_server
    names = {t.name for t in asyncio.run(build_server(None).list_tools())}
    assert "rea_prepare" in names and "rea_import" in names
