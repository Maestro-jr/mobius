"""Storage layer: migrations, the two load-bearing upserts, and the audit trail."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, EvidenceKind, FindingStatus,
                                JobStatus, Platform, Severity, Stage)
from themob.model.findings import Evidence, Finding, FindingSource, Location
from themob.storage.db import Database, MigrationError
from themob.storage.repositories import (AuditEntry, Project, Repositories,
                                         RepositoryError)
from themob.storage.workspace import Workspace, WorkspaceError, sha256_file


# --------------------------------------------------------------------- db

def test_migrations_are_idempotent(db: Database) -> None:
    """Every migration on disk is applied, and re-running changes nothing.

    Derived from the directory rather than a hardcoded set: a literal here has
    to be edited every time a migration lands, which tests the edit rather than
    the behaviour.
    """
    from themob.storage.db import MIGRATIONS_DIR

    on_disk = {int(p.name.split("_", 1)[0])
               for p in MIGRATIONS_DIR.glob("[0-9]*.sql")}
    assert on_disk, "no migrations were found on disk"
    assert db.applied_versions() == on_disk
    assert db.run_migrations() == []


def test_foreign_keys_are_enforced(db: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO entities (id, project_id, type, platform, key) "
                   "VALUES ('e','missing','app','android','k')")


def test_migration_filename_must_be_versioned(tmp_path: Path, db: Database) -> None:
    bad = tmp_path / "migrations"
    bad.mkdir()
    (bad / "oops.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(MigrationError):
        db.run_migrations(bad)


def test_transaction_rolls_back(db: Database, repos: Repositories) -> None:
    project = _project(repos)
    with pytest.raises(ValueError):
        with db.transaction() as cur:
            cur.execute("INSERT INTO entities (id, project_id, type, platform, key) "
                        "VALUES ('x',?,'app','android','rollback')",
                        (project.id,))
            raise ValueError("boom")
    assert repos.entities.get_by_key(project.id, EntityType.APP, "rollback") is None


# ---------------------------------------------------------------- projects

def _project(repos: Repositories, name: str = "Sample App") -> Project:
    return repos.projects.create(Project(
        name=name, target_platform=Platform.ANDROID,
        source_path="input/sample.apk", source_sha256="a" * 64))


def test_project_requires_name_and_hash(repos: Repositories) -> None:
    with pytest.raises(RepositoryError):
        repos.projects.create(Project(name="  ", source_sha256="a" * 64))
    with pytest.raises(RepositoryError):
        repos.projects.create(Project(name="ok", source_sha256=""))


def test_authorization_is_recorded(repos: Repositories) -> None:
    project = _project(repos)
    assert not project.is_authorized
    repos.projects.set_authorization(project.id, ref="ENG-42", by="tester")
    reloaded = repos.projects.get(project.id)
    assert reloaded is not None and reloaded.is_authorized
    assert reloaded.authorization_ref == "ENG-42"


def test_delete_cascades(repos: Repositories) -> None:
    project = _project(repos)
    repos.entities.upsert(project.id, _entity("com.example"))
    repos.projects.delete(project.id)
    assert repos.entities.count(project.id) == 0


# ---------------------------------------------------------------- entities

def _entity(key: str, etype: EntityType = EntityType.APP, **attrs) -> Entity:
    return Entity(type=etype, platform=Platform.ANDROID, key=key, label=key,
                  attributes=attrs)


def test_entity_upsert_converges_on_one_node(repos: Repositories) -> None:
    project = _project(repos)
    first = repos.entities.upsert(project.id, _entity("com.example", version="1.0"))
    second = repos.entities.upsert(project.id, _entity("com.example", min_sdk=24))

    assert second.id == first.id, "same (type, key) must not create a second node"
    assert repos.entities.count(project.id) == 1
    # Attributes from both analyzers survive the merge.
    assert second.attributes == {"version": "1.0", "min_sdk": 24}


def test_entity_upsert_incoming_attribute_wins(repos: Repositories) -> None:
    project = _project(repos)
    repos.entities.upsert(project.id, _entity("com.example", version="1.0"))
    merged = repos.entities.upsert(project.id, _entity("com.example", version="2.0"))
    assert merged.attributes["version"] == "2.0"


def test_a_null_from_a_later_analyzer_does_not_erase_what_an_earlier_one_found(
        repos: Repositories) -> None:
    """Null means "I have nothing to say", not "delete it".

    ``json_patch`` is RFC 7396, where a null member *removes* the key. androguard
    reads the network-security-config reference out of the manifest; apktool then
    reports None for the same attribute whenever it cannot resolve the file. Left
    alone, the second write deletes the first one's answer and the config auditor
    reports "no NSC declared" for an app that declares one.
    """
    project = _project(repos)
    repos.entities.upsert(project.id, _entity(
        "com.example", network_security_config="res/xml/nsc.xml", package="com.example"))
    merged = repos.entities.upsert(project.id, _entity(
        "com.example", network_security_config=None, decoded_manifest="a/M.xml"))

    assert merged.attributes["network_security_config"] == "res/xml/nsc.xml"
    assert merged.attributes["decoded_manifest"] == "a/M.xml"

    # A later analyzer with a real value still wins.
    richer = repos.entities.upsert(project.id, _entity(
        "com.example", network_security_config={"path": "res/xml/nsc.xml"}))
    assert richer.attributes["network_security_config"] == {"path": "res/xml/nsc.xml"}


def test_an_explicit_null_survives_on_a_new_node(repos: Repositories) -> None:
    """On insert a null is real information, so it is stored.

    ``exported_declared = None`` means the manifest omitted android:exported,
    which is exactly what the auditor needs to see, and is not the same as the
    attribute being absent.
    """
    project = _project(repos)
    stored = repos.entities.upsert(project.id, _entity(
        "MainActivity", EntityType.COMPONENT, exported_declared=None, exported=False))
    assert "exported_declared" in stored.attributes
    assert stored.attributes["exported_declared"] is None


def test_entity_key_is_required(repos: Repositories) -> None:
    project = _project(repos)
    with pytest.raises(RepositoryError):
        repos.entities.upsert(project.id, _entity(""))


def test_counts_by_type(repos: Repositories) -> None:
    project = _project(repos)
    repos.entities.upsert(project.id, _entity("com.example"))
    repos.entities.upsert(project.id, _entity("MainActivity", EntityType.COMPONENT))
    repos.entities.upsert(project.id, _entity("SyncService", EntityType.COMPONENT))
    counts = repos.entities.counts_by_type(project.id)
    assert counts[EntityType.APP] == 1
    assert counts[EntityType.COMPONENT] == 2
    assert counts[EntityType.SECRET] == 0


# ------------------------------------------------------------------- edges

def test_edge_upsert_is_idempotent(repos: Repositories) -> None:
    project = _project(repos)
    app = repos.entities.upsert(project.id, _entity("com.example"))
    comp = repos.entities.upsert(project.id, _entity("Main", EntityType.COMPONENT))
    repos.edges.connect(project.id, app, comp, EdgeType.DECLARES)
    repos.edges.connect(project.id, app, comp, EdgeType.DECLARES)
    assert repos.edges.count(project.id) == 1
    # A different relationship between the same pair is a distinct edge.
    repos.edges.connect(project.id, app, comp, EdgeType.EXPORTS)
    assert repos.edges.count(project.id) == 2


def test_edge_to_missing_entity_is_rejected(repos: Repositories) -> None:
    project = _project(repos)
    app = repos.entities.upsert(project.id, _entity("com.example"))
    with pytest.raises(sqlite3.IntegrityError):
        repos.edges.upsert(project.id, Edge(src_id=app.id, dst_id="nope",
                                            type=EdgeType.DECLARES))


# ---------------------------------------------------------------- findings

def _finding(fingerprint: str, tool: str, severity: Severity = Severity.HIGH,
             **kw) -> Finding:
    return Finding(
        fingerprint=fingerprint, title=kw.pop("title", "Hardcoded credential"),
        severity=severity, sources=[FindingSource(tool=tool, rule=kw.pop("rule", None))],
        **kw)


def test_findings_merge_on_fingerprint_and_keep_both_sources(repos: Repositories) -> None:
    project = _project(repos)
    fp = Finding.compute_fingerprint("MASWE-0001", Location(file="a/B.java"), "AKIA...")

    repos.findings.upsert(project.id, _finding(fp, "semgrep", rule="hardcoded-key"))
    merged = repos.findings.upsert(project.id, _finding(fp, "mobsf", rule="check-y"))

    assert repos.findings.count(project.id) == 1, "same fingerprint must merge"
    assert {s.tool for s in merged.sources} == {"semgrep", "mobsf"}


def test_merge_keeps_the_higher_severity(repos: Repositories) -> None:
    project = _project(repos)
    fp = "f" * 64
    repos.findings.upsert(project.id, _finding(fp, "toolA", Severity.LOW))
    merged = repos.findings.upsert(project.id, _finding(fp, "toolB", Severity.CRITICAL))
    assert merged.severity is Severity.CRITICAL
    # ...and does not downgrade on a later low-severity report.
    merged = repos.findings.upsert(project.id, _finding(fp, "toolC", Severity.INFO))
    assert merged.severity is Severity.CRITICAL


def test_merge_never_overwrites_a_human_status(repos: Repositories) -> None:
    project = _project(repos)
    fp = "e" * 64
    stored = repos.findings.upsert(project.id, _finding(fp, "toolA"))
    repos.findings.set_status(stored.id, FindingStatus.FALSE_POSITIVE)

    merged = repos.findings.upsert(project.id, _finding(fp, "toolB"))
    assert merged.status is FindingStatus.FALSE_POSITIVE, \
        "a re-run must not resurrect a finding the tester dismissed"


def test_fingerprint_is_deterministic_and_location_sensitive() -> None:
    loc = Location(file="src/Main.java", method="onCreate")
    assert (Finding.compute_fingerprint("MASWE-0001", loc, "x")
            == Finding.compute_fingerprint("MASWE-0001", loc, "x"))
    other = Location(file="src/Other.java", method="onCreate")
    assert (Finding.compute_fingerprint("MASWE-0001", loc, "x")
            != Finding.compute_fingerprint("MASWE-0001", other, "x"))


def test_evidence_and_entity_links_round_trip(repos: Repositories) -> None:
    project = _project(repos)
    app = repos.entities.upsert(project.id, _entity("com.example"))
    finding = _finding("d" * 64, "gitleaks")
    finding.evidence = [Evidence(kind=EvidenceKind.SNIPPET, value="AKIA...")]
    finding.entity_ids = [app.id]

    stored = repos.findings.upsert(project.id, finding)
    assert stored.evidence[0].kind is EvidenceKind.SNIPPET
    assert stored.entity_ids == [app.id]


def test_findings_list_is_severity_ordered(repos: Repositories) -> None:
    project = _project(repos)
    for i, sev in enumerate([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]):
        repos.findings.upsert(project.id, _finding(f"{i:064d}", "t", sev))
    order = [f.severity for f in repos.findings.list(project.id)]
    assert order == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_confidence_bounds_are_enforced(repos: Repositories) -> None:
    project = _project(repos)
    stored = repos.findings.upsert(project.id, _finding("c" * 64, "t"))
    with pytest.raises(RepositoryError):
        repos.findings.set_confidence(stored.id, 1.5)


# -------------------------------------------------------------------- jobs

def test_job_lifecycle(repos: Repositories) -> None:
    project = _project(repos)
    job = repos.jobs.create(project.id, Stage.UNPACK, "androguard-unpack")
    repos.jobs.start(job.id)
    repos.jobs.finish(job.id, JobStatus.SUCCEEDED)

    stored = repos.jobs.get(job.id)
    assert stored is not None
    assert stored.status is JobStatus.SUCCEEDED
    assert stored.started_at and stored.finished_at


def test_job_cannot_finish_into_a_non_terminal_status(repos: Repositories) -> None:
    project = _project(repos)
    job = repos.jobs.create(project.id, Stage.UNPACK, "androguard-unpack")
    with pytest.raises(RepositoryError):
        repos.jobs.finish(job.id, JobStatus.RUNNING)


# ------------------------------------------------------------------- audit

def test_audit_log_is_append_only(db: Database, repos: Repositories) -> None:
    project = _project(repos)
    entry = repos.audit.append(AuditEntry(
        project_id=project.id, actor="tester", action="project.authorized",
        target_sha256="a" * 64, detail={"ref": "ENG-42"}))

    with pytest.raises(sqlite3.IntegrityError):
        db.execute("UPDATE audit_log SET actor = 'x' WHERE id = ?", (entry.id,))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("DELETE FROM audit_log WHERE id = ?", (entry.id,))

    assert repos.audit.list(project.id)[0].detail == {"ref": "ENG-42"}


def test_audit_requires_actor_and_action(repos: Repositories) -> None:
    with pytest.raises(RepositoryError):
        repos.audit.append(AuditEntry(actor="", action="x"))


# --------------------------------------------------------------- workspace

def test_ingest_hashes_and_stores_the_sample(workspace: Workspace,
                                             sample_apk: Path) -> None:
    ingested = workspace.ingest(sample_apk)
    assert ingested.sha256 == sha256_file(sample_apk)
    assert ingested.relative == "input/sample.apk"
    assert workspace.resolve(ingested.relative) == ingested.path


def test_ingest_rejects_empty_and_missing_files(workspace: Workspace,
                                                tmp_path: Path) -> None:
    with pytest.raises(WorkspaceError):
        workspace.ingest(tmp_path / "nope.apk")
    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")
    with pytest.raises(WorkspaceError):
        workspace.ingest(empty)


def test_workspace_rejects_path_traversal(workspace: Workspace) -> None:
    for evil in ("../../etc/passwd", "raw/../../escape", "/etc/passwd", ""):
        with pytest.raises(WorkspaceError):
            workspace.resolve(evil)


def test_workspace_rejects_unsafe_directory_names(workspace: Workspace) -> None:
    for evil in ("../x", "a/b", ".hidden", ""):
        with pytest.raises(WorkspaceError):
            workspace.raw_dir(evil)


def test_a_failing_migration_leaves_the_schema_untouched(tmp_path: Path,
                                                         db: Database) -> None:
    """Regression: executescript() COMMITs any pending transaction first.

    A ``BEGIN`` issued from Python around it was therefore discarded and a
    migration applied statement by statement, leaving a half-migrated schema
    behind on failure. The transaction now lives inside the script.
    """
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "0009_half_broken.sql").write_text(
        "CREATE TABLE canary (id TEXT);\n"
        "CREATE TABLE canary (id TEXT);\n",          # duplicate: fails
        encoding="utf-8")

    with pytest.raises(MigrationError):
        db.run_migrations(directory)

    assert db.query_one(
        "SELECT name FROM sqlite_master WHERE name='canary'") is None
    assert 9 not in db.applied_versions()
