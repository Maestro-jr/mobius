-- 0002: the audit trail outlives the projects it describes.
--
-- 0001 gave audit_log.project_id a foreign key with ON DELETE SET NULL. That
-- cascade is an UPDATE, so the append-only trigger aborted it: once a project
-- had a single audit entry, which is immediately, since intake writes one, the
-- project could never be deleted. It also broke the authorization gate's
-- rollback, where a rejected attestation must remove the project it had just
-- created.
--
-- Both problems come from the same mistake: tying an immutable record to the
-- lifecycle of the thing it records. "This project was created, then deleted" is
-- exactly what an audit trail exists to preserve, so project_id becomes a plain
-- reference with no foreign key. Nothing may rewrite an audit row, including
-- SQLite's own cascades.

-- No PRAGMA foreign_keys toggle here: it is a no-op inside a transaction, and
-- this rebuild does not need one. audit_log is only ever the child side of a
-- foreign key, nothing references it, so dropping and renaming is safe with
-- enforcement left on.

DROP TRIGGER IF EXISTS audit_log_no_update;
DROP TRIGGER IF EXISTS audit_log_no_delete;

CREATE TABLE audit_log_new (
    id             TEXT PRIMARY KEY,
    project_id     TEXT,                 -- deliberately NOT a foreign key
    ts             TEXT NOT NULL DEFAULT (datetime('now')),
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    target_sha256  TEXT,
    detail         TEXT                  -- JSON
);

INSERT INTO audit_log_new (id, project_id, ts, actor, action, target_sha256, detail)
SELECT id, project_id, ts, actor, action, target_sha256, detail FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
