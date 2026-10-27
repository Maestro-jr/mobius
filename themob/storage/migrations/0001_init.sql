-- 0001_init.sql: themob initial schema.
-- Open the connection with  PRAGMA foreign_keys = ON;  (SQLite enforces FKs per-connection).
-- JSON columns are stored as TEXT; use the json1 functions to query them.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One assessment == one project (one uploaded app).
CREATE TABLE IF NOT EXISTS projects (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    target_platform    TEXT NOT NULL CHECK (target_platform IN ('android','ios')),
    source_path        TEXT NOT NULL,
    source_sha256      TEXT NOT NULL,
    authorization_ref  TEXT,                 -- attestation reference (authorized-targets-only gate)
    authorized_by      TEXT,
    authorized_at      TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Pipeline execution records. One per stage (or per analyzer within a stage).
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage        TEXT NOT NULL,
    analyzer     TEXT,                        -- which adapter, when a stage has several
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','running','succeeded','failed','skipped')),
    started_at   TEXT,
    finished_at  TEXT,
    error        TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status  ON jobs(status);

-- Graph nodes. UNIQUE(project_id, type, key) lets the correlator upsert so two
-- analyzers discovering the same thing converge to one node.
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    platform    TEXT NOT NULL CHECK (platform IN ('android','ios')),
    key         TEXT NOT NULL,
    label       TEXT,
    attributes  TEXT NOT NULL DEFAULT '{}',   -- JSON
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, type, key)
);
CREATE INDEX IF NOT EXISTS idx_entities_project_type ON entities(project_id, type);

-- Graph edges (typed relationships). UNIQUE prevents duplicate identical edges.
CREATE TABLE IF NOT EXISTS edges (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    src_id      TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    dst_id      TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    attributes  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, src_id, dst_id, type)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id);

-- Findings. UNIQUE(project_id, fingerprint) is the dedup/voting pivot: the
-- normalizer upserts on fingerprint so multiple tools reporting the same issue
-- merge into one row (see finding_sources for the agreement trail).
CREATE TABLE IF NOT EXISTS findings (
    id                         TEXT PRIMARY KEY,
    project_id                 TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint                TEXT NOT NULL,
    title                      TEXT NOT NULL,
    description                TEXT NOT NULL DEFAULT '',
    severity                   TEXT NOT NULL
                               CHECK (severity IN ('critical','high','medium','low','info')),
    confidence                 REAL NOT NULL DEFAULT 0.5
                               CHECK (confidence >= 0.0 AND confidence <= 1.0),
    status                     TEXT NOT NULL DEFAULT 'new'
                               CHECK (status IN ('new','confirmed','false_positive','accepted_risk')),
    requires_manual_validation INTEGER NOT NULL DEFAULT 1,   -- boolean 0/1
    masvs_category             TEXT,
    masvs_control              TEXT,
    maswe_id                   TEXT,
    mobile_top10               TEXT,
    cwe                        TEXT,
    location                   TEXT,                          -- JSON
    data_flow                  TEXT NOT NULL DEFAULT '[]',    -- JSON
    remediation                TEXT,                          -- JSON
    created_at                 TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                 TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_project_sev ON findings(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_masvs       ON findings(masvs_category);

-- The tools that reported a finding. Row count per finding == degree of agreement.
CREATE TABLE IF NOT EXISTS finding_sources (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    rule        TEXT,
    raw_ref     TEXT,
    UNIQUE (finding_id, tool, rule)
);
CREATE INDEX IF NOT EXISTS idx_finding_sources_finding ON finding_sources(finding_id);

-- Findings <-> entities (a finding can touch several graph nodes).
CREATE TABLE IF NOT EXISTS finding_entities (
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    entity_id   TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, entity_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id            TEXT PRIMARY KEY,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL
                  CHECK (kind IN ('snippet','artifact','screenshot','http','log')),
    value         TEXT NOT NULL,
    artifact_path TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- Append-only audit trail (mirrors TOPRECON). Immutability enforced by triggers.
CREATE TABLE IF NOT EXISTS audit_log (
    id             TEXT PRIMARY KEY,
    project_id     TEXT REFERENCES projects(id) ON DELETE SET NULL,
    ts             TEXT NOT NULL DEFAULT (datetime('now')),
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    target_sha256  TEXT,
    detail         TEXT                                       -- JSON
);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);
