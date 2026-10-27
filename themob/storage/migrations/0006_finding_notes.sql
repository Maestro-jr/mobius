-- 0006: what the tester said about a finding.
--
-- The build plan calls the confirm/annotate loop the thing that makes themob a
-- console rather than a report generator. A status on its own does not carry
-- that: "false positive" without a reason is an assertion the next person has
-- to take on trust, and six months later nobody remembers why.
--
-- A table rather than a column, for the same reason evidence is a table. A
-- finding accumulates notes as an assessment goes on: an initial doubt, the
-- reproduction attempt, the client's answer about whether that host is really
-- internal. Overwriting one field would keep only the last of those, and the
-- sequence is often the useful part.
--
-- Notes are append-only in practice but not enforced as immutable: unlike the
-- audit trail these are working notes, and a tester correcting their own typo
-- is not tampering. The audit trail records that the status changed and why,
-- which is the part that has to survive.

CREATE TABLE IF NOT EXISTS finding_notes (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author      TEXT NOT NULL DEFAULT '',
    text        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_finding_notes_finding
    ON finding_notes(finding_id, created_at);
