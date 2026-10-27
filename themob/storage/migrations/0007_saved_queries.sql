-- 0007: the questions a tester asks twice.
--
-- correlate/queries.py ships ten built-in questions, which are the ones every
-- mobile assessment asks. This table is for the eleventh: the one a particular
-- tester works out on a particular engagement and wants again next week.
--
-- Not scoped to a project, which is the whole point. A saved query is a way of
-- working, not a fact about one APK, and re-scoping it per project would mean
-- re-creating it for every app it was invented to be run against. Findings and
-- entities are per-project; the question asked of them is not.
--
-- The definition is stored as JSON rather than as columns. A Query is a small
-- set of optional clauses that will gain a predicate occasionally, and a column
-- per clause means a migration every time one is added, for a table that will
-- hold tens of rows. The loader validates on the way out, so a hand-edited or
-- out-of-date row is refused rather than half-applied.
--
-- `key` is the identity and it is unique. A saved query that shadowed a builtin
-- key would silently change what a builtin does, so the repository refuses
-- those by name rather than letting the collision decide.

CREATE TABLE IF NOT EXISTS saved_queries (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    definition  TEXT NOT NULL,              -- the Query, as JSON
    author      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_saved_queries_title
    ON saved_queries(title);
