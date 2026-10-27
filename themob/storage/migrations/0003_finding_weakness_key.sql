-- 0003: a finding remembers which weakness it is.
--
-- The canonical weakness key was already the thing findings were keyed by, but
-- only through the fingerprint, which is a SHA-256 and therefore one-way. Once
-- a finding was stored, nothing could ask what class of issue it was.
--
-- Two adapters happened to put the key in finding_sources.rule, but that column
-- means "which rule fired", and for gitleaks, apkleaks, semgrep and grype it
-- holds the tool's own rule id. Reading the weakness out of it worked for two
-- reporters by coincidence and was wrong for the rest.
--
-- Everything downstream needs this: the normalizer groups by weakness to score
-- agreement, the scorer maps it to MASVS and MASWE, and the report says what
-- kind of problem it is. Storing it is cheaper and more honest than
-- reconstructing it from a hash that cannot be reversed.
--
-- Nullable because rows written before this migration have no value to give,
-- and inventing one would be worse than admitting it is unknown. The normalizer
-- treats a null key as ungrouped rather than guessing.

ALTER TABLE findings ADD COLUMN weakness_key TEXT;

-- The normalizer's working set is "every finding of this weakness in this
-- project", which is exactly this index.
CREATE INDEX IF NOT EXISTS idx_findings_weakness
    ON findings(project_id, weakness_key);
