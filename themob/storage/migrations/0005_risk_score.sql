-- 0005: the scorer's output, and its reasoning.
--
-- Severity says how bad a class of problem is. It is the same for every app,
-- because it comes from the weakness pack, and that is the right question to
-- ask before looking at the package and the wrong one to stop at afterwards.
-- Two findings of one weakness are not equally urgent when an exported
-- component reaches one of them and nothing reaches the other.
--
-- risk carries that context as a number to sort by, 0 to 100, folding severity,
-- confidence and exposure together. It is an ordering, not a measurement, and
-- nothing should read more into it than that.
--
-- score_rationale is why the severity is what it is: "raised from medium
-- because an exported entry point reaches it directly". A rating a report
-- cannot explain in one sentence is a rating nobody trusts, and reconstructing
-- the reasoning later would mean re-running the whole graph walk.
--
-- Both nullable. A finding scored before this migration has neither, and the
-- scorer fills them on its next run rather than inventing a value now.

-- base_severity is what the reporter said before any context was applied. The
-- scorer raises severity for exposure, and severity is stored, so without a
-- stable base a second run would raise the already-raised value and a third
-- would raise it again. Recomputing from the weakness pack works for findings
-- themob rates itself and not for a CVE, where the advisory carries a better
-- severity than the pack's class default. Recording the starting point makes
-- the pass idempotent by construction rather than by luck.
ALTER TABLE findings ADD COLUMN base_severity TEXT;

ALTER TABLE findings ADD COLUMN risk REAL;
ALTER TABLE findings ADD COLUMN score_rationale TEXT;

-- "Worst first" is the default ordering everywhere a finding list appears.
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(project_id, risk DESC);
