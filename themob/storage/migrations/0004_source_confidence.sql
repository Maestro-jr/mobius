-- 0004: each reporter's own confidence, kept per source row.
--
-- A finding carries one confidence, and on merge the higher of the two wins. So
-- the moment two tools agree, the weaker reporter's number is gone.
--
-- That is exactly the number cross-tool voting needs. Combining agreement means
-- asking "how likely is it that all of these are wrong", and that question
-- cannot be answered from a single value that has already discarded all but the
-- most confident opinion. Without this column the normalizer would have to
-- substitute the merged figure for every reporter, which quietly assumes each
-- tool was as sure as the surest one.
--
-- Nullable: rows written before this migration never recorded it, and the
-- normalizer treats a null as "this reporter offered no number" rather than
-- inventing one.

ALTER TABLE finding_sources ADD COLUMN confidence REAL;
