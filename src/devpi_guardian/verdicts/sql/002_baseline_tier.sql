ALTER TABLE verdicts ADD COLUMN baseline_tier TEXT
    CHECK(
        baseline_tier IS NULL
        OR (
            typeof(baseline_tier) = 'text'
            AND baseline_tier IN ('same_tag', 'universal_wheel', 'sdist')
        )
    );

DROP TRIGGER verdicts_history_update_guard;

CREATE TRIGGER verdicts_history_update_guard
BEFORE UPDATE ON verdicts
WHEN NOT (
    OLD.is_current = 1
    AND NEW.is_current = 0
    AND NEW.id IS OLD.id
    AND NEW.sha256 IS OLD.sha256
    AND NEW.decision IS OLD.decision
    AND NEW.score IS OLD.score
    AND NEW.policy_version IS OLD.policy_version
    AND NEW.analyzer_version IS OLD.analyzer_version
    AND NEW.baseline_sha256 IS OLD.baseline_sha256
    AND NEW.baseline_tier IS OLD.baseline_tier
    AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'immutable verdict history');
END;

CREATE TRIGGER verdicts_baseline_pair_insert_guard
BEFORE INSERT ON verdicts
WHEN (NEW.baseline_sha256 IS NULL) != (NEW.baseline_tier IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'baseline sha256 and tier must be paired');
END;
