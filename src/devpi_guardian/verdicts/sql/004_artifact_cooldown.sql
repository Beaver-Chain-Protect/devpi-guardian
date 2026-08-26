ALTER TABLE artifacts ADD COLUMN cooldown_started_at TEXT;
ALTER TABLE artifacts ADD COLUMN cooldown_until TEXT;

CREATE TRIGGER artifacts_cooldown_pair_insert_guard
BEFORE INSERT ON artifacts
WHEN (NEW.cooldown_started_at IS NULL) != (NEW.cooldown_until IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'cooldown timestamps must be paired');
END;

CREATE TRIGGER artifacts_cooldown_update_guard
BEFORE UPDATE OF cooldown_started_at, cooldown_until ON artifacts
WHEN
    (NEW.cooldown_started_at IS NULL) != (NEW.cooldown_until IS NULL)
    OR (
        OLD.cooldown_started_at IS NOT NULL
        AND (
            NEW.cooldown_started_at IS NOT OLD.cooldown_started_at
            OR NEW.cooldown_until IS NOT OLD.cooldown_until
        )
    )
    OR (
        NEW.cooldown_started_at IS NOT NULL
        AND NEW.cooldown_until <= NEW.cooldown_started_at
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid artifact cooldown transition');
END;
