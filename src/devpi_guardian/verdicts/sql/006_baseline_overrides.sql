CREATE TABLE baseline_overrides (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    created_at TEXT NOT NULL,
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1))
);

CREATE UNIQUE INDEX baseline_overrides_one_current_idx
    ON baseline_overrides(sha256) WHERE is_current = 1;
CREATE INDEX baseline_overrides_sha256_idx
    ON baseline_overrides(sha256, created_at);

CREATE TRIGGER baseline_overrides_history_insert_guard
BEFORE INSERT ON baseline_overrides
WHEN EXISTS(SELECT 1 FROM baseline_overrides WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'immutable baseline override history');
END;

CREATE TRIGGER baseline_overrides_history_update_guard
BEFORE UPDATE ON baseline_overrides
WHEN NOT (
    OLD.is_current = 1
    AND NEW.is_current = 0
    AND NEW.id IS OLD.id
    AND NEW.sha256 IS OLD.sha256
    AND NEW.enabled IS OLD.enabled
    AND NEW.actor IS OLD.actor
    AND NEW.reason IS OLD.reason
    AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'immutable baseline override history');
END;

CREATE TRIGGER baseline_overrides_history_delete_guard
BEFORE DELETE ON baseline_overrides
BEGIN
    SELECT RAISE(ABORT, 'baseline override history is append-only');
END;
