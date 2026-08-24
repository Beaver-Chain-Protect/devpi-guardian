CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY
        CHECK(typeof(id) = 'integer' AND id > 0),
    event_version INTEGER NOT NULL
        CHECK(typeof(event_version) = 'integer' AND event_version = 1),
    canonicalization_version INTEGER NOT NULL
        CHECK(
            typeof(canonicalization_version) = 'integer'
            AND canonicalization_version = 1
        ),
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256)
        CHECK(
            typeof(sha256) = 'text'
            AND length(sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    previous_decision TEXT NOT NULL
        CHECK(previous_decision IN ('ALLOW', 'REVIEW', 'DENY')),
    new_decision TEXT NOT NULL
        CHECK(new_decision IN ('ALLOW', 'REVIEW', 'DENY')),
    reason TEXT NOT NULL,
    policy_version TEXT,
    analyzer_version TEXT,
    previous_hash TEXT NOT NULL
        CHECK(
            typeof(previous_hash) = 'text'
            AND length(previous_hash) = 64
            AND previous_hash NOT GLOB '*[^0-9a-f]*'
        ),
    event_hash TEXT NOT NULL
        CHECK(
            typeof(event_hash) = 'text'
            AND length(event_hash) = 64
            AND event_hash NOT GLOB '*[^0-9a-f]*'
        )
);

CREATE INDEX audit_events_sha256_occurred_at_idx
    ON audit_events(sha256, occurred_at);
CREATE INDEX audit_events_action_occurred_at_idx
    ON audit_events(action, occurred_at);
CREATE UNIQUE INDEX audit_events_event_hash_unique_idx
    ON audit_events(event_hash);

CREATE TRIGGER audit_events_chain_insert_guard
BEFORE INSERT ON audit_events
WHEN NEW.id IS NOT COALESCE(
        (SELECT MAX(id) + 1 FROM audit_events),
        1
    )
    OR NEW.previous_hash IS NOT COALESCE(
        (SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1),
        lower(hex(zeroblob(32)))
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid audit chain head');
END;

CREATE TRIGGER audit_events_update_guard
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_delete_guard
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
