CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE artifacts (
    sha256 TEXT NOT NULL PRIMARY KEY
        CHECK(
            typeof(sha256) = 'text'
            AND length(sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    size_bytes INTEGER NOT NULL
        CHECK(typeof(size_bytes) = 'integer' AND size_bytes >= 0),
    state TEXT NOT NULL
        CHECK(state IN ('DISCOVERED', 'SCANNING', 'ALLOW', 'REVIEW', 'DENY', 'ERROR')),
    discovered_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    lease_token TEXT
        CHECK(
            lease_token IS NULL
            OR (
                typeof(lease_token) = 'text'
                AND length(lease_token) = 64
                AND lease_token NOT GLOB '*[^0-9a-f]*'
            )
        ),
    last_error TEXT,
    CHECK(
        (
            state = 'SCANNING'
            AND lease_owner IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND lease_token IS NOT NULL
        )
        OR
        (
            state != 'SCANNING'
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
        )
    )
);
CREATE UNIQUE INDEX artifacts_lease_token_unique_idx
    ON artifacts(lease_token) WHERE lease_token IS NOT NULL;

CREATE TABLE release_mappings (
    id INTEGER PRIMARY KEY,
    stage TEXT NOT NULL,
    project TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    origin_url TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(stage, project, version, filename, sha256)
);
CREATE INDEX release_mappings_sha256_idx ON release_mappings(sha256);
CREATE INDEX release_mappings_project_idx ON release_mappings(project, version, filename);

CREATE TABLE verdicts (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'REVIEW', 'DENY')),
    score REAL NOT NULL,
    policy_version TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    baseline_sha256 TEXT REFERENCES artifacts(sha256),
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX verdicts_one_current_idx ON verdicts(sha256) WHERE is_current = 1;
CREATE INDEX verdicts_sha256_idx ON verdicts(sha256, created_at);

CREATE TABLE evidence (
    id INTEGER PRIMARY KEY,
    verdict_id INTEGER NOT NULL REFERENCES verdicts(id),
    rule_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('ALLOW', 'REVIEW', 'DENY')),
    file_path TEXT,
    line INTEGER CHECK(line IS NULL OR line > 0),
    message TEXT NOT NULL,
    details_json TEXT NOT NULL CHECK(json_valid(details_json))
);
CREATE INDEX evidence_verdict_id_idx ON evidence(verdict_id);

CREATE TABLE manual_overrides (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
    actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT,
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1))
);
CREATE UNIQUE INDEX manual_overrides_one_current_idx
    ON manual_overrides(sha256) WHERE is_current = 1;
CREATE INDEX manual_overrides_sha256_idx ON manual_overrides(sha256, created_at);

CREATE TRIGGER artifacts_identity_immutable
BEFORE UPDATE OF sha256, size_bytes, discovered_at ON artifacts
WHEN NEW.sha256 IS NOT OLD.sha256
  OR NEW.size_bytes IS NOT OLD.size_bytes
  OR NEW.discovered_at IS NOT OLD.discovered_at
BEGIN
    SELECT RAISE(ABORT, 'immutable artifact identity');
END;

CREATE TRIGGER artifacts_identity_delete_guard
BEFORE DELETE ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'immutable artifact identity');
END;

CREATE TRIGGER release_mappings_history_insert_guard
BEFORE INSERT ON release_mappings
WHEN EXISTS(SELECT 1 FROM release_mappings WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'immutable release mapping history');
END;

CREATE TRIGGER release_mappings_history_update_guard
BEFORE UPDATE ON release_mappings
BEGIN
    SELECT RAISE(ABORT, 'immutable release mapping history');
END;

CREATE TRIGGER release_mappings_history_delete_guard
BEFORE DELETE ON release_mappings
BEGIN
    SELECT RAISE(ABORT, 'immutable release mapping history');
END;

CREATE TRIGGER verdicts_history_insert_guard
BEFORE INSERT ON verdicts
WHEN EXISTS(SELECT 1 FROM verdicts WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'immutable verdict history');
END;

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
    AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'immutable verdict history');
END;

CREATE TRIGGER verdicts_history_delete_guard
BEFORE DELETE ON verdicts
BEGIN
    SELECT RAISE(ABORT, 'immutable verdict history');
END;

CREATE TRIGGER evidence_history_insert_guard
BEFORE INSERT ON evidence
WHEN EXISTS(SELECT 1 FROM evidence WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence history');
END;

CREATE TRIGGER evidence_history_update_guard
BEFORE UPDATE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence history');
END;

CREATE TRIGGER evidence_history_delete_guard
BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence history');
END;

CREATE TRIGGER manual_overrides_history_insert_guard
BEFORE INSERT ON manual_overrides
WHEN EXISTS(SELECT 1 FROM manual_overrides WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'immutable override history');
END;

CREATE TRIGGER manual_overrides_history_update_guard
BEFORE UPDATE ON manual_overrides
WHEN NOT (
    OLD.is_current = 1
    AND NEW.is_current = 0
    AND NEW.id IS OLD.id
    AND NEW.sha256 IS OLD.sha256
    AND NEW.decision IS OLD.decision
    AND NEW.actor IS OLD.actor
    AND NEW.reason IS OLD.reason
    AND NEW.created_at IS OLD.created_at
    AND NEW.expires_at IS OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'immutable override history');
END;

CREATE TRIGGER manual_overrides_history_delete_guard
BEFORE DELETE ON manual_overrides
BEGIN
    SELECT RAISE(ABORT, 'immutable override history');
END;
