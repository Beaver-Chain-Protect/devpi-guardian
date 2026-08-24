CREATE TABLE guardian_activation(
    singleton INTEGER NOT NULL PRIMARY KEY
        CHECK(typeof(singleton) = 'integer' AND singleton = 1),
    devpi_uuid TEXT NOT NULL
        CHECK(
            typeof(devpi_uuid) = 'text'
            AND length(devpi_uuid) BETWEEN 1 AND 4096
            AND length(trim(devpi_uuid)) > 0
            AND instr(devpi_uuid, char(0)) = 0
        ),
    activated_at TEXT NOT NULL,
    activation_version INTEGER NOT NULL
        CHECK(typeof(activation_version) = 'integer' AND activation_version = 1)
);

CREATE TRIGGER guardian_activation_immutable_update_guard
BEFORE UPDATE ON guardian_activation
BEGIN
    SELECT RAISE(ABORT, 'immutable guardian activation');
END;

CREATE TRIGGER guardian_activation_immutable_delete_guard
BEFORE DELETE ON guardian_activation
BEGIN
    SELECT RAISE(ABORT, 'immutable guardian activation');
END;
