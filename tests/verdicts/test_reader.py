import statistics
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.errors import InvalidSha256, StoreUnavailable
from devpi_guardian.verdicts.models import (
    AllowedRelease,
    ArtifactState,
    Decision,
    DecisionSource,
)
from devpi_guardian.verdicts.reader import SQLiteVerdictReader

SHA_ALLOW = "a" * 64
SHA_REVIEW = "b" * 64
SHA_MISSING = "c" * 64
NOW = datetime(2026, 8, 17, 0, 0, tzinfo=UTC)


class FetchallSpyCursor:
    def __init__(self, cursor, fetched_row_counts: list[int]) -> None:
        self._cursor = cursor
        self._fetched_row_counts = fetched_row_counts

    def fetchall(self):
        rows = self._cursor.fetchall()
        self._fetched_row_counts.append(len(rows))
        return rows


class FetchallSpyConnection:
    def __init__(self, connection, fetched_row_counts: list[int]) -> None:
        self._connection = connection
        self._fetched_row_counts = fetched_row_counts

    @property
    def in_transaction(self):
        return self._connection.in_transaction

    def execute(self, statement, parameters=()):
        cursor = self._connection.execute(statement, parameters)
        return FetchallSpyCursor(cursor, self._fetched_row_counts)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


class FetchallSpyFactory:
    def __init__(self, factory: ConnectionFactory) -> None:
        self._factory = factory
        self.path = factory.path
        self.fetched_row_counts: list[int] = []

    def connect(self):
        return FetchallSpyConnection(
            self._factory.connect(),
            self.fetched_row_counts,
        )


def seed_artifact(
    factory: ConnectionFactory,
    sha256: str,
    state: ArtifactState,
    automated: tuple[Decision, str] | None = None,
    manual: Decision | None = None,
    expires: datetime | None = None,
    *,
    expires_text: str | None = None,
) -> None:
    timestamp = NOW.isoformat()
    lease_values = (
        ("worker", (NOW + timedelta(minutes=10)).isoformat(), "f" * 64)
        if state is ArtifactState.SCANNING
        else (None, None, None)
    )
    last_error = "analysis failed" if state is ArtifactState.ERROR else None
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO artifacts(
                sha256, size_bytes, state, discovered_at, updated_at,
                lease_owner, lease_expires_at, lease_token, last_error
            ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                state.value,
                timestamp,
                timestamp,
                *lease_values,
                last_error,
            ),
        )
        if automated is not None:
            decision, policy_version = automated
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version, analyzer_version,
                    baseline_sha256, is_current, created_at
                ) VALUES (?, ?, 1.0, ?, 'analyzer-1', NULL, 1, ?)
                """,
                (sha256, decision.value, policy_version, timestamp),
            )
        if manual is not None:
            expiry = (
                expires_text
                if expires_text is not None
                else expires.isoformat()
                if expires is not None
                else None
            )
            connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at,
                    is_current
                ) VALUES (?, ?, 'tester', 'test override', ?, ?, 1)
                """,
                (
                    sha256,
                    manual.value,
                    timestamp,
                    expiry,
                ),
            )


def seed_release(
    factory: ConnectionFactory,
    sha256: str,
    *,
    stage: str = "root/dev",
    project: str = "demo-package",
    version: str = "1.0.0",
    filename: str = "demo_package-1.0.0-py3-none-any.whl",
    origin_url: str | None = None,
) -> None:
    with closing(factory.connect()) as connection, connection:
        default_origin = f"https://devpi.example/{stage}/+f/aa/{filename}"
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stage,
                project,
                version,
                filename,
                sha256,
                origin_url or default_origin,
                NOW.isoformat(),
            ),
        )


def test_list_allowed_releases_normalizes_project_and_returns_immutable_result(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    seed_release(factory, SHA_ALLOW)

    result = SQLiteVerdictReader(
        factory,
        now=lambda: NOW,
    ).list_allowed_releases("Demo_Package")

    origin_prefix = "https://devpi.example/root/dev/+f/aa/"
    origin_filename = "demo_package-1.0.0-py3-none-any.whl"
    expected_origin = origin_prefix + origin_filename
    assert result == (
        AllowedRelease(
            stage="root/dev",
            project="demo-package",
            version="1.0.0",
            filename="demo_package-1.0.0-py3-none-any.whl",
            sha256=SHA_ALLOW,
            origin_url=expected_origin,
        ),
    )
    assert isinstance(result, tuple)


def test_list_allowed_releases_returns_all_mappings_in_deterministic_order(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    shas = [f"{number:064x}" for number in range(1, 3)]
    for sha in shas:
        seed_artifact(
            factory,
            sha,
            ArtifactState.ALLOW,
            automated=(Decision.ALLOW, "policy-1"),
        )
    seed_release(
        factory,
        shas[0],
        stage="root/z",
        version="2.0.0",
        filename="z.whl",
    )
    seed_release(
        factory,
        shas[0],
        stage="root/a",
        version="1.0.0",
        filename="a.whl",
    )
    seed_release(
        factory,
        shas[1],
        stage="root/a",
        version="1.0.0",
        filename="b.whl",
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.list_allowed_releases("demo_package")

    actual = []
    for item in result:
        actual.append((item.stage, item.version, item.filename))
    expected = []
    for item in sorted(
        result,
        key=lambda item: (item.stage, item.version, item.filename),
    ):
        expected.append((item.stage, item.version, item.filename))
    assert actual == expected
    assert len(result) == 3
    assert {item.stage for item in result} == {"root/a", "root/z"}


@pytest.mark.parametrize(
    ("state", "automated"),
    [
        (ArtifactState.DISCOVERED, Decision.ALLOW),
        (ArtifactState.SCANNING, Decision.ALLOW),
        (ArtifactState.REVIEW, Decision.REVIEW),
        (ArtifactState.DENY, Decision.DENY),
        (ArtifactState.ERROR, Decision.ALLOW),
    ],
)
def test_list_allowed_releases_excludes_nonallow_states(
    tmp_path,
    state: ArtifactState,
    automated: Decision,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    sha = "1" * 64
    seed_artifact(factory, sha, state, automated=(automated, "policy-1"))
    seed_release(factory, sha)

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.list_allowed_releases("demo-package")

    assert result == ()


def test_list_allowed_releases_applies_manual_override_precedence(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    cases = (
        ("1" * 64, ArtifactState.ALLOW, Decision.ALLOW, Decision.ALLOW, None),
        ("2" * 64, ArtifactState.ALLOW, Decision.ALLOW, Decision.DENY, None),
        (
            "3" * 64,
            ArtifactState.REVIEW,
            Decision.REVIEW,
            Decision.ALLOW,
            None,
        ),
        (
            "4" * 64,
            ArtifactState.REVIEW,
            Decision.REVIEW,
            Decision.ALLOW,
            NOW + timedelta(minutes=1),
        ),
        (
            "5" * 64,
            ArtifactState.ALLOW,
            Decision.ALLOW,
            Decision.DENY,
            NOW + timedelta(minutes=1),
        ),
    )
    for sha, state, automated, manual, expires in cases:
        seed_artifact(
            factory,
            sha,
            state,
            automated=(automated, "policy-1"),
            manual=manual,
            expires=expires,
        )
        seed_release(factory, sha, filename=f"{sha[:4]}.whl")

    result = SQLiteVerdictReader(
        factory,
        now=lambda: NOW + timedelta(minutes=2),
    ).list_allowed_releases("demo-package")

    assert [item.sha256 for item in result] == [
        "1" * 64,
        "3" * 64,
        "5" * 64,
    ]


@pytest.mark.parametrize("project", [None, b"demo-package", "", " \t"])
def test_list_allowed_releases_rejects_invalid_project_before_connect(
    tmp_path,
    project,
) -> None:
    class NoConnectFactory:
        path = tmp_path / "guardian.db"

        def connect(self):
            raise AssertionError("connect must not be called")

    reader = SQLiteVerdictReader(NoConnectFactory(), now=lambda: NOW)

    with pytest.raises(ValueError):
        reader.list_allowed_releases(project)


def test_list_allowed_releases_rejects_str_subclass_before_connect(
    tmp_path,
) -> None:
    class Project(str):
        pass

    class NoConnectFactory:
        path = tmp_path / "guardian.db"

        def connect(self):
            raise AssertionError("connect must not be called")

    reader = SQLiteVerdictReader(NoConnectFactory(), now=lambda: NOW)

    with pytest.raises(ValueError):
        reader.list_allowed_releases(Project("demo-package"))


def test_list_allowed_releases_rejects_normalized_empty_project(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "devpi_guardian.verdicts.releases.normalize_name",
        lambda value: "",
    )

    class NoConnectFactory:
        path = tmp_path / "guardian.db"

        def connect(self):
            raise AssertionError("connect must not be called")

    reader = SQLiteVerdictReader(NoConnectFactory(), now=lambda: NOW)

    with pytest.raises(ValueError):
        reader.list_allowed_releases("demo-package")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", ""),
        ("version", ""),
        ("filename", ""),
        (
            "origin_url",
            "https://user:secret@example.test/pkg.whl?token=x#fragment",
        ),
        ("discovered_at", "not-a-timestamp"),
    ],
)
def test_list_allowed_releases_rejects_corrupt_mapping(
    tmp_path,
    field: str,
    value: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    seed_release(factory, SHA_ALLOW)
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            "DROP TRIGGER release_mappings_history_update_guard",
        )
        update = f"UPDATE release_mappings SET {field} = ?"
        connection.execute(update, (value,))

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).list_allowed_releases(
            "demo-package",
        )


def test_list_allowed_releases_rejects_missing_artifact(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    with closing(factory.connect()) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN")
        connection.execute(
            """
            INSERT INTO release_mappings(
                stage, project, version, filename, sha256,
                origin_url, discovered_at
            ) VALUES ('root/dev', 'demo-package', '1.0.0', 'demo.whl', ?,
                      'https://devpi.example/demo.whl', ?)
            """,
            (SHA_ALLOW, NOW.isoformat()),
        )
        connection.commit()

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).list_allowed_releases(
            "demo-package",
        )


def test_list_allowed_releases_uses_one_clock_and_connection(tmp_path) -> None:
    underlying = ConnectionFactory(tmp_path / "guardian.db")
    migrate(underlying)
    seed_artifact(
        underlying,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    seed_release(underlying, SHA_ALLOW)

    class CountingFactory:
        path = underlying.path

        def __init__(self) -> None:
            self.calls = 0

        def connect(self):
            self.calls += 1
            return underlying.connect()

    clock_calls = 0

    def now() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return NOW

    factory = CountingFactory()
    result = SQLiteVerdictReader(factory, now=now).list_allowed_releases(
        "demo-package",
    )

    assert len(result) == 1
    assert factory.calls == 1
    assert clock_calls == 1


def test_reader_allows_only_automated_allow(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    allowed = reader.get_effective_decision(SHA_ALLOW)
    blocked = reader.get_effective_decision(SHA_REVIEW)

    assert allowed.allowed is True
    assert allowed.effective_decision is Decision.ALLOW
    assert allowed.source is DecisionSource.AUTOMATED
    assert allowed.artifact_state is ArtifactState.ALLOW
    assert allowed.policy_version == "policy-1"
    assert blocked.allowed is False
    assert blocked.effective_decision is Decision.DENY
    assert blocked.source is DecisionSource.AUTOMATED
    assert blocked.artifact_state is ArtifactState.REVIEW


def test_current_manual_decision_overrides_automated_decision(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
        manual=Decision.DENY,
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.MANUAL_OVERRIDE
    assert result.artifact_state is ArtifactState.ALLOW
    assert result.policy_version == "policy-1"


def test_manual_allow_over_review_is_effective(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_REVIEW)

    assert result.allowed is True
    assert result.effective_decision is Decision.ALLOW
    assert result.source is DecisionSource.MANUAL_OVERRIDE
    assert result.artifact_state is ArtifactState.REVIEW


def test_expired_manual_allow_falls_back_to_automated_review(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
        expires=NOW + timedelta(minutes=1),
    )

    reader = SQLiteVerdictReader(
        factory,
        now=lambda: NOW + timedelta(minutes=1),
    )
    result = reader.get_effective_decision(SHA_REVIEW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.AUTOMATED
    assert result.artifact_state is ArtifactState.REVIEW


def test_missing_and_batch_results_are_fail_closed(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    results = reader.get_effective_decisions([SHA_ALLOW, SHA_MISSING])

    assert results[SHA_ALLOW].allowed is True
    assert results[SHA_MISSING].allowed is False
    assert results[SHA_MISSING].effective_decision is Decision.DENY
    assert results[SHA_MISSING].source is DecisionSource.MISSING
    assert results[SHA_MISSING].artifact_state is ArtifactState.MISSING
    assert results[SHA_MISSING].policy_version is None


@pytest.mark.parametrize(
    "state",
    [
        ArtifactState.DISCOVERED,
        ArtifactState.SCANNING,
        ArtifactState.REVIEW,
        ArtifactState.DENY,
        ArtifactState.ERROR,
    ],
)
def test_nonallow_lifecycle_states_block(
    tmp_path,
    state: ArtifactState,
) -> None:
    factory = ConnectionFactory(tmp_path / f"{state.value}.db")
    migrate(factory)
    automated_decision = (
        Decision(state.value)
        if state in (ArtifactState.REVIEW, ArtifactState.DENY)
        else Decision.ALLOW
    )
    seed_artifact(
        factory,
        SHA_ALLOW,
        state,
        automated=(automated_decision, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    result = reader.get_effective_decision(SHA_ALLOW)

    assert result.allowed is False
    assert result.effective_decision is Decision.DENY
    assert result.source is DecisionSource.AUTOMATED
    assert result.artifact_state is state


def test_mismatched_automated_verdict_is_store_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.REVIEW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    with pytest.raises(StoreUnavailable):
        reader.get_effective_decision(SHA_ALLOW)


def test_duplicate_inputs_return_one_result_per_distinct_sha(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )

    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    results = reader.get_effective_decisions(
        [SHA_MISSING, SHA_ALLOW, SHA_MISSING, SHA_ALLOW],
    )

    assert list(results) == [SHA_MISSING, SHA_ALLOW]
    assert len(results) == 2


def test_batch_chunks_large_input_and_preserves_missing_results(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    shas = [f"{number:064x}" for number in range(401)]
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    results = reader.get_effective_decisions(shas)

    assert list(results) == shas
    assert len(results) == 401
    assert all(not result.allowed for result in results.values())
    sources = (result.source for result in results.values())
    assert all(source is DecisionSource.MISSING for source in sources)


def test_invalid_caller_sha_raises_invalid_sha256(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    with pytest.raises(InvalidSha256):
        reader.get_effective_decisions([SHA_ALLOW, "NOT-A-SHA"])


def test_corrupt_artifact_state_maps_to_store_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(factory, SHA_ALLOW, ArtifactState.ALLOW)
    with closing(factory.connect()) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE artifacts SET state = 'CORRUPT' WHERE sha256 = ?",
            (SHA_ALLOW,),
        )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


def test_corrupt_expiry_maps_to_store_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        manual=Decision.ALLOW,
        expires_text="not-a-timestamp",
    )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


def test_manual_allow_without_required_current_verdict_is_unavailable(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        manual=Decision.ALLOW,
    )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_REVIEW,
        )


@pytest.mark.parametrize(
    "created_at",
    ["not-a-timestamp", "2026-08-17T09:00:00+09:00"],
)
def test_malformed_current_override_created_at_is_unavailable(
    tmp_path,
    created_at: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
    )
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            "DROP TRIGGER IF EXISTS manual_overrides_history_update_guard",
        )
        connection.execute(
            "UPDATE manual_overrides SET created_at = ?",
            (created_at,),
        )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_REVIEW,
        )


@pytest.mark.parametrize(
    "state",
    [ArtifactState.DISCOVERED, ArtifactState.SCANNING],
)
def test_current_override_on_active_lifecycle_is_unavailable(
    tmp_path,
    state: ArtifactState,
) -> None:
    factory = ConnectionFactory(tmp_path / f"{state.value}.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        state,
        automated=(Decision.ALLOW, "policy-1"),
        manual=Decision.ALLOW,
    )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


def test_malformed_artifact_updated_at_is_unavailable(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    with closing(factory.connect()) as connection, connection:
        connection.execute(
            "UPDATE artifacts SET updated_at = 'not-a-timestamp'",
        )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_ALLOW,
        )


@pytest.mark.parametrize("history", ["verdict", "override"])
def test_duplicate_current_join_rows_are_unavailable(
    tmp_path,
    history: str,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW if history == "override" else None,
    )
    with closing(factory.connect()) as connection, connection:
        if history == "verdict":
            connection.execute("DROP INDEX verdicts_one_current_idx")
            connection.execute(
                """
                INSERT INTO verdicts(
                    sha256, decision, score, policy_version,
                    analyzer_version, baseline_sha256, is_current, created_at
                ) VALUES (?, 'REVIEW', 1.0, 'policy-2', 'analyzer-2',
                          NULL, 1, ?)
                """,
                (SHA_REVIEW, NOW.isoformat()),
            )
        else:
            connection.execute("DROP INDEX manual_overrides_one_current_idx")
            connection.execute(
                """
                INSERT INTO manual_overrides(
                    sha256, decision, actor, reason, created_at, expires_at,
                    is_current
                ) VALUES (?, 'DENY', 'other', 'duplicate', ?, NULL, 1)
                """,
                (SHA_REVIEW, NOW.isoformat()),
            )

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(factory, now=lambda: NOW).get_effective_decision(
            SHA_REVIEW,
        )


def test_duplicate_current_reads_are_bounded_before_validation(
    tmp_path,
) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_REVIEW,
        ArtifactState.REVIEW,
        automated=(Decision.REVIEW, "policy-1"),
        manual=Decision.ALLOW,
    )
    with closing(factory.connect()) as connection, connection:
        connection.execute("DROP INDEX verdicts_one_current_idx")
        connection.execute("DROP INDEX manual_overrides_one_current_idx")
        timestamp = NOW.isoformat()
        verdict_parameters = []
        override_parameters = []
        for index in range(1, 300):
            verdict_parameters.append(
                (SHA_REVIEW, f"policy-{index}", timestamp),
            )
            override_parameters.append(
                (SHA_REVIEW, f"actor-{index}", timestamp),
            )
        connection.executemany(
            """
            INSERT INTO verdicts(
                sha256, decision, score, policy_version,
                analyzer_version, baseline_sha256, is_current, created_at
            ) VALUES (?, 'REVIEW', 1.0, ?, 'analyzer-duplicate',
                      NULL, 1, ?)
            """,
            verdict_parameters,
        )
        connection.executemany(
            """
            INSERT INTO manual_overrides(
                sha256, decision, actor, reason, created_at, expires_at,
                is_current
            ) VALUES (?, 'ALLOW', ?, 'duplicate', ?, NULL, 1)
            """,
            override_parameters,
        )
    spy_factory = FetchallSpyFactory(factory)

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(
            spy_factory,
            now=lambda: NOW,
        ).get_effective_decision(SHA_REVIEW)

    assert spy_factory.fetched_row_counts
    assert max(spy_factory.fetched_row_counts) <= 2


def test_single_delegates_to_batch(monkeypatch, tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    expected = reader._missing(SHA_ALLOW)
    calls: list[list[str]] = []

    def fake_batch(sha256s):
        calls.append(list(sha256s))
        return {SHA_ALLOW: expected}

    monkeypatch.setattr(reader, "get_effective_decisions", fake_batch)

    assert reader.get_effective_decision(SHA_ALLOW) == expected
    assert calls == [[SHA_ALLOW]]


def test_now_is_read_once_for_each_batch_call(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW

    SQLiteVerdictReader(factory, now=clock).get_effective_decisions(
        [SHA_ALLOW, SHA_MISSING] * 500,
    )

    assert calls == 1


@pytest.mark.performance
def test_fresh_store_single_lookup_p95_is_under_100_ms(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    seed_artifact(
        factory,
        SHA_ALLOW,
        ArtifactState.ALLOW,
        automated=(Decision.ALLOW, "policy-1"),
    )
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)

    durations_ms = []
    for _ in range(1_000):
        started = time.perf_counter_ns()
        assert reader.get_effective_decision(SHA_ALLOW).allowed is True
        durations_ms.append((time.perf_counter_ns() - started) / 1_000_000)

    p95 = statistics.quantiles(durations_ms, n=100)[94]
    print(f"fresh-store lookup p95={p95:.3f} ms")
    assert p95 < 100


def test_unavailable_reader_factory_fails_closed() -> None:
    class UnavailableFactory:
        path = "guardian.db"

        def connect(self):
            raise StoreUnavailable("guardian.db")

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(
            UnavailableFactory(),
            now=lambda: NOW,
        ).get_effective_decision(SHA_ALLOW)


def test_corrupt_database_fails_closed(tmp_path) -> None:
    path = tmp_path / "guardian.db"
    path.write_bytes(b"not-a-sqlite-database")

    with pytest.raises(StoreUnavailable):
        SQLiteVerdictReader(
            ConnectionFactory(path),
            now=lambda: NOW,
        ).get_effective_decision(SHA_ALLOW)
