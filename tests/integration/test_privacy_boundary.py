from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace

from devpi_guardian.admin.providers import ProductionAdminProviders
from devpi_guardian.admin.service import GuardianAdminService
from devpi_guardian.admin.views import ADMIN_SERVICE_REGISTRY_KEY, artifact_diff, inspect_artifact
from devpi_guardian.analyzers import finding_fingerprint
from devpi_guardian.audit import SQLiteAuditWriter
from devpi_guardian.baseline.artifact_source import HttpArtifactBytesSource
from devpi_guardian.baseline.diff import compare_release_to_baseline
from devpi_guardian.baseline.selection import ReleaseRecord
from devpi_guardian.verdicts.db import ConnectionFactory, migrate
from devpi_guardian.verdicts.models import ArtifactInput, Decision, ReleaseInput, VerdictInput
from devpi_guardian.verdicts.reader import SQLiteVerdictReader
from devpi_guardian.verdicts.store import SQLiteArtifactStore
from devpi_guardian.worker.discovery import FileDiscoverySink
from devpi_guardian.worker.models import (
    AnalysisBundle,
    AnalysisEvidence,
    AnalysisReport,
    AnalysisStep,
    VerifiedArtifact,
)
from devpi_guardian.worker.pipeline import QuarantineWorker, WorkerCycleStatus

NOW = datetime(2026, 8, 25, tzinfo=UTC)
BASELINE_SHA = "b" * 64
TARGET_SHA = "a" * 64
BASELINE_FILENAME = "x-1.0-py3-none-any.whl"
TARGET_FILENAME = "x-2.0-py3-none-any.whl"
AUTH_SECRET = "dict-auth-secret"
URL_SECRET = "url-user-secret"
QUERY_SECRET = "url-query-secret"
PATH_SECRET = "/Users/alice/My Secret/file.whl"
FULL_DIGEST_SECRET = "c" * 64


class _Lookup:
    def allowed_releases(self, project: str) -> list[ReleaseRecord]:
        assert project == "demo"
        return [
            ReleaseRecord(
                project="demo",
                version="1.0.0",
                filename=BASELINE_FILENAME,
                sha256=BASELINE_SHA,
                size_bytes=1,
            )
        ]


class _Resolver:
    def origin_url(self, sha256: str) -> str:
        assert sha256 == BASELINE_SHA
        return f"https://d/r/p/+e/x/{BASELINE_FILENAME}"

    def expected_size(self, sha256: str) -> int:
        assert sha256 == BASELINE_SHA
        return 1


class _FailingSession:
    def __init__(self, kind: str) -> None:
        self._kind = kind

    def get(self, url: str, **kwargs):
        if self._kind == "url":
            raise RuntimeError(
                f"GET https://{URL_SECRET}:ignored@example.invalid/pkg.whl?token={QUERY_SECRET}"
            )
        if self._kind == "digest":
            raise RuntimeError(f"digest={FULL_DIGEST_SECRET}")
        raise RuntimeError(
            f"{{'auth_token': '{AUTH_SECRET}'}} {PATH_SECRET} digest={FULL_DIGEST_SECRET}"
        )


class _Preparer:
    def __init__(self, bundle: AnalysisBundle) -> None:
        self._bundle = bundle

    def prepare(self, claim):
        return self._bundle


class _Engine:
    def __init__(self, report: AnalysisReport) -> None:
        self._report = report

    def analyze(self, bundle: AnalysisBundle) -> AnalysisReport:
        return self._report


class _Policy:
    def evaluate(self, target, report):
        return VerdictInput(
            sha256=target.sha256,
            decision=Decision.REVIEW,
            score=70,
            policy_version="policy-1",
            analyzer_version=report.analyzer_version,
            baseline_sha256=report.baseline_sha256,
            baseline_tier=report.baseline_tier,
            created_at=NOW,
        )


def _record_terminal(
    store: SQLiteArtifactStore, *, sha256: str, version: str, filename: str
) -> None:
    store.discover_artifact(
        ArtifactInput(sha256=sha256, size_bytes=1, discovered_at=NOW),
        ReleaseInput(
            stage="root/pypi",
            project="demo",
            version=version,
            filename=filename,
            sha256=sha256,
            origin_url=f"https://devpi.example/root/pypi/+f/{sha256[:3]}/{sha256[3:16]}/{filename}",
            discovered_at=NOW,
        ),
    )
    claim = store.claim_next("seed-worker", NOW + timedelta(minutes=5))
    assert claim is not None
    store.record_verdict(
        claim,
        VerdictInput(
            sha256=sha256,
            decision=Decision.ALLOW,
            score=0,
            policy_version="policy-1",
            analyzer_version="analyzer-1",
            baseline_sha256=None,
            baseline_tier=None,
            created_at=NOW,
        ),
        (),
    )


def _request(service: GuardianAdminService, sha256: str):
    return SimpleNamespace(
        registry={ADMIN_SERVICE_REGISTRY_KEY: service},
        matchdict={"sha256": sha256},
        params={},
    )


def test_baseline_download_error_is_sanitized_before_sqlite_and_f11_boundaries(tmp_path) -> None:
    factory = ConnectionFactory(tmp_path / "guardian.db")
    migrate(factory)
    store = SQLiteArtifactStore(factory, SQLiteAuditWriter(), now=lambda: NOW)
    _record_terminal(
        store,
        sha256=BASELINE_SHA,
        version="1.0.0",
        filename=BASELINE_FILENAME,
    )
    store.discover_artifact(
        ArtifactInput(sha256=TARGET_SHA, size_bytes=6, discovered_at=NOW),
        ReleaseInput(
            stage="root/pypi",
            project="demo",
            version="2.0.0",
            filename=TARGET_FILENAME,
            sha256=TARGET_SHA,
            origin_url=(
                "https://devpi.example/root/pypi/+f/"
                f"{TARGET_SHA[:3]}/{TARGET_SHA[3:16]}/{TARGET_FILENAME}"
            ),
            discovered_at=NOW,
        ),
    )

    target_path = tmp_path / TARGET_FILENAME
    target_path.write_bytes(b"target")
    target_release = ReleaseRecord(
        project="demo",
        version="2.0.0",
        filename=TARGET_FILENAME,
        sha256=TARGET_SHA,
        size_bytes=6,
    )

    def compare(kind: str):
        source = HttpArtifactBytesSource(
            _FailingSession(kind),
            _Resolver(),
            trusted_devpi_url="https://d",
        )
        try:
            return compare_release_to_baseline(
                target_release,
                target_path,
                lookup=_Lookup(),
                bytes_source=source,
            )
        finally:
            source.close()

    url_comparison = compare("url")
    diagnostic_comparison = compare("diagnostic")
    digest_comparison = compare("digest")

    assert url_comparison.has_baseline is True
    assert diagnostic_comparison.has_baseline is True
    assert digest_comparison.has_baseline is True
    assert len(url_comparison.findings) == 1
    assert len(diagnostic_comparison.findings) == 1
    url_finding, url_origin = url_comparison.findings[0]
    diagnostic_finding, diagnostic_origin = diagnostic_comparison.findings[0]
    assert url_finding.rule == diagnostic_finding.rule == "analyzer_error"
    assert URL_SECRET in url_finding.snippet
    assert QUERY_SECRET in url_finding.snippet
    assert AUTH_SECRET in diagnostic_finding.snippet
    assert PATH_SECRET in diagnostic_finding.snippet
    digest_finding, digest_origin = digest_comparison.findings[0]
    assert FULL_DIGEST_SECRET in digest_finding.snippet
    assert url_origin == diagnostic_origin == digest_origin == "diff_artifact"

    bundle = AnalysisBundle(
        target=VerifiedArtifact(
            stage="root/pypi",
            project="demo",
            version="2.0.0",
            filename=TARGET_FILENAME,
            sha256=TARGET_SHA,
            size_bytes=6,
            _stream=BytesIO(b"target"),
        )
    )
    report = AnalysisReport(
        analyzer_version="analyzer-1",
        has_baseline=True,
        baseline_sha256=BASELINE_SHA,
        baseline_tier="universal_wheel",
        evidence=(
            AnalysisEvidence("F7", url_finding, origin=url_origin),
            AnalysisEvidence("F7", diagnostic_finding, origin=diagnostic_origin),
            AnalysisEvidence("F7", digest_finding, origin=digest_origin),
        ),
        steps=(AnalysisStep("F7", "error"),),
    )
    worker = QuarantineWorker(
        store=store,
        preparer=_Preparer(bundle),
        analysis_engine=_Engine(report),
        policy_engine=_Policy(),
        worker_id="worker-1",
        now=lambda: NOW,
    )

    result = worker.run_once()

    assert result.status is WorkerCycleStatus.COMPLETED
    reader = SQLiteVerdictReader(factory, now=lambda: NOW)
    details = reader.get_artifact_details(TARGET_SHA)
    evidence = details.evidence[0]
    fingerprints = {
        finding_fingerprint(url_finding),
        finding_fingerprint(diagnostic_finding),
        finding_fingerprint(digest_finding),
    }
    assert evidence.details["fingerprint"] in fingerprints
    stored_text = " ".join(
        str(item.details) + item.message + str(item.file_path) for item in details.evidence
    )
    for secret in (URL_SECRET, QUERY_SECRET, AUTH_SECRET, PATH_SECRET, FULL_DIGEST_SECRET):
        assert secret not in stored_text
    assert details.summary.sha256 == TARGET_SHA
    assert details.baseline_sha256 == BASELINE_SHA

    with factory.connect() as connection:
        rows = connection.execute(
            "SELECT message, file_path, details_json FROM evidence WHERE verdict_id = "
            "(SELECT id FROM verdicts WHERE sha256 = ? AND is_current = 1)",
            (TARGET_SHA,),
        ).fetchall()
    assert rows
    assert all(
        secret not in " ".join(str(value) for value in row)
        for row in rows
        for secret in (URL_SECRET, QUERY_SECRET, AUTH_SECRET, PATH_SECRET, FULL_DIGEST_SECRET)
    )

    providers = ProductionAdminProviders(
        factory=factory,
        reader=reader,
        store=store,
        discovery=FileDiscoverySink(tmp_path / "discovery", now=lambda: NOW),
        policy_engine=None,
        worker=None,
    )
    diff = providers.artifact_diff(TARGET_SHA)
    assert diff["sha256"] == TARGET_SHA
    diff_text = str(diff)
    for secret in (URL_SECRET, QUERY_SECRET, AUTH_SECRET, PATH_SECRET, FULL_DIGEST_SECRET):
        assert secret not in diff_text

    service = GuardianAdminService(
        reader=reader, store=store, diff_reader=providers, now=lambda: NOW
    )
    details_response = inspect_artifact(_request(service, TARGET_SHA))
    diff_response = artifact_diff(_request(service, TARGET_SHA))
    assert details_response.status_code == 200
    assert diff_response.status_code == 200
    assert details_response.json_body["artifact"]["summary"]["sha256"] == TARGET_SHA
    assert diff_response.json_body["diff"]["sha256"] == TARGET_SHA
    for response in (details_response, diff_response):
        rendered = str(response.json_body)
        for secret in (URL_SECRET, QUERY_SECRET, AUTH_SECRET, PATH_SECRET, FULL_DIGEST_SECRET):
            assert secret not in rendered
