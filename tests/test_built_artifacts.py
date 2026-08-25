from __future__ import annotations

import configparser
import email
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest
from packaging.requirements import Requirement
from setuptools import find_packages


@pytest.fixture(scope="module")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    repository = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp("built-artifacts")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(output),
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    wheels = sorted(output.glob("*.whl"))
    sdists = sorted(output.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return {"wheel": wheels[0], "sdist": sdists[0]}


def _members(kind: str, path: Path) -> list[str]:
    if kind == "wheel":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    with tarfile.open(path, "r:gz") as archive:
        return [member.name for member in archive.getmembers()]


def _package_root(kind: str, member: str) -> PurePosixPath:
    path = PurePosixPath(member)
    if kind == "sdist":
        path = PurePosixPath(*path.parts[2:]) if path.parts[1:2] == ("src",) else path
    return path


def _read_member(kind: str, path: Path, member: str) -> bytes:
    if kind == "wheel":
        with zipfile.ZipFile(path) as archive:
            return archive.read(member)
    with tarfile.open(path, "r:gz") as archive:
        selected = archive.extractfile(member)
        assert selected is not None
        return selected.read()


def _archive_member(kind: str, members: list[str], suffix: str) -> str:
    matching = [member for member in members if member.endswith(suffix)]
    if kind == "sdist" and suffix == "/PKG-INFO":
        matching = [member for member in matching if member.count("/") == 1]
    assert len(matching) == 1
    return matching[0]


def test_built_wheel_and_sdist_contain_exact_packages_and_data(built_artifacts) -> None:
    expected_packages = set(find_packages("src"))
    expected_migrations = {
        f"devpi_guardian/verdicts/sql/{number:03d}_{name}.sql"
        for number, name in (
            (1, "initial"),
            (2, "baseline_tier"),
            (3, "guardian_activation"),
            (4, "artifact_cooldown"),
            (5, "audit_events"),
            (6, "baseline_overrides"),
        )
    }
    expected_schema = "devpi_guardian/analyzers/schemas/finding-report-v1.schema.json"

    for kind, archive in built_artifacts.items():
        members = _members(kind, archive)
        normalized = {_package_root(kind, member) for member in members}
        package_inits = {
            str(path.parent).replace("/", ".")
            for path in normalized
            if path.parts[:1] == ("devpi_guardian",) and path.name == "__init__.py"
        }
        assert package_inits == expected_packages

        migration_paths = {
            str(path)
            for path in normalized
            if str(path).startswith("devpi_guardian/verdicts/sql/") and path.suffix == ".sql"
        }
        assert migration_paths == expected_migrations
        assert [str(path) for path in normalized if str(path) == expected_schema] == [
            expected_schema
        ]


def test_built_metadata_has_dependency_and_entry_points(built_artifacts) -> None:
    for kind, archive in built_artifacts.items():
        members = _members(kind, archive)
        metadata_member = _archive_member(
            kind, members, ".dist-info/METADATA" if kind == "wheel" else "/PKG-INFO"
        )
        metadata = email.message_from_bytes(_read_member(kind, archive, metadata_member))
        requests = [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]
        assert any(
            requirement.name == "requests"
            and requirement.marker is None
            and str(requirement.specifier) == "<3,>=2.32"
            for requirement in requests
        )

        entry_points_member = _archive_member(
            kind,
            members,
            ".dist-info/entry_points.txt" if kind == "wheel" else "/entry_points.txt",
        )
        entry_points = configparser.ConfigParser()
        entry_points.read_string(_read_member(kind, archive, entry_points_member).decode())
        assert entry_points["devpi_server"]["guardian"] == "devpi_guardian.plugin"
        assert entry_points["console_scripts"]["guardian"] == "devpi_guardian.admin.cli:main"
