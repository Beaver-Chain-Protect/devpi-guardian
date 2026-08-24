"""Header-first, non-executing extraction for wheel and sdist artifacts."""

from __future__ import annotations

import ntpath
import os
import posixpath
import stat
import sys
import tarfile
import unicodedata
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .rules import rule
from .types import Finding, make_finding, sort_findings

MAX_UNCOMPRESSED_SIZE = 1_000_000_000
MAX_COMPRESSION_RATIO = 100.0
MAX_MEMBERS = 10_000
_COPY_CHUNK_SIZE = 1024 * 1024
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz", ".tbz2", ".txz")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)
_BIDI_CONTROL_CHARACTERS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


@dataclass(frozen=True)
class ExtractedArtifact:
    """Metadata for one extraction into a caller-owned temporary directory."""

    root: Path
    files: tuple[str, ...]
    executable_files: frozenset[str]
    findings: tuple[Finding, ...]
    usable: bool


@dataclass(frozen=True)
class _Member:
    archive_name: str
    relative_path: str
    size: int
    is_directory: bool
    executable: bool
    source: object


def _finding(rule_id: str, file: str, snippet: str, *, line: int | None = None) -> Finding:
    definition = rule(rule_id)
    return make_finding(
        rule=rule_id,
        action=definition.action,
        file=file,
        line=line,
        snippet=snippet,
        message=definition.message,
    )


def _error(artifact_path: Path, exc: BaseException) -> Finding:
    definition = rule("analyzer_error")
    return make_finding(
        rule="analyzer_error",
        action=definition.action,
        file=artifact_path.name or "<artifact>",
        line=None,
        snippet=f"{type(exc).__name__}: {exc}",
        message=definition.message,
    )


def _safe_relative_path(raw_name: str, destination: Path) -> tuple[str | None, str | None]:
    """Return a normalized POSIX path, or a human-readable rejection reason."""

    if not raw_name or "\x00" in raw_name:
        return None, "비어 있거나 NUL 문자를 포함한 멤버 경로"

    portable = raw_name.replace("\\", "/")
    drive, _ = ntpath.splitdrive(portable)
    if drive or portable.startswith("/"):
        return None, f"절대경로: {raw_name}"

    normalized = posixpath.normpath(portable)
    parts = PurePosixPath(normalized).parts
    if normalized in {"", "."}:
        return None, f"유효하지 않은 멤버 경로: {raw_name}"
    if any(part == ".." for part in PurePosixPath(portable).parts) or ".." in parts:
        return None, f"상위 디렉터리 이탈: {raw_name}"

    for part in parts:
        if any(character in _BIDI_CONTROL_CHARACTERS for character in part):
            return (
                None,
                f"표시 방향을 바꾸는 Unicode 제어문자 경로: {raw_name}",
            )
        if ":" in part:
            return (
                None,
                f"Windows 대체 데이터 스트림 또는 콜론 경로: {raw_name}",
            )
        if part.rstrip(" .") != part:
            return (
                None,
                f"Windows에서 모호해지는 끝 공백·마침표 경로: {raw_name}",
            )
        device_name = part.split(".", 1)[0].casefold()
        if device_name in _WINDOWS_RESERVED_NAMES:
            return None, f"Windows 예약 장치명 경로: {raw_name}"

    target_root = destination.resolve()
    target = (target_root / Path(*parts)).resolve()
    try:
        target.relative_to(target_root)
    except ValueError:
        return None, f"대상 디렉터리 밖 경로: {raw_name}"
    return PurePosixPath(*parts).as_posix(), None


def _portable_collision_key(relative_path: str) -> str:
    """Model case-insensitive Windows extraction collisions on every OS."""

    return "/".join(
        unicodedata.normalize("NFC", part.rstrip(" .")).casefold()
        for part in PurePosixPath(relative_path).parts
    )


def _path_type_conflict(
    collision_key: str,
    *,
    is_directory: bool,
    seen_paths: dict[str, bool],
) -> str | None:
    if collision_key in seen_paths:
        return "대소문자·끝 문자 정규화 후 경로가 충돌하는 멤버"
    parts = collision_key.split("/")
    for index in range(1, len(parts)):
        ancestor = "/".join(parts[:index])
        if ancestor in seen_paths and not seen_paths[ancestor]:
            return "상위 경로가 디렉터리가 아닌 파일인 멤버"
    if not is_directory and any(
        existing.startswith(f"{collision_key}/") for existing in seen_paths
    ):
        return "다른 멤버의 상위 디렉터리를 파일로 선언한 멤버"
    return None


def _bomb_reason(*, member_count: int, total_size: int, compressed_size: int) -> str | None:
    if member_count > MAX_MEMBERS:
        return f"파일 수 {member_count:,}개가 한도 {MAX_MEMBERS:,}개를 초과"
    if total_size > MAX_UNCOMPRESSED_SIZE:
        return f"예상 해제 크기 {total_size:,}바이트가 1GB 한도를 초과"
    ratio = total_size / max(compressed_size, 1)
    if ratio > MAX_COMPRESSION_RATIO:
        return f"예상 압축률 {ratio:.1f}:1이 {MAX_COMPRESSION_RATIO:.0f}:1 한도를 초과"
    return None


def _preflight_zip(
    archive: zipfile.ZipFile, destination: Path, artifact_name: str
) -> tuple[list[_Member], list[Finding]]:
    members: list[_Member] = []
    findings: list[Finding] = []
    seen_paths: dict[str, bool] = {}
    total_size = 0
    total_compressed = 0

    for count, info in enumerate(archive.infolist(), start=1):
        total_size += max(0, info.file_size)
        total_compressed += max(0, info.compress_size)
        bomb = _bomb_reason(
            member_count=count,
            total_size=total_size,
            compressed_size=total_compressed,
        )
        if bomb:
            findings.append(_finding("archive_bomb", artifact_name, bomb))
            return [], findings

        relative_path, rejection = _safe_relative_path(info.filename, destination)
        if rejection:
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    info.filename or artifact_name,
                    rejection,
                )
            )
            continue
        assert relative_path is not None

        if info.flag_bits & 0x1:
            findings.append(_finding("archive_unsafe_member", relative_path, "암호화된 ZIP 멤버"))
            continue

        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        is_directory = info.is_dir()
        if stat.S_ISLNK(unix_mode):
            findings.append(_finding("archive_unsafe_member", relative_path, "심볼릭 링크 멤버"))
            continue
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    relative_path,
                    "일반 파일이 아닌 특수 멤버",
                )
            )
            continue
        collision_key = _portable_collision_key(relative_path)
        conflict = _path_type_conflict(
            collision_key,
            is_directory=is_directory,
            seen_paths=seen_paths,
        )
        if conflict:
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    relative_path,
                    conflict,
                )
            )
            continue
        seen_paths[collision_key] = is_directory
        members.append(
            _Member(
                archive_name=info.filename,
                relative_path=relative_path,
                size=info.file_size,
                is_directory=is_directory,
                executable=bool(unix_mode & 0o111) and not is_directory,
                source=info,
            )
        )
    return members, findings


def _preflight_tar(
    archive: tarfile.TarFile,
    destination: Path,
    artifact_name: str,
    archive_size: int,
) -> tuple[list[_Member], list[Finding]]:
    members: list[_Member] = []
    findings: list[Finding] = []
    seen_paths: dict[str, bool] = {}
    total_size = 0

    for count, info in enumerate(archive, start=1):
        total_size += max(0, info.size)
        bomb = _bomb_reason(
            member_count=count,
            total_size=total_size,
            compressed_size=archive_size,
        )
        if bomb:
            findings.append(_finding("archive_bomb", artifact_name, bomb))
            return [], findings

        relative_path, rejection = _safe_relative_path(info.name, destination)
        if rejection:
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    info.name or artifact_name,
                    rejection,
                )
            )
            continue
        assert relative_path is not None

        if info.issym() or info.islnk():
            kind = "심볼릭 링크" if info.issym() else "하드 링크"
            findings.append(_finding("archive_unsafe_member", relative_path, f"{kind} 멤버"))
            continue
        if getattr(info, "sparse", None):
            findings.append(_finding("archive_unsafe_member", relative_path, "sparse tar 멤버"))
            continue
        if not (info.isfile() or info.isdir()):
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    relative_path,
                    "일반 파일이 아닌 특수 멤버",
                )
            )
            continue
        collision_key = _portable_collision_key(relative_path)
        conflict = _path_type_conflict(
            collision_key,
            is_directory=info.isdir(),
            seen_paths=seen_paths,
        )
        if conflict:
            findings.append(
                _finding(
                    "archive_unsafe_member",
                    relative_path,
                    conflict,
                )
            )
            continue
        seen_paths[collision_key] = info.isdir()
        members.append(
            _Member(
                archive_name=info.name,
                relative_path=relative_path,
                size=info.size,
                is_directory=info.isdir(),
                executable=bool(info.mode & 0o111) and info.isfile(),
                source=info,
            )
        )
    return members, findings


def _copy_limited(source: BinaryIO, target: BinaryIO, expected_size: int) -> None:
    copied = 0
    while True:
        chunk = source.read(_COPY_CHUNK_SIZE)
        if not chunk:
            break
        copied += len(chunk)
        if copied > expected_size or copied > MAX_UNCOMPRESSED_SIZE:
            raise ValueError("아카이브 헤더의 파일 크기보다 많은 데이터가 해제됨")
        target.write(chunk)
    if copied != expected_size:
        raise ValueError(f"아카이브 헤더 크기({expected_size})와 실제 크기({copied})가 다름")


def _extract_zip(archive: zipfile.ZipFile, members: Iterable[_Member], destination: Path) -> None:
    for member in members:
        target = destination / Path(*PurePosixPath(member.relative_path).parts)
        if member.is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        info = member.source
        assert isinstance(info, zipfile.ZipInfo)
        with archive.open(info, "r") as source, target.open("xb") as output:
            _copy_limited(source, output, member.size)


def _extract_tar_manually(
    archive: tarfile.TarFile, members: Iterable[_Member], destination: Path
) -> None:
    for member in members:
        target = destination / Path(*PurePosixPath(member.relative_path).parts)
        if member.is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        info = member.source
        assert isinstance(info, tarfile.TarInfo)
        source = archive.extractfile(info)
        if source is None:
            raise ValueError(f"일반 파일 데이터를 읽을 수 없음: {member.archive_name}")
        with source, target.open("xb") as output:
            _copy_limited(source, output, member.size)


def _extract_tar_data_filter(
    archive: tarfile.TarFile, members: Iterable[_Member], destination: Path
) -> None:
    """Use Python 3.12's hardened filter after our version-independent checks."""

    tar_members = [member.source for member in members]
    archive.extractall(path=destination, members=tar_members, filter="data")


def extract_artifact(artifact_path: str | os.PathLike[str], destination: Path) -> ExtractedArtifact:
    """Safely extract a wheel/zip or sdist/tar without executing its contents.

    All validation is completed from archive headers before the first member is
    written. Any unsafe member rejects the whole artifact. No exception escapes
    this function.
    """

    path = Path(artifact_path)
    destination = Path(destination)
    try:
        if not path.is_file():
            raise FileNotFoundError(path)
        destination.mkdir(parents=True, exist_ok=True)

        if path.name.lower().endswith((".whl", ".zip")):
            with zipfile.ZipFile(path) as archive:
                members, findings = _preflight_zip(archive, destination, path.name)
                if findings:
                    return ExtractedArtifact(
                        destination,
                        (),
                        frozenset(),
                        tuple(sort_findings(findings)),
                        False,
                    )
                _extract_zip(archive, members, destination)
        elif path.name.lower().endswith(_TAR_SUFFIXES):
            with tarfile.open(path, mode="r:*") as archive:
                members, findings = _preflight_tar(
                    archive, destination, path.name, path.stat().st_size
                )
                if findings:
                    return ExtractedArtifact(
                        destination,
                        (),
                        frozenset(),
                        tuple(sort_findings(findings)),
                        False,
                    )
                if sys.version_info >= (3, 12):
                    _extract_tar_data_filter(archive, members, destination)
                else:
                    _extract_tar_manually(archive, members, destination)
        else:
            raise ValueError(
                "지원 형식은 .whl/.zip/.tar.gz/.tgz/.tar.bz2/.tar.xz/.tbz2/.txz 입니다"
            )

        files = tuple(sorted(member.relative_path for member in members if not member.is_directory))
        executable_files = frozenset(
            member.relative_path for member in members if member.executable
        )
        return ExtractedArtifact(destination, files, executable_files, (), True)
    except BaseException as exc:  # The public analyzer contract forbids leakage.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return ExtractedArtifact(
            destination,
            (),
            frozenset(),
            (_error(path, exc),),
            False,
        )
