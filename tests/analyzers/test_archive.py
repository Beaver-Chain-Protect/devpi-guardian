from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import devpi_guardian.analyzers.archive as archive_module
from devpi_guardian.analyzers.archive import extract_artifact


def test_normal_wheel_and_sdist_extract(make_wheel, make_sdist, tmp_path: Path) -> None:
    wheel = make_wheel({"demo/__init__.py": "VALUE = 1\n"})
    sdist = make_sdist({"demo/__init__.py": "VALUE = 1\n"})

    wheel_result = extract_artifact(wheel, tmp_path / "wheel-out")
    sdist_result = extract_artifact(sdist, tmp_path / "sdist-out")

    assert wheel_result.usable and not wheel_result.findings
    assert sdist_result.usable and not sdist_result.findings
    assert (wheel_result.root / "demo" / "__init__.py").is_file()
    assert (sdist_result.root / "demo-1.0.0" / "demo" / "__init__.py").is_file()


@pytest.mark.parametrize(
    ("compression", "suffix"),
    [("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz"), ("w:bz2", ".tbz2"), ("w:xz", ".txz")],
)
def test_tar_compression_aliases_extract(tmp_path: Path, compression: str, suffix: str) -> None:
    artifact = tmp_path / f"demo-1.0.0{suffix}"
    with tarfile.open(artifact, compression) as archive:
        payload = b"VALUE = 1\n"
        info = tarfile.TarInfo("demo-1.0.0/demo/__init__.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    result = extract_artifact(artifact, tmp_path / "out")

    assert result.usable
    assert (result.root / "demo-1.0.0" / "demo" / "__init__.py").read_bytes() == payload


@pytest.mark.parametrize("suffix", [".tar.bz2", ".tar.xz", ".tbz2", ".txz"])
def test_corrupt_tar_compression_alias_returns_analyzer_error(tmp_path: Path, suffix: str) -> None:
    artifact = tmp_path / f"broken{suffix}"
    artifact.write_bytes(b"not a tar archive")

    result = extract_artifact(artifact, tmp_path / "out")

    assert [item.rule for item in result.findings] == ["analyzer_error"]


def _malicious_tar(tmp_path: Path, member: tarfile.TarInfo, data: bytes = b"x") -> Path:
    path = tmp_path / f"bad-{len(list(tmp_path.iterdir()))}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        if member.isreg():
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        else:
            archive.addfile(member)
    return path


def test_tar_path_traversal_is_rejected_before_write(tmp_path: Path) -> None:
    artifact = _malicious_tar(tmp_path, tarfile.TarInfo("../../etc/passwd"))
    output = tmp_path / "out"
    result = extract_artifact(artifact, output)

    assert not result.usable
    assert any(
        item.rule == "archive_unsafe_member" and item.action == "DENY" for item in result.findings
    )
    assert not any(path.is_file() for path in output.rglob("*"))


def test_tar_absolute_path_is_rejected(tmp_path: Path) -> None:
    artifact = _malicious_tar(tmp_path, tarfile.TarInfo("/tmp/owned"))
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert {item.rule for item in result.findings} == {"archive_unsafe_member"}


def test_tar_symlink_is_not_followed(tmp_path: Path) -> None:
    member = tarfile.TarInfo("demo/link")
    member.type = tarfile.SYMTYPE
    member.linkname = "../../outside"
    artifact = _malicious_tar(tmp_path, member)
    result = extract_artifact(artifact, tmp_path / "out")

    assert not result.usable
    assert any("링크" in item.snippet for item in result.findings)
    assert not (tmp_path / "out" / "demo" / "link").exists()


def test_compression_bomb_is_blocked_before_large_write(make_wheel, tmp_path: Path) -> None:
    artifact = make_wheel({"demo/huge.bin": b"0" * 2_000_000}, name="bomb.whl")
    output = tmp_path / "out"
    result = extract_artifact(artifact, output)

    assert not result.usable
    assert any(item.rule == "archive_bomb" for item in result.findings)
    assert sum(path.stat().st_size for path in output.rglob("*") if path.is_file()) == 0


def test_corrupt_archive_returns_analyzer_error(tmp_path: Path) -> None:
    artifact = tmp_path / "broken.whl"
    artifact.write_bytes(b"not a zip")
    result = extract_artifact(artifact, tmp_path / "out")

    assert not result.usable
    assert [item.rule for item in result.findings] == ["analyzer_error"]


def test_case_insensitive_zip_path_collision_is_rejected(make_wheel, tmp_path: Path) -> None:
    artifact = make_wheel(
        {"demo/Module.py": "VALUE = 1\n", "demo/module.py": "VALUE = 2\n"},
        name="collision.whl",
    )
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert any("충돌" in item.snippet for item in result.findings)


def test_unicode_normalization_path_collision_is_rejected(make_wheel, tmp_path: Path) -> None:
    artifact = make_wheel(
        {
            "demo/caf\u00e9.py": "VALUE = 1\n",
            "demo/cafe\u0301.py": "VALUE = 2\n",
        },
        name="unicode-collision.whl",
    )
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert any("충돌" in item.snippet for item in result.findings)


def test_bidirectional_control_character_path_is_rejected(make_wheel, tmp_path: Path) -> None:
    artifact = make_wheel(
        {"demo/safe\u202egnp.py": "VALUE = 1\n"},
        name="bidi-control.whl",
    )
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert any("Unicode 제어문자" in item.snippet for item in result.findings)


def test_windows_reserved_device_path_is_rejected(make_wheel, tmp_path: Path) -> None:
    artifact = make_wheel({"demo/CON.py": "VALUE = 1\n"}, name="reserved.whl")
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert any("예약 장치명" in item.snippet for item in result.findings)


def test_file_directory_prefix_conflict_is_rejected_before_write(
    make_wheel, tmp_path: Path
) -> None:
    artifact = make_wheel(
        {"demo": "not a directory", "demo/core.py": "VALUE = 1\n"},
        name="prefix-conflict.whl",
    )
    output = tmp_path / "out"
    result = extract_artifact(artifact, output)
    assert not result.usable
    assert any("상위 경로" in item.snippet for item in result.findings)
    assert not any(path.is_file() for path in output.rglob("*"))


def test_zip_symlink_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "symlink.whl"
    with zipfile.ZipFile(artifact, "w") as archive:
        info = zipfile.ZipInfo("demo/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../outside")
    result = extract_artifact(artifact, tmp_path / "out")
    assert not result.usable
    assert any("심볼릭 링크" in item.snippet for item in result.findings)


def test_python_311_manual_tar_path_is_supported(make_sdist, tmp_path: Path, monkeypatch) -> None:
    artifact = make_sdist({"demo/__init__.py": "VALUE = 1\n"})
    monkeypatch.setattr(archive_module.sys, "version_info", (3, 11, 9))

    result = extract_artifact(artifact, tmp_path / "manual-out")

    assert result.usable
    assert (result.root / "demo-1.0.0" / "demo" / "__init__.py").is_file()
