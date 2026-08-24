from __future__ import annotations

import base64
import csv
import hashlib
import io
import stat
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

Content = str | bytes


def _bytes(content: Content) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


@pytest.fixture
def make_wheel(tmp_path: Path):
    def factory(
        files: Mapping[str, Content],
        *,
        name: str = "demo-1.0.0-py3-none-any.whl",
        modes: Mapping[str, int] | None = None,
        include_record: bool = True,
    ) -> Path:
        path = tmp_path / name
        entries = dict(files)
        has_record = any(
            Path(member_name).name == "RECORD"
            and Path(member_name).parent.name.endswith(".dist-info")
            for member_name in entries
        )
        if include_record and name.lower().endswith(".whl") and not has_record:
            dist_info = next(
                (
                    Path(member_name).parent.as_posix()
                    for member_name in sorted(entries)
                    if Path(member_name).parent.name.endswith(".dist-info")
                ),
                "demo-1.0.0.dist-info",
            )
            record_name = f"{dist_info}/RECORD"
            rows: list[tuple[str, str, str]] = []
            for member_name, content in sorted(entries.items()):
                payload = _bytes(content)
                digest = (
                    base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
                    .decode("ascii")
                    .rstrip("=")
                )
                rows.append((member_name.replace("\\", "/"), f"sha256={digest}", str(len(payload))))
            rows.append((record_name, "", ""))
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\n")
            writer.writerows(rows)
            entries[record_name] = output.getvalue()
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member_name, content in sorted(entries.items()):
                info = zipfile.ZipInfo(member_name)
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = (modes or {}).get(member_name, 0o644)
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, _bytes(content))
        return path

    return factory


@pytest.fixture
def make_sdist(tmp_path: Path):
    def factory(
        files: Mapping[str, Content],
        *,
        name: str = "demo-1.0.0.tar.gz",
        prefix: str | None = "demo-1.0.0",
        modes: Mapping[str, int] | None = None,
    ) -> Path:
        path = tmp_path / name
        with tarfile.open(path, "w:gz") as archive:
            for member_name, content in sorted(files.items()):
                archive_name = f"{prefix}/{member_name}" if prefix else member_name
                payload = _bytes(content)
                info = tarfile.TarInfo(archive_name)
                info.size = len(payload)
                info.mode = (modes or {}).get(member_name, 0o644)
                archive.addfile(info, io.BytesIO(payload))
        return path

    return factory
