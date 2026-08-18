from __future__ import annotations

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
    ) -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member_name, content in sorted(files.items()):
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
