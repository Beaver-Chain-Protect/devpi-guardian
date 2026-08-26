"""Artifact builders for the F7 baseline-diff tests.

These mirror the `make_wheel` / `make_sdist` fixtures in
`tests/analyzers/conftest.py` as plain functions, because F7's tests live at
the top level of `tests/` where those fixtures are not visible.
"""

from __future__ import annotations

import io
import stat
import tarfile
import time
import zipfile
from collections.abc import Mapping
from pathlib import Path

Content = str | bytes


def _bytes(content: Content) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


def build_wheel(
    path: Path,
    files: Mapping[str, Content],
    *,
    mtime: tuple[int, int, int, int, int, int] = (2020, 1, 1, 0, 0, 0),
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member_name, content in sorted(files.items()):
            info = zipfile.ZipInfo(member_name, date_time=mtime)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, _bytes(content))
    return path


def build_sdist(
    path: Path,
    files: Mapping[str, Content],
    *,
    prefix: str | None = "demo-1.0.0",
    mtime: int = 1_577_836_800,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for member_name, content in sorted(files.items()):
            payload = _bytes(content)
            info = tarfile.TarInfo(f"{prefix}/{member_name}" if prefix else member_name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(payload))
    return path


def now_mtime() -> int:
    return int(time.time())
