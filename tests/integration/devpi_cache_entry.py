"""Create a real post-fetch devpi mirror cache entry in a stopped server."""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from devpi_common.metadata import normalize_name, splitbasename
from devpi_server.config import get_pluginmanager, parseoptions
from devpi_server.filestore import Digests
from devpi_server.main import xom_from_config


def _fetch(url: str) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, method="GET")
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"upstream returned HTTP {response.status}")
        return response.read()


def _materialize(
    server_dir: Path, direct_path: str, upstream_url: str, expected_sha256: str
) -> None:
    parsed = urlsplit(direct_path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("cache entry route must be a path without query or fragment")
    relpath = parsed.path.lstrip("/")
    if not relpath.startswith("root/pypi/+e/"):
        raise ValueError("cache entry route must be root/pypi/+e")
    filename = relpath.rsplit("/", 1)[-1]
    project, version, _extension = splitbasename(filename)
    project = normalize_name(project)
    content = _fetch(upstream_url)
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError("upstream content SHA-256 does not match fixture metadata")

    pluginmanager = get_pluginmanager()
    config = parseoptions(
        pluginmanager,
        ["devpi-server", "--serverdir", str(server_dir), "--requests-only"],
    )
    xom = xom_from_config(config)
    try:
        with xom.keyfs.write_transaction(allow_restart=True):
            key = xom.filestore.get_key_from_relpath(relpath)
            if key is None:
                raise RuntimeError("devpi did not recognize the mirror cache route")
            entry = xom.filestore.get_file_entry_from_key(key)
            entry.url = upstream_url
            entry.project = project
            entry.version = version
            entry.file_set_content(
                BytesIO(content),
                hashes=Digests({"sha256": expected_sha256}),
            )
    finally:
        xom._close_sessions()
        xom.thread_pool.shutdown()


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: devpi_cache_entry SERVER_DIR DIRECT_PATH UPSTREAM_URL SHA256")
    _materialize(Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    main()
