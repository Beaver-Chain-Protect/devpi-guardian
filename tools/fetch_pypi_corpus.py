"""Download verified latest PyPI sdist/pure-wheel pairs for offline evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
USER_AGENT = "devpi-guardian-corpus/0.1 (+offline-security-analysis)"


@dataclass(frozen=True)
class ReleaseFile:
    filename: str
    url: str
    sha256: str
    size: int


def _request_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(5 * 1024 * 1024 + 1)
    if len(payload) > 5 * 1024 * 1024:
        raise ValueError("PyPI metadata 응답이 5MB 한도를 초과했습니다")
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("PyPI metadata 최상위 값이 객체가 아닙니다")
    return data


def _release_file(raw: dict[str, Any]) -> ReleaseFile:
    filename = raw.get("filename")
    url = raw.get("url")
    size = raw.get("size")
    digests = raw.get("digests")
    sha256 = digests.get("sha256") if isinstance(digests, dict) else None
    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or not isinstance(url, str)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not isinstance(sha256, str)
        or len(sha256) != 64
    ):
        raise ValueError("PyPI release file metadata 형식이 올바르지 않습니다")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise ValueError(f"허용되지 않은 artifact URL: {url}")
    if size < 0 or size > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"artifact 크기 한도 초과: {filename} ({size:,} bytes)")
    return ReleaseFile(filename, url, sha256.lower(), size)


def select_latest_pair(
    data: dict[str, Any],
) -> tuple[str, ReleaseFile, ReleaseFile]:
    info = data.get("info")
    urls = data.get("urls")
    if not isinstance(info, dict) or not isinstance(urls, list):
        raise ValueError("PyPI project metadata에 info 또는 urls가 없습니다")
    version = info.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("PyPI project version을 확인할 수 없습니다")

    sdists: list[ReleaseFile] = []
    wheels: list[ReleaseFile] = []
    for raw in urls:
        if not isinstance(raw, dict) or raw.get("yanked") is True:
            continue
        package_type = raw.get("packagetype")
        filename = raw.get("filename")
        if not isinstance(filename, str):
            continue
        if package_type == "sdist" and filename.lower().endswith(".tar.gz"):
            sdists.append(_release_file(raw))
        elif package_type == "bdist_wheel" and filename.lower().endswith(
            ("-py3-none-any.whl", "-py2.py3-none-any.whl")
        ):
            wheels.append(_release_file(raw))
    if not sdists or not wheels:
        raise ValueError(f"{version} 릴리스에 sdist/pure wheel 쌍이 없습니다")
    return (
        version,
        sorted(sdists, key=lambda item: item.filename)[0],
        sorted(wheels, key=lambda item: item.filename)[0],
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(file: ReleaseFile, destination: Path) -> None:
    if destination.is_file():
        if _file_sha256(destination) == file.sha256:
            return
        raise ValueError(f"기존 파일의 SHA-256이 PyPI metadata와 다릅니다: {destination}")
    request = urllib.request.Request(file.url, headers={"User-Agent": USER_AGENT})
    temporary = destination.with_name(f"{destination.name}.part")
    temporary.unlink(missing_ok=True)
    digest = hashlib.sha256()
    written = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            temporary.open("xb") as output,
        ):
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES or written > file.size:
                    raise ValueError(f"다운로드 크기가 metadata를 초과했습니다: {file.filename}")
                digest.update(chunk)
                output.write(chunk)
        if written != file.size or digest.hexdigest() != file.sha256:
            raise ValueError(f"다운로드 무결성 검증 실패: {file.filename}")
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def fetch_corpus(packages: Iterable[str], output_dir: str | Path) -> tuple[Path, list[str]]:
    root = Path(output_dir).resolve()
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "source": "PyPI JSON API",
        "f8": [],
        "f9": [],
    }
    failures: list[str] = []

    for package in packages:
        package = package.strip()
        if not package:
            continue
        api_url = f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/json"
        try:
            data = _request_json(api_url)
            version, sdist, wheel = select_latest_pair(data)
            sdist_path = artifacts / sdist.filename
            wheel_path = artifacts / wheel.filename
            _download(sdist, sdist_path)
            _download(wheel, wheel_path)
            case_name = f"{package}=={version}"
            manifest["f8"].append(  # type: ignore[union-attr]
                {
                    "name": f"{case_name}:wheel",
                    "artifact": f"artifacts/{wheel.filename}",
                }
            )
            manifest["f9"].append(  # type: ignore[union-attr]
                {
                    "name": f"{case_name}:pair",
                    "sdist": f"artifacts/{sdist.filename}",
                    "wheel": f"artifacts/{wheel.filename}",
                }
            )
        except (
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            urllib.error.URLError,
        ) as exc:
            failures.append(f"{package}: {type(exc).__name__}: {exc}")

    manifest_path = root / "corpus.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path, failures


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PyPI 최신 릴리스의 검증된 sdist/pure-wheel 쌍을 내려받습니다."
    )
    parser.add_argument("packages", nargs="+", help="PyPI 프로젝트 이름")
    parser.add_argument("--output-dir", default=".corpus", help="corpus 저장 디렉터리")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="한 패키지라도 실패하면 종료 코드 1",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    manifest, failures = fetch_corpus(arguments.packages, arguments.output_dir)
    print(f"manifest: {manifest}")
    for failure in failures:
        print(f"skip: {failure}")
    return 1 if arguments.strict and failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
