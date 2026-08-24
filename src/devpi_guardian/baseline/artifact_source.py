"""F6's `ArtifactBytesSource`, fetching baseline artifacts over HTTP(S).

The HTTP session is injected, never constructed here, and this module makes no
decision about authentication. Whether the session carries an Authorization
header, a cookie jar, a client certificate, or nothing at all is entirely the
session's business: the only things passed to `get` are the URL, `stream`, and
`timeout`. When F5 settles on an authentication scheme, the wiring that builds
the session changes and this class does not.

Every downloaded file is verified against the SHA-256 that was asked for. A
mismatch is an error, never a warning, and the partial file is removed. F4
records `origin_url` but never fetches or rehashes it, so this verification is
the only thing standing between a tampered response and an F7 diff computed
against the wrong bytes.

F4's sanitizer strips userinfo, query, and fragment from `origin_url` but does
not constrain the scheme, and its README requires F6 to go through canonical
devpi HTTP(S) `+f`/`+e` rather than treat the URL as a trust bypass or a local
open. Only `http` and `https` are accepted here for that reason.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

#: Matches `analyzers.archive.MAX_UNCOMPRESSED_SIZE`, so a download can never
#: hand the extractor more bytes than the extractor would accept.
MAX_ARTIFACT_BYTES = 1_000_000_000
DEFAULT_TIMEOUT_SECONDS = 30.0
_CHUNK_SIZE = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_HASH_PREFIX_PATTERN = re.compile(r"[0-9a-f]{3}", re.ASCII)
_HASH_SUFFIX_PATTERN = re.compile(r"[0-9a-f]{13}", re.ASCII)
_SAFE_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*", re.ASCII)


class ArtifactDownloadError(Exception):
    """A baseline artifact could not be fetched or could not be trusted."""


class ArtifactDigestMismatch(ArtifactDownloadError):
    """The downloaded bytes do not hash to the requested SHA-256."""


@runtime_checkable
class OriginUrlResolver(Protocol):
    """Resolves an approved digest to the URL it can be downloaded from."""

    def origin_url(self, sha256: str) -> str: ...

    def expected_size(self, sha256: str) -> int: ...


class HttpResponse(Protocol):
    """The slice of an HTTP response this module uses."""

    status_code: int

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class HttpSession(Protocol):
    """The slice of an HTTP session this module uses.

    Deliberately narrow: anything that can answer `get` works, including a
    `requests.Session` with any authentication already configured on it.
    """

    def get(
        self,
        url: str,
        *,
        stream: bool,
        timeout: float,
        allow_redirects: bool,
    ) -> HttpResponse: ...


class HttpArtifactBytesSource:
    """Download baseline artifacts and verify them, into a temporary directory.

    Use it as a context manager so the downloaded files are removed when the
    comparison is done:

        with HttpArtifactBytesSource(
            session, lookup, trusted_devpi_url="https://devpi.example"
        ) as source:
            ...

    `close()` does the same for callers that manage the lifetime themselves.
    """

    def __init__(
        self,
        session: HttpSession,
        resolver: OriginUrlResolver,
        *,
        trusted_devpi_url: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = MAX_ARTIFACT_BYTES,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._session = session
        self._resolver = resolver
        self._trusted_base = _canonical_devpi_base(trusted_devpi_url)
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._root: Path | None = None
        self._downloaded: dict[str, Path] = {}

    # -- lifetime ---------------------------------------------------------

    def __enter__(self) -> HttpArtifactBytesSource:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """Remove every file this source downloaded."""

        root, self._root = self._root, None
        self._downloaded.clear()
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)

    def _directory(self) -> Path:
        if self._root is None:
            self._root = Path(tempfile.mkdtemp(prefix="devpi-guardian-baseline-"))
        return self._root

    # -- the ArtifactBytesSource protocol ---------------------------------

    def open(self, sha256: str) -> Path:
        """Return a local path holding exactly the bytes of `sha256`.

        The same digest is downloaded once; later calls reuse the file.
        """

        digest = self._canonical(sha256)
        cached = self._downloaded.get(digest)
        if cached is not None:
            return cached

        url = self._url_for(digest)
        expected_size = self._expected_size_for(digest)
        target = self._directory() / _local_name(digest, url)
        try:
            actual = self._download(url, target, expected_size)
        except ArtifactDownloadError:
            target.unlink(missing_ok=True)
            raise
        except Exception as exc:
            # Whatever the injected session raises - connection error, read
            # timeout, TLS failure - becomes one explicit download error, so
            # the caller never has to know which HTTP library is in use.
            target.unlink(missing_ok=True)
            raise ArtifactDownloadError(
                f"{url} 다운로드 실패: {type(exc).__name__}: {exc}"
            ) from exc

        if actual != digest:
            # Fail closed: comparing against bytes that are not the approved
            # baseline would silently invalidate every F7 finding.
            target.unlink(missing_ok=True)
            raise ArtifactDigestMismatch(
                f"{url}의 SHA-256이 요청값과 다름: 요청={digest}, 실제={actual}"
            )

        self._downloaded[digest] = target
        return target

    # -- internals --------------------------------------------------------

    @staticmethod
    def _canonical(sha256: object) -> str:
        if not isinstance(sha256, str) or _SHA256_PATTERN.fullmatch(sha256) is None:
            raise ArtifactDownloadError(f"sha256이 소문자 64자리 16진수가 아님: {sha256!r}")
        return sha256

    def _url_for(self, digest: str) -> str:
        url = self._resolver.origin_url(digest)
        return _validate_artifact_url(url, digest, self._trusted_base)

    def _expected_size_for(self, digest: str) -> int:
        size = self._resolver.expected_size(digest)
        if type(size) is not int or size < 0:
            raise ArtifactDownloadError(f"저장된 artifact 크기가 유효하지 않음: {size!r}")
        if size > self._max_bytes:
            raise ArtifactDownloadError(
                f"저장된 artifact 크기가 한도 {self._max_bytes:,}바이트를 초과"
            )
        return size

    def _download(self, url: str, target: Path, expected_size: int) -> str:
        response = self._session.get(
            url,
            stream=True,
            timeout=self._timeout,
            allow_redirects=False,
        )
        try:
            status = getattr(response, "status_code", None)
            if status != 200:
                raise ArtifactDownloadError(f"{url} 응답 상태 {status}")
            digest = hashlib.sha256()
            written = 0
            with target.open("xb") as handle:
                for chunk in response.iter_content(_CHUNK_SIZE):
                    if not chunk:
                        continue
                    chunk_size = len(chunk)
                    if written + chunk_size > self._max_bytes:
                        raise ArtifactDownloadError(
                            f"{url} 크기가 한도 {self._max_bytes:,}바이트를 초과"
                        )
                    if written + chunk_size > expected_size:
                        raise ArtifactDownloadError(
                            f"{url} 크기가 저장값을 초과: 저장={expected_size}"
                        )
                    written += chunk_size
                    digest.update(chunk)
                    handle.write(chunk)
            if written != expected_size:
                raise ArtifactDownloadError(
                    f"{url} 크기가 저장값과 다름: 저장={expected_size}, 실제={written}"
                )
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        return digest.hexdigest()


def _canonical_devpi_base(value: str) -> tuple[str, str, int, str]:
    """Return the normalized scheme, host, port, and mount path."""

    if type(value) is not str:
        raise ValueError("trusted_devpi_url must be a URL string")
    if _has_control(value):
        raise ValueError("trusted_devpi_url contains control characters")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid trusted_devpi_url: {value!r}") from exc
    if scheme not in _ALLOWED_SCHEMES or not hostname:
        raise ValueError(f"invalid trusted_devpi_url: {value!r}")
    if not hostname.isascii() or "%" in parsed.netloc:
        raise ValueError("trusted_devpi_url host must be ASCII and unencoded")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("trusted_devpi_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("trusted_devpi_url must not contain query or fragment")
    base_path = _validated_base_path(parsed.path)
    host = hostname.lower()
    if host.endswith("."):
        raise ValueError("trusted_devpi_url host has ambiguous trailing dot")
    effective_port = port if port is not None else _default_port(scheme)
    return scheme, host, effective_port, base_path


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _validate_artifact_url(url: str, digest: str, trusted_base: tuple[str, str, int, str]) -> str:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ArtifactDownloadError(f"origin_url이 유효하지 않음: {url!r}") from exc
    if scheme not in _ALLOWED_SCHEMES or not hostname:
        raise ArtifactDownloadError(f"지원하지 않는 origin_url 스킴 또는 호스트: {url}")
    if not hostname.isascii() or "%" in parsed.netloc:
        raise ArtifactDownloadError(f"origin_url 호스트가 ASCII가 아니거나 인코딩됨: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise ArtifactDownloadError("origin_url에 credentials가 포함됨")
    if parsed.query or parsed.fragment:
        raise ArtifactDownloadError("origin_url에 query 또는 fragment가 포함됨")
    trusted_scheme, trusted_host, trusted_port, base_path = trusted_base
    stored_host = hostname.lower()
    if stored_host.endswith("."):
        raise ArtifactDownloadError(f"origin_url 호스트의 trailing dot이 모호함: {url}")
    stored_port = port if port is not None else _default_port(scheme)
    if (scheme, stored_host, stored_port) != (trusted_scheme, trusted_host, trusted_port):
        raise ArtifactDownloadError(f"origin_url이 trusted devpi URL과 다름: {url}")

    path = parsed.path
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "%" in path
        or "\\" in path
        or _has_control(path)
    ):
        raise ArtifactDownloadError(f"artifact 경로가 정규화되지 않음: {url}")
    if base_path:
        prefix = f"{base_path}/"
        if not path.startswith(prefix):
            raise ArtifactDownloadError(f"artifact 경로가 trusted mount 밖에 있음: {url}")
        prefix_length = len(prefix)
        relative_path = path[prefix_length:]
    else:
        relative_path = path.lstrip("/")
    parts = relative_path.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ArtifactDownloadError(f"artifact 경로가 완전하지 않음: {url}")
    if len(parts) < 3 or not all(_is_safe_component(part) for part in parts[:2]):
        raise ArtifactDownloadError(f"devpi stage 경로가 유효하지 않음: {url}")
    marker = parts[2]
    if marker == "+f":
        if len(parts) != 6:
            raise ArtifactDownloadError(f"+f artifact route가 완전하지 않음: {url}")
        first, second, filename = parts[3:]
        if (
            _HASH_PREFIX_PATTERN.fullmatch(first) is None
            or _HASH_SUFFIX_PATTERN.fullmatch(second) is None
            or first + second != digest[:16]
            or not _is_safe_component(filename)
        ):
            raise ArtifactDownloadError(f"+f artifact route가 digest와 일치하지 않음: {url}")
    elif marker == "+e":
        if len(parts) != 5 or not all(_is_safe_component(part) for part in parts[3:]):
            raise ArtifactDownloadError(f"+e artifact route가 완전하지 않음: {url}")
    else:
        raise ArtifactDownloadError(f"artifact route marker가 유효하지 않음: {url}")
    canonical_path = f"{base_path}/{relative_path}" if base_path else f"/{relative_path}"
    return urlunsplit((scheme, _render_netloc(stored_host, stored_port), canonical_path, "", ""))


def _validated_base_path(path: str) -> str:
    if not path or path == "/":
        return ""
    if not path.startswith("/") or path.endswith("/"):
        raise ValueError("trusted_devpi_url base path is not normalized")
    if "%" in path or "\\" in path or _has_control(path):
        raise ValueError("trusted_devpi_url base path is not safe")
    parts = path[1:].split("/")
    if not parts or not all(_is_safe_component(part) for part in parts):
        raise ValueError("trusted_devpi_url base path is not safe")
    return "/" + "/".join(parts)


def _is_safe_component(value: str) -> bool:
    return value not in {".", ".."} and _SAFE_COMPONENT_PATTERN.fullmatch(value) is not None


def _has_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _render_netloc(host: str, port: int) -> str:
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{rendered_host}:{port}"


def _local_name(digest: str, url: str) -> str:
    """Name the temporary file so its archive type stays recognizable.

    `analyzers.archive.extract_artifact` decides between zip and tar from the
    filename suffix, so a file named only by its digest would be rejected as
    an unsupported format. The digest prefix keeps the name unique; the
    filename from the origin URL supplies the suffix, stripped of anything
    that is not a plain filename character.
    """

    candidate = PurePosixPath(urlsplit(url).path).name
    safe = "".join(
        character for character in candidate if character.isalnum() or character in "._-"
    ).lstrip(".")
    return f"{digest}-{safe}" if safe else digest
