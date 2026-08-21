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
from urllib.parse import urlsplit

#: Matches `analyzers.archive.MAX_UNCOMPRESSED_SIZE`, so a download can never
#: hand the extractor more bytes than the extractor would accept.
MAX_ARTIFACT_BYTES = 1_000_000_000
DEFAULT_TIMEOUT_SECONDS = 30.0
_CHUNK_SIZE = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class ArtifactDownloadError(Exception):
    """A baseline artifact could not be fetched or could not be trusted."""


class ArtifactDigestMismatch(ArtifactDownloadError):
    """The downloaded bytes do not hash to the requested SHA-256."""


@runtime_checkable
class OriginUrlResolver(Protocol):
    """Resolves an approved digest to the URL it can be downloaded from."""

    def origin_url(self, sha256: str) -> str: ...


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

    def get(self, url: str, *, stream: bool, timeout: float) -> HttpResponse: ...


class HttpArtifactBytesSource:
    """Download baseline artifacts and verify them, into a temporary directory.

    Use it as a context manager so the downloaded files are removed when the
    comparison is done:

        with HttpArtifactBytesSource(session, lookup) as source:
            ...

    `close()` does the same for callers that manage the lifetime themselves.
    """

    def __init__(
        self,
        session: HttpSession,
        resolver: OriginUrlResolver,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = MAX_ARTIFACT_BYTES,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._session = session
        self._resolver = resolver
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
        target = self._directory() / _local_name(digest, url)
        try:
            actual = self._download(url, target)
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
        scheme = urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            # `file:` and friends would turn a recorded URL into a local open,
            # which the F4 README explicitly forbids for F6.
            raise ArtifactDownloadError(f"지원하지 않는 origin_url 스킴: {url}")
        return url

    def _download(self, url: str, target: Path) -> str:
        response = self._session.get(url, stream=True, timeout=self._timeout)
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
                    written += len(chunk)
                    if written > self._max_bytes:
                        raise ArtifactDownloadError(
                            f"{url} 크기가 한도 {self._max_bytes:,}바이트를 초과"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        return digest.hexdigest()


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
