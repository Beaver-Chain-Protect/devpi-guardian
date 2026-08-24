from __future__ import annotations

import hashlib
import html.parser
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_HOST = "127.0.0.1"
_READINESS_TIMEOUT = 20.0
_SHUTDOWN_TIMEOUT = 10.0
_START_ATTEMPTS = 3
_MAX_DIAGNOSTIC_CHARS = 12_000
_URL = re.compile(r"https?://[^\s\"'<>]+")
_URL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _loopback_environment() -> dict[str, str]:
    environment = os.environ.copy()
    bypass = "127.0.0.1,localhost,::1"
    environment["NO_PROXY"] = bypass
    environment["no_proxy"] = bypass
    return environment


def _executable(name: str) -> str:
    environment_executable = Path(sys.executable).with_name(name)
    if environment_executable.is_file():
        executable = str(environment_executable)
    else:
        executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required test executable is unavailable: {name}")
    return str(Path(executable).resolve())


def _sanitize_url(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or "localhost"
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        sanitized_parts = (parsed.scheme, host, parsed.path, "", "")
        return urllib.parse.urlunsplit(sanitized_parts)
    except ValueError:
        return "<redacted-url>"


def _sanitize(value: str) -> str:
    sanitized = _URL.sub(_sanitize_url, value)
    sanitized = re.sub(
        r"--password(?:=|\s+)\S*",
        "--password=<redacted>",
        sanitized,
    )
    return sanitized[-_MAX_DIAGNOSTIC_CHARS:]


def _safe_args(args: list[str]) -> tuple[str, ...]:
    result = []
    redact_next = False
    for arg in args:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
        elif arg == "--password":
            result.append(arg)
            redact_next = True
        elif arg.startswith("--password="):
            result.append("--password=<redacted>")
        else:
            result.append(_sanitize(arg))
    return tuple(result)


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        safe_args = _safe_args(args)
        message = f"command timed out after 60 seconds: {safe_args!r}"
        raise RuntimeError(message) from None
    sanitized = subprocess.CompletedProcess(
        _safe_args(args),
        completed.returncode,
        _sanitize(completed.stdout),
        _sanitize(completed.stderr),
    )
    if check and completed.returncode != 0:
        message = (
            f"command failed with exit code {completed.returncode}: "
            f"{sanitized.args!r}\n"
            f"stdout:\n{sanitized.stdout}\n"
            f"stderr:\n{sanitized.stderr}"
        )
        raise RuntimeError(message)
    return sanitized


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class MirrorArtifact:
    direct_path: str
    filename: str
    project: str
    version: str
    sha256: str
    content: bytes


@dataclass(slots=True)
class RunningDevpi:
    base_url: str
    guardian_db: Path
    client_dir: Path
    server_dir: Path
    uv_executable: str
    mirror_artifact: MirrorArtifact | None = None
    mirror_upstream_requests: list[str] | None = None
    _server: _ServerProcess | None = field(default=None, repr=False)
    _log_dir: Path | None = field(default=None, repr=False)
    _offline: bool = field(default=True, repr=False)
    _restart_generation: int = field(default=0, repr=False)

    def api(
        self,
        *args: str,
        cwd: Path | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = _loopback_environment()
        environment["DEVPI_CLIENTDIR"] = str(self.client_dir)
        return _run(
            [_executable("devpi"), *args],
            cwd=cwd,
            env=environment,
            check=check,
        )

    def request(
        self,
        path_or_url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResult:
        url = urllib.parse.urljoin(self.base_url, path_or_url)
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers=dict(headers or {}),
        )
        try:
            with _URL_OPENER.open(request, timeout=5) as response:
                return HttpResult(
                    response.status,
                    dict(response.headers.items()),
                    response.read(),
                )
        except urllib.error.HTTPError as error:
            with error:
                return HttpResult(
                    error.code,
                    dict(error.headers.items()),
                    error.read(),
                )
        except urllib.error.URLError as error:
            reason = _sanitize(str(error.reason))
            message = f"request failed for {_sanitize(url)}: {reason}"
            raise RuntimeError(message) from None

    def status_code(self, path_or_url: str, *, method: str = "GET") -> int:
        return self.request(path_or_url, method=method).status

    def restart(self) -> None:
        """Restart on the same port with the same server and Guardian data."""
        server = self._server
        log_dir = self._log_dir
        if server is None or log_dir is None:
            raise RuntimeError("devpi-server lifecycle is unavailable")

        port = server.port
        _terminate(server)
        self._server = None
        self._restart_generation += 1
        restarted = _start_server(
            self.server_dir,
            self.guardian_db,
            log_dir,
            offline=self._offline,
            preferred_port=port,
            log_label=f"restart-{self._restart_generation}",
        )
        self._server = restarted
        self.base_url = restarted.base_url
        self.api("use", restarted.base_url)
        self.api("login", "root", "--password=")
        self.api("use", "root/dev")

    def close(self) -> None:
        """Stop the current process and verify that its port is released."""
        if self._server is None:
            return
        _terminate(self._server)
        self._server = None

    def reset_guardian_db_and_expect_failure(self) -> str:
        """Remove this test DB and return the bounded startup diagnostic."""
        server = self._server
        log_dir = self._log_dir
        if server is None or log_dir is None:
            raise RuntimeError("devpi-server lifecycle is unavailable")
        _terminate(server)
        self._server = None
        _remove_temporary_guardian_db(self.guardian_db)
        try:
            _start_server(
                self.server_dir,
                self.guardian_db,
                log_dir,
                offline=self._offline,
                preferred_port=server.port,
                log_label="expected-activation-failure",
            )
        except RuntimeError as error:
            return str(error)
        raise AssertionError("devpi-server unexpectedly became ready")


@dataclass(frozen=True, slots=True)
class _ServerProcess:
    process: subprocess.Popen[bytes]
    base_url: str
    port: int
    log_path: Path


class _FirstLink(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.href: str | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag == "a" and self.href is None:
            self.href = dict(attrs).get("href")


class _QuietFileHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


@dataclass(frozen=True, slots=True)
class _LocalUpstream:
    base_url: str
    artifact: MirrorArtifact
    requests: list[str]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind((_HOST, 0))
        return int(candidate.getsockname()[1])


def _read_log(log_path: Path) -> str:
    try:
        contents = log_path.read_text(encoding="utf-8", errors="replace")
        return _sanitize(contents)
    except OSError as error:
        return f"<server log unavailable: {_sanitize(str(error))}>"


def _terminate(server: _ServerProcess) -> None:
    process = server.process
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=_SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=_SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                diagnostic = _read_log(server.log_path)
                message = "devpi-server did not exit after terminate and kill"
                raise RuntimeError(f"{message}\n{diagnostic}") from None

    deadline = time.monotonic() + 5.0
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                candidate.bind((_HOST, server.port))
                return
            except OSError:
                pass
        if time.monotonic() >= deadline:
            diagnostic = _read_log(server.log_path)
            message = f"devpi-server left port {server.port} occupied"
            message = f"{message} after shutdown\n{diagnostic}"
            raise RuntimeError(message)
        time.sleep(0.05)


def _remove_temporary_guardian_db(path: Path) -> None:
    """Delete the explicitly allocated temporary Guardian DB and sidecars."""
    resolved = path.resolve()
    is_guardian_db = resolved.name == "guardian.db"
    is_guardian_directory = resolved.parent.name in {
        "guardian",
        "mirror-guardian",
    }
    if not is_guardian_db or not is_guardian_directory:
        raise ValueError("refusing to remove a non-test Guardian DB")
    sidecars = (
        resolved.with_name(resolved.name + "-wal"),
        resolved.with_name(resolved.name + "-shm"),
    )
    for target in (resolved, *sidecars):
        target.unlink(missing_ok=True)


def _start_server(
    server_dir: Path,
    guardian_db: Path,
    log_dir: Path,
    *,
    offline: bool = True,
    preferred_port: int | None = None,
    log_label: str = "initial",
) -> _ServerProcess:
    for attempt in range(1, _START_ATTEMPTS + 1):
        port = preferred_port if preferred_port is not None else _free_port()
        base_url = f"http://{_HOST}:{port}"
        log_path = log_dir / f"devpi-server-{log_label}-{attempt}.log"
        args = [
            _executable("devpi-server"),
            "--serverdir",
            str(server_dir),
            "--host",
            _HOST,
            "--port",
            str(port),
            "--threads",
            "4",
            "--connection-limit",
            "8",
            "--request-timeout",
            "2",
            "--enable-core-metadata",
        ]
        if offline:
            args.append("--offline-mode")
        args.extend(("--guardian-db", str(guardian_db)))
        environment = _loopback_environment()
        environment["PYTHONUNBUFFERED"] = "1"
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                args,
                cwd=server_dir.parent,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        server = _ServerProcess(process, base_url, port, log_path)
        deadline = time.monotonic() + _READINESS_TIMEOUT
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with _URL_OPENER.open(
                    f"{base_url}/+status",
                    timeout=0.5,
                ) as response:
                    response.read()
                    if response.status == 200:
                        return server
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)

        diagnostic = _read_log(log_path)
        _terminate(server)
        port_collision = "address already in use" in diagnostic.lower()
        if port_collision and attempt < _START_ATTEMPTS:
            continue
        message = "devpi-server failed readiness"
        message = f"{message} {attempt}/{_START_ATTEMPTS}\n{diagnostic}"
        raise RuntimeError(message)
    raise AssertionError("unreachable")


def _write_mirror_wheel(root: Path) -> MirrorArtifact:
    project = "mirror-guardian"
    version = "1.0.0"
    filename = "mirror_guardian-1.0.0-py3-none-any.whl"
    wheel = root / "packages" / filename
    wheel.parent.mkdir(parents=True)
    dist_info = "mirror_guardian-1.0.0.dist-info"
    metadata = "Metadata-Version: 2.1\nName: mirror-guardian\nVersion: 1.0.0\n"

    def member(name: str, content: str) -> tuple[zipfile.ZipInfo, str]:
        info = zipfile.ZipInfo(name, date_time=(2026, 8, 18, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        return info, content

    with zipfile.ZipFile(wheel, "w") as archive:
        for info, content in (
            member("mirror_guardian/__init__.py", '__version__ = "1.0.0"\n'),
            member(
                f"{dist_info}/METADATA",
                metadata,
            ),
            member(
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nGenerator: guardian-integration\n"
                "Root-Is-Purelib: true\nTag: py3-none-any\n",
            ),
            member(f"{dist_info}/RECORD", ""),
        ):
            archive.writestr(info, content)

    simple = root / "simple" / project / "index.html"
    simple.parent.mkdir(parents=True)
    simple.write_text(
        f'<!doctype html><a href="../../packages/{filename}">{filename}</a>\n',
        encoding="utf-8",
    )
    (root / "simple" / "index.html").write_text(
        f'<!doctype html><a href="{project}/">{project}</a>\n',
        encoding="utf-8",
    )
    content = wheel.read_bytes()
    return MirrorArtifact(
        "",
        filename,
        project,
        version,
        hashlib.sha256(content).hexdigest(),
        content,
    )


@pytest.fixture
def local_upstream(tmp_path: Path) -> _LocalUpstream:
    root = tmp_path / "upstream"
    artifact = _write_mirror_wheel(root)
    requests: list[str] = []

    class TrackingFileHandler(_QuietFileHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            super().do_GET()

        def do_HEAD(self) -> None:
            requests.append(self.path)
            super().do_HEAD()

    handler = partial(TrackingFileHandler, directory=str(root))
    httpd = ThreadingHTTPServer((_HOST, 0), handler)
    port = int(httpd.server_address[1])
    thread = threading.Thread(
        target=httpd.serve_forever,
        name="guardian-local-upstream",
    )
    thread.start()
    try:
        yield _LocalUpstream(f"http://{_HOST}:{port}", artifact, requests)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("local upstream server did not stop")


@pytest.fixture
def running_devpi(tmp_path: Path) -> RunningDevpi:
    server_dir = tmp_path / "server"
    client_dir = tmp_path / "client"
    log_dir = tmp_path / "logs"
    guardian_db = tmp_path / "guardian" / "guardian.db"
    log_dir.mkdir()
    guardian_db.parent.mkdir()

    _run([_executable("devpi-init"), "--serverdir", str(server_dir)])
    server = _start_server(server_dir, guardian_db, log_dir)
    running = RunningDevpi(
        server.base_url,
        guardian_db,
        client_dir,
        server_dir,
        _executable("uv"),
        _server=server,
        _log_dir=log_dir,
    )
    try:
        running.api("use", server.base_url)
        running.api("login", "root", "--password=")
        running.api("index", "-c", "root/dev", "bases=")
        running.api("use", "root/dev")
        yield running
    finally:
        running.close()


@pytest.fixture
def running_mirror_devpi(
    tmp_path: Path,
    local_upstream: _LocalUpstream,
) -> RunningDevpi:
    server_dir = tmp_path / "mirror-server"
    client_dir = tmp_path / "mirror-client"
    log_dir = tmp_path / "mirror-logs"
    guardian_db = tmp_path / "mirror-guardian" / "guardian.db"
    log_dir.mkdir()
    guardian_db.parent.mkdir()
    _run([_executable("devpi-init"), "--serverdir", str(server_dir)])

    protected: _ServerProcess | None = None
    running: RunningDevpi | None = None
    try:
        protected = _start_server(
            server_dir,
            guardian_db,
            log_dir,
            offline=False,
        )
        client = RunningDevpi(
            protected.base_url,
            guardian_db,
            client_dir,
            server_dir,
            _executable("uv"),
        )
        client.api("use", protected.base_url)
        client.api("login", "root", "--password=")
        client.api(
            "index",
            "root/pypi",
            f"mirror_url={local_upstream.base_url}/simple/",
            "mirror_cache_expiry=0",
        )
        simple_path = f"/root/pypi/+simple/{local_upstream.artifact.project}/"
        simple = client.request(simple_path)
        if simple.status != 200:
            requests = _sanitize(repr(local_upstream.requests))
            raise RuntimeError(
                f"local root/pypi metadata returned HTTP {simple.status}; "
                f"upstream requests={requests}"
            )
        parser = _FirstLink()
        parser.feed(simple.body.decode("utf-8"))
        if parser.href is None:
            message = "local root/pypi metadata lacked a release link"
            raise RuntimeError(message)
        simple_url = urllib.parse.urljoin(protected.base_url, simple_path)
        direct_url = urllib.parse.urljoin(simple_url, parser.href)
        if "/root/pypi/+e/" not in direct_url:
            safe_url = _sanitize(direct_url)
            message = f"hashless mirror did not create +e: {safe_url}"
            raise RuntimeError(message)
        parsed_direct = urllib.parse.urlsplit(direct_url)
        direct_path = urllib.parse.urlunsplit(
            (
                "",
                "",
                parsed_direct.path,
                parsed_direct.query,
                parsed_direct.fragment,
            )
        )
        mirror_artifact = MirrorArtifact(
            direct_path,
            local_upstream.artifact.filename,
            local_upstream.artifact.project,
            local_upstream.artifact.version,
            local_upstream.artifact.sha256,
            local_upstream.artifact.content,
        )

        running = RunningDevpi(
            protected.base_url,
            guardian_db,
            client_dir,
            server_dir,
            _executable("uv"),
            mirror_artifact,
            local_upstream.requests,
            _server=protected,
            _log_dir=log_dir,
            _offline=False,
        )
        yield running
    finally:
        if running is not None:
            running.close()
        elif protected is not None:
            _terminate(protected)
