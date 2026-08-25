"""Canonical devpi artifact routes shared by worker intake paths."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

_DEVPI_NAME = re.compile(r"[A-Za-z0-9._@-]+", re.ASCII)
_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9._+@~-]+", re.ASCII)
_HASH_PREFIX = re.compile(r"[0-9a-f]{3}", re.ASCII)
_HASH_SUFFIX = re.compile(r"[0-9a-f]{13}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_NUMERIC_HOST = re.compile(r"[0-9.]+", re.ASCII)


class DevpiRouteError(ValueError):
    """A devpi route or base URL is not canonical."""


def _control(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def _devpi_name(value: str) -> bool:
    return _DEVPI_NAME.fullmatch(value) is not None and value not in {".", ".."}


def _artifact_name(value: str) -> bool:
    return (
        value not in {".", ".."}
        and bool(value.lstrip("."))
        and _ARTIFACT_NAME.fullmatch(value) is not None
    )


def validate_artifact_relpath(
    relpath: str,
    *,
    stage: str | None = None,
    filename: str | None = None,
    sha256: str | None = None,
) -> tuple[str, ...]:
    """Validate raw, canonical devpi ``+f``/``+e`` route components."""

    if (
        not isinstance(relpath, str)
        or not relpath
        or relpath.startswith("/")
        or "//" in relpath
        or "%" in relpath
        or "\\" in relpath
        or "?" in relpath
        or "#" in relpath
        or _control(relpath)
    ):
        raise DevpiRouteError("artifact route is not canonical")
    parts = tuple(relpath.split("/"))
    if len(parts) < 3 or not _devpi_name(parts[0]) or not _devpi_name(parts[1]):
        raise DevpiRouteError("artifact stage route is not canonical")
    actual_stage = f"{parts[0]}/{parts[1]}"
    if stage is not None and actual_stage != stage:
        raise DevpiRouteError("artifact route stage does not match")
    if filename is not None and parts[-1] != filename:
        raise DevpiRouteError("artifact route filename does not match")
    marker = parts[2]
    if marker == "+f":
        if len(parts) != 6:
            raise DevpiRouteError("+f route is incomplete")
        prefix, suffix, route_filename = parts[3:]
        if not _HASH_PREFIX.fullmatch(prefix) or not _HASH_SUFFIX.fullmatch(suffix):
            raise DevpiRouteError("+f route hash directories are invalid")
        if sha256 is not None and (
            _SHA256.fullmatch(sha256) is None or prefix + suffix != sha256[:16]
        ):
            raise DevpiRouteError("+f route hash directories do not match SHA-256")
        if not _artifact_name(route_filename):
            raise DevpiRouteError("+f route filename is invalid")
    elif marker == "+e":
        if len(parts) != 5 or not _artifact_name(parts[3]) or not _artifact_name(parts[4]):
            raise DevpiRouteError("+e route is invalid")
    else:
        raise DevpiRouteError("artifact route marker is invalid")
    if filename is not None and not _artifact_name(filename):
        raise DevpiRouteError("artifact filename is invalid")
    return parts


def _canonical_host(hostname: str) -> str:
    if not hostname or not hostname.isascii() or hostname.endswith("."):
        raise DevpiRouteError("host is not canonical")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    if _NUMERIC_HOST.fullmatch(hostname):
        raise DevpiRouteError("numeric host is not canonical")
    if len(hostname) > 253:
        raise DevpiRouteError("host is too long")
    labels = hostname.lower().split(".")
    if not labels or any(
        not label
        or len(label) > 63
        or label[0] == "-"
        or label[-1] == "-"
        or re.fullmatch(r"[A-Za-z0-9-]+", label, re.ASCII) is None
        for label in labels
    ):
        raise DevpiRouteError("host labels are invalid")
    return ".".join(labels)


@dataclass(frozen=True, slots=True)
class DevpiBase:
    scheme: str
    host: str
    port: int
    mount: str

    @classmethod
    def parse(cls, value: str) -> DevpiBase:
        if not isinstance(value, str) or _control(value) or "\\" in value:
            raise DevpiRouteError("base URL is not canonical")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except (TypeError, ValueError) as error:
            raise DevpiRouteError("base URL is not canonical") from error
        scheme = parsed.scheme.lower()
        if (
            scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
        ):
            raise DevpiRouteError("base URL is not canonical")
        host = _canonical_host(parsed.hostname)
        effective_port = port if port is not None else (443 if scheme == "https" else 80)
        if not 1 <= effective_port <= 65535:
            raise DevpiRouteError("base URL port is invalid")
        path = parsed.path
        if path in {"", "/"}:
            mount = ""
        else:
            if not path.startswith("/") or path.endswith("/") or "//" in path:
                raise DevpiRouteError("base URL mount is not canonical")
            mount_parts = path[1:].split("/")
            if not mount_parts or not all(_devpi_name(part) for part in mount_parts):
                raise DevpiRouteError("base URL mount is not canonical")
            mount = "/" + "/".join(mount_parts)
        return cls(scheme, host, effective_port, mount)

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def endpoint(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port

    @staticmethod
    def endpoint_for_url(value: str) -> tuple[str, str, int]:
        if not isinstance(value, str) or _control(value) or "\\" in value:
            raise DevpiRouteError("URL is not canonical")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except (TypeError, ValueError) as error:
            raise DevpiRouteError("URL is not canonical") from error
        scheme = parsed.scheme.lower()
        if (
            scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "%" in parsed.netloc
        ):
            raise DevpiRouteError("URL is not canonical")
        host = _canonical_host(parsed.hostname)
        effective_port = port if port is not None else (443 if scheme == "https" else 80)
        if not 1 <= effective_port <= 65535:
            raise DevpiRouteError("URL port is invalid")
        return scheme, host, effective_port

    @property
    def url(self) -> str:
        return urlunsplit((self.scheme, self.netloc, self.mount or "/", "", ""))

    def origin_for(self, relpath: str) -> str:
        validate_artifact_relpath(relpath)
        path = f"{self.mount}/{relpath}" if self.mount else f"/{relpath}"
        return urlunsplit((self.scheme, self.netloc, path, "", ""))

    def resolve_link(self, href: str) -> tuple[str, str]:
        if not isinstance(href, str) or _control(href) or "\\" in href:
            raise DevpiRouteError("artifact link is not canonical")
        raw = urlsplit(href)
        if (
            raw.query
            or "//" in raw.path
            or "%" in raw.path
            or any(segment in {".", ".."} for segment in raw.path.split("/"))
        ):
            raise DevpiRouteError("artifact link query is not allowed")
        absolute = urljoin(self.url.rstrip("/") + "/", href)
        parsed = urlsplit(absolute)
        try:
            port = parsed.port
        except ValueError as error:
            raise DevpiRouteError("artifact link port is invalid") from error
        host = _canonical_host(parsed.hostname or "")
        effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme.lower(), host, effective_port) != (self.scheme, self.host, self.port):
            raise DevpiRouteError("artifact link is outside configured devpi origin")
        if parsed.username is not None or parsed.password is not None or parsed.query:
            raise DevpiRouteError("artifact link credentials or query are not allowed")
        path = parsed.path
        prefix = f"{self.mount}/" if self.mount else "/"
        if not path.startswith(prefix):
            raise DevpiRouteError("artifact link is outside configured devpi mount")
        prefix_length = len(prefix)
        relpath = path[prefix_length:]
        if not relpath:
            raise DevpiRouteError("artifact link has no artifact route")
        return relpath, urlunsplit((self.scheme, self.netloc, path, "", ""))
