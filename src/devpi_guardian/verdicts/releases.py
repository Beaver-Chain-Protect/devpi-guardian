from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit

from devpi_common.metadata import normalize_name


def sanitize_origin_url(value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError("origin_url must be a nonblank string")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("origin_url must be a valid absolute URL") from None
    if (
        not parsed.scheme
        or not parsed.netloc
        or hostname is None
        or not hostname
        or any(character.isspace() for character in hostname)
    ):
        raise ValueError("origin_url must be a valid absolute URL")

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    sanitized = SplitResult(parsed.scheme, netloc, parsed.path, "", "")
    return urlunsplit(sanitized)


def normalize_requested_project(value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError("project must be a nonblank string")
    normalized = normalize_name(value)
    if not normalized:
        raise ValueError("project must have a normalized name")
    return normalized
