"""Small, bounded standard-library client for the Guardian administrator API."""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

_MAX_BODY_BYTES = 1024 * 1024
_MAX_TEXT = 4096
_MAX_URL_BYTES = 8192
_METHODS = frozenset(("GET", "POST", "DELETE"))


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class ClientInputError(ValueError):
    """The caller supplied an invalid client URL, query, or JSON value."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(request: urllib.request.Request, timeout: float):
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _controls(value: str) -> bool:
    return any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)


def _encoded_size(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ClientInputError("URL contains invalid Unicode") from exc


def _component_valid(value: str) -> bool:
    try:
        return (
            len(value) <= _MAX_TEXT and _encoded_size(value) <= _MAX_TEXT and not _controls(value)
        )
    except ValueError:
        return False


def _json_text_valid(value: str) -> bool:
    if any(
        char == "\x00"
        or 0xD800 <= ord(char) <= 0xDFFF
        or (ord(char) < 0x20 and char not in "\n\r\t")
        or 0x7F <= ord(char) <= 0x9F
        for char in value
    ):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _json_snapshot(value: Any, *, depth: int = 0, seen: set[int] | None = None) -> Any:
    if depth > 32:
        raise ValueError("JSON input is too deeply nested")
    seen = set() if seen is None else seen
    if isinstance(value, str):
        if not _json_text_valid(value) or len(value.encode("utf-8")) > _MAX_BODY_BYTES:
            raise ValueError("JSON input contains invalid text")
        return value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("JSON input contains a non-finite number")
        return value
    identity = id(value)
    if identity in seen:
        raise ValueError("JSON input contains a cycle")
    seen.add(identity)
    try:
        if isinstance(value, Mapping):
            if len(value) > 10_000:
                raise ValueError("JSON input has too many values")
            result = {}
            for key, item in value.items():
                if not isinstance(key, str) or not _json_text_valid(key):
                    raise ValueError("JSON object keys must be strings")
                result[key] = _json_snapshot(item, depth=depth + 1, seen=seen)
            return result
        if isinstance(value, (list, tuple)):
            if len(value) > 10_000:
                raise ValueError("JSON input has too many values")
            return [_json_snapshot(item, depth=depth + 1, seen=seen) for item in value]
    finally:
        seen.discard(identity)
    raise ValueError("JSON input contains an unsupported value")


def _strict_json_bytes(value: Any) -> bytes:
    snapshot = _json_snapshot(value)
    try:
        data = json.dumps(
            snapshot, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ClientInputError("JSON input is invalid") from exc
    if len(data) > _MAX_BODY_BYTES:
        raise ClientInputError("JSON input is too large")
    return data


def _read_json(response, *, status: int) -> dict[str, Any]:
    try:
        headers = getattr(response, "headers", {})
        content_type = headers.get("Content-Type", "") if hasattr(headers, "get") else ""
    except (AttributeError, TypeError, ValueError):
        raise ApiError(status, "invalid_response", "server returned invalid JSON") from None
    media_type = content_type.split(";", 1)[0].strip().lower()
    if not (media_type == "application/json" or media_type.endswith("+json")):
        raise ApiError(status, "invalid_response", "server returned invalid JSON")
    try:
        raw = response.read(_MAX_BODY_BYTES + 1)
        if not isinstance(raw, bytes) or len(raw) > _MAX_BODY_BYTES:
            raise ValueError("response is too large")
        text = raw.decode("utf-8")
        payload = json.loads(
            text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value))
        )
    except (
        AttributeError,
        OSError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ApiError(status, "invalid_response", "server returned invalid JSON") from exc
    try:
        payload = _json_snapshot(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ApiError(status, "invalid_response", "server returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ApiError(status, "invalid_response", "server returned invalid JSON")
    return payload


class GuardianApiClient:
    def __init__(
        self,
        *,
        api_url: str,
        auth_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not isinstance(api_url, str) or not api_url.strip():
            raise ClientInputError("api_url must not be blank")
        try:
            parsed = urllib.parse.urlsplit(api_url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ClientInputError("api_url is invalid") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ClientInputError("api_url port is invalid")
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise ClientInputError("api_url must use http or https with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ClientInputError("api_url must not contain credentials")
        if (
            parsed.query
            or parsed.fragment
            or _controls(api_url)
            or _encoded_size(api_url) > _MAX_URL_BYTES
            or any(
                segment in {".", ".."} for segment in urllib.parse.unquote(parsed.path).split("/")
            )
        ):
            raise ClientInputError("api_url must not contain query, fragment, or controls")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ClientInputError("timeout must be a finite positive number")
        if auth_token is not None and (
            not isinstance(auth_token, str)
            or not auth_token
            or len(auth_token) > _MAX_TEXT
            or _controls(auth_token)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in auth_token)
        ):
            raise ClientInputError("auth_token is invalid")
        self._api_url = api_url.rstrip("/")
        self._auth_token = auth_token
        self._timeout = float(timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(method, str) or method not in _METHODS:
            raise ClientInputError("HTTP method is invalid")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or _controls(path)
            or len(path) > _MAX_TEXT
            or _encoded_size(path) > _MAX_TEXT
            or "?" in path
            or "#" in path
            or any(segment in {".", ".."} for segment in urllib.parse.unquote(path).split("/"))
        ):
            raise ClientInputError("request path is invalid")
        if query is not None:
            if not isinstance(query, dict):
                raise ClientInputError("query must be an object")
            if len(query) > 32:
                raise ClientInputError("query has too many values")
            for key, value in query.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > _MAX_TEXT
                    or _encoded_size(key) > _MAX_TEXT
                    or _controls(key)
                    or not isinstance(value, (str, int, float, bool))
                ):
                    raise ClientInputError("query contains an invalid value")
                if isinstance(value, str) and (
                    len(value) > _MAX_TEXT or _encoded_size(value) > _MAX_TEXT or _controls(value)
                ):
                    raise ClientInputError("query contains an invalid value")
                if isinstance(value, float) and not math.isfinite(value):
                    raise ClientInputError("query contains a non-finite number")
        if body is not None and not isinstance(body, dict):
            raise ClientInputError("body must be an object")
        quoted_path = urllib.parse.quote(path, safe="/%:@-._~!$&'()*+,;=%")
        if _encoded_size(quoted_path) > _MAX_TEXT:
            raise ClientInputError("request path is invalid")
        url = self._api_url + quoted_path
        if query:
            encoded_query = urllib.parse.urlencode(query)
            if _encoded_size(encoded_query) > _MAX_TEXT:
                raise ClientInputError("query is too large")
            url += "?" + encoded_query
        if _encoded_size(url) > _MAX_URL_BYTES:
            raise ClientInputError("request URL is too large")
        data = None if body is None else _strict_json_bytes(body)
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _open(request, self._timeout) as response:
                payload = _read_json(response, status=502)
        except urllib.error.HTTPError as exc:
            try:
                payload = _read_json(exc, status=exc.code)
            except ApiError:
                raise ApiError(
                    exc.code, "invalid_response", "server returned invalid JSON"
                ) from exc
            error = payload.get("error")
            if (
                not isinstance(error, dict)
                or not isinstance(error.get("code"), str)
                or not isinstance(error.get("message"), str)
            ):
                raise ApiError(
                    exc.code, "invalid_response", "server returned invalid JSON"
                ) from exc
            code, message = error["code"], error["message"]
            if not _component_valid(code) or not _component_valid(message):
                raise ApiError(
                    exc.code, "invalid_response", "server returned invalid JSON"
                ) from exc
            raise ApiError(exc.code, code, message) from exc
        return payload
