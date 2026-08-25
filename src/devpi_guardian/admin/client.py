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
_METHODS = frozenset(("GET", "POST", "DELETE"))


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(request: urllib.request.Request, timeout: float):
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _controls(value: str) -> bool:
    return any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)


def _json_snapshot(value: Any, *, depth: int = 0, seen: set[int] | None = None) -> Any:
    if depth > 32:
        raise ValueError("JSON input is too deeply nested")
    seen = set() if seen is None else seen
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_BODY_BYTES or _controls(value):
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
                if not isinstance(key, str) or _controls(key):
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
        raise ValueError("JSON input is invalid") from exc
    if len(data) > _MAX_BODY_BYTES:
        raise ValueError("JSON input is too large")
    return data


def _read_json(response, *, status: int) -> dict[str, Any]:
    content_type = response.headers.get("Content-Type", "") if hasattr(response, "headers") else ""
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
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
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
            raise ValueError("api_url must not be blank")
        try:
            parsed = urllib.parse.urlsplit(api_url)
            hostname = parsed.hostname
        except ValueError as exc:
            raise ValueError("api_url is invalid") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise ValueError("api_url must use http or https with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("api_url must not contain credentials")
        if parsed.query or parsed.fragment or _controls(api_url):
            raise ValueError("api_url must not contain query, fragment, or controls")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a finite positive number")
        if auth_token is not None and (
            not isinstance(auth_token, str)
            or not auth_token
            or len(auth_token) > _MAX_TEXT
            or _controls(auth_token)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in auth_token)
        ):
            raise ValueError("auth_token is invalid")
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
            raise ValueError("HTTP method is invalid")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or _controls(path)
        ):
            raise ValueError("request path is invalid")
        if query is not None:
            if not isinstance(query, dict):
                raise ValueError("query must be an object")
            for key, value in query.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > _MAX_TEXT
                    or _controls(key)
                    or not isinstance(value, (str, int, float, bool))
                ):
                    raise ValueError("query contains an invalid value")
                if isinstance(value, float) and not math.isfinite(value):
                    raise ValueError("query contains a non-finite number")
        if body is not None and not isinstance(body, dict):
            raise ValueError("body must be an object")
        url = self._api_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
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
            if (
                len(code) > _MAX_TEXT
                or len(message) > _MAX_TEXT
                or _controls(code)
                or _controls(message)
            ):
                raise ApiError(
                    exc.code, "invalid_response", "server returned invalid JSON"
                ) from exc
            raise ApiError(exc.code, code, message) from exc
        return payload
