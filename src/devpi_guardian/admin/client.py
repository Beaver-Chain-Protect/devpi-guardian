"""Small standard-library client for the Guardian administrator API."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class GuardianApiClient:
    def __init__(
        self,
        *,
        api_url: str,
        auth_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._auth_token = auth_token
        self._timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        url = self._api_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            self._raise_http_error(exc)
        if not isinstance(payload, dict):
            raise ApiError(502, "invalid_response", "server returned invalid JSON")
        return payload

    @staticmethod
    def _raise_http_error(exc: urllib.error.HTTPError) -> None:
        code = "http_error"
        message = f"server returned HTTP {exc.code}"
        try:
            payload = json.load(exc)
            error = payload.get("error", {})
            if isinstance(error, dict):
                code = str(error.get("code", code))
                message = str(error.get("message", message))
        except (OSError, TypeError, ValueError):
            pass
        raise ApiError(exc.code, code, message) from exc
