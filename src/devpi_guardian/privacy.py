"""Bounded redaction for diagnostics crossing persistence or API boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping

MAX_DIAGNOSTIC_LENGTH = 4096

_URL = re.compile(r"(?i)(?<![\w])(?:https?|ftp)://[^\s<>'\"`]+")
_SENSITIVE_KEY = (
    r"(?:"
    r"x[-_ ]?devpi[-_ ]?auth"
    r"|auth[-_ ]?(?:token|key|secret)"
    r"|client[-_ ]?(?:secret|token|key)"
    r"|access[-_ ]?(?:token|secret|key)"
    r"|refresh[-_ ]?(?:token|secret|key)"
    r"|bearer[-_ ]?(?:token|secret|key)"
    r"|session[-_ ]?(?:token|secret|key)"
    r"|token"
    r"|password"
    r"|passwd"
    r"|secret"
    r"|api[-_ ]?key"
    r"|credential"
    r"|authorization"
    r")"
)
_HEADER_CREDENTIAL = re.compile(
    r"(?ix)"
    r"(?P<key_quote>(?:\\['\"]|['\"])?)"
    r"(?P<key>(?<![\w])(?:authorization|x[-_ ]?devpi[-_ ]?auth)(?![\w]))"
    r"(?P=key_quote)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<scheme>Bearer|Basic)(?P<scheme_separator>\s+))?"
    r"(?:"
    r"(?P<quote>(?:\\['\"]|['\"]))(?:\\.|(?! (?P=quote) ).)*(?P=quote)"
    r"|(?P<bare>[^\s,;}\]]+)"
    r")"
)
_SECRET_ASSIGNMENT = re.compile(
    rf"(?ix)"
    rf"(?P<key_quote>(?:\\['\"]|['\"])?)"
    rf"(?P<key>(?<![\w]){_SENSITIVE_KEY}(?![\w]))"
    rf"(?P=key_quote)"
    rf"(?P<separator>\s*[:=]\s*)"
    rf"(?:"
    rf"(?P<quote>(?:\\['\"]|['\"]))(?:\\.|(?! (?P=quote) ).)*(?P=quote)"
    rf"|(?P<bare>[^\s,;}}\[\]]+)"
    rf")"
)
_AUTH_SCHEME = re.compile(
    r"(?ix)"
    r"(?P<scheme>(?<![\w])(?:Bearer|Basic))(?:\s+)"
    r"(?:"
    r"(?P<quote>(?:\\['\"]|['\"]))(?:\\.|(?! (?P=quote) ).)*(?P=quote)"
    r"|(?P<bare>[^\s,;}\]]+)"
    r")"
)
_DIGEST = re.compile(r"(?i)\b[0-9a-f]{64}\b")
_PATH_STRUCTURAL_DELIMITERS = r",;:'\"<>{}=\[\]()|`"
_PATH_BODY_EXCLUDED = rf"\n{_PATH_STRUCTURAL_DELIMITERS}"
_POSIX_PATH_WITH_SPACES = re.compile(
    rf"(?<![\w:])/(?!\+)"
    rf"(?=[^{_PATH_BODY_EXCLUDED}]*\s)"
    rf"[^{_PATH_BODY_EXCLUDED}]*?\.[A-Za-z0-9]+"
    rf"(?=[{_PATH_STRUCTURAL_DELIMITERS}]|\s|$)"
)
_POSIX_PATH_WITH_SPACES_TERMINAL = re.compile(
    rf"(?<![\w:])/(?!\+)"
    rf"(?=[^{_PATH_BODY_EXCLUDED}]*\s)"
    rf"(?![^{_PATH_BODY_EXCLUDED}]*\.[A-Za-z0-9]+[{_PATH_STRUCTURAL_DELIMITERS}]|"
    rf"[^{_PATH_BODY_EXCLUDED}]*\.[A-Za-z0-9]+\s)"
    rf"[^{_PATH_BODY_EXCLUDED}]+?(?=[{_PATH_STRUCTURAL_DELIMITERS}]|$)"
)
_POSIX_PATH = re.compile(rf"(?<![\w:])/(?!\+)(?:[^\s/]+/)+[^\s{_PATH_STRUCTURAL_DELIMITERS}]+")
_POSIX_SINGLE_COMPONENT_PATH = re.compile(
    rf"(?<![\w:])/(?!\+)[^\s/{_PATH_STRUCTURAL_DELIMITERS}]+"
    rf"(?=[\s{_PATH_STRUCTURAL_DELIMITERS}]|$)"
)
_WINDOWS_PATH_WITH_SPACES = re.compile(
    rf"(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)"
    rf"(?=[^{_PATH_BODY_EXCLUDED}]*\s)"
    rf"[^{_PATH_BODY_EXCLUDED}]*?\.[A-Za-z0-9]+"
    rf"(?=[{_PATH_STRUCTURAL_DELIMITERS}]|\s|$)"
)
_WINDOWS_PATH_WITH_SPACES_TERMINAL = re.compile(
    rf"(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)"
    rf"(?=[^{_PATH_BODY_EXCLUDED}]*\s)"
    rf"(?![^{_PATH_BODY_EXCLUDED}]*\.[A-Za-z0-9]+[{_PATH_STRUCTURAL_DELIMITERS}]|"
    rf"[^{_PATH_BODY_EXCLUDED}]*\.[A-Za-z0-9]+\s)"
    rf"[^{_PATH_BODY_EXCLUDED}]+?(?=[{_PATH_STRUCTURAL_DELIMITERS}]|$)"
)
_WINDOWS_PATH = re.compile(rf"(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)[^\s{_PATH_STRUCTURAL_DELIMITERS}]+")
_DIAGNOSTIC_FIELDS = frozenset(
    {
        "diagnostic",
        "last_error",
        "message",
        "snippet",
        "file",
        "file_path",
        "origin",
        "source",
        "sink",
        "details",
        "reason",
        "failure_reason",
    }
)
_IDENTITY_FIELDS = frozenset({"sha256", "baseline_sha256", "fingerprint"})
_CANONICAL_IDENTITY = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SENSITIVE_KEY_NAME = re.compile(rf"(?ix)^{_SENSITIVE_KEY}$")


def _replace_credential(match: re.Match[str]) -> str:
    quoted_key = match.group("key_quote") or ""
    key = f"{quoted_key}{match.group('key')}{quoted_key}"
    return f"{key}{match.group('separator')}[REDACTED]"


def _replace_header_credential(match: re.Match[str]) -> str:
    quoted_key = match.group("key_quote") or ""
    key = f"{quoted_key}{match.group('key')}{quoted_key}"
    scheme = match.group("scheme")
    if scheme is None:
        return f"{key}{match.group('separator')}[REDACTED]"
    return f"{key}{match.group('separator')}{scheme} [REDACTED]"


def _replace_auth_scheme(match: re.Match[str]) -> str:
    return f"{match.group('scheme')} [REDACTED]"


def sanitize_diagnostic(value: object) -> str:
    """Return a deterministic, bounded diagnostic safe for storage and APIs."""

    if not isinstance(value, str):
        value = str(value)
    text = "".join(
        " "
        if (
            ord(character) < 32
            or 127 <= ord(character) <= 159
            or 0xD800 <= ord(character) <= 0xDFFF
        )
        else character
        for character in value
    )
    text = _URL.sub("[URL]", text)
    text = _HEADER_CREDENTIAL.sub(_replace_header_credential, text)
    text = _SECRET_ASSIGNMENT.sub(_replace_credential, text)
    text = _AUTH_SCHEME.sub(_replace_auth_scheme, text)
    text = _POSIX_PATH_WITH_SPACES.sub("[PATH]", text)
    text = _POSIX_SINGLE_COMPONENT_PATH.sub("[PATH]", text)
    text = _POSIX_PATH_WITH_SPACES_TERMINAL.sub("[PATH]", text)
    text = _POSIX_PATH.sub("[PATH]", text)
    text = _WINDOWS_PATH_WITH_SPACES.sub("[PATH]", text)
    text = _WINDOWS_PATH_WITH_SPACES_TERMINAL.sub("[PATH]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _DIGEST.sub("[DIGEST]", text)
    return text[:MAX_DIAGNOSTIC_LENGTH]


def sanitize_diagnostic_fields(
    value: object,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
    _diagnostic_context: bool = False,
) -> object:
    """Sanitize only diagnostic-shaped fields in a JSON-compatible graph."""

    if _depth > 32:
        raise ValueError("diagnostic graph is too deeply nested")
    seen = set() if _seen is None else _seen
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise ValueError("diagnostic graph contains a cycle")
        seen.add(identity)
        try:
            result: dict[object, object] = {}
            for key, item in value.items():
                if isinstance(key, str) and key in _IDENTITY_FIELDS:
                    if isinstance(item, str) and _CANONICAL_IDENTITY.fullmatch(item):
                        result[key] = item
                    elif isinstance(item, (Mapping, list, tuple)):
                        result[key] = sanitize_diagnostic_fields(
                            item,
                            _depth=_depth + 1,
                            _seen=seen,
                            _diagnostic_context=True,
                        )
                    elif isinstance(item, str):
                        result[key] = sanitize_diagnostic(item)
                    else:
                        result[key] = item
                elif isinstance(key, str) and _SENSITIVE_KEY_NAME.fullmatch(key):
                    if isinstance(item, (Mapping, list, tuple)):
                        sanitize_diagnostic_fields(
                            item,
                            _depth=_depth + 1,
                            _seen=seen,
                            _diagnostic_context=True,
                        )
                    result[key] = None if item is None else "[REDACTED]"
                elif isinstance(key, str) and key in _DIAGNOSTIC_FIELDS and item is not None:
                    result[key] = sanitize_diagnostic_fields(
                        item,
                        _depth=_depth + 1,
                        _seen=seen,
                        _diagnostic_context=True,
                    )
                else:
                    result[key] = sanitize_diagnostic_fields(
                        item,
                        _depth=_depth + 1,
                        _seen=seen,
                        _diagnostic_context=_diagnostic_context,
                    )
            return result
        finally:
            seen.discard(identity)
    if isinstance(value, list):
        identity = id(value)
        if identity in seen:
            raise ValueError("diagnostic graph contains a cycle")
        seen.add(identity)
        try:
            return [
                sanitize_diagnostic_fields(
                    item,
                    _depth=_depth + 1,
                    _seen=seen,
                    _diagnostic_context=_diagnostic_context,
                )
                for item in value
            ]
        finally:
            seen.discard(identity)
    if isinstance(value, tuple):
        identity = id(value)
        if identity in seen:
            raise ValueError("diagnostic graph contains a cycle")
        seen.add(identity)
        try:
            return tuple(
                sanitize_diagnostic_fields(
                    item,
                    _depth=_depth + 1,
                    _seen=seen,
                    _diagnostic_context=_diagnostic_context,
                )
                for item in value
            )
        finally:
            seen.discard(identity)
    return sanitize_diagnostic(value) if _diagnostic_context and isinstance(value, str) else value


def sanitize_diagnostic_graph(value: object) -> object:
    """Sanitize a complete structured diagnostic graph at a trust boundary."""

    return sanitize_diagnostic_fields(value, _diagnostic_context=True)
