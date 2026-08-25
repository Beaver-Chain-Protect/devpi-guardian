"""Bounded redaction for diagnostics crossing persistence or API boundaries."""

from __future__ import annotations

import re

MAX_DIAGNOSTIC_LENGTH = 4096

_URL = re.compile(r"(?i)(?<![\w])(?:https?|ftp)://[^\s<>'\"`]+")
_SENSITIVE_KEY = (
    r"(?:"
    r"x[-_ ]?devpi[-_ ]?auth"
    r"|auth[-_ ]?(?:token|key)"
    r"|access[-_ ]?token"
    r"|refresh[-_ ]?token"
    r"|bearer[-_ ]?token"
    r"|session[-_ ]?token"
    r"|token"
    r"|password"
    r"|passwd"
    r"|secret"
    r"|api[-_ ]?key"
    r"|credential"
    r")"
)
_HEADER_CREDENTIAL = re.compile(
    r"(?ix)"
    r"(?P<key>(?<![\w])(?:authorization|x[-_ ]?devpi[-_ ]?auth)(?![\w]))"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<scheme>Bearer|Basic)(?P<scheme_separator>\s+))?"
    r"(?:"
    r"(?P<quote>['\"])(?P<quoted>[^'\"]*)(?P=quote)"
    r"|(?P<bare>[^\s,;]+)"
    r")"
)
_SECRET_ASSIGNMENT = re.compile(
    rf"(?ix)"
    rf"(?P<key>(?<![\w]){_SENSITIVE_KEY}(?![\w]))"
    rf"(?P<separator>\s*[:=]\s*)"
    rf"(?:"
    rf"(?P<quote>['\"])(?P<quoted>[^'\"]*)(?P=quote)"
    rf"|(?P<bare>[^\s,;]+)"
    rf")"
)
_AUTH_SCHEME = re.compile(
    r"(?ix)"
    r"(?P<scheme>(?<![\w])(?:Bearer|Basic))(?:\s+)"
    r"(?:"
    r"(?P<quote>['\"])(?P<quoted>[^'\"]*)(?P=quote)"
    r"|(?P<bare>[^\s,;]+)"
    r")"
)
_DIGEST = re.compile(r"(?i)\b[0-9a-f]{64}\b")
_POSIX_PATH = re.compile(r"(?<![\w:])/(?:[^\s/]+/)+[^\s,;:'\"]+")
_WINDOWS_PATH = re.compile(r"(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)[^\s,;:'\"]+")


def _replace_credential(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('separator')}[REDACTED]"


def _replace_header_credential(match: re.Match[str]) -> str:
    scheme = match.group("scheme")
    if scheme is None:
        return f"{match.group('key')}{match.group('separator')}[REDACTED]"
    return f"{match.group('key')}{match.group('separator')}{scheme} [REDACTED]"


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
    text = _POSIX_PATH.sub("[PATH]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _DIGEST.sub("[DIGEST]", text)
    return text[:MAX_DIAGNOSTIC_LENGTH]
