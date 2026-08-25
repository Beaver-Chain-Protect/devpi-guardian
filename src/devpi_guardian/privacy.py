"""Bounded redaction for diagnostics crossing persistence or API boundaries."""

from __future__ import annotations

import re

MAX_DIAGNOSTIC_LENGTH = 4096

_URL = re.compile(r"(?i)(?<![\w])(?:https?|ftp)://[^\s<>'\"`]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:token|password|passwd|secret|api[_-]?key|authorization|credential)\s*[:=]\s*[^\s,;]+"
)
_DIGEST = re.compile(r"(?i)\b[0-9a-f]{64}\b")
_POSIX_PATH = re.compile(r"(?<![\w:])/(?:[^\s/]+/)+[^\s,;:]+")
_WINDOWS_PATH = re.compile(r"(?<![\w])(?:[A-Za-z]:\\|\\\\)[^\s,;]+")


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
    text = _SECRET_ASSIGNMENT.sub(
        lambda match: match.group(0).split("=", 1)[0].split(":", 1)[0] + "=[REDACTED]",
        text,
    )
    text = _POSIX_PATH.sub("[PATH]", text)
    text = _WINDOWS_PATH.sub("[PATH]", text)
    text = _DIGEST.sub("[DIGEST]", text)
    return text[:MAX_DIAGNOSTIC_LENGTH]
