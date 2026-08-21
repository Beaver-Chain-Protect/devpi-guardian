"""Shared analyzer result types.

An empty finding list means only that the implemented rules did not detect a
problem. It must not be interpreted as proof that an artifact is safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Action = Literal["REVIEW", "DENY"]


@dataclass(frozen=True)
class Finding:
    """One deterministic, human-readable piece of security evidence."""

    rule: str
    action: Action
    file: str
    line: int | None
    snippet: str
    message: str
    source: str | None = None
    sink: str | None = None


def make_finding(
    *,
    rule: str,
    action: Action,
    file: str,
    line: int | None,
    snippet: str,
    message: str,
    source: str | None = None,
    sink: str | None = None,
) -> Finding:
    """Create a normalized finding while enforcing the 200-character limit."""

    normalized_file = file.replace("\\", "/") or "<artifact>"
    normalized_snippet = " ".join(snippet.split())[:200]
    return Finding(
        rule=rule,
        action=action,
        file=normalized_file,
        line=line if line is None or line >= 1 else None,
        snippet=normalized_snippet,
        message=" ".join(message.split()),
        source=source,
        sink=sink,
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Return de-duplicated findings in the public deterministic order."""

    unique = set(findings)
    return sorted(
        unique,
        key=lambda item: (
            item.file,
            -1 if item.line is None else item.line,
            item.rule,
            item.action,
            item.snippet,
            item.source or "",
            item.sink or "",
        ),
    )
