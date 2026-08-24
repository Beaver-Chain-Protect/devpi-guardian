from __future__ import annotations

# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this devpi fixture module.
# ruff: noqa: I001
from dataclasses import dataclass
from dataclasses import field
from typing import TYPE_CHECKING
import pytest


if TYPE_CHECKING:
    from devpi_guardian.verdicts.models import AuditEventInput


pytest_plugins = ["test_devpi_server.plugin"]


@dataclass
class RecordingAuditWriter:
    events: list[AuditEventInput] = field(default_factory=list)
    fail: bool = False

    def append_in_transaction(
        self,
        _connection,
        event: AuditEventInput,
    ) -> None:
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.events.append(event)


@pytest.fixture
def audit_writer() -> RecordingAuditWriter:
    return RecordingAuditWriter()
