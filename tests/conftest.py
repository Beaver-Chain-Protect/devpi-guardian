from dataclasses import dataclass, field

import pytest

from devpi_guardian.verdicts.models import AuditEventInput


@dataclass
class RecordingAuditWriter:
    events: list[AuditEventInput] = field(default_factory=list)
    fail: bool = False

    def append_in_transaction(
        self,
        connection,
        event: AuditEventInput,
    ) -> None:
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.events.append(event)


@pytest.fixture
def audit_writer() -> RecordingAuditWriter:
    return RecordingAuditWriter()
