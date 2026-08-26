from __future__ import annotations

# Project Ruff and upstream devpi intentionally use conflicting import layouts.
# Keep devpi's no-section, from-first style in this devpi fixture module.
# ruff: noqa: I001
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import TYPE_CHECKING
import pytest


if TYPE_CHECKING:
    from devpi_guardian.verdicts.models import AuditEventInput


pytest_plugins = ["test_devpi_server.plugin"]


@pytest.fixture(scope="session")
def devpi_server():
    """Run the official fixture with an explicit private Guardian quarantine root."""
    from _pytest_devpi_server import DevpiServer

    class GuardianDevpiServer(DevpiServer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.quarantine_root = Path(self.workspace).resolve() / "guardian-quarantine"
            self.quarantine_root.mkdir(parents=True, exist_ok=False)
            self.quarantine_root.chmod(0o700)

        @property
        def run_cmd(self):
            command = super().run_cmd
            base_url = f"http://{self.hostname}:{self.port}"
            command.extend(
                (
                    "--guardian-quarantine-root",
                    str(self.quarantine_root),
                    "--guardian-base-url",
                    base_url,
                )
            )
            return command

    with GuardianDevpiServer() as server:
        server.start()
        yield server


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
