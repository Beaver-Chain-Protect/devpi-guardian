"""Fast, durable handoff from the devpi Simple path to the F5 worker."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from devpi_guardian.verdicts.models import validate_sha256

_DISCOVERY_SINK_XOM_ATTRIBUTE = "_devpi_guardian_discovery_sink"


class DiscoveryUnavailable(RuntimeError):
    """Discovery metadata could not be durably registered."""


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    """Untrusted Simple-link metadata captured before downloading bytes."""

    stage: str
    project: str
    filename: str
    sha256: str
    link_href: str

    def __post_init__(self) -> None:
        for field_name in ("stage", "project", "filename", "link_href"):
            value = getattr(self, field_name)
            if type(value) is not str or not value.strip() or "\x00" in value:
                raise ValueError(f"{field_name} must be a nonblank safe string")
        validate_sha256(self.sha256)


class DiscoverySink(Protocol):
    def discover(self, candidate: DiscoveryCandidate) -> None: ...


class FileDiscoverySink:
    """Persist one immutable JSON job per distinct release mapping."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def discover(self, candidate: DiscoveryCandidate) -> None:
        if type(candidate) is not DiscoveryCandidate:
            raise ValueError("candidate must be a DiscoveryCandidate")
        payload = json.dumps(
            asdict(candidate),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        mapping_digest = hashlib.sha256(payload).hexdigest()
        pending = self.root / "pending"
        incoming = self.root / "incoming"
        final = pending / f"{candidate.sha256}-{mapping_digest}.json"
        temporary: Path | None = None
        try:
            pending.mkdir(parents=True, exist_ok=True)
            incoming.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(prefix="discovery-", dir=incoming)
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, final)
            except FileExistsError:
                if final.read_bytes() != payload:
                    raise DiscoveryUnavailable(
                        "existing discovery job does not match metadata"
                    ) from None
            self._sync_directory(pending)
            return None
        except DiscoveryUnavailable:
            raise
        except OSError as exc:
            raise DiscoveryUnavailable(str(self.root)) from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def set_discovery_sink(xom, sink: DiscoverySink) -> None:
    if not callable(getattr(sink, "discover", None)):
        raise TypeError("sink must provide discover(candidate)")
    setattr(xom, _DISCOVERY_SINK_XOM_ATTRIBUTE, sink)


def get_discovery_sink(xom) -> DiscoverySink:
    try:
        return getattr(xom, _DISCOVERY_SINK_XOM_ATTRIBUTE)
    except AttributeError as exc:
        raise DiscoveryUnavailable("discovery sink is not initialized") from exc
