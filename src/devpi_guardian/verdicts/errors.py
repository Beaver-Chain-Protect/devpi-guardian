class GuardianStoreError(Exception):
    """Base class for verdict store failures."""


class InvalidSha256(ValueError, GuardianStoreError):
    """The digest is not a canonical lowercase SHA-256."""


class ArtifactNotFound(GuardianStoreError):
    """The requested Artifact does not exist."""


class TransitionConflict(GuardianStoreError):
    """The current Artifact state does not permit the requested transition."""


class StoreUnavailable(GuardianStoreError):
    """SQLite could not safely answer the request."""


class MigrationError(GuardianStoreError):
    """The schema could not be migrated to the required version."""
