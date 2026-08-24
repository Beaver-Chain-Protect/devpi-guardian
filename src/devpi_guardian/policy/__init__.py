"""F10 deterministic policy assessment for worker analysis reports.

The policy package is deliberately independent from persistence and from F5's
evidence conversion.  It validates the report at its boundary, computes an
immutable assessment, and adapts that assessment to the existing
``VerdictInput`` port.
"""

from .engine import (
    PolicyAssessment,
    PolicyConfig,
    PolicyEngine,
    PolicyInputError,
)

__all__ = [
    "PolicyAssessment",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyInputError",
]
