# devpi-guardian

devpi-guardian is a devpi-server plugin that exposes only Artifact SHA-256 values
whose current effective verdict is ALLOW. All missing, pending, denied, errored,
or unavailable verdicts fail closed.

The approved F3/F4 design is in
docs/superpowers/specs/2026-08-17-devpi-guardian-f3-f4-design.md.
