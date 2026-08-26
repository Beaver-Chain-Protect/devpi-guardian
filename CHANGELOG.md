# Changelog

All notable changes to devpi-guardian are documented in this file. The project
uses PEP 440 versions compatible with Semantic Versioning. Release-specific
entries are assembled from the `news/` fragments and Git history; raw commit
logs are not used as release notes.

## Unreleased

devpi-guardian is in pre-release development and has not published a stable
release.

### Added

- Fail-closed devpi release-file enforcement backed by effective SHA-256
  verdicts.
- A read-only Guardian Simple index, durable SQLite verdict and audit history,
  fenced analysis claims, and administrative override and rescan operations.
- A dedicated quarantine worker, deterministic artifact analyzers, baseline
  selection and release-diff evidence, and administrator API and CLI surfaces.
- Python 3.11 through 3.14 CI, locked dependency resolution, automated tests,
  formatting and lint checks, package builds, and security-focused static
  analysis.

### Security

- Published a private vulnerability reporting and coordinated disclosure
  process.
- No public release has yet fixed a vulnerability with an assigned CVE or
  equivalent identifier.
