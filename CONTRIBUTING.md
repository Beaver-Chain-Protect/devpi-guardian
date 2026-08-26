# Contributing to devpi-guardian

devpi-guardian welcomes bug reports, enhancement proposals, documentation
improvements, tests, and code changes in English.

## Report a bug or propose a change

Search the [issue tracker] before opening a new issue. Include a minimal
reproduction, expected and actual behavior, the devpi-guardian and Python
versions, and relevant sanitized logs. Do not include credentials, private
package names, private URLs, or other sensitive data.

For a security vulnerability, follow [SECURITY.md] instead of opening a public
issue.

[issue tracker]: https://github.com/Beaver-Chain-Protect/devpi-guardian/issues
[SECURITY.md]: SECURITY.md

## Contribution process

1. Open an issue before a substantial or security-sensitive change so the
   design, compatibility, and migration impact can be agreed on.
2. Fork the repository and create a focused branch from `main`.
3. Add or update automated tests for every behavior change. Major new
   functionality is not accepted without tests that exercise its success and
   failure paths.
4. Keep implementation, tests, documentation, and a `news/*.feature` release
   note fragment in the same pull request when they describe one change.
5. Run the complete verification commands below.
6. Open a pull request that explains the problem, approach, security impact,
   compatibility or migration impact, and verification performed. A maintainer
   reviews and merges accepted pull requests.

Small typo and documentation-only fixes may omit the preliminary issue and
release-note fragment when the pull request explains why.

## Development environment

Python 3.11 or newer and [uv] are required. Create the locked development
environment with:

```console
uv sync --locked --extra test
```

[uv]: https://docs.astral.sh/uv/

## Acceptance requirements

- Preserve the fail-closed enforcement, immutable history, transaction, claim
  fencing, privacy, and quarantine boundaries documented in `README.md` and
  the approved specifications.
- Add focused tests before production changes and keep the full suite passing.
- Format and lint Python with the repository's Ruff and Flake8 configuration.
- Do not add secrets, credentials, private package data, or unsanitized logs.
- Pin GitHub Actions by full commit SHA.
- Keep user-facing behavior and external interfaces documented in English.

Run the same checks used by CI before requesting review:

```console
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run flake8 src tests
uv run bandit -q -r src -ll -iii
uv lock --check
uv build
```

Bandit is the project's security-focused static analyzer. CI rejects findings
of medium-or-higher severity when Bandit reports them with high confidence.
Maintainers must investigate confirmed medium-or-higher exploitable findings
and fix them before release. Lower-confidence output may also be reviewed with
`uv run bandit -r src` when changing a flagged area.

## Release notes and versions

Public releases use PEP 440 versions compatible with Semantic Versioning and
are tagged in Git. Human-readable release notes are assembled from `news/`
fragments and recorded in [CHANGELOG.md]. Release notes identify any fixed
public vulnerabilities that had a CVE or similar identifier at release time.

[CHANGELOG.md]: CHANGELOG.md
