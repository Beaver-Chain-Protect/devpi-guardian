# Security policy

devpi-guardian is security-sensitive software. Please report suspected
vulnerabilities privately so maintainers can investigate and coordinate a fix
before public disclosure.

## Supported versions

The project is in pre-release development and has not published a stable
release. Security fixes are applied to the `main` branch. This table will be
updated when supported release lines exist.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Unreleased development branches | No |

## Report a vulnerability

Use GitHub's [private vulnerability reporting form] for this repository. Do
not open a public issue for a suspected vulnerability.

Include, when available:

- the affected commit or version and deployment configuration;
- a concise impact statement and the security boundary involved;
- reproducible steps or a minimal proof of concept;
- relevant sanitized logs, stack traces, or test cases; and
- any proposed mitigation or disclosure constraints.

Never include live credentials, private package contents, or personal data.
Use synthetic test data and redact URLs and logs.

[private vulnerability reporting form]: https://github.com/Beaver-Chain-Protect/devpi-guardian/security/advisories/new

## Response and disclosure

Maintainers aim to acknowledge a report within 14 days, assess severity and
affected versions, and keep the reporter informed while remediation proceeds.
Confirmed vulnerabilities are fixed on supported branches, tested, and
documented in the applicable release notes. When an identifier such as a CVE
or GitHub Security Advisory is assigned before release, the release notes name
it explicitly.

Please allow maintainers a reasonable opportunity to investigate and publish
a fix before public disclosure. We will coordinate disclosure timing with the
reporter and credit reporters who want public acknowledgment.
