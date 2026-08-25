import pytest

from devpi_guardian.privacy import MAX_DIAGNOSTIC_LENGTH, sanitize_diagnostic


def test_sanitize_diagnostic_redacts_secrets_paths_urls_controls_digests_and_bounds() -> None:
    digest = "a" * 64
    value = (
        "RuntimeError: origin=https://user:secret@example.invalid/pkg.whl?token=query-secret "
        "credential=/Users/alice/private/file.whl token=header-secret sha256="
        + digest
        + "\n\t"
        + "x" * 5000
        + " TAIL-SECRET"
    )

    result = sanitize_diagnostic(value)

    assert result.startswith("RuntimeError: origin=[URL]")
    assert "secret@example.invalid" not in result
    assert "query-secret" not in result
    assert "header-secret" not in result
    assert "/Users/alice/private/file.whl" not in result
    assert digest not in result
    assert "\n" not in result
    assert "\t" not in result
    assert "TAIL-SECRET" not in result
    assert len(result) == MAX_DIAGNOSTIC_LENGTH


@pytest.mark.parametrize(
    ("value", "secret"),
    [
        ("X-Devpi-Auth: dXNlcjpzZWNyZXQ=", "dXNlcjpzZWNyZXQ="),
        ("authorization: Bearer bearer-secret", "bearer-secret"),
        ("AUTHORIZATION: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("auth_token=secret-token", "secret-token"),
        ("Auth-Token: 'quoted secret'", "quoted secret"),
        ("C:/Users/alice/private/file.whl", "C:/Users/alice/private/file.whl"),
        (r"C:\\Users\\alice\\private\\file.whl", r"C:\\Users\\alice\\private\\file.whl"),
        ("token=secret-at-string-boundary", "secret-at-string-boundary"),
    ],
)
def test_sanitize_diagnostic_redacts_credential_variants_and_windows_paths(
    value: str,
    secret: str,
) -> None:
    result = sanitize_diagnostic(value)

    assert secret not in result


def test_sanitize_diagnostic_preserves_harmless_security_prose() -> None:
    value = "The token bucket was empty; authorization policy was reviewed."

    assert sanitize_diagnostic(value) == value
