import pytest

from devpi_guardian.privacy import (
    MAX_DIAGNOSTIC_LENGTH,
    sanitize_diagnostic,
    sanitize_diagnostic_fields,
)


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
        ("client_secret=client-secret", "client-secret"),
        ("client-secret: client-secret-value", "client-secret-value"),
        ("client secret=client-secret-space", "client-secret-space"),
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


def test_sanitize_diagnostic_preserves_public_guardian_route_text() -> None:
    value = "route=/+guardian/api/v1/health"

    assert sanitize_diagnostic(value) == value


@pytest.mark.parametrize(
    ("value", "secret"),
    [
        ("{'auth_token': 'dict-auth-secret'}", "dict-auth-secret"),
        ('{"client_secret": "json-client-secret"}', "json-client-secret"),
        ("{'X-Devpi-Auth': 'header-dict-secret'}", "header-dict-secret"),
    ],
)
def test_sanitize_diagnostic_redacts_quoted_mapping_keys(value: str, secret: str) -> None:
    result = sanitize_diagnostic(value)

    assert secret not in result
    assert "[REDACTED]" in result


def test_sanitize_diagnostic_redacts_posix_paths_with_spaces() -> None:
    value = "download failed at /Users/alice/My Secret/file.whl"

    result = sanitize_diagnostic(value)

    assert "/Users/alice/My Secret/file.whl" not in result
    assert result == "download failed at [PATH]"


@pytest.mark.parametrize(
    "value",
    [
        "download failed at /Users/alice/My Secret/cache dir",
        "download failed at /tmp/My Dir",
        r"download failed at C:\Users\alice\My Secret\cache dir",
        r"download failed at C:\My Dir",
        r"download failed at \\fileserver\Share Name\cache dir",
        r"download failed at \\server\Share Name",
    ],
)
def test_sanitize_diagnostic_redacts_complete_extensionless_paths_with_spaces(
    value: str,
) -> None:
    result = sanitize_diagnostic(value)

    assert result == "download failed at [PATH]"


def test_sanitize_diagnostic_redacts_json_escaped_quoted_secret_value() -> None:
    value = r'{"client_secret":"abc\"def"}'

    result = sanitize_diagnostic(value)

    assert "abc" not in result
    assert "def" not in result
    assert result == r'{"client_secret":[REDACTED]}'


def test_sanitize_diagnostic_redacts_json_escaped_header_credential() -> None:
    value = r'{"Authorization":"Bearer abc\"def"}'

    result = sanitize_diagnostic(value)

    assert "abc" not in result
    assert "def" not in result
    assert result == r'{"Authorization":[REDACTED]}'


def test_sanitize_diagnostic_does_not_consume_following_prose_after_path() -> None:
    value = "download failed at /tmp/a.whl while retrying"

    assert sanitize_diagnostic(value) == "download failed at [PATH] while retrying"


def test_sanitize_diagnostic_fields_rejects_cycles() -> None:
    value: dict[str, object] = {}
    value["nested"] = value

    with pytest.raises(ValueError, match="cycle"):
        sanitize_diagnostic_fields(value)


def test_sanitize_diagnostic_fields_rejects_cycle_below_diagnostic_key() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    value = {"message": cycle}

    with pytest.raises(ValueError, match="cycle"):
        sanitize_diagnostic_fields(value)


def test_sanitize_diagnostic_fields_preserves_structured_shape_and_safe_digests() -> None:
    digest = "a" * 64
    value = {
        "message": {
            "auth_token": "nested-token",
            "nested": [{"client_secret": "nested-secret"}],
            "sha256": digest,
            "baseline_sha256": digest,
            "fingerprint": digest,
        }
    }

    result = sanitize_diagnostic_fields(value)

    assert result == {
        "message": {
            "auth_token": "[REDACTED]",
            "nested": [{"client_secret": "[REDACTED]"}],
            "sha256": digest,
            "baseline_sha256": digest,
            "fingerprint": digest,
        }
    }


def test_sanitize_diagnostic_fields_redacts_noncanonical_identity_values() -> None:
    value = {"message": {"sha256": "https://user:secret@example.invalid/a.whl"}}

    result = sanitize_diagnostic_fields(value)

    assert result == {"message": {"sha256": "[URL]"}}


def test_sanitize_diagnostic_fields_rejects_deep_composite_below_diagnostic_key() -> None:
    value: object = "leaf"
    for _ in range(34):
        value = [value]

    with pytest.raises(ValueError, match="deeply nested"):
        sanitize_diagnostic_fields({"message": value})
