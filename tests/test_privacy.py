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
