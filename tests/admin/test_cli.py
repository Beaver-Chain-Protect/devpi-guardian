from __future__ import annotations

import json

from devpi_guardian.admin.cli import EXIT_DOMAIN, EXIT_OK, EXIT_USAGE, main


class Client:
    def __init__(self, responses) -> None:
        self.responses = responses
        self.calls = []

    def request(self, method, path, *, body=None, query=None):
        self.calls.append((method, path, body, query))
        return self.responses.pop(0)


def test_cli_approve_calls_api_and_emits_json(capsys) -> None:
    client = Client([{"sha256": "a" * 64, "status": "approved"}])

    exit_code = main(
        [
            "--api-url",
            "https://devpi.example",
            "--json",
            "artifact",
            "approve",
            "a" * 64,
            "--reason",
            "reviewed",
        ],
        client_factory=lambda **kwargs: client,
    )

    assert exit_code == EXIT_OK
    assert client.calls == [
        (
            "POST",
            "/+guardian/api/v1/artifacts/" + "a" * 64 + "/approve",
            {"reason": "reviewed"},
            None,
        )
    ]
    assert json.loads(capsys.readouterr().out)["status"] == "approved"


def test_cli_domain_error_has_stable_exit_code(capsys) -> None:
    class DomainError(Exception):
        status = 409
        code = "transition_conflict"

    class FailingClient:
        def request(self, *args, **kwargs):
            raise DomainError("state conflict")

    exit_code = main(
        ["--api-url", "https://devpi.example", "health"],
        client_factory=lambda **kwargs: FailingClient(),
    )

    assert exit_code == EXIT_DOMAIN
    assert "state conflict" in capsys.readouterr().err


def test_cli_exposes_diff_audit_and_baseline_commands(tmp_path) -> None:
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps([{"sha256": "a" * 64}]))
    client = Client(
        [
            {"diff": {}},
            {"items": [], "total": 0},
            {"items": []},
            {"status": "added"},
            {"status": "removed"},
            {"imported": 1},
        ]
    )
    common = ["--api-url", "https://devpi.example"]

    assert main([*common, "artifact", "diff", "a" * 64], client_factory=lambda **_: client) == 0
    assert main([*common, "audit", "list", "--limit", "20"], client_factory=lambda **_: client) == 0
    assert main([*common, "baseline", "list", "demo"], client_factory=lambda **_: client) == 0
    assert (
        main(
            [*common, "baseline", "add", "a" * 64, "--reason", "trusted"],
            client_factory=lambda **_: client,
        )
        == 0
    )
    assert (
        main(
            [*common, "baseline", "remove", "a" * 64, "--reason", "revoked"],
            client_factory=lambda **_: client,
        )
        == 0
    )
    assert (
        main(
            [*common, "baseline", "import", str(baseline_file), "--reason", "bootstrap"],
            client_factory=lambda **_: client,
        )
        == 0
    )

    assert client.calls[0][0:2] == (
        "GET",
        "/+guardian/api/v1/artifacts/" + "a" * 64 + "/diff",
    )
    assert client.calls[1] == (
        "GET",
        "/+guardian/api/v1/audit",
        None,
        {"limit": 20, "offset": 0},
    )
    assert client.calls[2][0:2] == ("GET", "/+guardian/api/v1/baselines")
    assert client.calls[5][2]["records"] == [{"sha256": "a" * 64}]


def test_cli_policy_validate_and_simulate_read_json_file(tmp_path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"revision": "2"}))
    client = Client([{"valid": True}, {"decision": "REVIEW"}])
    common = ["--api-url", "https://devpi.example"]

    assert (
        main(
            [*common, "policy", "validate", str(policy_file)],
            client_factory=lambda **_: client,
        )
        == 0
    )
    assert (
        main(
            [*common, "policy", "simulate", str(policy_file), "--sha256", "a" * 64],
            client_factory=lambda **_: client,
        )
        == 0
    )

    assert client.calls == [
        (
            "POST",
            "/+guardian/api/v1/policy/validate",
            {"policy": {"revision": "2"}},
            None,
        ),
        (
            "POST",
            "/+guardian/api/v1/policy/simulate",
            {"policy": {"revision": "2"}, "sha256": "a" * 64},
            None,
        ),
    ]


def test_cli_reads_auth_token_from_file_without_putting_it_in_arguments(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    captured = {}
    client = Client([{"database": "ok"}])

    def factory(**kwargs):
        captured.update(kwargs)
        return client

    exit_code = main(
        [
            "--api-url",
            "https://devpi.example",
            "--auth-token-file",
            str(token_file),
            "health",
        ],
        client_factory=factory,
    )

    assert exit_code == EXIT_OK
    assert captured["auth_token"] == "secret-token"


def test_cli_invalid_local_json_is_a_usage_error(tmp_path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json")

    exit_code = main(
        ["--api-url", "https://devpi.example", "policy", "validate", str(invalid)],
        client_factory=lambda **_: Client([]),
    )

    assert exit_code == EXIT_USAGE
    assert "could not read JSON input" in capsys.readouterr().err
