from __future__ import annotations

import json

from devpi_guardian.admin.cli import EXIT_DOMAIN, EXIT_OK, main


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
