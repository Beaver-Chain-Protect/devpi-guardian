from __future__ import annotations

import json
import math
from io import BytesIO
from urllib.error import HTTPError

import pytest

from devpi_guardian.admin.cli import EXIT_DOMAIN, EXIT_OK, EXIT_USAGE, main
from devpi_guardian.admin.client import ApiError, GuardianApiClient


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


def test_cli_revoke_calls_api(capsys) -> None:
    client = Client([{"sha256": "a" * 64, "status": "override_revoked"}])

    exit_code = main(
        [
            "--api-url",
            "https://devpi.example",
            "--json",
            "artifact",
            "revoke",
            "a" * 64,
            "--reason",
            "withdrawn",
        ],
        client_factory=lambda **kwargs: client,
    )

    assert exit_code == EXIT_OK
    assert client.calls == [
        (
            "POST",
            "/+guardian/api/v1/artifacts/" + "a" * 64 + "/revoke",
            {"reason": "withdrawn"},
            None,
        )
    ]
    assert json.loads(capsys.readouterr().out)["status"] == "override_revoked"


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
    assert client.calls[0][0:2] == ("GET", "/+guardian/api/v1/artifacts/" + "a" * 64 + "/diff")
    assert client.calls[1] == ("GET", "/+guardian/api/v1/audit", None, {"limit": 20, "offset": 0})
    assert client.calls[2][0:2] == ("GET", "/+guardian/api/v1/baselines")
    assert client.calls[5][2]["records"] == [{"sha256": "a" * 64}]


def test_cli_policy_validate_and_simulate_read_json_file(tmp_path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"revision": "2"}))
    client = Client([{"valid": True}, {"decision": "REVIEW"}])
    common = ["--api-url", "https://devpi.example"]
    assert (
        main([*common, "policy", "validate", str(policy_file)], client_factory=lambda **_: client)
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
        ("POST", "/+guardian/api/v1/policy/validate", {"policy": {"revision": "2"}}, None),
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

    assert (
        main(
            ["--api-url", "https://devpi.example", "--auth-token-file", str(token_file), "health"],
            client_factory=factory,
        )
        == EXIT_OK
    )
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


def test_client_maps_malformed_success_json_to_sanitized_api_error(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args):
            return b"not-json"

    monkeypatch.setattr("devpi_guardian.admin.client._open", lambda *args, **kwargs: Response())

    with pytest.raises(ApiError) as raised:
        GuardianApiClient(api_url="https://devpi.example").request("GET", "/health")

    assert raised.value.status == 502
    assert raised.value.code == "invalid_response"


def test_client_requires_bounded_json_content_type_and_read_cap(monkeypatch) -> None:
    calls = []

    class Response:
        def __init__(self):
            self.headers = {"Content-Type": "application/json; charset=utf-8"}
            self.status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            calls.append(amount)
            return b'{"ok":true}'

    monkeypatch.setattr("devpi_guardian.admin.client._open", lambda *args, **kwargs: Response())
    result = GuardianApiClient(api_url="https://devpi.example").request("GET", "/health")
    assert result == {"ok": True}
    assert calls == [1024 * 1024 + 1]


def test_client_sanitizes_http_error_shape(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise HTTPError(
            "https://devpi.example/health",
            409,
            "Conflict",
            {"Content-Type": "application/json"},
            BytesIO(b'{"error":{"code":"transition_conflict","message":"state conflict"}}'),
        )

    monkeypatch.setattr("devpi_guardian.admin.client._open", fail)
    with pytest.raises(ApiError) as raised:
        GuardianApiClient(api_url="https://devpi.example").request("GET", "/health")
    assert (raised.value.status, raised.value.code, str(raised.value)) == (
        409,
        "transition_conflict",
        "state conflict",
    )


@pytest.mark.parametrize(
    "api_url",
    [
        "ftp://devpi.example",
        "https://user:pass@devpi.example",
        "https://devpi.example/?x=1",
        "https://devpi.example/#x",
        "https://devpi.example\n",
    ],
)
def test_client_rejects_unsafe_api_origins(api_url) -> None:
    with pytest.raises(ValueError):
        GuardianApiClient(api_url=api_url)


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, -math.inf, True])
def test_client_rejects_non_finite_timeout(timeout) -> None:
    with pytest.raises(ValueError):
        GuardianApiClient(api_url="https://devpi.example", timeout=timeout)


def test_client_rejects_invalid_request_shapes() -> None:
    client = GuardianApiClient(api_url="https://devpi.example")
    with pytest.raises(ValueError):
        client.request("get", "/health")
    with pytest.raises(ValueError):
        client.request("GET", "health")
    with pytest.raises(ValueError):
        client.request("GET", "/health", body=[])


def test_cli_invalid_timeout_is_usage_error(capsys) -> None:
    assert main(["--api-url", "https://devpi.example", "--timeout", "nan", "health"]) == EXIT_USAGE
    assert "timeout" in capsys.readouterr().err
