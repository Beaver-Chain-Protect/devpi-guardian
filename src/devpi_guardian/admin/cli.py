"""Command-line client for F11 administrator operations."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any

from .client import GuardianApiClient

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_NETWORK = 4
EXIT_DOMAIN = 5
_PREFIX = "/+guardian/api/v1"


class CliInputError(ValueError):
    """A local CLI input file could not be read safely."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian")
    parser.add_argument("--api-url", required=True)
    authentication = parser.add_mutually_exclusive_group()
    authentication.add_argument("--auth-token")
    authentication.add_argument("--auth-token-file")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json", action="store_true", dest="as_json")
    commands = parser.add_subparsers(dest="group", required=True)

    quarantine = commands.add_parser("quarantine")
    quarantine_sub = quarantine.add_subparsers(dest="action", required=True)
    listing = quarantine_sub.add_parser("list")
    listing.add_argument("--state")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--offset", type=int, default=0)

    artifact = commands.add_parser("artifact")
    artifact_sub = artifact.add_subparsers(dest="action", required=True)
    inspect = artifact_sub.add_parser("inspect")
    inspect.add_argument("sha256")
    diff = artifact_sub.add_parser("diff")
    diff.add_argument("sha256")
    for action in ("approve", "block", "rescan"):
        command = artifact_sub.add_parser(action)
        command.add_argument("sha256")
        command.add_argument("--reason", required=True)

    exception = commands.add_parser("exception")
    exception_sub = exception.add_subparsers(dest="action", required=True)
    add = exception_sub.add_parser("add")
    add.add_argument("sha256")
    add.add_argument("--expires-at", required=True)
    add.add_argument("--reason", required=True)

    commands.add_parser("health")

    audit = commands.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="action", required=True)
    audit_list = audit_sub.add_parser("list")
    audit_list.add_argument("--sha256")
    audit_list.add_argument("--actor")
    audit_list.add_argument("--action-name", dest="action_name")
    audit_list.add_argument("--limit", type=int, default=50)
    audit_list.add_argument("--offset", type=int, default=0)

    baseline = commands.add_parser("baseline")
    baseline_sub = baseline.add_subparsers(dest="action", required=True)
    baseline_list = baseline_sub.add_parser("list")
    baseline_list.add_argument("project")
    for action in ("add", "remove"):
        command = baseline_sub.add_parser(action)
        command.add_argument("sha256")
        command.add_argument("--reason", required=True)
    baseline_import = baseline_sub.add_parser("import")
    baseline_import.add_argument("path")
    baseline_import.add_argument("--reason", required=True)

    policy = commands.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="action", required=True)
    policy_validate = policy_sub.add_parser("validate")
    policy_validate.add_argument("path")
    policy_simulate = policy_sub.add_parser("simulate")
    policy_simulate.add_argument("path")
    policy_simulate.add_argument("--sha256", required=True)
    return parser


def _json_file(path: str, *, array: bool) -> Any:
    try:
        with Path(path).open(encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, ValueError) as exc:
        raise CliInputError(f"could not read JSON input: {path}") from exc
    expected = list if array else dict
    if not isinstance(payload, expected):
        kind = "array" if array else "object"
        raise CliInputError(f"{path} must contain a JSON {kind}")
    return payload


def _auth_token(args: argparse.Namespace) -> str | None:
    if args.auth_token_file is None:
        return args.auth_token
    try:
        token = Path(args.auth_token_file).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise CliInputError("could not read authentication token file") from exc
    if not token:
        raise CliInputError("authentication token file is empty")
    return token


def _call(client: GuardianApiClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.group == "health":
        return client.request("GET", f"{_PREFIX}/health")
    if args.group == "quarantine":
        query: dict[str, object] = {"limit": args.limit, "offset": args.offset}
        if args.state:
            query["state"] = args.state
        return client.request("GET", f"{_PREFIX}/quarantine", query=query)
    if args.group == "artifact":
        base = f"{_PREFIX}/artifacts/{args.sha256}"
        if args.action == "inspect":
            return client.request("GET", base)
        if args.action == "diff":
            return client.request("GET", f"{base}/diff")
        return client.request(
            "POST",
            f"{base}/{args.action}",
            body={"reason": args.reason},
        )
    if args.group == "exception":
        return client.request(
            "POST",
            f"{_PREFIX}/artifacts/{args.sha256}/exceptions",
            body={"reason": args.reason, "expires_at": args.expires_at},
        )
    if args.group == "audit":
        query = {"limit": args.limit, "offset": args.offset}
        for key in ("sha256", "actor"):
            value = getattr(args, key)
            if value:
                query[key] = value
        if args.action_name:
            query["action"] = args.action_name
        return client.request("GET", f"{_PREFIX}/audit", query=query)
    if args.group == "baseline":
        if args.action == "list":
            return client.request("GET", f"{_PREFIX}/baselines", query={"project": args.project})
        if args.action == "add":
            return client.request(
                "POST",
                f"{_PREFIX}/baselines",
                body={"sha256": args.sha256, "reason": args.reason},
            )
        if args.action == "remove":
            return client.request(
                "DELETE",
                f"{_PREFIX}/baselines/{args.sha256}",
                body={"reason": args.reason},
            )
        return client.request(
            "POST",
            f"{_PREFIX}/baselines/import",
            body={"records": _json_file(args.path, array=True), "reason": args.reason},
        )
    policy = _json_file(args.path, array=False)
    body = {"policy": policy}
    if args.action == "simulate":
        body["sha256"] = args.sha256
    return client.request("POST", f"{_PREFIX}/policy/{args.action}", body=body)


def _print(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None, *, client_factory=GuardianApiClient) -> int:
    args = _parser().parse_args(argv)
    try:
        client = client_factory(
            api_url=args.api_url,
            auth_token=_auth_token(args),
            timeout=args.timeout,
        )
        _print(_call(client, args), as_json=args.as_json)
        return EXIT_OK
    except CliInputError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        status = getattr(exc, "status", None)
        print(str(exc), file=sys.stderr)
        if status in (401, 403):
            return EXIT_AUTH
        if isinstance(status, int):
            return EXIT_DOMAIN
        if isinstance(exc, (OSError, TimeoutError, urllib.error.URLError)):
            return EXIT_NETWORK
        raise


if __name__ == "__main__":
    raise SystemExit(main())
