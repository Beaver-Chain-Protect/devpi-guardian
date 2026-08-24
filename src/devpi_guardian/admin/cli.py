"""Command-line client for F11 administrator operations."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from typing import Any

from .client import GuardianApiClient

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_NETWORK = 4
EXIT_DOMAIN = 5
_PREFIX = "/+guardian/api/v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--auth-token")
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
    return parser


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
        return client.request(
            "POST",
            f"{base}/{args.action}",
            body={"reason": args.reason},
        )
    return client.request(
        "POST",
        f"{_PREFIX}/artifacts/{args.sha256}/exceptions",
        body={"reason": args.reason, "expires_at": args.expires_at},
    )


def _print(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None, *, client_factory=GuardianApiClient) -> int:
    args = _parser().parse_args(argv)
    client = client_factory(
        api_url=args.api_url,
        auth_token=args.auth_token,
        timeout=args.timeout,
    )
    try:
        _print(_call(client, args), as_json=args.as_json)
        return EXIT_OK
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
