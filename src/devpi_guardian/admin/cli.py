"""Command-line client for F11 administrator operations."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
from typing import Any

from devpi_guardian.verdicts.models import validate_sha256

from .client import ApiError, GuardianApiClient, _controls, _json_snapshot

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
    for action in ("approve", "block", "revoke", "rescan"):
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
        raw = _safe_file_bytes(path, limit=1024 * 1024, private=False)
        payload = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
        payload = _json_snapshot(payload)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
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
        token = (
            _safe_file_bytes(args.auth_token_file, limit=4096, private=True).decode("utf-8").strip()
        )
        if (
            len(token) > 4096
            or not token
            or _controls(token)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in token)
        ):
            raise ValueError("authentication token is invalid")
    except (OSError, UnicodeError, ValueError) as exc:
        raise CliInputError("could not read authentication token file") from exc
    return token


def _safe_file_bytes(path: str, *, limit: int, private: bool) -> bytes:
    if not isinstance(path, str) or not path or len(path) > 4096 or _controls(path):
        raise OSError("file path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise OSError("file is not a bounded regular file")
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OSError("authentication token permissions are unsafe")
        data = os.read(descriptor, limit + 1)
        if len(data) > limit:
            raise OSError("file is too large")
        return data
    finally:
        os.close(descriptor)


def _sha(value: object) -> str:
    if not isinstance(value, str):
        raise CliInputError("sha256 is required")
    try:
        return validate_sha256(value)
    except ValueError as exc:
        raise CliInputError("sha256 must be a lowercase 64-character hexadecimal digest") from exc


def _call(client: GuardianApiClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.group == "health":
        return client.request("GET", f"{_PREFIX}/health")
    if args.group == "quarantine":
        query: dict[str, object] = {"limit": args.limit, "offset": args.offset}
        if args.state:
            query["state"] = args.state
        return client.request("GET", f"{_PREFIX}/quarantine", query=query)
    if args.group == "artifact":
        base = f"{_PREFIX}/artifacts/{_sha(args.sha256)}"
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
        sha256 = _sha(args.sha256)
        return client.request(
            "POST",
            f"{_PREFIX}/artifacts/{sha256}/exceptions",
            body={"reason": args.reason, "expires_at": args.expires_at},
        )
    if args.group == "audit":
        query = {"limit": args.limit, "offset": args.offset}
        for key in ("sha256", "actor"):
            value = getattr(args, key)
            if value:
                query[key] = _sha(value) if key == "sha256" else value
        if args.action_name:
            query["action"] = args.action_name
        return client.request("GET", f"{_PREFIX}/audit", query=query)
    if args.group == "baseline":
        if args.action == "list":
            return client.request("GET", f"{_PREFIX}/baselines", query={"project": args.project})
        if args.action == "add":
            sha256 = _sha(args.sha256)
            return client.request(
                "POST",
                f"{_PREFIX}/baselines",
                body={"sha256": sha256, "reason": args.reason},
            )
        if args.action == "remove":
            sha256 = _sha(args.sha256)
            return client.request(
                "DELETE",
                f"{_PREFIX}/baselines/{sha256}",
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
        body["sha256"] = _sha(args.sha256)
    return client.request("POST", f"{_PREFIX}/policy/{args.action}", body=body)


def _print(payload: dict[str, Any], *, as_json: bool) -> None:
    try:
        rendered = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=None if as_json else 2,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CliInputError("server returned invalid JSON") from exc
    print(rendered)


def main(argv: list[str] | None = None, *, client_factory=GuardianApiClient) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code == 0 else EXIT_USAGE
    try:
        client = client_factory(
            api_url=args.api_url,
            auth_token=_auth_token(args),
            timeout=args.timeout,
        )
        _print(_call(client, args), as_json=args.as_json)
        return EXIT_OK
    except (CliInputError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except ApiError as exc:
        print(str(exc), file=sys.stderr)
        if exc.status in (401, 403):
            return EXIT_AUTH
        return EXIT_DOMAIN
    except Exception as exc:
        status = getattr(exc, "status", None)
        print(str(exc) if isinstance(status, int) else "guardian request failed", file=sys.stderr)
        if status in (401, 403):
            return EXIT_AUTH
        if isinstance(status, int):
            return EXIT_DOMAIN
        if isinstance(exc, (OSError, TimeoutError, urllib.error.URLError)):
            return EXIT_NETWORK
        raise


if __name__ == "__main__":
    raise SystemExit(main())
