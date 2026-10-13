"""`openmcp` command-line interface (argparse; no extra dependencies)."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from openmcp_gateway import PROJECT_NAME, __version__
from openmcp_gateway.config import (
    ConfigError,
    GatewayConfig,
    StdioServerConfig,
    load_config,
    resolve_config_path,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _print_err(message: str) -> None:
    print(message, file=sys.stderr)


def _load(args: argparse.Namespace) -> GatewayConfig:
    return load_config(args.config)


# ----------------------------------------------------------------- serve


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from openmcp_gateway.app import create_app
    from openmcp_gateway.logconfig import configure_logging

    if args.host:
        os.environ["OPENMCP_GATEWAY__HOST"] = args.host
    if args.port is not None:
        os.environ["OPENMCP_GATEWAY__PORT"] = str(args.port)
    config = _load(args)
    configure_logging(config.logging.level, config.logging.format)
    for warning in config.warnings():
        _print_err(f"warning: {warning}")

    _config_path = resolve_config_path(args.config)
    trusted = config.gateway.trusted_proxies
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(config, config_path=_config_path),
            host=config.gateway.host,
            port=config.gateway.port,
            log_config=None,
            proxy_headers=bool(trusted),
            forwarded_allow_ips=",".join(trusted) if trusted else None,
            server_header=False,
            timeout_graceful_shutdown=10,
        )
    )
    server.run()
    return EXIT_OK


# ----------------------------------------------------------------- config


def cmd_config_validate(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    config = _load(args)
    print(
        f"ok: {path or 'built-in defaults'} — {len(config.servers)} server(s), auth.mode={config.auth.mode}"
    )
    for warning in config.warnings():
        print(f"warning: {warning}")
    return EXIT_OK


def cmd_config_show(args: argparse.Namespace) -> int:
    config = _load(args)
    data = config.model_dump(mode="json")
    # Only hashes are stored, but there is no reason to print them.
    for tok in data["auth"]["tokens"]:
        tok["sha256"] = tok["sha256"][:8] + "…"
    print(json.dumps(data, indent=2))
    return EXIT_OK


# ----------------------------------------------------------------- tokens


def cmd_token_generate(args: argparse.Namespace) -> int:
    from openmcp_gateway.auth.backends import generate_token, hash_token

    token = generate_token()
    print("# Give this token to the client. It is shown once and never stored by the gateway.")
    print(f"token: {token}")
    print("# Put this entry under auth.tokens in your config:")
    # Least privilege: an admin token gets no MCP server access unless asked for.
    default_servers: list[str] = [] if args.admin else ["*"]
    entry: dict[str, Any] = {
        "name": args.name,
        "sha256": hash_token(token),
        "servers": args.servers or default_servers,
    }
    if args.admin:
        entry["roles"] = ["admin"]
    print(f"- {json.dumps(entry)}")
    return EXIT_OK


def cmd_token_hash(args: argparse.Namespace) -> int:
    from openmcp_gateway.auth.backends import hash_token

    token = sys.stdin.readline().strip()
    if not token:
        _print_err("error: provide the token on stdin")
        return EXIT_USAGE
    print(hash_token(token))
    return EXIT_OK


# ----------------------------------------------------------------- server (admin API client)

ADMIN_TOKEN_ENV = "OPENMCP_ADMIN_TOKEN"  # noqa: S105 - variable name, not a secret


class AdminClientError(Exception):
    pass


def _admin_request(args: argparse.Namespace, method: str, path: str, body: Any = None) -> Any:
    """Call the running gateway's admin API using only the standard library."""
    import urllib.error
    import urllib.request

    token = os.environ.get(ADMIN_TOKEN_ENV)
    if not token:
        raise AdminClientError(
            f"set {ADMIN_TOKEN_ENV} to an admin token (see `openmcp token generate --admin`)"
        )
    base = args.url
    if not base:
        cfg = _load(args)
        host = cfg.gateway.host
        host = "127.0.0.1" if host in ("0.0.0.0", "::") else host  # noqa: S104 - client side
        if ":" in host:
            host = f"[{host}]"
        base = f"http://{host}:{cfg.gateway.port}"
    if not base.startswith(("http://", "https://")):
        raise AdminClientError("--url must start with http:// or https://")
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if isinstance(body, bytes):
        data = body
        headers["Content-Type"] = "application/zip"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        base.rstrip("/") + path, data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:  # noqa: S310
            body = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        with contextlib.suppress(ValueError, AttributeError):
            detail = json.loads(detail).get("detail", detail)
        if isinstance(detail, dict) and "details" in detail:
            detail = detail["error"] + "".join(f"\n  - {d}" for d in detail["details"])
        raise AdminClientError(f"{exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise AdminClientError(f"cannot reach gateway at {base}: {exc.reason}") from None
    return json.loads(body) if body else None


def _print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    print("  ".join(c.upper().ljust(widths[c]) for c in columns))
    for row in rows:
        print(
            "  ".join(
                str(row.get(c, "") if row.get(c) is not None else "-").ljust(widths[c]) for c in columns
            )
        )


def cmd_server(args: argparse.Namespace) -> int:
    try:
        action = args.server_command
        if action == "list":
            rows = _admin_request(args, "GET", "/admin/servers")
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                _print_table(rows, ["id", "state", "pid", "protocol_version", "in_flight", "last_error"])
        elif action == "inspect":
            print(json.dumps(_admin_request(args, "GET", f"/admin/servers/{args.id}"), indent=2))
        elif action in ("start", "stop", "restart"):
            row = _admin_request(args, "POST", f"/admin/servers/{args.id}/{action}")
            print(f"{row['id']}: {row['state']}")
        elif action == "tools":
            rows = _admin_request(args, "GET", f"/admin/servers/{args.id}/tools")
            _print_table(rows, ["name", "exposed_as"])
        elif action == "add":
            import yaml

            try:
                definition = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise AdminClientError(f"cannot read {args.file}: {exc}") from None
            if not isinstance(definition, dict):
                raise AdminClientError("the file must contain a single server definition (a mapping)")
            row = _admin_request(args, "POST", "/admin/servers", definition)
            print(f"{row['id']}: registered ({row['state']})")
            if row.get("last_error"):
                print(f"last error: {row['last_error']}")
        elif action == "remove":
            _admin_request(args, "DELETE", f"/admin/servers/{args.id}")
            print(f"{args.id}: removed")
        elif action == "logs":
            lines = _admin_request(args, "GET", f"/admin/servers/{args.id}/logs?limit={args.limit}")
            if not lines:
                print("(no stderr output captured)")
            for line in lines:
                print(line["text"] + (" …" if line["truncated"] else ""))
    except AdminClientError as exc:
        _print_err(f"error: {exc}")
        return EXIT_ERROR
    return EXIT_OK


# ----------------------------------------------------------------- packages


def _package_bytes(path_arg: str, args: argparse.Namespace) -> bytes:
    from openmcp_gateway.packages.archive import PackageValidationError, archive_directory

    path = Path(path_arg)
    if path.is_dir():
        try:
            return archive_directory(path, _load(args).packages.limits)
        except PackageValidationError as exc:
            raise AdminClientError(
                "cannot package directory:" + "".join(f"\n  - {e}" for e in exc.errors)
            ) from None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AdminClientError(f"cannot read {path}: {exc.strerror}") from None


def cmd_package(args: argparse.Namespace) -> int:
    from openmcp_gateway.packages.archive import PackageValidationError, inspect_archive, policy_from_config

    action = args.package_command
    try:
        if action == "validate":
            data = _package_bytes(args.path, args)
            try:
                pkg = inspect_archive(data, policy_from_config(_load(args).packages))
            except PackageValidationError as exc:
                print("INVALID")
                for err in exc.errors:
                    print(f"  - {err}")
                return EXIT_ERROR
            meta = pkg.metadata
            print(f"ok: {meta.name}@{meta.version} — {len(pkg.files)} files, {pkg.size} bytes")
            print(f"digest: sha256:{pkg.digest}")
            print(f"entrypoint: {meta.entrypoint}; locked dependencies: {'yes' if pkg.lock_digest else 'no'}")
            for warning in pkg.warnings:
                print(f"warning: {warning}")
        elif action == "upload":
            row = _admin_request(args, "POST", "/admin/packages", _package_bytes(args.path, args))
            state = "registered" if row["created"] else "already registered (identical content)"
            print(f"{row['name']}@{row['version']}: {state}")
            print(f"digest: sha256:{row['digest']}\nartifact: {row['artifact_uri']}")
        elif action == "register-dir":
            row = _admin_request(
                args, "POST", "/admin/packages/register-directory", {"path": str(Path(args.path).resolve())}
            )
            print(f"{row['name']}@{row['version']}: {'registered' if row['created'] else 'unchanged'}")
        elif action == "list":
            _print_table(_admin_request(args, "GET", "/admin/packages"), ["name", "latest", "versions"])
        elif action == "versions":
            rows = _admin_request(args, "GET", f"/admin/packages/{args.name}")
            for row in rows:
                row["digest"] = row["digest"][:12]
                row["used_by"] = ",".join(row["used_by"]) or "-"
            _print_table(rows, ["version", "digest", "size", "file_count", "created_at", "used_by"])
        elif action == "files":
            rows = _admin_request(args, "GET", f"/admin/packages/{args.name}/{args.version}/files")
            for row in rows:
                row["sha256"] = row["sha256"][:12]
            _print_table(rows, ["path", "size", "sha256"])
        elif action == "verify":
            try:
                row = _admin_request(args, "POST", f"/admin/packages/{args.name}/{args.version}/verify")
            except AdminClientError as exc:
                print(f"FAILED: {exc}")
                return EXIT_ERROR
            print(f"ok: digest sha256:{row['digest']}, {row['files']} files verified")
        elif action == "delete":
            _admin_request(args, "DELETE", f"/admin/packages/{args.name}/{args.version}")
            print(f"{args.name}@{args.version}: deleted")
        elif action == "deploy":
            body = {
                "server_id": args.id,
                "network": args.network,
                "start": not args.no_start,
                "args": args.arg or [],
            }
            row = _admin_request(args, "POST", f"/admin/packages/{args.name}/{args.version}/deploy", body)
            print(f"{row['server_id']}: {row['state']}" + (f" ({row['error']})" if row.get("error") else ""))
            return EXIT_OK if row["state"] in ("ready", "stopped") else EXIT_ERROR
    except AdminClientError as exc:
        _print_err(f"error: {exc}")
        return EXIT_ERROR
    return EXIT_OK


# ----------------------------------------------------------------- doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose configuration and try to start each server once."""
    from openmcp_gateway.errors import GatewayError
    from openmcp_gateway.runtime.manager import ServerManager
    from openmcp_gateway.security.env import build_child_env

    problems = 0
    print(f"{PROJECT_NAME} {__version__} on Python {sys.version.split()[0]}")
    try:
        config = _load(args)
    except ConfigError as exc:
        print(f"FAIL config: {exc}")
        return EXIT_ERROR
    print(f"ok   config: {resolve_config_path(args.config) or 'built-in defaults'}")
    for warning in config.warnings():
        print(f"warn config: {warning}")

    for server in config.servers:
        label = f"server {server.id}"
        if not server.enabled:
            print(f"skip {label}: disabled")
            continue
        if isinstance(server, StdioServerConfig):
            try:
                env, _ = build_child_env(server)
            except GatewayError as exc:
                print(f"FAIL {label}: {exc.public_message}")
                problems += 1
                continue
            command = server.command
            if os.sep not in command and shutil.which(command, path=env.get("PATH", "")) is None:
                print(f"FAIL {label}: command {command!r} not found on the child PATH")
                problems += 1
                continue
        if args.no_start:
            print(f"ok   {label}: configuration looks valid (start skipped)")
            continue

        one = config.model_copy(update={"servers": [server]})

        async def probe(cfg: GatewayConfig = one, sid: str = server.id) -> tuple[int, str | None]:
            manager = ServerManager(cfg)
            try:
                managed = await manager.ensure_ready(sid)
                tools = await manager.list_tools(sid)
                proto = managed.upstream.protocol_version if managed.upstream else None
                return len(tools), proto
            finally:
                await manager.shutdown()

        try:
            count, proto = asyncio.run(probe())
            print(f"ok   {label}: started, protocol {proto}, {count} tool(s)")
        except GatewayError as exc:
            print(f"FAIL {label}: {exc.public_message}")
            problems += 1

    print("no problems found" if not problems else f"{problems} problem(s) found")
    return EXIT_OK if not problems else EXIT_ERROR


# ----------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openmcp", description=f"{PROJECT_NAME} command-line interface")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="config file (default: $OPENMCP_CONFIG or ./openmcp.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway")
    serve.add_argument("--host", help="override gateway.host")
    serve.add_argument("--port", type=int, help="override gateway.port")
    serve.set_defaults(func=cmd_serve)

    config = sub.add_parser("config", help="configuration utilities")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("validate", help="validate the configuration").set_defaults(
        func=cmd_config_validate
    )
    config_sub.add_parser("show", help="print the effective configuration").set_defaults(func=cmd_config_show)

    token = sub.add_parser("token", help="bearer token utilities")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    gen = token_sub.add_parser("generate", help="create a new token and its config entry")
    gen.add_argument("--name", required=True, help="principal name")
    gen.add_argument("--server", dest="servers", action="append", help="allowed server id (repeatable)")
    gen.add_argument("--admin", action="store_true", help="grant the admin role")
    gen.set_defaults(func=cmd_token_generate)
    token_sub.add_parser("hash", help="hash a token read from stdin").set_defaults(func=cmd_token_hash)

    server = sub.add_parser("server", help=f"manage servers of a running gateway (needs ${ADMIN_TOKEN_ENV})")
    server.add_argument("--url", help="gateway base URL (default: derived from config)")
    server.add_argument("--timeout", type=float, default=60.0, help="request timeout in seconds")
    server_sub = server.add_subparsers(dest="server_command", required=True)
    lst = server_sub.add_parser("list", help="list servers and their state")
    lst.add_argument("--json", action="store_true")
    for name, help_text in (
        ("inspect", "show details for one server"),
        ("start", "start a server (clears restart backoff)"),
        ("stop", "stop a server"),
        ("restart", "stop then start a server"),
        ("tools", "list a server's discovered tools"),
    ):
        p = server_sub.add_parser(name, help=help_text)
        p.add_argument("id")
    add = server_sub.add_parser("add", help="register a server from a YAML/JSON file (admin API)")
    add.add_argument("file", help="file containing one server definition")
    rm = server_sub.add_parser("remove", help="remove a server registered via the admin API")
    rm.add_argument("id")
    logs = server_sub.add_parser("logs", help="show captured (redacted) stderr")
    logs.add_argument("id")
    logs.add_argument("--limit", type=int, default=100)
    server.set_defaults(func=cmd_server)

    package = sub.add_parser("package", help="multi-file MCP server packages")
    package.add_argument("--url", help="gateway base URL (default: derived from config)")
    package.add_argument("--timeout", type=float, default=300.0, help="request timeout in seconds")
    pkg_sub = package.add_subparsers(dest="package_command", required=True)
    p = pkg_sub.add_parser(
        "validate", help="validate a ZIP or directory locally (nothing is uploaded or run)"
    )
    p.add_argument("path")
    p = pkg_sub.add_parser("upload", help="upload a ZIP or directory as a new immutable version")
    p.add_argument("path")
    p = pkg_sub.add_parser("register-dir", help="register a directory on the gateway host (development)")
    p.add_argument("path")
    pkg_sub.add_parser("list", help="list packages")
    p = pkg_sub.add_parser("versions", help="list versions of a package")
    p.add_argument("name")
    for name, help_text in (
        ("files", "list files in a version"),
        ("verify", "re-verify a stored version's integrity"),
        ("delete", "delete a version (subject to retention policy)"),
    ):
        p = pkg_sub.add_parser(name, help=help_text)
        p.add_argument("name")
        p.add_argument("version")
    p = pkg_sub.add_parser("deploy", help="create a server running a version")
    p.add_argument("name")
    p.add_argument("version")
    p.add_argument("--id", required=True, help="server id (tool namespace)")
    p.add_argument("--network", choices=["allow", "deny"], default="allow")
    p.add_argument("--arg", action="append", help="extra argument for the entrypoint (repeatable)")
    p.add_argument("--no-start", action="store_true", help="create the server without starting it")
    package.set_defaults(func=cmd_package)

    doctor = sub.add_parser("doctor", help="diagnose configuration and server startup")
    doctor.add_argument("--no-start", action="store_true", help="do not launch servers")
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        _print_err(f"error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
