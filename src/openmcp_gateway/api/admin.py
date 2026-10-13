"""Administrative HTTP API (`/admin/*`).

Always requires a static bearer token; most routes need the `admin` role,
`/admin/metrics` also accepts the narrower `metrics` role. Responses never
include environment values, only variable names; command arguments and
captured stderr pass through the redactor.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ValidationError

from openmcp_gateway.auth.backends import GatewayUser
from openmcp_gateway.auth.principal import Principal
from openmcp_gateway.config import (
    GatewayConfig,
    HttpServerConfig,
    PackageServerConfig,
    ServerConfig,
    StdioServerConfig,
)
from openmcp_gateway.errors import GatewayError
from openmcp_gateway.gateway import tool_allowed
from openmcp_gateway.packages.runtime import describe as describe_package
from openmcp_gateway.redaction import redactor
from openmcp_gateway.routing.namespace import qualify
from openmcp_gateway.runtime.manager import ManagedServer, ServerManager
from openmcp_gateway.storage.base import SERVER_ADAPTER, ServerRepository

from openmcp_gateway.audit import get_audit_logger

logger = logging.getLogger("openmcp_gateway.admin")

_UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}


def _principal(request: Request) -> Principal:
    user = request.scope.get("user")
    if not isinstance(user, GatewayUser) or user.principal.anonymous:
        raise HTTPException(401, "valid admin bearer token required", headers=_UNAUTHORIZED)
    return user.principal


def require_admin(request: Request) -> Principal:
    principal = _principal(request)
    if not principal.is_admin:
        raise HTTPException(403, "admin role required")
    return principal


def require_metrics(request: Request) -> Principal:
    principal = _principal(request)
    if not (principal.is_admin or "metrics" in principal.roles):
        raise HTTPException(403, "admin or metrics role required")
    return principal


Admin = Annotated[Principal, Depends(require_admin)]


class ServerSummary(BaseModel):
    id: str
    source: str
    transport: str
    description: str
    enabled: bool
    autostart: bool
    state: str
    pid: int | None
    protocol_version: str | None
    upstream_name: str | None
    upstream_version: str | None
    in_flight: int
    queued: int
    recent_failures: int
    restarts_exhausted: bool
    last_error: str | None
    uptime_seconds: float | None


class ServerDetail(ServerSummary):
    command: str | None
    args: list[str] | None
    env_names: list[str] | None
    url: str | None
    header_names: list[str] | None
    package: dict[str, Any] | None
    capabilities: dict[str, Any] | None
    instructions: str | None
    rpc_stats: dict[str, int] | None
    limits: dict[str, Any]


class ToolInfo(BaseModel):
    name: str
    exposed_as: str | None
    description: str | None


class LogLine(BaseModel):
    ts: float
    text: str
    truncated: bool


def _summary(server: ManagedServer) -> dict[str, Any]:
    up = server.upstream
    return {
        "id": server.id,
        "source": server.source,
        "transport": server.config.transport,
        "description": server.config.description,
        "enabled": server.config.enabled,
        "autostart": server.config.autostart,
        "state": server.state.value,
        "pid": up.pid if up else None,
        "protocol_version": up.protocol_version if up else None,
        "upstream_name": up.server_info.name if up and up.server_info else None,
        "upstream_version": up.server_info.version if up and up.server_info else None,
        "in_flight": server.in_flight,
        "queued": server.waiting,
        "recent_failures": len(server.failures),
        "restarts_exhausted": server.restarts_exhausted,
        "last_error": server.last_error,
        "uptime_seconds": round(time.time() - up.started_at, 3) if up and up.started_at else None,
    }


def build_router(manager: ServerManager, repository: ServerRepository, config: GatewayConfig) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

    def validate_definition(body: dict[str, Any]) -> ServerConfig:
        try:
            definition = SERVER_ADAPTER.validate_python(body)
        except ValidationError as exc:
            detail = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
            raise HTTPException(422, detail) from None
        if isinstance(definition, StdioServerConfig) and not config.admin.allow_stdio_registration:
            raise HTTPException(403, "registering stdio servers is disabled (admin.allow_stdio_registration)")
        if isinstance(definition, PackageServerConfig) and manager.package_runtime is None:
            raise HTTPException(403, "packages are not enabled on this gateway (packages.enabled)")
        return definition

    async def check_package_exists(definition: ServerConfig) -> None:
        runtime = manager.package_runtime
        if not isinstance(definition, PackageServerConfig) or runtime is None:
            return
        if await runtime.service.catalog.get(definition.package, definition.version) is None:
            raise HTTPException(422, f"package {definition.package}@{definition.version} is not registered")

    async def maybe_start(server: ManagedServer) -> None:
        if server.config.enabled and server.config.autostart:
            # Registration succeeds even if the first start fails; state reports it.
            with contextlib.suppress(GatewayError):
                await manager.ensure_ready(server.id)

    def get_server(server_id: str) -> ManagedServer:
        server = manager.get(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        return server

    @router.get("/servers", response_model=list[ServerSummary], summary="List servers")
    async def list_servers(_: Admin) -> list[dict[str, Any]]:
        return [_summary(s) for s in manager.all()]

    @router.get("/servers/{server_id}", response_model=ServerDetail, summary="Inspect a server")
    async def inspect_server(server_id: str, _: Admin) -> dict[str, Any]:
        server = get_server(server_id)
        cfg = server.config
        up = server.upstream
        transport: dict[str, Any] = dict.fromkeys(
            ("command", "args", "env_names", "url", "header_names", "package")
        )
        if isinstance(cfg, HttpServerConfig):
            transport["url"] = redactor.redact(cfg.url)
            transport["header_names"] = sorted({*cfg.headers, *cfg.headers_from_host})
        elif isinstance(cfg, PackageServerConfig):
            transport["args"] = [redactor.redact(a) for a in cfg.args]
            transport["env_names"] = sorted({*cfg.env, *cfg.env_from_host, *cfg.inherit_env})
            transport["package"] = {
                "name": cfg.package,
                "version": cfg.version,
                "network": cfg.network,
                "runtime": describe_package(up),
            }
        else:
            transport["command"] = redactor.redact(cfg.command)
            transport["args"] = [redactor.redact(a) for a in cfg.args]
            transport["env_names"] = sorted({*cfg.env, *cfg.env_from_host, *cfg.inherit_env})
        return {
            **_summary(server),
            **transport,
            "capabilities": up.capabilities.model_dump(mode="json", by_alias=True, exclude_none=True)
            if up and up.capabilities
            else None,
            "instructions": up.instructions if up else None,
            "rpc_stats": up.stats() if up else None,
            "limits": {
                "max_concurrency": cfg.max_concurrency,
                "max_queue": cfg.max_queue,
                "queue_timeout": cfg.queue_timeout,
                "timeouts": cfg.timeouts.model_dump(),
                "restart": cfg.restart.model_dump(),
            },
        }

    async def _lifecycle(server_id: str, principal: Principal, action: str) -> dict[str, Any]:
        server = get_server(server_id)
        get_audit_logger().log(event="admin_action", principal=principal.name, action=action, server=server_id)
        try:
            if action in ("stop", "restart"):
                await manager.stop(server_id)
            if action in ("start", "restart"):
                await manager.start(server_id)
        except GatewayError as exc:
            raise HTTPException(409, exc.public_message) from None
        return _summary(server)

    @router.post("/servers/{server_id}/start", response_model=ServerSummary, summary="Start a server")
    async def start_server(server_id: str, principal: Admin) -> dict[str, Any]:
        return await _lifecycle(server_id, principal, "start")

    @router.post("/servers/{server_id}/stop", response_model=ServerSummary, summary="Stop a server")
    async def stop_server(server_id: str, principal: Admin) -> dict[str, Any]:
        return await _lifecycle(server_id, principal, "stop")

    @router.post("/servers/{server_id}/restart", response_model=ServerSummary, summary="Restart a server")
    async def restart_server(server_id: str, principal: Admin) -> dict[str, Any]:
        return await _lifecycle(server_id, principal, "restart")

    @router.post("/servers", response_model=ServerSummary, status_code=201, summary="Register a server")
    async def register_server(body: dict[str, Any], principal: Admin) -> dict[str, Any]:
        definition = validate_definition(body)
        if manager.get(definition.id) is not None:
            raise HTTPException(409, "a server with this id already exists")
        await check_package_exists(definition)
        await repository.put(definition)
        server = manager.add_server(definition, source="registry")
        get_audit_logger().log(event="admin_action", principal=principal.name, action="register", server=server.id)
        await maybe_start(server)
        return _summary(server)

    @router.put("/servers/{server_id}", response_model=ServerSummary, summary="Replace a registered server")
    async def replace_server(server_id: str, body: dict[str, Any], principal: Admin) -> dict[str, Any]:
        existing = get_server(server_id)
        if existing.source != "registry":
            raise HTTPException(409, "servers defined in the configuration file are read-only")
        definition = validate_definition(body)
        if definition.id != server_id:
            raise HTTPException(422, "id in body must match the path")
        await check_package_exists(definition)
        await repository.put(definition)
        server = await manager.replace_server(definition)
        get_audit_logger().log(event="admin_action", principal=principal.name, action="replace", server=server_id)
        await maybe_start(server)
        return _summary(server)

    @router.delete("/servers/{server_id}", status_code=204, summary="Remove a registered server")
    async def remove_server(server_id: str, principal: Admin) -> Response:
        existing = get_server(server_id)
        if existing.source != "registry":
            raise HTTPException(409, "servers defined in the configuration file are read-only")
        await manager.remove_server(server_id)
        await repository.delete(server_id)
        get_audit_logger().log(event="admin_action", principal=principal.name, action="remove", server=server_id)
        return Response(status_code=204)

    @router.get("/servers/{server_id}/tools", response_model=list[ToolInfo], summary="Discovered tools")
    async def server_tools(server_id: str, _: Admin) -> list[dict[str, Any]]:
        server = get_server(server_id)
        try:
            tools = await manager.list_tools(server_id)
        except GatewayError as exc:
            raise HTTPException(409, exc.public_message) from None
        return [
            {
                "name": t.name,
                "exposed_as": qualify(server.id, t.name) if tool_allowed(server.config, t.name) else None,
                "description": t.description,
            }
            for t in tools
        ]

    @router.get(
        "/servers/{server_id}/logs", response_model=list[LogLine], summary="Captured stderr (redacted)"
    )
    async def server_logs(
        server_id: str, _: Admin, limit: Annotated[int, Query(ge=1, le=10_000)] = 100
    ) -> list[dict[str, Any]]:
        server = get_server(server_id)
        if server.upstream is None:
            return []
        lines = list(server.upstream.stderr)[-limit:]
        return [{"ts": ln.ts, "text": ln.text, "truncated": ln.truncated} for ln in lines]

    @router.get("/metrics", summary="Prometheus metrics", response_class=Response)
    async def metrics(request: Request, _: Annotated[Principal, Depends(require_metrics)]) -> Response:
        body, content_type = request.app.state.metrics.render()
        return Response(body, media_type=content_type)

    @router.get("/config", summary="Effective configuration (secrets redacted)")
    async def get_config(_: Admin) -> dict[str, Any]:
        data: dict[str, Any] = config.model_dump(mode="json")
        # Truncate SHA-256 hashes so the response is safe to log/share.
        for tok in data.get("auth", {}).get("tokens", []):
            h = str(tok.get("sha256", ""))
            if len(h) == 64:
                tok["sha256"] = h[:8] + "…[redacted]"
        return data

    class _LogLevelRequest(BaseModel):
        level: Literal["debug", "info", "warning", "error"]

    @router.post("/log-level", summary="Change root log level at runtime")
    async def set_log_level(body: _LogLevelRequest, principal: Admin) -> dict[str, str]:
        logging.getLogger().setLevel(body.level.upper())
        get_audit_logger().log(
            event="log_level_changed", principal=principal.name, detail=body.level
        )
        return {"level": body.level}

    return router
