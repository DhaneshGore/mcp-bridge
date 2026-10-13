"""Application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route

from openmcp_gateway import PROJECT_SLUG, __version__
from openmcp_gateway.api import admin, health, packages
from openmcp_gateway.api.middleware import RequestIdMiddleware, RequirePrincipal
from openmcp_gateway.audit import setup_audit_logger
from openmcp_gateway.auth.backends import GatewayAuthBackend, build_authenticators
from openmcp_gateway.config import ConfigError, GatewayConfig, RateLimitConfig
from openmcp_gateway.downstream.server import build_mcp_server
from openmcp_gateway.gateway import GatewayService
from openmcp_gateway.observability.metrics import GatewayMetrics
from openmcp_gateway.packages.runtime import PackageRuntime
from openmcp_gateway.packages.service import PackageService, build_package_service
from openmcp_gateway.runtime.manager import ServerManager
from openmcp_gateway.security.ratelimit import RateLimiter, TokenBucketLimiter
from openmcp_gateway.storage.base import ServerRepository
from openmcp_gateway.storage.memory import MemoryServerRepository
from openmcp_gateway.storage.sqlite import SchemaTooNewError, SqliteServerRepository

logger = logging.getLogger(__name__)

ADMIN_PREFIX = "/admin"


def transport_security(config: GatewayConfig) -> TransportSecuritySettings:
    """Host/Origin validation for the MCP endpoint (DNS-rebinding protection)."""
    gw = config.gateway
    hosts = list(gw.allowed_hosts)
    origins = list(gw.allowed_origins)
    if gw.is_loopback():
        hosts += ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        origins += ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    if not hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
    )


def build_rate_limiter(cfg: RateLimitConfig) -> RateLimiter | None:
    if cfg.per_principal_rps is None and cfg.global_rps is None:
        return None
    return RateLimiter(
        global_limit=TokenBucketLimiter(cfg.global_rps, cfg.global_burst) if cfg.global_rps else None,
        per_principal=TokenBucketLimiter(cfg.per_principal_rps, cfg.per_principal_burst)
        if cfg.per_principal_rps
        else None,
    )


def build_repository(config: GatewayConfig) -> ServerRepository:
    if config.storage.backend == "sqlite":
        try:
            return SqliteServerRepository(config.storage.path)
        except (sqlite3.Error, OSError, SchemaTooNewError) as exc:
            raise ConfigError(f"cannot open registry database {config.storage.path}: {exc}") from None
    return MemoryServerRepository()


async def load_registered_servers(manager: ServerManager, repository: ServerRepository) -> None:
    for definition in await repository.list():
        if manager.get(definition.id) is not None:
            logger.warning(
                "ignoring registered server that conflicts with the configuration file",
                extra={"server": definition.id},
            )
            continue
        manager.add_server(definition, source="registry")


def create_app(
    config: GatewayConfig,
    *,
    manager: ServerManager | None = None,
    repository: ServerRepository | None = None,
    config_path: Path | None = None,
) -> FastAPI:
    setup_audit_logger(config.admin)
    from openmcp_gateway.observability.tracing import setup_tracing

    setup_tracing(config.telemetry)
    manager = manager or ServerManager(config)
    repository = repository or build_repository(config)
    package_service: PackageService | None = None
    if config.packages.enabled:
        package_service = build_package_service(config.packages, usage=manager.package_users)
        manager.package_runtime = PackageRuntime(config.packages, package_service)
    metrics = GatewayMetrics(manager)
    manager.add_observer(metrics.observe_upstream)
    service = GatewayService(
        manager, rate_limiter=build_rate_limiter(config.rate_limits), observer=metrics.observe_mcp
    )
    mcp_server = build_mcp_server(service, name=config.gateway.name)
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        security_settings=transport_security(config),
        max_request_body_size=config.limits.max_request_body_bytes,
        session_idle_timeout=config.limits.session_idle_timeout,
        max_sessions=config.limits.max_sessions,
    )
    mcp_authn, admin_authn = build_authenticators(config.auth)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "gateway starting",
            extra={"version": __version__, "servers": len(config.servers), "auth_mode": config.auth.mode},
        )
        _reload_task: asyncio.Task[None] | None = None
        try:
            async with session_manager.run():
                await load_registered_servers(manager, repository)
                await manager.start_autostart()
                app.state.started = True
                if config_path is not None:
                    from openmcp_gateway.reload import ConfigReloader

                    reloader = ConfigReloader(
                        config_path, app, manager, (mcp_authn, admin_authn), metrics
                    )
                    _reload_task = asyncio.create_task(reloader.watch(), name="config-hot-reload")
                yield
                app.state.started = False
        finally:
            if _reload_task is not None:
                _reload_task.cancel()
            await manager.shutdown()
            await repository.close()
            if package_service is not None:
                await package_service.close()
            from openmcp_gateway.audit import get_audit_logger

            get_audit_logger().close()
            logger.info("gateway stopped")

    app = FastAPI(
        title=config.gateway.name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        openapi_tags=[],
    )

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi
        schema = get_openapi(
            title=app.title,
            version=app.version,
            routes=app.routes,
        )
        schema.setdefault("components", {})
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "opaque",
                "description": "Gateway bearer token. Generate with `openmcp token generate`.",
            }
        }
        schema["security"] = [{"BearerAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
    app.state.config = config
    app.state.manager = manager
    app.state.service = service
    app.state.metrics = metrics
    app.state.started = False

    app.include_router(health.router)
    if config.auth.mode == "jwt" or config.auth.oauth is not None:
        from openmcp_gateway.api.wellknown import build_wellknown_router

        app.include_router(build_wellknown_router(config))
    if config.admin.enabled:
        app.include_router(admin.build_router(manager, repository, config))
        if package_service is not None:
            app.include_router(packages.build_packages_router(package_service, manager, repository))

    app.router.routes.append(
        Route(
            config.gateway.mcp_path,
            endpoint=RequirePrincipal(StreamableHTTPASGIApp(session_manager), realm=PROJECT_SLUG),
            methods=["GET", "POST", "DELETE"],
            include_in_schema=False,
        )
    )
    app.add_middleware(
        AuthenticationMiddleware,
        backend=GatewayAuthBackend(mcp_authn, admin_authn, admin_prefix=ADMIN_PREFIX),
    )
    app.add_middleware(RequestIdMiddleware)
    return app
