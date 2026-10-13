"""Remote upstream over Streamable HTTP, using the official SDK client (ADR 0002).

All connections go through `GuardedTransport`, so every destination address is
validated at connect time (security/ssrf.py). The SDK client lives in a
dedicated task because its anyio task groups must be entered and exited by the
same task; requests from other tasks use its session concurrently.

The gateway authenticates to upstreams with its *own* configured credentials;
client tokens are never passed through.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Any

import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.dispatcher import ProgressFnT
from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT

from openmcp_gateway import PROJECT_SLUG, __version__
from openmcp_gateway.config import HttpServerConfig
from openmcp_gateway.errors import (
    GatewayError,
    UpstreamClosedError,
    UpstreamProtocolError,
    UpstreamRpcError,
    UpstreamStartError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)
from openmcp_gateway.redaction import redactor
from openmcp_gateway.security.ssrf import EgressDeniedError, EgressPolicy, GuardedTransport
from openmcp_gateway.upstream.base import StderrLine
from openmcp_gateway.upstream.jsonrpc import NotificationHandler

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 10.0


def build_headers(config: HttpServerConfig, host_env: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if host_env is None else host_env
    headers = dict(config.headers)
    missing = []
    for header, env_name in config.headers_from_host.items():
        value = source.get(env_name)
        if value is None:
            missing.append(env_name)
            continue
        headers[header] = value
        redactor.register([value])
    if missing:
        raise UpstreamStartError(
            f"server {config.id!r}: required gateway environment variable(s) not set: {', '.join(missing)}"
        )
    return headers


class HttpUpstream:
    def __init__(
        self,
        config: HttpServerConfig,
        *,
        policy: EgressPolicy,
        max_message_bytes: int,
        on_notification: NotificationHandler | None = None,
        on_exit: Callable[[HttpUpstream], None] | None = None,
        host_env: dict[str, str] | None = None,
    ) -> None:
        self.config = config
        self.server_id = config.id
        self._policy = policy
        self._max_message_bytes = max_message_bytes
        self._on_notification = on_notification
        self._on_exit = on_exit
        self._host_env = host_env
        self._client: Client | None = None
        self._runner: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._dead = False
        self._stopping = False
        self._counters: Counter[str] = Counter()
        self.protocol_version: str | None = None
        self.server_info: types.Implementation | None = None
        self.capabilities: types.ServerCapabilities | None = None
        self.instructions: str | None = None
        self.started_at: float | None = None

    # ------------------------------------------------------------ status

    @property
    def alive(self) -> bool:
        return (
            self._client is not None
            and not self._dead
            and self._runner is not None
            and not self._runner.done()
        )

    @property
    def pid(self) -> int | None:
        return None

    @property
    def returncode(self) -> int | None:
        return None

    @property
    def stderr(self) -> Sequence[StderrLine]:
        return ()

    def stats(self) -> dict[str, int]:
        return dict(self._counters)

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        cfg = self.config
        headers = build_headers(cfg, self._host_env)
        # Propagate W3C trace context to the upstream (no-op when OTel is not configured).
        from opentelemetry.propagate import inject

        inject(headers)
        policy = EgressPolicy(
            allow_private=cfg.allow_private_network or self._policy.allow_private,
            allowed_networks=self._policy.allowed_networks,
        )
        http = httpx2.AsyncClient(
            transport=GuardedTransport(policy, max_body_bytes=self._max_message_bytes, verify=cfg.verify_tls),
            headers=headers,
            timeout=httpx2.Timeout(cfg.timeouts.request, connect=_CONNECT_TIMEOUT),
            follow_redirects=False,
            trust_env=False,
        )
        client = Client(
            streamable_http_client(cfg.url, http_client=http, max_sse_event_size=self._max_message_bytes),
            mode=cfg.protocol,
            client_info=types.Implementation(name=PROJECT_SLUG, version=__version__),
            cache=None,  # the gateway caches listings itself
            read_timeout_seconds=cfg.timeouts.request,
        )
        ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._runner = asyncio.create_task(self._run(client, http, ready), name=f"{cfg.id}-http")
        try:
            async with asyncio.timeout(cfg.timeouts.startup):
                await asyncio.shield(ready)
        except TimeoutError:
            await self.stop()
            raise UpstreamStartError(f"server {cfg.id!r}: connection timed out") from None
        except GatewayError as exc:
            await self.stop()
            raise UpstreamStartError(exc.public_message) from None
        self._client = client
        self.protocol_version = client.protocol_version
        self.server_info = client.server_info
        self.capabilities = client.server_capabilities
        self.instructions = client.instructions
        self.started_at = time.time()
        logger.info(
            "connected to remote upstream",
            extra={"server": cfg.id, "protocol_version": self.protocol_version},
        )

    async def _run(self, client: Client, http: httpx2.AsyncClient, ready: asyncio.Future[None]) -> None:
        try:
            async with http, client:
                ready.set_result(None)
                await self._stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(_start_error(self.server_id, exc))
            elif not isinstance(exc, asyncio.CancelledError):
                logger.warning(
                    "remote upstream connection ended",
                    extra={"server": self.server_id, "error": type(exc).__name__},
                )
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            self._mark_dead()

    async def stop(self) -> None:
        self._stopping = True
        self._stop.set()
        runner = self._runner
        if runner is not None and not runner.done():
            try:
                async with asyncio.timeout(self.config.timeouts.shutdown):
                    await asyncio.shield(runner)
            except (TimeoutError, Exception):
                runner.cancel()
                with contextlib.suppress(BaseException):
                    await runner
        self._client = None

    def _mark_dead(self) -> None:
        if self._dead:
            return
        self._dead = True
        if not self._stopping and self._client is not None and self._on_exit is not None:
            self._on_exit(self)

    # ------------------------------------------------------------ requests

    async def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        client = self._client
        if client is None or not self.alive:
            raise UpstreamClosedError(f"server {self.server_id!r} is not connected")
        params = params or {}
        limit = timeout if timeout is not None else self.config.timeouts.request
        self._counters["requests_sent"] += 1
        try:
            async with asyncio.timeout(limit):
                result = await self._dispatch(client, method, params)
        except TimeoutError:
            self._counters["timeouts"] += 1
            raise UpstreamTimeoutError(
                f"server {self.server_id!r} did not answer {method} within {limit:g}s"
            ) from None
        except MCPError as exc:
            if exc.code == CONNECTION_CLOSED:
                self._counters["connection_errors"] += 1
                self._mark_dead()
                raise UpstreamClosedError(f"server {self.server_id!r} connection closed") from None
            if exc.code == REQUEST_TIMEOUT:
                self._counters["timeouts"] += 1
                raise UpstreamTimeoutError(f"server {self.server_id!r} did not answer {method}") from None
            self._counters["error_responses"] += 1
            raise UpstreamRpcError(exc.code, exc.message, exc.data) from None
        except (httpx2.TransportError, OSError) as exc:
            self._counters["connection_errors"] += 1
            self._mark_dead()
            raise UpstreamUnavailableError(
                f"server {self.server_id!r} is unreachable ({type(exc).__name__})"
            ) from None
        self._counters["responses_matched"] += 1
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def _dispatch(self, client: Client, method: str, params: dict[str, Any]) -> types.Result:
        cursor = params.get("cursor")
        if method == "tools/list":
            return await client.list_tools(cursor=cursor)
        if method == "tools/call":
            token = (params.get("_meta") or {}).get("progressToken")
            callback = self._progress_callback(token) if token is not None else None
            return await client.call_tool(params["name"], params.get("arguments"), progress_callback=callback)
        if method == "prompts/list":
            return await client.list_prompts(cursor=cursor)
        if method == "prompts/get":
            return await client.get_prompt(params["name"], params.get("arguments"))
        if method == "resources/list":
            return await client.list_resources(cursor=cursor)
        if method == "resources/read":
            return await client.read_resource(params["uri"])
        if method == "ping":
            return await client.send_ping()
        raise UpstreamProtocolError(f"method {method!r} is not supported for remote upstreams")

    def _progress_callback(self, token: Any) -> ProgressFnT:
        async def on_progress(progress: float, total: float | None, message: str | None) -> None:
            if self._on_notification is None:
                return
            params: dict[str, Any] = {"progressToken": token, "progress": progress}
            if total is not None:
                params["total"] = total
            if message is not None:
                params["message"] = message
            self._on_notification("notifications/progress", params)

        return on_progress


def _walk(exc: BaseException) -> list[BaseException]:
    """Flatten an exception, its causes/contexts and exception-group members."""
    out: list[BaseException] = []
    stack = [exc]
    while stack:
        current = stack.pop()
        if any(current is seen for seen in out):
            continue
        out.append(current)
        if isinstance(current, BaseExceptionGroup):
            stack.extend(current.exceptions)
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                stack.append(linked)
    return out


def _start_error(server_id: str, exc: BaseException) -> GatewayError:
    """Translate a connection failure into a sanitized start error."""
    chain = _walk(exc)
    if any(isinstance(e, EgressDeniedError) for e in chain):
        return UpstreamStartError(f"server {server_id!r}: destination not allowed by egress policy")
    mcp_error = next((e for e in chain if isinstance(e, MCPError)), None)
    if mcp_error is not None:
        return UpstreamStartError(f"server {server_id!r}: handshake failed ({mcp_error.code})")
    transport = next((e for e in chain if isinstance(e, httpx2.TransportError | OSError)), exc)
    return UpstreamStartError(f"server {server_id!r}: connection failed ({type(transport).__name__})")
