"""Gateway service: authorization, routing and aggregation.

This layer is transport-free: it takes a `Principal` and plain parameters and
returns `mcp_types` models, raising `GatewayError`/`UpstreamRpcError`. The
downstream MCP server (downstream/server.py) adapts it to the SDK.
"""

from __future__ import annotations

import asyncio
import fnmatch
import itertools
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from opentelemetry import trace
from opentelemetry.trace import StatusCode

import mcp_types as types
from pydantic import ValidationError

from openmcp_gateway.auth.principal import Principal
from openmcp_gateway.config import AnyServerConfig
from openmcp_gateway.errors import (
    GatewayError,
    UnknownTargetError,
    UnknownToolError,
    UpstreamProtocolError,
)
from openmcp_gateway.routing.namespace import MAX_RECOMMENDED_TOOL_NAME, origin_meta, qualify, split
from openmcp_gateway.runtime.manager import ManagedServer, ServerManager
from openmcp_gateway.security.ratelimit import RateLimiter

# (method, exception or None, seconds)
McpObserver = Callable[[str, BaseException | None, float], None]

logger = logging.getLogger(__name__)

T = TypeVar("T")

# (progress, total, message) -> None
ProgressSink = Callable[[float, float | None, str | None], Awaitable[None]]


@dataclass
class _ProgressRoute:
    server_id: str
    sink: ProgressSink


def tool_allowed(config: AnyServerConfig, name: str) -> bool:
    flt = config.tools
    if any(fnmatch.fnmatchcase(name, pat) for pat in flt.deny):
        return False
    return not flt.allow or any(fnmatch.fnmatchcase(name, pat) for pat in flt.allow)


class GatewayService:
    def __init__(
        self,
        manager: ServerManager,
        *,
        rate_limiter: RateLimiter | None = None,
        observer: McpObserver | None = None,
    ) -> None:
        self.manager = manager
        self._rate_limiter = rate_limiter
        self._observer = observer
        self._progress: dict[str, _ProgressRoute] = {}
        self._progress_ids = itertools.count(1)
        self._background: set[asyncio.Task[None]] = set()
        manager.add_listener(self._on_upstream_notification)

    # ------------------------------------------------------------ public API
    # Each public operation is rate-limited and observed in one place.

    async def _run(self, method: str, principal: Principal, op: Callable[[], Awaitable[T]]) -> T:
        tracer = trace.get_tracer("openmcp_gateway")
        with tracer.start_as_current_span(
            f"mcp.{method}",
            attributes={"mcp.method": method, "mcp.principal": principal.name},
        ) as span:
            started = time.perf_counter()
            error: BaseException | None = None
            try:
                if self._rate_limiter is not None:
                    self._rate_limiter.check(principal.name)
                return await op()
            except BaseException as exc:
                error = exc
                span.set_status(StatusCode.ERROR)
                span.record_exception(exc)
                raise
            finally:
                if self._observer is not None:
                    self._observer(method, error, time.perf_counter() - started)

    async def list_tools(self, principal: Principal) -> list[types.Tool]:
        return await self._run("tools/list", principal, lambda: self._list_tools(principal))

    async def call_tool(
        self,
        principal: Principal,
        name: str,
        arguments: dict[str, Any] | None,
        *,
        progress: ProgressSink | None = None,
    ) -> types.CallToolResult:
        return await self._run(
            "tools/call", principal, lambda: self._call_tool(principal, name, arguments, progress=progress)
        )

    async def list_prompts(self, principal: Principal) -> list[types.Prompt]:
        return await self._run("prompts/list", principal, lambda: self._list_prompts(principal))

    async def get_prompt(
        self, principal: Principal, name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        return await self._run("prompts/get", principal, lambda: self._get_prompt(principal, name, arguments))

    async def list_resources(self, principal: Principal) -> list[types.Resource]:
        return await self._run("resources/list", principal, lambda: self._list_resources(principal))

    async def read_resource(self, principal: Principal, uri: str) -> types.ReadResourceResult:
        return await self._run("resources/read", principal, lambda: self._read_resource(principal, uri))

    # ------------------------------------------------------------ helpers

    def _visible_servers(self, principal: Principal) -> list[ManagedServer]:
        return [s for s in self.manager.all() if s.config.enabled and principal.can_use(s.id)]

    def _resolve(self, principal: Principal, qualified: str, kind: type[GatewayError]) -> tuple[str, str]:
        parts = split(qualified)
        if parts is None:
            raise kind(f"unknown {_kind_noun(kind)}: {qualified}")
        server_id, name = parts
        server = self.manager.get(server_id)
        # Unknown, disabled and forbidden servers are indistinguishable to the caller.
        if server is None or not server.config.enabled or not principal.can_use(server_id):
            raise kind(f"unknown {_kind_noun(kind)}: {qualified}")
        return server_id, name

    async def _gather_per_server(
        self, servers: list[ManagedServer], fetch: Callable[[str], Awaitable[list[T]]]
    ) -> list[tuple[ManagedServer, list[T]]]:
        results = await asyncio.gather(*(fetch(s.id) for s in servers), return_exceptions=True)
        out: list[tuple[ManagedServer, list[T]]] = []
        for server, result in zip(servers, results, strict=True):
            if isinstance(result, BaseException):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                logger.warning(
                    "omitting server from listing",
                    extra={
                        "server": server.id,
                        "error": result.public_message
                        if isinstance(result, GatewayError)
                        else type(result).__name__,
                    },
                )
                continue
            out.append((server, result))
        return out

    # ------------------------------------------------------------ tools

    async def _list_tools(self, principal: Principal) -> list[types.Tool]:
        listed = await self._gather_per_server(self._visible_servers(principal), self.manager.list_tools)
        tools: list[types.Tool] = []
        for server, server_tools in listed:
            for tool in server_tools:
                if not tool_allowed(server.config, tool.name):
                    continue
                name = qualify(server.id, tool.name)
                if not principal.can_use_tool(name):
                    continue
                if len(name) > MAX_RECOMMENDED_TOOL_NAME:
                    logger.warning("namespaced tool name exceeds 128 characters", extra={"tool": name})
                tools.append(
                    tool.model_copy(
                        update={
                            "name": name,
                            "meta": {**(tool.meta or {}), **origin_meta(server.id, tool.name)},
                        }
                    )
                )
        return tools

    async def _call_tool(
        self,
        principal: Principal,
        name: str,
        arguments: dict[str, Any] | None,
        *,
        progress: ProgressSink | None = None,
    ) -> types.CallToolResult:
        server_id, tool_name = self._resolve(principal, name, UnknownToolError)
        server = self.manager.get(server_id)
        assert server is not None
        if not tool_allowed(server.config, tool_name):
            raise UnknownToolError(f"unknown tool: {name}")
        if not principal.can_use_tool(name):
            raise UnknownToolError(f"unknown tool: {name}")

        params: dict[str, Any] = {"name": tool_name, "arguments": arguments or {}}
        token = self._register_progress(server_id, progress) if progress else None
        if token is not None:
            params["_meta"] = {"progressToken": token}
        try:
            raw = await self.manager.request(server_id, "tools/call", params)
        finally:
            if token is not None:
                self._progress.pop(token, None)
        return _validate(types.CallToolResult, raw, server_id, "tools/call")

    # ------------------------------------------------------------ prompts

    async def _list_prompts(self, principal: Principal) -> list[types.Prompt]:
        listed = await self._gather_per_server(self._visible_servers(principal), self.manager.list_prompts)
        prompts: list[types.Prompt] = []
        for server, server_prompts in listed:
            for prompt in server_prompts:
                prompts.append(
                    prompt.model_copy(
                        update={
                            "name": qualify(server.id, prompt.name),
                            "meta": {**(prompt.meta or {}), **origin_meta(server.id, prompt.name)},
                        }
                    )
                )
        return prompts

    async def _get_prompt(
        self, principal: Principal, name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        server_id, prompt_name = self._resolve(principal, name, UnknownTargetError)
        params: dict[str, Any] = {"name": prompt_name}
        if arguments:
            params["arguments"] = arguments
        raw = await self.manager.request(server_id, "prompts/get", params)
        return _validate(types.GetPromptResult, raw, server_id, "prompts/get")

    # ------------------------------------------------------------ resources

    async def _list_resources(self, principal: Principal) -> list[types.Resource]:
        """Resources keep their upstream URIs (they may appear in tool results).

        A URI offered by more than one visible server is ambiguous; it is
        omitted and logged rather than routed to an arbitrary owner.
        """
        listed = await self._gather_per_server(self._visible_servers(principal), self.manager.list_resources)
        owners: dict[str, list[str]] = {}
        for server, resources in listed:
            for res in resources:
                owners.setdefault(str(res.uri), []).append(server.id)
        out: list[types.Resource] = []
        for server, resources in listed:
            for res in resources:
                uri = str(res.uri)
                if len(owners[uri]) > 1:
                    continue
                out.append(
                    res.model_copy(update={"meta": {**(res.meta or {}), **origin_meta(server.id, res.name)}})
                )
        ambiguous = sorted(u for u, o in owners.items() if len(o) > 1)
        if ambiguous:
            logger.warning("omitting ambiguous resource URIs", extra={"count": len(ambiguous)})
        return out

    async def _read_resource(self, principal: Principal, uri: str) -> types.ReadResourceResult:
        servers = self._visible_servers(principal)
        listed = await self._gather_per_server(servers, self.manager.list_resources)
        owners = [server.id for server, resources in listed if any(str(r.uri) == uri for r in resources)]
        if len(owners) != 1:
            # Not found, not visible, or ambiguous: same answer.
            raise UnknownTargetError(f"unknown resource: {uri}")
        raw = await self.manager.request(owners[0], "resources/read", {"uri": uri})
        return _validate(types.ReadResourceResult, raw, owners[0], "resources/read")

    # ------------------------------------------------------------ progress

    def _register_progress(self, server_id: str, sink: ProgressSink) -> str:
        token = f"omg-progress-{next(self._progress_ids)}"
        self._progress[token] = _ProgressRoute(server_id, sink)
        return token

    def _on_upstream_notification(self, server_id: str, method: str, params: Any) -> None:
        if method != "notifications/progress" or not isinstance(params, dict):
            return
        token = params.get("progressToken")
        route = self._progress.get(token) if isinstance(token, str) else None
        # A server may only report progress on tokens issued to it.
        if route is None or route.server_id != server_id:
            return
        progress = params.get("progress")
        if not isinstance(progress, int | float) or isinstance(progress, bool):
            return
        total = params.get("total")
        message = params.get("message")
        task = asyncio.ensure_future(
            route.sink(
                float(progress),
                float(total) if isinstance(total, int | float) and not isinstance(total, bool) else None,
                message if isinstance(message, str) else None,
            )
        )
        self._background.add(task)
        task.add_done_callback(self._progress_done)

    def _progress_done(self, task: asyncio.Task[None]) -> None:
        self._background.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.debug("failed to relay progress notification")


M = TypeVar("M", bound=types.Result)


def _validate(model: type[M], raw: Any, server_id: str, method: str) -> M:
    try:
        return model.model_validate(raw)
    except ValidationError:
        raise UpstreamProtocolError(f"server {server_id!r} returned an invalid {method} result") from None


def _kind_noun(kind: type[GatewayError]) -> str:
    return "tool" if kind is UnknownToolError else "prompt"
