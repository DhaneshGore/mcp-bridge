"""Prometheus metrics (per-app registry; no global state).

Label values are bounded: methods come from a fixed set, servers and
principals from configuration. Tool names are never used as labels.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import TYPE_CHECKING

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from prometheus_client.registry import Collector

from openmcp_gateway import __version__
from openmcp_gateway.errors import (
    GatewayError,
    OverloadedError,
    RateLimitedError,
    UnknownTargetError,
    UnknownToolError,
    UpstreamClosedError,
    UpstreamRpcError,
    UpstreamTimeoutError,
    UpstreamUnavailableError,
)

if TYPE_CHECKING:
    from openmcp_gateway.runtime.manager import ServerManager

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)


def outcome_of(exc: BaseException | None) -> str:
    if exc is None:
        return "ok"
    if isinstance(exc, UpstreamRpcError):
        return "upstream_error"
    if isinstance(exc, UpstreamTimeoutError):
        return "timeout"
    if isinstance(exc, RateLimitedError):
        return "rate_limited"
    if isinstance(exc, OverloadedError):
        return "overloaded"
    if isinstance(exc, UnknownToolError | UnknownTargetError):
        return "not_found"
    if isinstance(exc, UpstreamUnavailableError | UpstreamClosedError):
        return "unavailable"
    if isinstance(exc, GatewayError):
        return "gateway_error"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    return "internal_error"


class GatewayMetrics:
    def __init__(self, manager: ServerManager) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.mcp_requests = Counter(
            "openmcp_mcp_requests",
            "MCP requests handled for clients, by method and outcome.",
            ["method", "outcome"],
            registry=self.registry,
        )
        self.mcp_latency = Histogram(
            "openmcp_mcp_request_duration_seconds",
            "Latency of MCP requests handled for clients.",
            ["method"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.upstream_requests = Counter(
            "openmcp_upstream_requests",
            "Requests sent to upstream servers, by server, method and outcome.",
            ["server", "method", "outcome"],
            registry=self.registry,
        )
        self.upstream_latency = Histogram(
            "openmcp_upstream_request_duration_seconds",
            "Latency of upstream requests.",
            ["server"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.config_reloads = Counter(
            "openmcp_config_reloads_total",
            "Number of successful configuration hot-reloads.",
            registry=self.registry,
        )
        self.registry.register(_RuntimeCollector(manager))

    def observe_mcp(self, method: str, exc: BaseException | None, seconds: float) -> None:
        self.mcp_requests.labels(method, outcome_of(exc)).inc()
        self.mcp_latency.labels(method).observe(seconds)

    def observe_upstream(self, server: str, method: str, exc: BaseException | None, seconds: float) -> None:
        self.upstream_requests.labels(server, method, outcome_of(exc)).inc()
        self.upstream_latency.labels(server).observe(seconds)

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


class _RuntimeCollector(Collector):
    """Reads live server state at scrape time."""

    def __init__(self, manager: ServerManager) -> None:
        self._manager = manager

    def collect(self) -> Iterable[Metric]:
        info = GaugeMetricFamily("openmcp_build_info", "Gateway build information.", labels=["version"])
        info.add_metric([__version__], 1)
        yield info

        up = GaugeMetricFamily("openmcp_upstream_up", "1 if the upstream server is ready.", labels=["server"])
        state = GaugeMetricFamily(
            "openmcp_upstream_state",
            "Current lifecycle state (1 for the active state).",
            labels=["server", "state"],
        )
        in_flight = GaugeMetricFamily(
            "openmcp_upstream_in_flight", "Requests currently executing upstream.", labels=["server"]
        )
        queued = GaugeMetricFamily(
            "openmcp_upstream_queued", "Requests waiting for a concurrency slot.", labels=["server"]
        )
        failures = GaugeMetricFamily(
            "openmcp_upstream_recent_failures", "Failures inside the restart window.", labels=["server"]
        )
        rpc = CounterMetricFamily(
            "openmcp_upstream_rpc_events",
            "Low-level JSON-RPC events for the current upstream process (resets on restart).",
            labels=["server", "event"],
        )
        for server in self._manager.all():
            sid = server.id
            up.add_metric([sid], 1 if server.state.value == "ready" else 0)
            state.add_metric([sid, server.state.value], 1)
            in_flight.add_metric([sid], server.in_flight)
            queued.add_metric([sid], server.waiting)
            failures.add_metric([sid], len(server.failures))
            if server.upstream is not None:
                for event, value in server.upstream.stats().items():
                    rpc.add_metric([sid, event], value)
        yield from (up, state, in_flight, queued, failures, rpc)
