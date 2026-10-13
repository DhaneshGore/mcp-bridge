"""OpenTelemetry tracing setup.

Configures the global OTel tracer provider when ``telemetry.otel_endpoint``
is set. Falls back silently to the no-op provider (which is always present
via the ``opentelemetry-api`` core dependency) when the endpoint is not
configured or when the SDK optional extra is not installed.

Usage::

    # In app.py / create_app:
    from openmcp_gateway.observability.tracing import setup_tracing, get_tracer
    setup_tracing(config.telemetry)

    # In gateway.py or wherever spans are needed:
    tracer = get_tracer()
    with tracer.start_as_current_span("mcp.tools/list") as span:
        span.set_attribute("mcp.principal", principal.name)
        ...
"""

from __future__ import annotations

import logging

from opentelemetry import trace
from opentelemetry.propagate import set_global_textmap
from opentelemetry.trace import Tracer

from openmcp_gateway.config import TelemetryConfig

logger = logging.getLogger(__name__)

_TRACER_NAME = "openmcp_gateway"


def setup_tracing(config: TelemetryConfig) -> None:
    """Configure the global OTel provider. Safe to call multiple times; no-op after the first."""
    if config.otel_endpoint is None:
        return

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    except ImportError:
        logger.warning(
            "telemetry.otel_endpoint is set but opentelemetry-sdk is not installed; "
            "install openmcp-gateway[otel] to enable tracing"
        )
        return

    resource = Resource.create({"service.name": config.service_name})
    sampler = ParentBased(root=TraceIdRatioBased(config.sample_rate))
    provider = TracerProvider(resource=resource, sampler=sampler)
    exporter = OTLPSpanExporter(endpoint=config.otel_endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    set_global_textmap(TraceContextTextMapPropagator())
    logger.info(
        "otel tracing enabled",
        extra={"endpoint": config.otel_endpoint, "sample_rate": config.sample_rate},
    )


def get_tracer() -> Tracer:
    """Return the gateway tracer (no-op when OTel SDK is not configured)."""
    return trace.get_tracer(_TRACER_NAME)
