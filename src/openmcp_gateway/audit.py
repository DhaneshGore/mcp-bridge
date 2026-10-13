"""Persistent audit log for admin actions and security events.

Each event is written as a single JSON object followed by a newline
(JSON Lines format) to the configured file, and is also emitted to
the ``openmcp_gateway.audit`` Python logger for aggregation by any
attached log handler.

Usage::

    # In app.py / create_app:
    setup_audit_logger(config.admin)

    # In admin route handlers:
    get_audit_logger().log(
        event="server_started",
        principal="alice",
        server="github",
    )
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any

from openmcp_gateway.config import AdminConfig
from openmcp_gateway.logconfig import request_id_var

logger = logging.getLogger("openmcp_gateway.audit")

_audit_logger: AuditLogger | None = None


class AuditLogger:
    """Writes JSON Lines audit records to a file and to the Python logger."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._file: io.TextIOWrapper | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = path.open("a", encoding="utf-8", buffering=1)  # line-buffered

    def log(self, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id_var.get(),
            **fields,
        }
        logger.info("audit", extra=record)
        if self._file is not None:
            try:
                self._file.write(json.dumps(record, default=str) + "\n")
            except OSError:
                logger.warning("audit log write failed", exc_info=True)

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def setup_audit_logger(config: AdminConfig) -> None:
    """Initialise the module-level audit logger from config. Call once at startup."""
    global _audit_logger
    _audit_logger = AuditLogger(config.audit_log_path)


def get_audit_logger() -> AuditLogger:
    """Return the active audit logger (a no-op logger before setup is called)."""
    if _audit_logger is None:
        return AuditLogger(None)
    return _audit_logger
