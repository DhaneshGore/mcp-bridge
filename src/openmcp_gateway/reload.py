"""Configuration hot-reload watcher.

Watches the YAML config file for changes and applies a diff in-place:

* Auth tokens are updated atomically (new tokens added, revoked ones removed).
* Servers added in the file are registered and auto-started.
* Servers removed from the file are stopped and deregistered.
* Servers whose definition changed are restarted with the new config.

Registry servers (added via the admin API at runtime) are never touched.

Requires the ``hot-reload`` optional extra::

    pip install openmcp-gateway[hot-reload]

If ``watchfiles`` is not installed, the watcher silently does nothing.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from openmcp_gateway.config import AnyServerConfig, AuthConfig, GatewayConfig, load_config
from openmcp_gateway.observability.metrics import GatewayMetrics

if TYPE_CHECKING:
    from fastapi import FastAPI

    from openmcp_gateway.runtime.manager import ServerManager

logger = logging.getLogger(__name__)


class _Reloadable(Protocol):
    def reload(self, config: AuthConfig) -> None: ...


class ConfigReloader:
    """Watches *config_path* and applies diffs to the running gateway."""

    def __init__(
        self,
        config_path: Path,
        app: FastAPI,
        manager: ServerManager,
        authenticators: tuple[Any, Any],
        metrics: GatewayMetrics,
    ) -> None:
        self._path = config_path
        self._app = app
        self._manager = manager
        self._authenticators = authenticators
        self._metrics = metrics

    async def watch(self) -> None:
        try:
            import watchfiles
        except ImportError:
            logger.debug("watchfiles not installed; config hot-reload disabled")
            return

        logger.info("config hot-reload enabled", extra={"path": str(self._path)})
        async for _ in watchfiles.awatch(self._path):
            await self._reload()

    async def _reload(self) -> None:
        try:
            new_config: GatewayConfig = load_config(self._path)
        except Exception:
            logger.warning("config hot-reload: failed to parse new config; keeping current", exc_info=True)
            return

        old_config: GatewayConfig = self._app.state.config
        changes = 0

        # --- Auth tokens ---
        for auth in self._authenticators:
            if hasattr(auth, "reload"):
                auth.reload(new_config.auth)
        changes += 1

        # --- Servers ---
        old_servers = {s.id: s for s in old_config.servers}
        new_servers = {s.id: s for s in new_config.servers}

        added = set(new_servers) - set(old_servers)
        removed = set(old_servers) - set(new_servers)
        changed = {
            sid
            for sid in set(old_servers) & set(new_servers)
            if old_servers[sid].model_dump() != new_servers[sid].model_dump()
        }

        for sid in added:
            cfg = new_servers[sid]
            server = self._manager.add_server(cfg, source="config")
            if cfg.enabled and cfg.autostart:
                asyncio.create_task(self._manager.start(sid), name=f"reload-start-{sid}")
            logger.info("config hot-reload: server added", extra={"server": sid})
            changes += 1

        for sid in removed:
            existing = self._manager.get(sid)
            if existing is not None and existing.source == "config":
                asyncio.create_task(self._manager.remove_server(sid), name=f"reload-remove-{sid}")
                logger.info("config hot-reload: server removed", extra={"server": sid})
                changes += 1

        for sid in changed:
            cfg = new_servers[sid]
            asyncio.create_task(self._replace(sid, cfg), name=f"reload-replace-{sid}")
            logger.info("config hot-reload: server changed, restarting", extra={"server": sid})
            changes += 1

        self._app.state.config = new_config
        self._metrics.config_reloads.inc()
        logger.info("config hot-reload applied", extra={"changes": changes})

    async def _replace(self, sid: str, cfg: AnyServerConfig) -> None:
        try:
            await self._manager.replace_server(cfg)
            if cfg.enabled and cfg.autostart:
                await self._manager.start(sid)
        except Exception:
            logger.warning("config hot-reload: failed to replace server", extra={"server": sid}, exc_info=True)
