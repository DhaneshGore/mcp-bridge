from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. `servers` contains server ids or '*'."""

    name: str
    servers: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    anonymous: bool = False
    # Ordered (pattern, action) pairs; first match wins; default=allow when empty.
    tool_rules: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    def can_use(self, server_id: str) -> bool:
        return "*" in self.servers or server_id in self.servers

    def can_use_tool(self, qualified_name: str) -> bool:
        """Return True if this principal may call *qualified_name*.

        Iterates ``tool_rules`` in order; the first matching pattern decides.
        Falls back to ``True`` (allow) when no rule matches, preserving
        backward compatibility with tokens that carry no rules.
        """
        for pattern, action in self.tool_rules:
            if fnmatch.fnmatchcase(qualified_name, pattern):
                return action == "allow"
        return True


ANONYMOUS = Principal(name="anonymous", servers=frozenset({"*"}), anonymous=True)
