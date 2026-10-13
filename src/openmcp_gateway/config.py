"""Configuration models, loading and validation.

Configuration comes from (highest precedence first):

1. Environment variables prefixed ``OPENMCP_`` with ``__`` as the nesting
   delimiter, e.g. ``OPENMCP_GATEWAY__PORT=9000``.
2. A YAML file (``--config``, ``$OPENMCP_CONFIG`` or ``./openmcp.yaml``).
3. Built-in defaults, which are safe for local development.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    IPvAnyNetwork,
    Tag,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from openmcp_gateway import PROJECT_NAME

SERVER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PRINCIPAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_CONFIG_FILENAMES = ("openmcp.yaml", "openmcp.yml")
ENV_PREFIX = "OPENMCP_"


class ConfigError(Exception):
    """Raised when configuration cannot be loaded or is invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimeoutConfig(_Strict):
    startup: float = Field(30.0, gt=0, le=600, description="Seconds allowed for spawn + initialize.")
    request: float = Field(60.0, gt=0, le=3600, description="Default per-request timeout.")
    shutdown: float = Field(5.0, gt=0, le=120, description="Grace period per shutdown stage.")


class RestartPolicy(_Strict):
    policy: Literal["on-failure", "never"] = Field("on-failure", description="Restart after failures?")
    max_restarts: int = Field(5, ge=0, le=1000, description="Failures tolerated within `window`.")
    window: float = Field(300.0, gt=0, description="Sliding window (seconds) for counting failures.")
    backoff_initial: float = Field(
        1.0, gt=0, description="First retry delay (seconds); doubles each failure."
    )
    backoff_max: float = Field(60.0, gt=0, description="Upper bound for the retry delay.")

    @model_validator(mode="after")
    def _check_backoff(self) -> RestartPolicy:
        if self.backoff_max < self.backoff_initial:
            raise ValueError("restart.backoff_max must be >= restart.backoff_initial")
        return self


class ToolFilter(_Strict):
    """Glob patterns (fnmatch) over the upstream's own tool names."""

    allow: list[str] = Field(
        default_factory=list, description="If non-empty, only matching tools are exposed."
    )
    deny: list[str] = Field(default_factory=list, description="Matching tools are never exposed.")


class _ServerBase(_Strict):
    """Fields shared by every upstream transport."""

    id: str = Field(description="Stable identifier; also the tool namespace prefix.")
    description: str = Field("", description="Free text shown in the admin API.")
    enabled: bool = Field(True, description="Disabled servers are never started or listed.")
    autostart: bool = Field(
        True, description="Start with the gateway and restart in the background; false = start on first use."
    )

    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig, description="See servers[].timeouts.")
    max_concurrency: int = Field(16, ge=1, le=1024, description="Max in-flight requests to this server.")
    max_queue: int = Field(64, ge=0, le=100_000, description="Max requests waiting for a concurrency slot.")
    queue_timeout: float = Field(10.0, gt=0, le=600, description="Max seconds a request waits for a slot.")
    restart: RestartPolicy = Field(default_factory=RestartPolicy, description="See servers[].restart.")
    tools: ToolFilter = Field(default_factory=ToolFilter, description="See servers[].tools.")

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not SERVER_ID_RE.match(v):
            raise ValueError(
                "server id must match ^[a-z0-9][a-z0-9-]{0,47}$ (lowercase letters, digits, '-'; no '_')"
            )
        return v


class _ProcessEnv(_Strict):
    """Environment settings shared by transports that launch a local process."""

    env: dict[str, str] = Field(default_factory=dict, description="Literal environment values.")
    env_from_host: dict[str, str] = Field(
        default_factory=dict,
        description="Child variable -> gateway environment variable. Values are treated as secrets.",
    )
    inherit_env: list[str] = Field(
        default_factory=list, description="Extra gateway variables to pass through."
    )

    @field_validator("env", "env_from_host")
    @classmethod
    def _check_env_keys(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            if not ENV_NAME_RE.match(key):
                raise ValueError(f"invalid environment variable name: {key!r}")
            if "\x00" in value:
                raise ValueError(f"NUL byte in environment value for {key!r}")
        return v

    @field_validator("inherit_env")
    @classmethod
    def _check_inherit(cls, v: list[str]) -> list[str]:
        for key in v:
            if not ENV_NAME_RE.match(key):
                raise ValueError(f"invalid environment variable name: {key!r}")
        return v


class StdioServerConfig(_ServerBase, _ProcessEnv):
    transport: Literal["stdio"] = Field("stdio", description="Local subprocess speaking MCP over stdio.")
    command: str = Field(min_length=1, description="Executable name or path. Never run through a shell.")
    args: list[str] = Field(default_factory=list, description="Arguments, passed verbatim (no shell).")
    cwd: Path | None = Field(None, description="Working directory for the process.")

    @field_validator("command", "args")
    @classmethod
    def _no_nul(cls, v: str | list[str]) -> str | list[str]:
        items = [v] if isinstance(v, str) else v
        if any("\x00" in s for s in items):
            raise ValueError("NUL bytes are not allowed in command or args")
        return v


PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PACKAGE_VERSION_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class PackageServerConfig(_ServerBase, _ProcessEnv):
    """A registered multi-file package, run in an isolated runtime directory."""

    transport: Literal["package"] = Field(description="Run an uploaded MCP server package version.")
    package: str = Field(description="Package name (from its metadata.json).")
    version: str = Field(description="Exact package version to run; versions are immutable.")
    args: list[str] = Field(
        default_factory=list, description="Extra arguments appended to the package's declared args."
    )
    network: Literal["allow", "deny"] = Field(
        "allow", description="deny: block all outbound/inbound TCP for this server (Landlock)."
    )

    @field_validator("package")
    @classmethod
    def _check_package(cls, v: str) -> str:
        if not PACKAGE_NAME_RE.match(v):
            raise ValueError("package must match ^[a-z0-9][a-z0-9-]{0,63}$")
        return v

    @field_validator("version")
    @classmethod
    def _check_version(cls, v: str) -> str:
        if not PACKAGE_VERSION_RE.match(v):
            raise ValueError("version must be an exact semantic version such as 1.2.0")
        return v

    @field_validator("args")
    @classmethod
    def _no_nul(cls, v: list[str]) -> list[str]:
        if any("\x00" in s for s in v):
            raise ValueError("NUL bytes are not allowed in args")
        return v


HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_RESERVED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "accept",
        "connection",
        "transfer-encoding",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
    }
)


class HttpServerConfig(_ServerBase):
    """A remote MCP server reached over Streamable HTTP."""

    transport: Literal["http"] = Field(description="Remote server over Streamable HTTP.")
    url: str = Field(description="Streamable HTTP endpoint, e.g. https://mcp.example.com/mcp")
    headers: dict[str, str] = Field(default_factory=dict, description="Non-secret headers sent upstream.")
    headers_from_host: dict[str, str] = Field(
        default_factory=dict,
        description="Header -> gateway environment variable holding its value (e.g. Authorization). Secret.",
    )
    protocol: Literal["auto", "legacy"] = Field(
        "auto", description="auto: prefer 2026-07-28 and fall back to the initialize handshake."
    )
    allow_private_network: bool = Field(
        False,
        description="Permit loopback/private/link-local destinations. Only for trusted internal deployments.",
    )
    allow_insecure_http: bool = Field(False, description="Permit plain http:// URLs.")
    verify_tls: bool = Field(True, description="Verify the upstream TLS certificate.")

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(v)
        if parts.scheme not in ("http", "https"):
            raise ValueError("url must use http or https")
        if not parts.hostname:
            raise ValueError("url must include a host")
        if parts.username or parts.password:
            raise ValueError("credentials in the url are not allowed; use headers_from_host")
        if parts.fragment:
            raise ValueError("url must not contain a fragment")
        return v

    @field_validator("headers", "headers_from_host")
    @classmethod
    def _check_headers(cls, v: dict[str, str]) -> dict[str, str]:
        for name, value in v.items():
            if not HEADER_NAME_RE.match(name):
                raise ValueError(f"invalid header name: {name!r}")
            if name.lower() in _RESERVED_HEADERS:
                raise ValueError(f"header {name!r} is managed by the gateway and cannot be set")
            if any(c in value for c in "\r\n\x00"):
                raise ValueError(f"invalid characters in header {name!r}")
        return v

    @model_validator(mode="after")
    def _check_scheme(self) -> HttpServerConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// requires allow_insecure_http: true")
        for env_name in self.headers_from_host.values():
            if not ENV_NAME_RE.match(env_name):
                raise ValueError(f"invalid environment variable name: {env_name!r}")
        return self


def _server_discriminator(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("transport", "stdio"))
    return str(getattr(value, "transport", "stdio"))


ServerConfig = Annotated[
    Annotated[StdioServerConfig, Tag("stdio")]
    | Annotated[HttpServerConfig, Tag("http")]
    | Annotated[PackageServerConfig, Tag("package")],
    Discriminator(_server_discriminator),
]
AnyServerConfig = StdioServerConfig | HttpServerConfig | PackageServerConfig


class HttpConfig(_Strict):
    name: str = Field(PROJECT_NAME, description="Display name reported to MCP clients.")
    host: str = Field("127.0.0.1", description="Bind address. Non-loopback requires authentication.")
    port: int = Field(8080, ge=0, le=65535, description="Bind port.")
    mcp_path: str = Field("/mcp", pattern=r"^/[A-Za-z0-9/_-]*$", description="Path of the MCP endpoint.")
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Extra Host header values accepted on the MCP endpoint (DNS-rebinding protection).",
    )
    allowed_origins: list[str] = Field(
        default_factory=list, description="Extra Origin header values accepted on the MCP endpoint."
    )
    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="Proxy IPs whose X-Forwarded-* headers are honoured. Empty = honour none.",
    )
    ready_requires_all_servers: bool = Field(
        False, description="If true, /ready fails while any enabled autostart server is not ready."
    )

    @field_validator("mcp_path")
    @classmethod
    def _check_mcp_path(cls, v: str) -> str:
        reserved = ("/admin", "/health", "/ready", "/version", "/openapi.json", "/.well-known")
        if v == "/" or any(v == r or v.startswith(r + "/") for r in reserved):
            raise ValueError(f"mcp_path must not be '/' or overlap the built-in routes {', '.join(reserved)}")
        return v

    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)


class LoggingConfig(_Strict):
    level: Literal["debug", "info", "warning", "error"] = Field("info", description="Minimum log level.")
    format: Literal["json", "text"] = Field("json", description="json for machines, text for humans.")
    stderr_buffer_lines: int = Field(200, ge=0, le=100_000, description="Captured stderr lines per server.")
    stderr_line_bytes: int = Field(
        2048, ge=64, le=1_048_576, description="Longer stderr lines are truncated."
    )


class LimitsConfig(_Strict):
    max_request_body_bytes: int = Field(
        4 * 1024 * 1024, ge=1024, description="Largest client request body (larger: HTTP 413)."
    )
    max_upstream_message_bytes: int = Field(
        16 * 1024 * 1024, ge=1024, description="Largest single message accepted from an upstream."
    )
    max_sessions: int = Field(1000, ge=1, description="Concurrent MCP sessions (beyond: HTTP 503).")
    session_idle_timeout: float = Field(1800.0, gt=0, description="Seconds before an idle session expires.")
    max_tools_per_server: int = Field(
        5000, ge=1, description="Cap on items read from one upstream listing (tools, prompts, resources)."
    )


class ToolRule(_Strict):
    """Glob-based allow/deny rule applied to a fully-qualified tool name (e.g. ``github__*``)."""

    pattern: str = Field(description="fnmatch glob matched against the qualified tool name.")
    action: Literal["allow", "deny"] = Field(description="What to do when the pattern matches.")

    @field_validator("pattern")
    @classmethod
    def _check_pattern(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool rule pattern must not be empty")
        return v


class TokenConfig(_Strict):
    name: str = Field(description="Principal name, used in logs and session binding.")
    sha256: str = Field(description="Hex SHA-256 of the token. Generate with `openmcp token generate`.")
    servers: list[str] = Field(default_factory=lambda: ["*"], description="Server ids, or '*' for all.")
    roles: list[Literal["admin", "metrics"]] = Field(
        default_factory=list, description="admin: full admin API; metrics: read /admin/metrics only."
    )
    tool_rules: list[ToolRule] = Field(
        default_factory=list,
        description=(
            "Ordered allow/deny rules for qualified tool names (e.g. 'github__*'). "
            "First matching rule wins; default is allow when no rules match."
        ),
    )

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not PRINCIPAL_NAME_RE.match(v):
            raise ValueError("token name must match ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
        return v

    @field_validator("sha256")
    @classmethod
    def _check_hash(cls, v: str) -> str:
        v = v.lower()
        if not SHA256_HEX_RE.match(v):
            raise ValueError("sha256 must be 64 hex characters (the hash, never the token itself)")
        return v


class JWTConfig(_Strict):
    """Configuration for JWT/OIDC bearer-token validation (auth.mode: jwt)."""

    jwks_url: str | None = Field(
        None,
        description="URL of the JWKS endpoint (mutually exclusive with inline_jwks).",
    )
    inline_jwks: dict[str, Any] | None = Field(
        None,
        description="Literal JWKS object (for air-gapped deployments or tests).",
    )
    issuer: str | None = Field(None, description="Expected value of the 'iss' claim; None skips the check.")
    audience: str | None = Field(None, description="Expected value of the 'aud' claim; None skips the check.")
    algorithms: list[str] = Field(
        default_factory=lambda: ["RS256", "ES256"],
        description="Allowed signing algorithms.",
    )
    principal_claim: str = Field("sub", description="JWT claim used as the Principal name.")
    roles_claim: str | None = Field(
        None,
        description="JWT claim containing a list of role strings (mapped to Principal.roles).",
    )
    jwks_refresh_interval: float = Field(
        3600.0,
        gt=0,
        description="Seconds between background JWKS refreshes.",
    )

    @model_validator(mode="after")
    def _check_jwks_source(self) -> JWTConfig:
        if self.jwks_url is None and self.inline_jwks is None:
            raise ValueError("jwt config requires either jwks_url or inline_jwks")
        if self.jwks_url is not None and self.inline_jwks is not None:
            raise ValueError("jwt config accepts jwks_url or inline_jwks, not both")
        return self


class OAuthConfig(_Strict):
    """Metadata for RFC 8707 OAuth 2.1 Protected Resource discovery."""

    authorization_server_url: str | None = Field(
        None,
        description="URL of the authorization server (included in the well-known metadata).",
    )
    resource: str | None = Field(
        None,
        description=(
            "Resource identifier URI. Defaults to the gateway's own base URL when None."
        ),
    )
    scopes_supported: list[str] = Field(
        default_factory=list,
        description="Scopes advertised in the well-known metadata.",
    )


class AuthConfig(_Strict):
    mode: Literal["none", "bearer", "optional", "jwt"] = Field(
        "none",
        description=(
            "none: anonymous MCP access; bearer: static token required; "
            "optional: static token validated when provided, anonymous otherwise; "
            "jwt: OIDC/JWT bearer token required."
        ),
    )
    allow_unauthenticated_non_loopback: bool = Field(
        False, description="Permit mode=none/optional on a non-loopback bind. Dangerous; for trusted networks only."
    )
    tokens: list[TokenConfig] = Field(
        default_factory=list, description="Client and admin tokens (see auth.tokens[])."
    )
    jwt: JWTConfig | None = Field(
        None,
        description="JWT/OIDC validation config. Required when mode=jwt.",
    )
    oauth: OAuthConfig | None = Field(
        None,
        description="OAuth 2.1 protected resource metadata. Enables /.well-known/oauth-protected-resource.",
    )

    @model_validator(mode="after")
    def _check_tokens(self) -> AuthConfig:
        names = [t.name for t in self.tokens]
        if len(names) != len(set(names)):
            raise ValueError("token names must be unique")
        hashes = [t.sha256 for t in self.tokens]
        if len(hashes) != len(set(hashes)):
            raise ValueError("token hashes must be unique")
        if self.mode == "bearer" and not self.tokens:
            raise ValueError("auth.mode=bearer requires at least one token")
        if self.mode == "jwt" and self.jwt is None:
            raise ValueError("auth.mode=jwt requires an auth.jwt configuration block")
        return self


class RateLimitConfig(_Strict):
    """Token buckets per gateway process (not shared across replicas)."""

    per_principal_rps: float | None = Field(None, gt=0, description="Sustained requests/s per principal.")
    per_principal_burst: int = Field(20, ge=1, description="Requests a principal may make in a burst.")
    global_rps: float | None = Field(None, gt=0, description="Sustained requests/s across all principals.")
    global_burst: int = Field(100, ge=1, description="Gateway-wide burst size.")


class SecurityConfig(_Strict):
    allowed_egress_networks: list[IPvAnyNetwork] = Field(
        default_factory=list,
        description="Non-public networks remote upstreams may reach (e.g. 10.20.0.0/16).",
    )


class StorageConfig(_Strict):
    """Where servers registered via the admin API are kept."""

    backend: Literal["memory", "sqlite"] = Field("memory", description="memory: lost on restart.")
    path: Path = Field(Path("openmcp-registry.db"), description="SQLite file (backend=sqlite).")


class PackageLimits(_Strict):
    max_archive_bytes: int = Field(50 * 1024 * 1024, ge=1024, description="Largest accepted ZIP upload.")
    max_files: int = Field(2000, ge=1, description="Maximum number of files in a package.")
    max_extracted_bytes: int = Field(
        200 * 1024 * 1024, ge=1024, description="Maximum total size of all files after extraction."
    )
    max_file_bytes: int = Field(50 * 1024 * 1024, ge=1, description="Maximum size of one extracted file.")
    max_compression_ratio: float = Field(
        100.0, ge=1, description="Maximum uncompressed/compressed ratio, per file and overall (zip bombs)."
    )
    max_path_depth: int = Field(16, ge=1, description="Maximum directory depth of a file path.")
    max_path_length: int = Field(255, ge=16, description="Maximum length of a file path in bytes.")


DEFAULT_PACKAGE_EXTENSIONS = (
    ".py",
    ".pyi",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".md",
    ".rst",
    ".cfg",
    ".ini",
    ".csv",
    ".tsv",
    ".html",
    ".htm",
    ".css",
    ".xml",
    ".svg",
    ".jinja",
    ".jinja2",
    ".j2",
    ".tmpl",
    ".tpl",
    ".lock",
    ".typed",
)
DEFAULT_PACKAGE_FILENAMES = ("LICENSE", "NOTICE", "README", "py.typed", "requirements.lock")


class ArtifactStoreConfig(_Strict):
    backend: Literal["local", "s3"] = Field(
        "local", description="local: a directory; s3: any S3-compatible object store."
    )
    path: Path = Field(Path("openmcp-data/artifacts"), description="Directory for backend=local.")
    bucket: str | None = Field(None, description="Bucket for backend=s3.")
    prefix: str = Field("packages/", description="Key prefix for backend=s3.")
    endpoint_url: str | None = Field(None, description="S3 endpoint for non-AWS stores (MinIO, Ceph, ...).")
    region: str | None = Field(None, description="S3 region.")
    access_key_id_env: str | None = Field(
        None, description="Gateway env var holding the access key id (default: the AWS credential chain)."
    )
    secret_access_key_env: str | None = Field(None, description="Gateway env var holding the secret key.")

    @model_validator(mode="after")
    def _check(self) -> ArtifactStoreConfig:
        if self.backend == "s3" and not self.bucket:
            raise ValueError("packages.artifacts.bucket is required for backend=s3")
        return self


class CatalogConfig(_Strict):
    backend: Literal["sqlite", "mongodb"] = Field(
        "sqlite", description="Where package metadata, versions and checksums are recorded."
    )
    path: Path = Field(Path("openmcp-data/packages.db"), description="SQLite file for backend=sqlite.")
    mongodb_uri_env: str = Field(
        "OPENMCP_MONGODB_URI", description="Gateway env var holding the MongoDB connection string."
    )
    database: str = Field("openmcp", description="MongoDB database name.")
    collection: str = Field("package_versions", description="MongoDB collection name.")


class DependencyPolicy(_Strict):
    policy: Literal["none", "locked"] = Field(
        "locked",
        description="none: reject packages that declare dependencies; locked: require a hash-pinned lock "
        "file and install wheels only.",
    )
    index_url: str | None = Field(None, description="Package index for installs (default: pip's default).")
    find_links: list[Path] = Field(default_factory=list, description="Local wheel directories.")
    no_index: bool = Field(False, description="Install only from find_links (offline).")
    allowed_projects: list[str] = Field(
        default_factory=list, description="If non-empty, only these distribution names may be installed."
    )
    install_timeout: float = Field(300.0, gt=0, description="Seconds allowed for one environment install.")
    inherit_gateway_packages: bool = Field(
        True,
        description="Expose the gateway's own installed packages (e.g. the MCP SDK) to package servers, "
        "after the package's locked dependencies.",
    )


class SandboxConfig(_Strict):
    isolation: Literal["landlock", "none"] = Field(
        "landlock",
        description="landlock: Linux kernel sandbox restricting each server to its own files (required "
        "unless set to none).",
    )
    extra_read_paths: list[Path] = Field(
        default_factory=list, description="Additional read-only paths visible to package servers."
    )
    max_open_files: int = Field(1024, ge=16, description="RLIMIT_NOFILE for package processes.")
    max_file_size_bytes: int = Field(
        1024 * 1024 * 1024, ge=1024, description="RLIMIT_FSIZE: largest file a package process may write."
    )
    max_memory_bytes: int | None = Field(
        None,
        ge=64 * 1024 * 1024,
        description="RLIMIT_AS (virtual memory) per package process; unset = no limit.",
    )
    max_cpu_seconds: int | None = Field(
        None,
        ge=1,
        description="RLIMIT_CPU: total CPU seconds per package process (it is killed beyond this).",
    )
    max_processes: int | None = Field(
        None,
        ge=1,
        description="RLIMIT_NPROC. Linux counts every process of the gateway's user; set it above that.",
    )
    block_unix_sockets: bool = Field(
        True,
        description="seccomp: deny creating AF_UNIX sockets (e.g. Docker socket); socketpair still works.",
    )


class RetentionPolicy(_Strict):
    allow_delete: bool = Field(True, description="Allow deleting package versions through the admin API.")
    keep_latest: int = Field(
        0, ge=0, description="The newest N versions of each package can never be deleted."
    )


class PackagesConfig(_Strict):
    enabled: bool = Field(False, description="Enable package upload, storage and package servers.")
    limits: PackageLimits = Field(default_factory=PackageLimits)
    allowed_extensions: list[str] = Field(
        default_factory=lambda: list(DEFAULT_PACKAGE_EXTENSIONS),
        description="File extensions permitted inside packages (lower case, with dot).",
    )
    allowed_filenames: list[str] = Field(
        default_factory=lambda: list(DEFAULT_PACKAGE_FILENAMES),
        description="Extension-less file names permitted inside packages.",
    )
    artifacts: ArtifactStoreConfig = Field(default_factory=ArtifactStoreConfig)
    catalog: CatalogConfig = Field(default_factory=CatalogConfig)
    cache_dir: Path = Field(Path("openmcp-data/cache"), description="Verified artifacts and environments.")
    runtime_dir: Path = Field(Path("openmcp-data/runtime"), description="Per-instance runtime directories.")
    allow_directory_registration: bool = Field(
        False, description="Allow registering a package from a local directory (trusted development only)."
    )
    directory_roots: list[Path] = Field(
        default_factory=list, description="Directories under which directory registration is allowed."
    )
    dependencies: DependencyPolicy = Field(default_factory=DependencyPolicy)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    retention: RetentionPolicy = Field(default_factory=RetentionPolicy)

    @field_validator("allowed_extensions")
    @classmethod
    def _check_ext(cls, v: list[str]) -> list[str]:
        out = []
        for ext in v:
            if not re.match(r"^\.[a-z0-9]{1,16}$", ext):
                raise ValueError(f"invalid extension {ext!r} (expected lower case like '.json')")
            if ext in (
                ".so",
                ".pyd",
                ".dll",
                ".dylib",
                ".exe",
                ".pyc",
                ".pyo",
                ".sh",
                ".bat",
                ".cmd",
                ".pth",
            ):
                raise ValueError(f"extension {ext!r} is executable or loader-related and cannot be allowed")
            out.append(ext)
        return out


class AdminConfig(_Strict):
    enabled: bool = Field(True, description="Mount the /admin API (still requires an admin token).")
    allow_stdio_registration: bool = Field(
        False,
        description="Allow registering stdio servers via the admin API (equivalent to code execution).",
    )
    audit_log_path: Path | None = Field(
        None,
        description=(
            "Path to a JSON Lines audit log file. Each admin action is appended as one JSON object. "
            "Disabled when None (default)."
        ),
    )


class TelemetryConfig(_Strict):
    """Optional OpenTelemetry tracing configuration."""

    otel_endpoint: str | None = Field(
        None,
        description=(
            "OTLP HTTP endpoint for span export (e.g. http://otel-collector:4318). "
            "Tracing is disabled when None (default)."
        ),
    )
    service_name: str = Field("openmcp-gateway", description="Service name reported in traces.")
    sample_rate: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Fraction of traces to sample (1.0 = all, 0.0 = none).",
    )


class GatewayConfig(BaseSettings):
    """Root configuration object."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        extra="forbid",
        # Only nested sections are overridable from the environment; this keeps
        # unrelated OPENMCP_* variables (like OPENMCP_CONFIG) from colliding.
        env_ignore_empty=True,
    )

    gateway: HttpConfig = Field(default_factory=HttpConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    admin: AdminConfig = Field(default_factory=AdminConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    packages: PackagesConfig = Field(default_factory=PackagesConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    servers: list[ServerConfig] = Field(default_factory=list)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Environment overrides the file (passed as init kwargs); no .env files.
        return (env_settings, init_settings)

    @model_validator(mode="after")
    def _cross_checks(self) -> GatewayConfig:
        if not self.packages.enabled and any(isinstance(s, PackageServerConfig) for s in self.servers):
            raise ValueError("servers with transport: package require packages.enabled: true")
        ids = [s.id for s in self.servers]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate server ids: {', '.join(dupes)}")
        if (
            self.auth.mode in ("none", "optional")
            and not self.gateway.is_loopback()
            and not self.auth.allow_unauthenticated_non_loopback
        ):
            raise ValueError(
                f"refusing to listen on non-loopback address {self.gateway.host!r} without authentication; "
                "set auth.mode=bearer (recommended) or auth.allow_unauthenticated_non_loopback=true"
            )
        return self

    def server(self, server_id: str) -> AnyServerConfig | None:
        return next((s for s in self.servers if s.id == server_id), None)

    def warnings(self) -> list[str]:
        """Non-fatal problems worth surfacing in `config validate` and `doctor`."""
        out: list[str] = []
        known = {s.id for s in self.servers}
        for tok in self.auth.tokens:
            for sid in tok.servers:
                if sid != "*" and sid not in known:
                    out.append(f"token {tok.name!r} references unknown server {sid!r}")
        if self.auth.mode in ("none", "optional") and self.auth.allow_unauthenticated_non_loopback:
            out.append("authentication is disabled on a non-loopback address")
        if self.auth.mode == "none" and self.auth.tokens:
            out.append(
                "auth.tokens are ignored for MCP traffic because auth.mode=none (admin still uses them)"
            )
        if not self.gateway.is_loopback() and not self.gateway.allowed_hosts:
            out.append(
                "gateway.allowed_hosts is empty on a non-loopback bind; Host/Origin validation on the MCP "
                "endpoint is disabled"
            )
        for srv in self.servers:
            if isinstance(srv, HttpServerConfig) and srv.allow_private_network:
                out.append(f"server {srv.id!r} may connect to private/loopback addresses")
        if self.packages.enabled and self.packages.sandbox.isolation == "none":
            out.append("package servers run without filesystem isolation (packages.sandbox.isolation=none)")
        if self.packages.enabled and self.auth.mode == "none":
            out.append(
                "packages are enabled while MCP access is unauthenticated: any package server with network "
                "access can call every other server's tools through this gateway's loopback endpoint; "
                "use auth.mode=bearer or network: deny"
            )
        if self.packages.allow_directory_registration:
            out.append("directory registration is enabled; use only for trusted local development")
        if self.admin.allow_stdio_registration:
            out.append("admin.allow_stdio_registration=true lets admin-token holders run arbitrary commands")
        return out


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_config_path(explicit: str | os.PathLike[str] | None) -> Path | None:
    """Return the config file to load, or None to run on defaults."""
    if explicit:
        return Path(explicit)
    from_env = os.environ.get("OPENMCP_CONFIG")
    if from_env:
        return Path(from_env)
    for name in DEFAULT_CONFIG_FILENAMES:
        candidate = Path(name)
        if candidate.is_file():
            return candidate
    return None


def load_config(path: str | os.PathLike[str] | None = None) -> GatewayConfig:
    """Load and validate configuration. Raises ConfigError with a readable message."""
    resolved = resolve_config_path(path)
    data: dict[str, Any] = {}
    if resolved is not None:
        try:
            raw = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config file {resolved}: {exc.strerror}") from exc
        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {resolved}: {exc}") from exc
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ConfigError(f"{resolved}: top level must be a mapping")
        data = loaded
    try:
        return GatewayConfig(**data)
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, resolved)) from None


def format_validation_error(exc: ValidationError, source: Path | None) -> str:
    where = str(source) if source else "configuration"
    lines = [f"invalid {where}:"]
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        msg = err["msg"].removeprefix("Value error, ")
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)
