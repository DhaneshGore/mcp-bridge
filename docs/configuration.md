# Configuration

The gateway reads one YAML file, optionally overridden by environment
variables. Validate any change with:

```bash
openmcp --config path/to/openmcp.yaml config validate
openmcp --config path/to/openmcp.yaml config show     # effective config as JSON
```

## Where configuration comes from

1. `--config PATH`, else `$OPENMCP_CONFIG`, else `./openmcp.yaml` or
   `./openmcp.yml`. With no file, built-in defaults are used (no servers).
2. Environment variables override the file. The variable name is
   `OPENMCP_` + the path in upper case, joined by `__`:

   | Setting | Environment variable |
   | --- | --- |
   | `gateway.port` | `OPENMCP_GATEWAY__PORT=9000` |
   | `auth.mode` | `OPENMCP_AUTH__MODE=bearer` |
   | `logging.format` | `OPENMCP_LOGGING__FORMAT=text` |

   Lists (such as `servers`) can be set this way only as JSON; prefer the file.
3. `openmcp serve --host/--port` override both.

Unknown keys are errors, so a typo cannot be silently ignored.

## Development vs production

There is one configuration schema; the difference is in values. Starting
points:

* [`examples/openmcp.yaml`](../examples/openmcp.yaml): local development,
  loopback only, no authentication.
* [`examples/production.yaml`](../examples/production.yaml): bearer tokens,
  non-loopback bind, Host allowlist, rate limits, SQLite registry.

The gateway refuses to start on a non-loopback address with `auth.mode: none`
unless you set `auth.allow_unauthenticated_non_loopback: true`.

## Secrets

* Client tokens are stored only as SHA-256 hashes (`openmcp token generate`).
* Values a server needs (API keys) belong in the gateway's environment and are
  referenced by name with `env_from_host` (stdio) or `headers_from_host`
  (HTTP). Referenced values are redacted from logs and captured stderr, and
  are never returned by the admin API or written to the SQLite registry.
* Literal `env:` and `headers:` values are stored and displayed as-is. Do not
  put secrets there.

## Reference

The tables below are generated from the code
(`python scripts/gen_config_reference.py`).

<!-- BEGIN GENERATED REFERENCE -->

### `gateway`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `str` | `"OpenMCP Gateway"` | Display name reported to MCP clients. |
| `host` | `str` | `"127.0.0.1"` | Bind address. Non-loopback requires authentication. |
| `port` | `int` | `8080` | Bind port. |
| `mcp_path` | `str` | `"/mcp"` | Path of the MCP endpoint. |
| `allowed_hosts` | `list[str]` | `[]` | Extra Host header values accepted on the MCP endpoint (DNS-rebinding protection). |
| `allowed_origins` | `list[str]` | `[]` | Extra Origin header values accepted on the MCP endpoint. |
| `trusted_proxies` | `list[str]` | `[]` | Proxy IPs whose X-Forwarded-* headers are honoured. Empty = honour none. |
| `ready_requires_all_servers` | `bool` | `False` | If true, /ready fails while any enabled autostart server is not ready. |

### `auth`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | `Literal['none', 'bearer', 'optional', 'jwt']` | `"none"` | none: anonymous MCP access; bearer: static token required; optional: static token validated when provided, anonymous otherwise; jwt: OIDC/JWT bearer token required. |
| `allow_unauthenticated_non_loopback` | `bool` | `False` | Permit mode=none/optional on a non-loopback bind. Dangerous; for trusted networks only. |
| `tokens` | `list[TokenConfig]` | `[]` | Client and admin tokens (see auth.tokens[]). |
| `jwt` | `JWTConfig \| None` | `None` | JWT/OIDC validation config. Required when mode=jwt. |
| `oauth` | `OAuthConfig \| None` | `None` | OAuth 2.1 protected resource metadata. Enables /.well-known/oauth-protected-resource. |

### `auth.tokens[]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `str` | **required** | Principal name, used in logs and session binding. |
| `sha256` | `str` | **required** | Hex SHA-256 of the token. Generate with `openmcp token generate`. |
| `servers` | `list[str]` | `['*']` | Server ids, or '*' for all. |
| `roles` | `list[Literal['admin', 'metrics']]` | `[]` | admin: full admin API; metrics: read /admin/metrics only. |
| `tool_rules` | `list[ToolRule]` | `[]` | Ordered allow/deny rules for qualified tool names (e.g. 'github__*'). First matching rule wins; default is allow when no rules match. |

### `admin`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `True` | Mount the /admin API (still requires an admin token). |
| `allow_stdio_registration` | `bool` | `False` | Allow registering stdio servers via the admin API (equivalent to code execution). |
| `audit_log_path` | `Path \| None` | `None` | Path to a JSON Lines audit log file. Each admin action is appended as one JSON object. Disabled when None (default). |

### `limits`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_request_body_bytes` | `int` | `4194304` | Largest client request body (larger: HTTP 413). |
| `max_upstream_message_bytes` | `int` | `16777216` | Largest single message accepted from an upstream. |
| `max_sessions` | `int` | `1000` | Concurrent MCP sessions (beyond: HTTP 503). |
| `session_idle_timeout` | `float` | `1800.0` | Seconds before an idle session expires. |
| `max_tools_per_server` | `int` | `5000` | Cap on items read from one upstream listing (tools, prompts, resources). |

### `rate_limits`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `per_principal_rps` | `float \| None` | `None` | Sustained requests/s per principal. |
| `per_principal_burst` | `int` | `20` | Requests a principal may make in a burst. |
| `global_rps` | `float \| None` | `None` | Sustained requests/s across all principals. |
| `global_burst` | `int` | `100` | Gateway-wide burst size. |

### `logging`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `level` | `Literal['debug', 'info', 'warning', 'error']` | `"info"` | Minimum log level. |
| `format` | `Literal['json', 'text']` | `"json"` | json for machines, text for humans. |
| `stderr_buffer_lines` | `int` | `200` | Captured stderr lines per server. |
| `stderr_line_bytes` | `int` | `2048` | Longer stderr lines are truncated. |

### `security`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_egress_networks` | `list[IPvAnyNetwork]` | `[]` | Non-public networks remote upstreams may reach (e.g. 10.20.0.0/16). |

### `storage`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `backend` | `Literal['memory', 'sqlite']` | `"memory"` | memory: lost on restart. |
| `path` | `Path` | `PosixPath('openmcp-registry.db')` | SQLite file (backend=sqlite). |

### `packages`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `False` | Enable package upload, storage and package servers. |
| `limits` | `PackageLimits` | (see section) | See `packages.limits`. |
| `allowed_extensions` | `list[str]` | `['.py', '.pyi', '.json', '.yaml', '.yml', '.toml', '.txt', '.md', '.rst', '.cfg', '.ini', '.csv', '.tsv', '.html', '.htm', '.css', '.xml', '.svg', '.jinja', '.jinja2', '.j2', '.tmpl', '.tpl', '.lock', '.typed']` | File extensions permitted inside packages (lower case, with dot). |
| `allowed_filenames` | `list[str]` | `['LICENSE', 'NOTICE', 'README', 'py.typed', 'requirements.lock']` | Extension-less file names permitted inside packages. |
| `artifacts` | `ArtifactStoreConfig` | (see section) | See `packages.artifacts`. |
| `catalog` | `CatalogConfig` | (see section) | See `packages.catalog`. |
| `cache_dir` | `Path` | `PosixPath('openmcp-data/cache')` | Verified artifacts and environments. |
| `runtime_dir` | `Path` | `PosixPath('openmcp-data/runtime')` | Per-instance runtime directories. |
| `allow_directory_registration` | `bool` | `False` | Allow registering a package from a local directory (trusted development only). |
| `directory_roots` | `list[Path]` | `[]` | Directories under which directory registration is allowed. |
| `dependencies` | `DependencyPolicy` | (see section) | See `packages.dependencies`. |
| `sandbox` | `SandboxConfig` | (see section) | See `packages.sandbox`. |
| `retention` | `RetentionPolicy` | (see section) | See `packages.retention`. |

### `packages.limits`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_archive_bytes` | `int` | `52428800` | Largest accepted ZIP upload. |
| `max_files` | `int` | `2000` | Maximum number of files in a package. |
| `max_extracted_bytes` | `int` | `209715200` | Maximum total size of all files after extraction. |
| `max_file_bytes` | `int` | `52428800` | Maximum size of one extracted file. |
| `max_compression_ratio` | `float` | `100.0` | Maximum uncompressed/compressed ratio, per file and overall (zip bombs). |
| `max_path_depth` | `int` | `16` | Maximum directory depth of a file path. |
| `max_path_length` | `int` | `255` | Maximum length of a file path in bytes. |

### `packages.artifacts`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `backend` | `Literal['local', 's3']` | `"local"` | local: a directory; s3: any S3-compatible object store. |
| `path` | `Path` | `PosixPath('openmcp-data/artifacts')` | Directory for backend=local. |
| `bucket` | `str \| None` | `None` | Bucket for backend=s3. |
| `prefix` | `str` | `"packages/"` | Key prefix for backend=s3. |
| `endpoint_url` | `str \| None` | `None` | S3 endpoint for non-AWS stores (MinIO, Ceph, ...). |
| `region` | `str \| None` | `None` | S3 region. |
| `access_key_id_env` | `str \| None` | `None` | Gateway env var holding the access key id (default: the AWS credential chain). |
| `secret_access_key_env` | `str \| None` | `None` | Gateway env var holding the secret key. |

### `packages.catalog`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `backend` | `Literal['sqlite', 'mongodb']` | `"sqlite"` | Where package metadata, versions and checksums are recorded. |
| `path` | `Path` | `PosixPath('openmcp-data/packages.db')` | SQLite file for backend=sqlite. |
| `mongodb_uri_env` | `str` | `"OPENMCP_MONGODB_URI"` | Gateway env var holding the MongoDB connection string. |
| `database` | `str` | `"openmcp"` | MongoDB database name. |
| `collection` | `str` | `"package_versions"` | MongoDB collection name. |

### `packages.dependencies`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `Literal['none', 'locked']` | `"locked"` | none: reject packages that declare dependencies; locked: require a hash-pinned lock file and install wheels only. |
| `index_url` | `str \| None` | `None` | Package index for installs (default: pip's default). |
| `find_links` | `list[Path]` | `[]` | Local wheel directories. |
| `no_index` | `bool` | `False` | Install only from find_links (offline). |
| `allowed_projects` | `list[str]` | `[]` | If non-empty, only these distribution names may be installed. |
| `install_timeout` | `float` | `300.0` | Seconds allowed for one environment install. |
| `inherit_gateway_packages` | `bool` | `True` | Expose the gateway's own installed packages (e.g. the MCP SDK) to package servers, after the package's locked dependencies. |

### `packages.sandbox`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `isolation` | `Literal['landlock', 'none']` | `"landlock"` | landlock: Linux kernel sandbox restricting each server to its own files (required unless set to none). |
| `extra_read_paths` | `list[Path]` | `[]` | Additional read-only paths visible to package servers. |
| `max_open_files` | `int` | `1024` | RLIMIT_NOFILE for package processes. |
| `max_file_size_bytes` | `int` | `1073741824` | RLIMIT_FSIZE: largest file a package process may write. |
| `max_memory_bytes` | `int \| None` | `None` | RLIMIT_AS (virtual memory) per package process; unset = no limit. |
| `max_cpu_seconds` | `int \| None` | `None` | RLIMIT_CPU: total CPU seconds per package process (it is killed beyond this). |
| `max_processes` | `int \| None` | `None` | RLIMIT_NPROC. Linux counts every process of the gateway's user; set it above that. |
| `block_unix_sockets` | `bool` | `True` | seccomp: deny creating AF_UNIX sockets (e.g. Docker socket); socketpair still works. |

### `packages.retention`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_delete` | `bool` | `True` | Allow deleting package versions through the admin API. |
| `keep_latest` | `int` | `0` | The newest N versions of each package can never be deleted. |

### `servers[] (all transports)`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `id` | `str` | **required** | Stable identifier; also the tool namespace prefix. |
| `description` | `str` | `""` | Free text shown in the admin API. |
| `enabled` | `bool` | `True` | Disabled servers are never started or listed. |
| `autostart` | `bool` | `True` | Start with the gateway and restart in the background; false = start on first use. |
| `timeouts` | `TimeoutConfig` | (see section) | See servers[].timeouts. |
| `max_concurrency` | `int` | `16` | Max in-flight requests to this server. |
| `max_queue` | `int` | `64` | Max requests waiting for a concurrency slot. |
| `queue_timeout` | `float` | `10.0` | Max seconds a request waits for a slot. |
| `restart` | `RestartPolicy` | (see section) | See servers[].restart. |
| `tools` | `ToolFilter` | (see section) | See servers[].tools. |

### `servers[] with transport: stdio (default)`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `env` | `dict[str, str]` | `{}` | Literal environment values. |
| `env_from_host` | `dict[str, str]` | `{}` | Child variable -> gateway environment variable. Values are treated as secrets. |
| `inherit_env` | `list[str]` | `[]` | Extra gateway variables to pass through. |
| `transport` | `Literal['stdio']` | `"stdio"` | Local subprocess speaking MCP over stdio. |
| `command` | `str` | **required** | Executable name or path. Never run through a shell. |
| `args` | `list[str]` | `[]` | Arguments, passed verbatim (no shell). |
| `cwd` | `Path \| None` | `None` | Working directory for the process. |

### `servers[] with transport: http`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `transport` | `Literal['http']` | **required** | Remote server over Streamable HTTP. |
| `url` | `str` | **required** | Streamable HTTP endpoint, e.g. https://mcp.example.com/mcp |
| `headers` | `dict[str, str]` | `{}` | Non-secret headers sent upstream. |
| `headers_from_host` | `dict[str, str]` | `{}` | Header -> gateway environment variable holding its value (e.g. Authorization). Secret. |
| `protocol` | `Literal['auto', 'legacy']` | `"auto"` | auto: prefer 2026-07-28 and fall back to the initialize handshake. |
| `allow_private_network` | `bool` | `False` | Permit loopback/private/link-local destinations. Only for trusted internal deployments. |
| `allow_insecure_http` | `bool` | `False` | Permit plain http:// URLs. |
| `verify_tls` | `bool` | `True` | Verify the upstream TLS certificate. |

### `servers[] with transport: package`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `env` | `dict[str, str]` | `{}` | Literal environment values. |
| `env_from_host` | `dict[str, str]` | `{}` | Child variable -> gateway environment variable. Values are treated as secrets. |
| `inherit_env` | `list[str]` | `[]` | Extra gateway variables to pass through. |
| `transport` | `Literal['package']` | **required** | Run an uploaded MCP server package version. |
| `package` | `str` | **required** | Package name (from its metadata.json). |
| `version` | `str` | **required** | Exact package version to run; versions are immutable. |
| `args` | `list[str]` | `[]` | Extra arguments appended to the package's declared args. |
| `network` | `Literal['allow', 'deny']` | `"allow"` | deny: block all outbound/inbound TCP for this server (Landlock). |

### `servers[].timeouts`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `startup` | `float` | `30.0` | Seconds allowed for spawn + initialize. |
| `request` | `float` | `60.0` | Default per-request timeout. |
| `shutdown` | `float` | `5.0` | Grace period per shutdown stage. |

### `servers[].restart`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `Literal['on-failure', 'never']` | `"on-failure"` | Restart after failures? |
| `max_restarts` | `int` | `5` | Failures tolerated within `window`. |
| `window` | `float` | `300.0` | Sliding window (seconds) for counting failures. |
| `backoff_initial` | `float` | `1.0` | First retry delay (seconds); doubles each failure. |
| `backoff_max` | `float` | `60.0` | Upper bound for the retry delay. |

### `servers[].tools`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow` | `list[str]` | `[]` | If non-empty, only matching tools are exposed. |
| `deny` | `list[str]` | `[]` | Matching tools are never exposed. |

<!-- END GENERATED REFERENCE -->
