# Running an Efferian Hub

## Initialize and serve

Build the Hub with `make build app=hub`. Put the resulting `efferian-hub` executable on your `PATH` for the commands below. A new installation needs a state directory and an initial human administrator.

```sh
efferian-hub init --state-dir ./hub-state --admin-token-out ./hub-admin.token
efferian-hub serve --state-dir ./hub-state
```

The default administrator name is `admin`. Serve listens on `127.0.0.1:8080` by default. Serve and offline administration take an exclusive `hub.lock` and require an existing database and matching master key. The state directory is private (`0700`). Init creates the key and token file with mode `0600`. The Hub also accepts an existing owner-only key with mode `0400`. Keep the token and master key in protected storage.

Omit `--admin-token-out` or pass `-` to receive the initial token on stdout exactly once. Output files use a new path in an existing writable, operator-controlled directory. The Hub reserves a private temporary file there before issuing a token. It rejects output paths inside its initialization staging directory. If initialization reports that the database was published but token delivery failed, stop any running Hub and use offline token recovery. A failed initialization can leave the master key on disk. Inspect the database and key together before retrying.

`GET /v1/health` returns a minimal liveness response. `GET /v1/info` reports the Hub ID and version. `GET /v1/openapi.json` describes the routes and credentials. The current identity and token scope are available at `GET /v1/me` with an API bearer in the `Authorization` header. An unrestricted human Admin with a global admin grant can use `GET /v1/admin/status`.

## Configure access

Serve accepts an optional `--config PATH` to read a flat TOML file. Offline token recovery accepts the same file, including the SQLite page budget. Command flags take precedence over environment variables, then TOML, then defaults. Each TOML key has an environment variable consisting of `EFFERIAN_HUB_` followed by the uppercase key. Host, origin, and egress CIDR lists (`allowed_hosts`, `allowed_origins`, `allowed_egress_cidrs`) use TOML arrays or comma-separated values with no empty elements or whitespace around each element in the environment and flags.

| Setting | Default | Flag where available |
| --- | --- | --- |
| `state_dir` | Required | `--state-dir` |
| `listen` | `127.0.0.1:8080` | `--listen` |
| `allowed_hosts` | Loopback authorities for the bound port | `--allowed-hosts` |
| `allowed_origins` | `[]` | `--allowed-origins` |
| `max_active_tokens_per_principal` | `64` | `--max-active-tokens-per-principal` |
| `sqlite_synchronous` | `full` | |
| `max_page_count` | `1048576` | |
| `allowed_egress_cidrs` | `[]` | |
| `allow_insecure_http_egress` | `false` | |
| `max_tcp_connections` | `2048` | |
| `max_pre_auth_in_flight` | `128` | |
| `max_app_requests` | `1024` | |
| `max_requests_per_principal` | `64` | |
| `max_control_requests` | `64` | |
| `max_runtime_ms` | `300000` | |
| `upstream_hard_timeout_ms` | `300000` | |
| `deadline_grace_ms` | `30000` (min `30000`) | |
| `max_node_concurrent_executions` | `64` | |
| `max_concurrent_waiters` | `512` | |
| `max_concurrent_waiters_per_principal` | `32` | |
| `max_event_streams` | `256` | |
| `max_event_streams_per_principal` | `8` | |
| `max_concurrent_upstream_executions` | `256` | |
| `max_concurrent_upstream_executions_per_upstream` | `32` | |
| `max_concurrent_upstream_executions_per_principal` | `16` | |
| `max_managed_agents_per_member` | `16` | |
| `max_managed_agents_per_orchestrator` | `256` | |
| `max_active_nodes_per_orchestrator` | `256` | |
| `max_pending_enrollments_per_issuer` | `64` | |
| `orchestrator_agent_token_ttl_ms` | `86400000` (max `86400000`) | |
| `orchestrator_enrollment_ttl_ms` | `900000` (max `900000`) | |

The Hub serves HTTP/1. Terminate external TLS at a trusted reverse proxy and forward an allowed Host authority. Any non-loopback listener requires an explicit, nonempty `allowed_hosts` list. Match the authority exactly, including a port when clients send one (canonical ports `1..=65535` without leading zeros). Loopback defaults are `127.0.0.1:<port>`, `localhost:<port>` and `[::1]:<port>`. The health probe accepts any syntactically valid Host. Origin checks apply whenever a client supplies an Origin header. Use HTTP or HTTPS origins with no path; default scheme ports (`:443` for `https`, `:80` for `http`) are normalized. A client can pin the Hub identity by sending the expected Hub ID in `X-Efferian-Hub`.

Administrators can manage principals, grants and API tokens at `/v1/principals`, `/v1/grants` and `/v1/tokens`. Grants are allow-only. Tokens can narrow their principal's access (up to 256 entries each in `allowed_profiles` and `allowed_nodes`; up to 64 entries in `allowed_node_tags` and enrollment `tags`). Token labels are trimmed and must be 1 to 128 bytes without ASCII control characters. In `GET /v1/me`, `owned_agents` follows `GET /v1/principals` visibility (populated for unrestricted global Administrators and Members). Member and orchestrator delegation stays within managed resources and token scope. Promoting a service to orchestrator returns `409 quota_exceeded` when its existing managed agents exceed the configured limit. Disabled agents count until they are deleted or claimed by garbage collection. A mutation that would remove the last active human Admin with a global admin grant returns `409 last_admin`.

In a node credential incident, revoke the node with `POST /v1/nodes/{id}/revoke`. This revokes unconsumed tickets targeting that node and marks its active executions unknown. After restoring the node host, an unrestricted global Admin can mint a fresh ticket at `POST /v1/nodes/{id}/reenroll-tokens`. Exchange it at `POST /v1/enrollment/exchange` to rotate the node credential and preserve its ID and tags. Use the credential class specified for each operation.

## Publish and invoke tools

An unrestricted Admin registers upstreams at `/v1/upstreams`, defines tools at `/v1/tools`, and sets profile bindings at `/v1/profiles`. An effective tool update creates an immutable revision. A profile binds public names to specific revisions and serves them after `POST /v1/profiles/{slug}/publish` creates an edition. Use `GET /v1/profiles/{slug}/tools` to list tools and `GET /v1/profiles/{slug}/tools/{public_name}` for the input schema and available targets. Profile, edition, tool and upstream disable routes take effect for new invocations. Resource deletion returns `409 resource_in_use` while active references exist.

Members can store private accounts through `/v1/accounts` and bind them through `/v1/account-bindings/me/{upstream_slug}` where they can access a published caller-bound tool. An Admin can manage shared accounts and refresh an upstream's discovery cache explicitly. Account reads return metadata. Changing an upstream URL to a different origin requires removing its HTTP authentication accounts or creating a separate upstream.

Use `POST /v1/profiles/{slug}/invoke` with a UUIDv7 `request_id` if the request may need to be repeated. Keep the same invocation inputs on retry. An authorized replay returns the original execution even after a catalog update or target disconnect. A change to the invocation inputs returns `409 request_id_conflict`. A pending invocation returns `202` and an execution ID. Use `GET /v1/executions/{id}` to read its state and add `wait_ms` up to `25000` to wait for a terminal state. Use `sensitive=true` to request the result where permitted. Cancel with `POST /v1/executions/{id}/cancel`.

## Resume events and stop the Hub

`GET /v1/events` returns a JSON page. `GET /v1/events/stream` returns newline-delimited events and sends a ping every 15 seconds. Both accept `after` and a comma-separated `kinds` filter. Save the latest processed sequence for reconnects. A cursor outside the retained range requires resynchronization. Rebuild state from the REST resources before connecting again. The stream response disables buffering in proxies that honor `X-Accel-Buffering`.

`SIGTERM` and `SIGINT` stop execution admission, release long polls with the current execution state, close event streams, and drain storage before checkpointing the WAL. On restart, unfinished upstream executions become `unknown` and pending node executions remain available for bridge reconciliation.

## Back up and restore

```sh
efferian-hub sqlite-snapshot --state-dir ./hub-state --out ./hub-backup.sqlite3
```

The snapshot command can run while the Hub is serving. It checks the stored Hub ID and writes a consistent SQLite copy with mode `0600` and atomically publishes it at an unused path. Back up `hub.master.key` separately. Restore the snapshot to `hub.sqlite3` in a private state directory with mode `0600` on the database and its original master key with mode `0400` or `0600`. Use a fresh destination or clear stale SQLite sidecars while the Hub is stopped. A restore also restores the access and revocation state from the time of the snapshot.

## Recover administrator access offline

Stop the Hub first, then mint a fresh unrestricted token for an existing active global administrator.

```sh
efferian-hub admin create-token --state-dir ./hub-state --principal admin --out ./hub-recovery.token
```

With the default quota of 64 active tokens per principal, pass `--max-active-tokens-per-principal 65` for this command if all 64 remain active. Restart with the original quota, authenticate with the recovery token, and revoke lost tokens through `POST /v1/tokens/{id}/revoke`. Use the same `--config` or page budget as serve if the database has grown past the default 4 GiB limit.
