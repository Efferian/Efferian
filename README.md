# Efferian

Efferian is a distributed agent tools platform. The Hub, Node and CLI share a Rust workspace with protocol contracts, authorization rules and OS primitives. Each executable installs the ring TLS provider at startup.

## Build from a clean checkout

Use Linux on x86-64 or ARM64 with Git, GNU Make, GNU coreutils, curl, a local Docker Engine and Docker Compose 5 or newer. The repository pins DevKit 0.6.0 and its Rust toolchain. From the repository root, run:

```sh
make setup
make doctor
make check
make test
make build
```

The first setup needs network access to fetch the engine, container image and locked Cargo dependencies. After setup, checks, tests and builds run in gcc-only Rust containers with networking disabled. A disconnected runner needs the pinned engine, images and Cargo cache staged in advance. The checkout owns one root `Cargo.lock` and a shared `target/` directory.

DevKit builds each application separately so Cargo resolves its production features in isolation. The binaries are named `efferian-hub`, `efferian-node` and `efferian`. To work on one component, use commands such as `make test app=hub` or `make check package=efferian-client`.

## Workspace boundaries

| Component | Responsibility | Direct workspace dependencies |
| --- | --- | --- |
| `efferian-protocol` | Shared wire contracts | None |
| `efferian-platform` | OS primitives | None |
| `efferian-authz` | Authorization policy | Protocol |
| `efferian-client` | Hub API client | Protocol |
| `apps/hub` | Hub executable | Protocol with `openapi`, Platform, Authz. Tests may use Client. |
| `apps/node` | Node executable | Protocol, Platform with `process` |
| `apps/cli` | Command-line executable | Protocol, Platform, Client |

`make check` runs formatting and Clippy, checks dependency declarations, scans the entire lockfile and inspects the features Cargo actually compiled for each binary. It also checks tracked text for local home paths and private-key headers and enforces the ten-block unsafe budget in Platform. The Rust line-count report is informational. `make test` includes a fresh-process TLS check and a network-free MCP transport test using the locked SDK. Protocol integration tests also run with the Hub’s optional `openapi` feature to check the generated schemas against their wire representations.

## Platform primitives

Use separate sidecar files such as `hub.lock` and `node.lock` for exclusive instance locks. `PrivateFs` manages private directories, bounded secret reads and atomic file replacement. If an atomic write reports `sync_published_parent`, the complete replacement is visible and its crash durability is unknown. Verify the visible state before retrying. Path validation assumes that operators keep the relevant directory entries, sensitive files and ACLs under trusted control throughout use. Configure every operator-created mount alias that exposes protected state under an allowed root as a forbidden root. Working directories and the parents of SSH files require directory search permission. Startup cleanup runs under the instance lock before any ephemeral guards are issued. Each guard owns its entry name through removal. On Linux, restoring owner permissions on an unreadable directory uses the service's mounted procfs at `/proc/self/fd`.

Only Node enables the Platform `process` feature. Its `ProcessHandle` owns the group through cleanup and keeps the leader unreaped until the final group signal. Explicit termination gives signalable group members the full TERM grace period, then escalates and collects the leader. Callers retain the handle through cleanup. Take each piped stdout and stderr and read both concurrently with waiting, or select inherited or null output when a stream is unused. Spawn on a thread with SIGCHLD unblocked and keep signal delivery and child collection available to the handle. Pipe registration errors after OS spawn trigger group cleanup and leader collection. The command may already have performed work when such an error is returned. The guarantee covers the original process group while Node is running.

## Hub storage

The Hub storage module owns a single `hub.sqlite3` writer under the `hub.lock` sidecar. The database uses WAL, full synchronous commits by default and eight read-only connections for snapshots. State changes and their outbox events commit together. Live subscribers also receive a dedicated revocation feed and must invalidate cached permissions if it reports a gap or closes.

Staged initialization borrows the instance lock exclusively. Startup checks that SQLite actually opened the writer with write access. Priority commands commit individually. When work is waiting and eligible, the writer runs a work batch after at most 16 consecutive priority commands. With an oversized WAL, the writer attempts a passive checkpoint, then requests truncation with a 50 ms busy timeout and a retry cooldown of 30 seconds by default.

The default database page budget is 4 GiB. At 75% used pages, background cleanup can discard retained execution output. At 85%, admission rejects new invocations while replays, revocations and finalization can use available pages. The page budget tracks logical SQLite capacity. These writes still require free filesystem space for the database and WAL. Cleanup uses the token creator index to check references when removing a disabled managed agent. If a restored snapshot needs rollback recovery, Hub verifies the recovered identity and page budget in private staging first. This requires temporary space for a copy.

Run `make gate_sqlite_hygiene` to verify the schema, SQLite settings and read-only behavior in the pinned environment. `make test app=hub` also exercises process crashes, transaction rollback, bounded maintenance and recovery.

## License

Efferian is licensed under the GNU Affero General Public License v3.0 only. DevKit files and retained template configuration carry the DevKit MIT notice. [Efferian license](LICENSE) · [DevKit notice](.devkit/runtime/LICENSE)
