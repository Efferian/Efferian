# Efferian

Efferian is a distributed agent tools platform. The Rust workspace provides the build foundation and shared OS primitives for the Hub, Node and CLI. Each executable installs the ring TLS provider at startup.

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

`make check` runs formatting and Clippy, checks dependency declarations, scans the entire lockfile and inspects the features Cargo actually compiled for each binary. It also checks tracked text for local home paths and private-key headers and enforces the ten-block unsafe budget in Platform. The Rust line-count report is informational. `make test` includes a fresh-process TLS check and a network-free MCP transport test using the locked SDK.

## Platform primitives

Use separate sidecar files such as `hub.lock` and `node.lock` for exclusive instance locks. `PrivateFs` manages private directories, bounded secret reads and atomic file replacement. If an atomic write reports `sync_published_parent`, the complete replacement is visible and its crash durability is unknown. Verify the visible state before retrying. Path validation assumes that operators keep the relevant directory entries, sensitive files and ACLs under trusted control throughout use.

Only Node enables the Platform `process` feature. Its `ProcessHandle` owns the group through cleanup and keeps the leader unreaped until the final group signal. Explicit termination gives signalable group members the full TERM grace period, then escalates and collects the leader. Callers retain the handle through cleanup and service any extracted pipes separately. The guarantee covers the original process group while Node is running.

## License

Efferian is licensed under the GNU Affero General Public License v3.0 only. DevKit files and retained template configuration carry the DevKit MIT notice. [Efferian license](LICENSE) · [DevKit notice](.devkit/runtime/LICENSE)
