use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

const PROTOCOL: &str = "efferian-protocol";
const PLATFORM: &str = "efferian-platform";
const AUTHZ: &str = "efferian-authz";
const CLIENT: &str = "efferian-client";
const HUB: &str = "efferian-hub";
const NODE: &str = "efferian-node";
const CLI: &str = "efferian-cli";

#[derive(Deserialize)]
struct Metadata {
    workspace_root: PathBuf,
    packages: Vec<Package>,
    resolve: Option<Resolution>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    id: String,
    manifest_path: PathBuf,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String, // Cargo reports the package name here even for renamed dependencies.
    path: Option<PathBuf>,
    kind: Option<String>,
    target: Option<String>,
    optional: bool,
}

#[derive(Deserialize)]
struct Resolution {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    features: BTreeSet<String>,
}

fn cargo(args: &[&str]) -> Result<String> {
    let output = Command::new(env!("CARGO"))
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(args)
        .args(["--locked", "--offline"])
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err(format!("cargo {} failed ({})", args.join(" "), output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn check_direct_edges(package: &Package, paths: &BTreeMap<&str, PathBuf>) -> Result {
    let consumer = package.name.as_str();
    let allowed: &[&str] = match consumer {
        AUTHZ | CLIENT => &[PROTOCOL],
        HUB => &[PROTOCOL, PLATFORM, AUTHZ],
        NODE => &[PROTOCOL, PLATFORM],
        CLI => &[PROTOCOL, PLATFORM, CLIENT],
        _ => &[],
    };
    let forbidden: &[&str] = match consumer {
        PROTOCOL => &["tokio", "rusqlite", "axum", "reqwest", "rmcp", "libc"],
        AUTHZ => &["tokio", "rusqlite", "axum", "reqwest"],
        _ => &[],
    };
    for dependency in &package.dependencies {
        let name = dependency.name.as_str();
        let kind = dependency.kind.as_deref().unwrap_or("normal");
        let target = dependency.target.as_deref().unwrap_or("all targets");
        let edge = format!("{consumer} -> {name} ({kind}, {target})");
        if let Some(expected) = paths.get(name) {
            let hub_dev_client = consumer == HUB && name == CLIENT && kind == "dev";
            if !(kind == "normal" && allowed.contains(&name) || hub_dev_client) {
                return Err(format!("forbidden internal dependency: {edge}").into());
            }
            if dependency.path.as_ref() != Some(expected) {
                return Err(
                    format!("internal dependency must use its workspace path: {edge}").into(),
                );
            }
        } else if dependency.path.is_some() || forbidden.contains(&name) {
            return Err(format!("forbidden direct dependency: {edge}").into());
        }
    }
    let optional = match consumer {
        PROTOCOL => Some("utoipa"),
        PLATFORM => Some("tokio"),
        _ => None,
    };
    if let Some(name) = optional {
        let mut declarations = package
            .dependencies
            .iter()
            .filter(|d| d.name == name && d.kind.is_none())
            .peekable();
        if declarations.peek().is_none() || declarations.any(|d| !d.optional) {
            return Err(format!("{consumer} must keep {name} optional").into());
        }
    }
    Ok(())
}

fn check_runtime_graph(consumer: &str, forbidden: &[&str]) -> Result {
    let tree = cargo(&[
        "tree",
        "-p",
        consumer,
        "--edges",
        "normal,no-proc-macro",
        "--prefix",
        "none",
    ])?;
    for line in tree.lines() {
        if let Some(name) = line.split_whitespace().next()
            && forbidden.contains(&name)
        {
            return Err(format!("{consumer} has forbidden runtime dependency {name}").into());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "reason")]
enum CargoMessage {
    #[serde(rename = "compiler-artifact")]
    Artifact {
        package_id: String,
        features: BTreeSet<String>,
    },
    #[serde(other)]
    Other,
}

fn check_app_features(app: &str, bin: &str, packages: &BTreeMap<&str, &Package>) -> Result {
    let output = cargo(&[
        "check",
        "-p",
        app,
        "--bin",
        bin,
        "--message-format=json-render-diagnostics",
    ])?;
    let mut seen = BTreeSet::new();
    for line in output.lines() {
        if let CargoMessage::Artifact {
            package_id,
            features,
        } = serde_json::from_str(line)?
        {
            for (name, feature, expected) in [
                (PROTOCOL, "openapi", app == HUB),
                (PLATFORM, "process", app == NODE),
            ] {
                if package_id == packages[name].id {
                    if features.contains(feature) != expected {
                        return Err(format!("cargo check -p {app}: expected {name}/{feature}={expected}, compiled features {features:?}").into());
                    }
                    seen.insert(name);
                }
            }
        }
    }
    if seen != BTreeSet::from([PROTOCOL, PLATFORM]) {
        return Err(
            format!("cargo check -p {app}: missing shared crate artifacts (saw {seen:?})").into(),
        );
    }
    Ok(())
}

#[test]
fn gate_crate_dag() -> Result {
    let metadata: Metadata =
        serde_json::from_str(&cargo(&["metadata", "--format-version=1", "--no-deps"])?)?;
    let paths: BTreeMap<_, _> = [
        (PROTOCOL, "packages/efferian-protocol"),
        (PLATFORM, "packages/efferian-platform"),
        (AUTHZ, "packages/efferian-authz"),
        (CLIENT, "packages/efferian-client"),
        (HUB, "apps/hub"),
        (NODE, "apps/node"),
        (CLI, "apps/cli"),
    ]
    .into_iter()
    .map(|(name, path)| (name, metadata.workspace_root.join(path)))
    .collect();
    let packages: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();
    if packages.keys().ne(paths.keys()) {
        return Err(format!("unexpected workspace members: {:?}", packages.keys()).into());
    }
    for (name, p) in &packages {
        if p.manifest_path != paths[name].join("Cargo.toml") {
            return Err(format!(
                "unexpected manifest for {name}: {}",
                p.manifest_path.display()
            )
            .into());
        }
        check_direct_edges(p, &paths)?;
    }
    for (name, feature) in [(PROTOCOL, "openapi"), (PLATFORM, "process")] {
        let defaults = cargo(&[
            "tree",
            "-p",
            name,
            "--edges=normal",
            "--depth=0",
            "--prefix=none",
            "--format={f}",
        ])?;
        if defaults.trim().split(',').any(|f| f == feature) {
            return Err(format!("{name}/{feature} must default off").into());
        }
    }
    let pure_crate_exclusions = &["tokio", "rusqlite", "axum", "reqwest", "rmcp", "jsonschema"];
    check_runtime_graph(PROTOCOL, pure_crate_exclusions)?;
    check_runtime_graph(AUTHZ, pure_crate_exclusions)?;
    check_runtime_graph(CLIENT, &["rusqlite", "axum", "rmcp"])?;
    check_runtime_graph(NODE, &["axum", "rmcp", AUTHZ, "chacha20poly1305"])?;
    check_runtime_graph(CLI, &["rusqlite", "axum", "rmcp", "chacha20poly1305"])?;
    for (app, bin) in [(HUB, HUB), (NODE, NODE), (CLI, "efferian")] {
        check_app_features(app, bin, &packages)?;
    }
    Ok(())
}

fn banned(name: &str) -> bool {
    [
        "openssl",
        "openssl-sys",
        "cmake",
        "clang-sys",
        "bindgen",
        "libproc",
        "r2d2",
        "rustls-platform-verifier",
        "openssl-probe",
        "rustls-pemfile",
    ]
    .contains(&name)
        || ["native-tls", "cxx", "aws-lc-", "quinn", "sqlx"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

#[derive(Deserialize)]
struct Lockfile {
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
}

fn check_lock(contents: &str) -> Result {
    let lock: Lockfile = toml::from_str(contents)?;
    for package in lock.package {
        if banned(&package.name) {
            return Err(format!("Cargo.lock contains banned package {}", package.name).into());
        }
    }
    Ok(())
}

#[test]
fn lock_rules_cover_families_and_exact_matches() -> Result {
    let lock = "[[package]]\nname = 'wasm-bindgen'\n[[package]]\nname = 'bindgen-helper'\n";
    check_lock(lock)?;
    for name in ["quinn-udp", "cxxbridge-macro", "bindgen"] {
        assert!(check_lock(&format!("{lock}[[package]]\nname = '{name}'")).is_err());
    }
    Ok(())
}

fn check_transport_features(name: &str, active: &BTreeSet<String>) -> Result {
    let required: &[&str] = match name {
        "reqwest" => &["json", "stream", "rustls-tls-webpki-roots-no-provider"],
        "rmcp" => &[
            "client",
            "server",
            "base64",
            "transport-streamable-http-client",
            "transport-streamable-http-server",
            "schemars",
        ],
        _ => return Ok(()),
    };
    for feature in required {
        if !active.contains(*feature) {
            return Err(format!("missing resolved feature: {name}/{feature}").into());
        }
    }
    for feature in active {
        let blocked = match name {
            "reqwest" => matches!(
                feature.as_str(),
                "default"
                    | "default-tls"
                    | "gzip"
                    | "brotli"
                    | "deflate"
                    | "zstd"
                    | "__rustls-ring"
            ),
            _ => {
                matches!(feature.as_str(), "default" | "transport-child-process")
                    || feature.contains("reqwest")
            }
        };
        if blocked {
            return Err(format!("forbidden resolved feature: {name}/{feature}").into());
        }
    }
    Ok(())
}

#[test]
fn gate_banned_crates() -> Result {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    check_lock(&fs::read_to_string(root.join("Cargo.lock"))?)?;
    let metadata: Metadata = serde_json::from_str(&cargo(&["metadata", "--format-version=1"])?)?;
    let resolution = metadata
        .resolve
        .ok_or("Cargo omitted the resolved feature graph")?;
    let features: BTreeMap<_, _> = resolution
        .nodes
        .iter()
        .map(|n| (&n.id, &n.features))
        .collect();
    for name in ["reqwest", "rmcp"] {
        let mut packages = metadata
            .packages
            .iter()
            .filter(|p| p.name == name)
            .peekable();
        if packages.peek().is_none() {
            return Err(format!("missing required dependency {name}").into());
        }
        for package in packages {
            let active = features
                .get(&package.id)
                .ok_or("missing resolved package")?;
            check_transport_features(name, active)?;
        }
    }
    Ok(())
}

#[test]
fn gate_sqlite_hygiene() -> Result {
    let output = Command::new(env!("CARGO"))
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "test",
            "-p",
            HUB,
            "--test",
            "gate_sqlite_hygiene",
            "--locked",
            "--offline",
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "Hub SQLite hygiene gate failed ({}):\n{stdout}\n{stderr}",
            output.status
        )
        .into());
    }
    let passed = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("test result: ok. ")?;
            rest.split_whitespace().next()?.parse::<usize>().ok()
        })
        .unwrap_or(0);
    if passed == 0 {
        return Err(
            format!("Hub SQLite hygiene gate executed zero tests:\n{stdout}\n{stderr}").into(),
        );
    }
    Ok(())
}
