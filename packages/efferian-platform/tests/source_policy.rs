use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use toml::Value;

const PLATFORM: &str = "packages/efferian-platform";
const REQUIRED_CLIPPY_LINTS: &[&str] = &[
    "unwrap_used",
    "expect_used",
    "panic",
    "todo",
    "unimplemented",
    "await_holding_lock",
    "dbg_macro",
    "exit",
];

fn read_manifest(directory: &Path) -> Result<Value, Box<dyn Error>> {
    let contents = fs::read_to_string(directory.join("Cargo.toml"))?;
    Ok(toml::from_str(&contents)?)
}

fn lint_level<'a>(settings: &'a Value, group: &str, lint: &str) -> Option<&'a str> {
    let entry = settings.get("lints")?.get(group)?.get(lint)?;
    entry.as_str().or_else(|| entry.get("level")?.as_str())
}

#[test]
fn all_members_enforce_the_production_lints() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = read_manifest(&root)?;
    let workspace = manifest.get("workspace").ok_or("missing [workspace]")?;
    assert_eq!(lint_level(workspace, "rust", "unsafe_code"), Some("forbid"));
    let platform = read_manifest(&root.join(PLATFORM))?;
    for (name, settings) in [("workspace", workspace), (PLATFORM, &platform)] {
        for lint in REQUIRED_CLIPPY_LINTS {
            assert!(
                matches!(
                    lint_level(settings, "clippy", lint),
                    Some("deny" | "forbid")
                ),
                "{name}: clippy::{lint} must be denied"
            );
        }
    }
    assert!(
        matches!(
            lint_level(&platform, "clippy", "undocumented_unsafe_blocks"),
            Some("deny" | "forbid")
        ),
        "{PLATFORM}: unsafe blocks must have a safety comment"
    );

    let members = workspace
        .get("members")
        .and_then(Value::as_array)
        .ok_or("missing workspace members")?;
    for member in members {
        let path = member.as_str().ok_or("invalid workspace member path")?;
        if path != PLATFORM {
            let manifest = read_manifest(&root.join(path))?;
            let inherits = manifest.get("lints").and_then(|v| v.get("workspace"));
            assert_eq!(
                inherits.and_then(Value::as_bool),
                Some(true),
                "{path} must inherit the workspace lints"
            );
        }
    }
    Ok(())
}

// Inspect tokens before cfg evaluation, including blocks inside macro bodies.
fn unsafe_blocks(tokens: TokenStream) -> usize {
    let mut count = 0;
    let mut after_unsafe = false;
    for token in tokens {
        match token {
            TokenTree::Ident(word) => after_unsafe = word == "unsafe",
            TokenTree::Group(group) => {
                if after_unsafe && group.delimiter() == Delimiter::Brace {
                    count += 1;
                }
                count += unsafe_blocks(group.stream());
                after_unsafe = false;
            }
            _ => after_unsafe = false,
        }
    }
    count
}

fn count_sources(directory: &Path) -> Result<usize, Box<dyn Error>> {
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            count += count_sources(&path)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let tokens = fs::read_to_string(&path)?
                .parse()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            count += unsafe_blocks(tokens);
        }
    }
    Ok(count)
}

#[test]
fn platform_has_at_most_ten_unsafe_blocks_across_all_sources() -> Result<(), Box<dyn Error>> {
    let count = count_sources(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    assert!(
        count <= 10,
        "{PLATFORM} contains {count} unsafe blocks (budget 10)"
    );
    Ok(())
}

#[test]
fn clippy_checks_the_opt_in_library_features() -> Result<(), Box<dyn Error>> {
    // The component checks lint each library as a primary package with defaults.
    // Re-run the two feature owners as primary packages to lint their opt-in code.
    let status = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "clippy",
            "-p",
            "efferian-platform",
            "-p",
            "efferian-protocol",
            "--all-features",
            "--lib",
            "--locked",
            "--offline",
            "--",
            "-D",
            "warnings",
        ])
        .status()?;
    assert!(
        status.success(),
        "Clippy failed on opt-in features: {status}"
    );
    Ok(())
}
