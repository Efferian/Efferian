// The default package test target must exercise both production feature sets.
#![cfg(not(feature = "process"))]

use std::error::Error;
use std::process::{Command, Output};

fn cargo(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .args(["-p", "efferian-platform", "--locked", "--offline"])
        .output()?;
    assert!(
        output.status.success(),
        "cargo {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

#[test]
fn production_platform_builds_with_and_without_process_support() -> Result<(), Box<dyn Error>> {
    cargo(&["check", "--lib"])?;
    let tree = cargo(&["tree", "--edges=normal", "--prefix=none"])?;
    let tree = String::from_utf8(tree.stdout)?;
    assert!(
        !tree.lines().any(|line| line.starts_with("tokio ")),
        "platform with default features must not depend on Tokio:\n{tree}"
    );

    cargo(&["check", "--lib", "--features", "process"])?;
    Ok(())
}

#[test]
fn default_test_target_runs_the_process_group_suite() -> Result<(), Box<dyn Error>> {
    let output = cargo(&[
        "test",
        "--features",
        "process",
        "--lib",
        "--test",
        "process_group",
    ])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("normal_leader_exit_cleans_up_a_live_worker_before_reap"),
        "{stdout}"
    );
    Ok(())
}
