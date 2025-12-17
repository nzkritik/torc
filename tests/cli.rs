use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn test_help_option() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("torc")?;
    cmd.arg("--help");
    cmd.assert().success();
    Ok(())
}

#[test]
fn test_connect_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("torc")?;
    cmd.arg("connect");
    // Connect command may not work without sudo, but should run and return normally
    cmd.assert()
        .success(); // Connect should complete execution normally even if it fails with sudo issues
    Ok(())
}

#[test]
fn test_status_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("torc")?;
    cmd.arg("status");
    cmd.assert()
        .success();
    Ok(())
}
