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
fn test_system_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("torc")?;
    cmd.arg("system");
    cmd.assert().success();
    Ok(())
}

#[test]
fn test_system_status_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("torc")?;
    cmd.arg("system").arg("status");
    cmd.assert().success();
    Ok(())
}
