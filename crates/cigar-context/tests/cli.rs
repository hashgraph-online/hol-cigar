//! Actual process-boundary tests of the optional JSON command-line interface.
#![cfg(feature = "bpe")]

use cigar_context::{ContextSnapshot, O200kTokenizer};
use std::error::Error;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn cli(input: &str) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cigar-context"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(input.as_bytes())?;
    Ok(child.wait_with_output()?)
}

#[test]
fn cli_returns_a_verified_snapshot() -> Result<(), Box<dyn Error>> {
    let output = cli(
        r#"{"domain":"local","documents":[{"id":"a","source":"src/a","text":"retry identity"}],"request":{"query":"retry","max_tokens":100}}"#,
    )?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let snapshot: ContextSnapshot = serde_json::from_slice(&output.stdout)?;
    snapshot.verify(&O200kTokenizer::new()?)?;
    assert!(snapshot.render().contains("retry identity"));
    Ok(())
}

#[test]
fn cli_rejects_ambiguous_and_malformed_inputs_without_leaking_their_text()
-> Result<(), Box<dyn Error>> {
    for input in [
        r#"{"SECRET_CANARY":true}"#,
        r#"{"domain":"local","documents":[{"id":"a","source":"a","text":"SECRET_CANARY"},{"id":"a","source":"a","text":"second"}],"request":{"query":"retry"}}"#,
        r#"{"domain":"local","documents":[],"request":{"query":"retry","required":["a"]}}"#,
    ] {
        let output = cli(input)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET_CANARY"));
    }
    Ok(())
}

#[test]
fn cli_exposes_help_and_the_actual_package_version() -> Result<(), Box<dyn Error>> {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cigar-context"))
            .arg(argument)
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("cigar-context"));
        if argument == "--version" {
            assert!(text.contains(env!("CARGO_PKG_VERSION")));
        }
    }
    Ok(())
}
