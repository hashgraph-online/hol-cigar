//! CIGAR command-line interface composition binary.

use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Write as _};

#[tokio::main]
async fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut terminal = cigar_cli::TerminalContext {
        stdin: io::stdin().is_terminal(),
        stdout: io::stdout().is_terminal(),
        stderr: io::stderr().is_terminal(),
        width: std::env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok()),
        unicode: std::env::var_os("NO_UNICODE").is_none(),
        confirmed: None,
        progress_started: false,
    };
    if cigar_cli::confirmation_needed(&arguments, terminal) {
        let _ignored = io::stderr().write_all(b"Confirm reviewed state change? [y/N] ");
        let _ignored = io::stderr().flush();
        let mut answer = String::new();
        terminal.confirmed = Some(
            io::stdin()
                .read_line(&mut answer)
                .is_ok_and(|_| matches!(answer.trim(), "y" | "Y" | "yes" | "YES")),
        );
    }
    if let Some(progress) = cigar_cli::progress_start(&arguments, terminal) {
        let _ignored = io::stderr().write_all(progress.as_bytes());
        let _ignored = io::stderr().flush();
        terminal.progress_started = true;
    }
    let outcome = cigar_cli::run(arguments, terminal).await;
    if !outcome.stdout.is_empty() {
        let _ignored = io::stdout().write_all(outcome.stdout.as_bytes());
    }
    if !outcome.stderr.is_empty() {
        let _ignored = io::stderr().write_all(outcome.stderr.as_bytes());
    }
    std::process::exit(outcome.status.into());
}
