//! Authoritative CIGAR workspace task runner.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match xtask::run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
