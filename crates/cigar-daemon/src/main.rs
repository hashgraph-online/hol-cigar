//! CIGAR daemon process entry point.

use cigar_daemon::{execute_process_command_async, render_process_outcome};
use std::ffi::OsString;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let outcome = execute_process_command_async(&arguments).await;
    let status = render_process_outcome(
        &outcome,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    if status != 0 {
        std::process::exit(i32::from(status));
    }
}
