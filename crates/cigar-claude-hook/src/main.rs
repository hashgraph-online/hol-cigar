//! CIGAR Claude Code hook process boundary.

#[tokio::main]
async fn main() {
    let status = cigar_claude_hook::run_process(std::env::args_os().skip(1).collect()).await;
    std::process::exit(status.into());
}
