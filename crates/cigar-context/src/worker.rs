//! The `cigar-context-worker` binary: a thin wrapper around [`cigar_context::worker`].
fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    cigar_context::worker::main(&args)
}
