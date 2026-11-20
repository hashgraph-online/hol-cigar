//! The `cigar-context-worker` binary: a thin wrapper around [`hol_cigar::worker`].
fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    hol_cigar::worker::main(&args)
}
