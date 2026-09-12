//! Qualification fixture: successful handshake, then deliberately never replies.
use std::io::{BufRead, Write};
fn main() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut line = String::new();
    input.read_line(&mut line)?;
    println!(r#"{{"id":1,"ok":true,"result":{{"protocol":"cigar.context-worker.v1","core_version":"0.10.1","max_frame_bytes":33554432,"max_response_bytes":67108864}}}}"#);
    std::io::stdout().flush()?;
    // Do not drain stdin: a large next command must exercise a blocked pipe write.
    loop { std::thread::park(); }
}
