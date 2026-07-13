//! CIGAR stdio MCP composition binary.

use std::io::{self, Write as _};
use std::process::ExitCode;

use cigar_mcp::{CliBackend, MCP_PROTOCOL_VERSION, serve};
use cigar_protocol::BuildMetadata;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().unwrap_or_else(|| "serve".to_owned());
    if arguments.next().is_some() {
        return usage_error();
    }
    match mode.as_str() {
        "serve" => serve_mode(),
        "doctor" => doctor_mode(),
        "schema-noop" => schema_noop_mode(),
        _ => usage_error(),
    }
}

fn serve_mode() -> ExitCode {
    let backend = match CliBackend::from_env() {
        Ok(backend) => backend,
        Err(_) => {
            write_stderr("cigar-mcp: daemon endpoint configuration rejected\n");
            return ExitCode::from(2);
        }
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    match serve(stdin.lock(), stdout.lock(), backend) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            write_stderr("cigar-mcp: stdio transport failed\n");
            ExitCode::from(1)
        }
    }
}

fn doctor_mode() -> ExitCode {
    let mut backend = match CliBackend::from_env() {
        Ok(backend) => backend,
        Err(_) => {
            println!(r#"{{"status":"rejected","daemon":"unavailable"}}"#);
            return ExitCode::from(2);
        }
    };
    if backend.is_available() {
        println!(r#"{{"status":"ok","daemon":"available"}}"#);
        ExitCode::SUCCESS
    } else {
        println!(r#"{{"status":"degraded","daemon":"unavailable"}}"#);
        ExitCode::from(1)
    }
}

fn schema_noop_mode() -> ExitCode {
    let metadata = BuildMetadata::current(env!("CARGO_PKG_VERSION")).to_stable_json();
    println!(r#"{{"status":"ok","protocol_version":"{MCP_PROTOCOL_VERSION}","build":{metadata}}}"#);
    ExitCode::SUCCESS
}

fn usage_error() -> ExitCode {
    write_stderr("usage: cigar-mcp [serve|doctor|schema-noop]\n");
    ExitCode::from(2)
}

fn write_stderr(message: &str) {
    let _result = io::stderr().lock().write_all(message.as_bytes());
}
