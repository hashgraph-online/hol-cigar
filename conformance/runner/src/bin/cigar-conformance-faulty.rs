//! Deliberately non-conformant process used only by negative runner tests.

use cigar_conformance::{AdapterRequest, AdapterResponse, CaseOutcome};
use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let mode = executable
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("fault mode unavailable")?;
    if mode.contains("crash") {
        std::process::exit(9);
    }
    if mode.contains("timeout") {
        std::thread::sleep(Duration::from_secs(30));
        return Ok(());
    }
    if mode.contains("flood") {
        let chunk = [b'x'; 8192];
        let mut stdout = std::io::stdout().lock();
        for _index in 0..64 {
            stdout.write_all(&chunk)?;
        }
        return Ok(());
    }
    if mode.contains("malformed") {
        std::io::stdout().write_all(b"{malformed\n")?;
        return Ok(());
    }
    if mode.contains("skipped") {
        std::io::stdout().write_all(
            b"{\"schema_version\":\"cigar.conformance.response.v1\",\"status\":\"skipped\"}\n",
        )?;
        return Ok(());
    }

    let mut request_bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut request_bytes)?;
    let request: AdapterRequest = serde_json::from_slice(&request_bytes)?;
    let (outcome, digest) = if mode.contains("wrong") {
        (
            CaseOutcome::Success,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    } else {
        expected_for_case(&request.case_id)?
    };
    let escaped = if mode.contains("escape") {
        attempted_escape(&request)?
    } else {
        false
    };
    if mode.contains("stateful") {
        let home = std::env::var_os("HOME").ok_or("HOME unavailable")?;
        let marker = PathBuf::from(home).join("adapter-state");
        if marker.exists() {
            return Err("case namespace was reused".into());
        }
        std::fs::write(marker, b"state")?;
    }
    let response = AdapterResponse {
        schema_version: "cigar.conformance.response.v1".to_owned(),
        case_id: request.case_id,
        challenge: request.challenge,
        outcome,
        public_digest: if escaped {
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
        } else {
            digest.to_owned()
        },
        diagnostic: None,
    };
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

fn attempted_escape(request: &AdapterRequest) -> Result<bool, Box<dyn Error>> {
    let path = request
        .input
        .get("probe_path")
        .and_then(serde_json::Value::as_str)
        .ok_or("probe path unavailable")?;
    let address = request
        .input
        .get("probe_address")
        .and_then(serde_json::Value::as_str)
        .ok_or("probe address unavailable")?
        .parse::<SocketAddr>()?;
    let wrote = std::fs::write(path, b"sandbox escaped").is_ok();
    let connected = TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok();
    Ok(wrote || connected)
}

fn expected_for_case(case_id: &str) -> Result<(CaseOutcome, &'static str), Box<dyn Error>> {
    let value = match case_id {
        "CORE-CANON-001" => (
            CaseOutcome::Success,
            "1220e76d14455f390432ae81cb4ec53ba92d7ec514430a26d02bf8cbc1572d9f7835",
        ),
        "CORE-CANON-002" => (
            CaseOutcome::Success,
            "1220f9fdfe3c53b2771544e0e5bf5d0daea624c64d58563c50ce3964db104d9d2878",
        ),
        "CORE-CANON-003" => (
            CaseOutcome::Success,
            "1220a5a000159f8e4a0a9eec860c1eca6ceb54d589f73af64348e2909178d99e8599",
        ),
        "CORE-BUNDLE-001" => (
            CaseOutcome::Success,
            "122057c842fc7702a85a2a558ead8a1ebae11717bf977bf9c7faa5a56cc8e46c2c6e",
        ),
        "CORE-REJECT-001" => (
            CaseOutcome::Rejected,
            "sha256:8b136cccbef3a14675b24ae9b3923f0a6d69c314daf63e358939339a4bb70d24",
        ),
        "CORE-REJECT-002" => (
            CaseOutcome::Rejected,
            "sha256:0f9eb98b4cd0a68fc93ce2a587d2bf3a341758b0e41e72e97865f940aa92966f",
        ),
        "CORE-REJECT-003" => (
            CaseOutcome::Rejected,
            "sha256:ac6c30c318e2f3cb7a997968f9858a807afd7af2e9cbd4f2187312edbfa90ebd",
        ),
        "CORE-REJECT-004" => (
            CaseOutcome::Rejected,
            "sha256:0d250abf198d499232f5286c86b4027c1a1006277b189b4b010d6c092734051e",
        ),
        "CORE-ERROR-001" => (
            CaseOutcome::Success,
            "sha256:4cc799337e5463fbb25c2a86b8c508aee2ecb639e362ec764482b52808a75986",
        ),
        "CORE-DIFFERENTIAL-001" => (
            CaseOutcome::Success,
            "sha256:17f45f2224c49d72ab25b252cd0b262671b8664b2709dd97be6107a43c8d66a9",
        ),
        _ => return Err("unknown case".into()),
    };
    Ok(value)
}
