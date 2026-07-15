//! Exact CBOR-size probe for the valid protocol fixtures used by local-scale preflight.

use cigar_protocol::{ContextAtomV1, ContextEdge, Validate};
use serde_json::json;
use std::error::Error;
use std::io::{self, Write as _};

fn fixture<T>(target: &str) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned + Validate,
{
    let fixture = cigar_testkit::deterministic_protocol_fixture(target)
        .ok_or("required deterministic protocol fixture is absent")?;
    let value: T = serde_json::from_value(fixture.input)?;
    value.validate()?;
    Ok(value)
}

fn cbor_length<T: serde::Serialize>(value: &T) -> Result<usize, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    Ok(bytes.len())
}

fn main() -> Result<(), Box<dyn Error>> {
    let atom: ContextAtomV1 = fixture("ContextAtomV1")?;
    let edge: ContextEdge = fixture("ContextEdge")?;
    let atom_bytes = cbor_length(&atom)?;
    let edge_bytes = cbor_length(&edge)?;
    let version_text_bytes = cbor_length(&atom.version_id)?;
    let uuid_text_bytes = cbor_length(&atom.atom_id)?;
    let output = json!({
        "schema_version": "cigar.local-scale-record-probe.v1",
        "atom_cbor_bytes": atom_bytes,
        "edge_cbor_bytes": edge_bytes,
        "uuid_cbor_text_bytes": uuid_text_bytes,
        "version_cbor_text_bytes": version_text_bytes,
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
