//! Verifies the shared semantic-bundle fixture and prints its cross-SDK bundle identity.

use cigar_sdk::verify_semantic_bundle_fixture_json;

const FIXTURE: &[u8] = include_bytes!("../fixtures/semantic-bundle-v1.json");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle_id = verify_semantic_bundle_fixture_json(FIXTURE)?;
    println!("{}", bundle_id.as_str());
    Ok(())
}
