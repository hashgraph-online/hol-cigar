//! Shared cross-SDK semantic quickstart qualification.

use cigar_sdk::verify_semantic_bundle_fixture_json;

const PACKAGE_FIXTURE: &[u8] = include_bytes!("../fixtures/semantic-bundle-v1.json");
const SHARED_FIXTURE: &[u8] = include_bytes!("../../fixtures/semantic-bundle-v1.json");
const EXPECTED: &str = "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84";

#[test]
fn shared_fixture_produces_the_frozen_bundle_id() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(PACKAGE_FIXTURE, SHARED_FIXTURE);
    let identity = verify_semantic_bundle_fixture_json(SHARED_FIXTURE)?;
    assert_eq!(identity.as_str(), EXPECTED);
    Ok(())
}
