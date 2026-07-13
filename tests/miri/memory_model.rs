use cigar_canon::{CanonicalNode, from_deterministic_cbor, to_deterministic_cbor};
use cigar_protocol::{RelativePath, SourceUri};
use std::collections::BTreeMap;

#[test]
fn canonical_and_identity_memory_model_is_clean() {
    let node = CanonicalNode::Map(BTreeMap::from([
        ("a".to_owned(), CanonicalNode::Unsigned(1)),
        (
            "b".to_owned(),
            CanonicalNode::Array(vec![CanonicalNode::Text("é".to_owned())]),
        ),
    ]));
    let encoded = to_deterministic_cbor(&node).expect("canonical CBOR encoding");
    assert_eq!(
        from_deterministic_cbor(&encoded).expect("canonical CBOR decoding"),
        node
    );
    assert!(RelativePath::new(b"safe/path".to_vec()).is_ok());
    assert!(RelativePath::new(b"/absolute".to_vec()).is_err());
    assert!(SourceUri::new("file:///bounded/path").is_ok());
}
