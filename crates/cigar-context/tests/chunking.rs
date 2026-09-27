//! Parser-owned boundaries preserve exact source bytes; the native library makes no AST claim.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use cigar_context::{ContextError, Document};

#[test]
fn explicit_boundaries_partition_utf8_and_line_endings_with_absolute_citations() {
    let mut document = Document::new(
        "code",
        "project://code",
        "// café 🦀\r\nfn a() {\r\n  run();\r\n}\r\n\r\nfn b() {}\n",
    );
    document.start_line = 40;
    let chunks = document.chunks_at_lines(&[45]).unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].id, "code:L40");
    assert_eq!(chunks[1].id, "code:L45");
    assert_eq!(chunks[0].start_line, 40);
    assert_eq!(chunks[1].start_line, 45);
    assert_eq!(chunks[1].text, "fn b() {}\n");
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect::<String>(),
        document.text
    );
    assert!(chunks.iter().all(|chunk| chunk.source == document.source));
    assert_eq!(
        document.chunks_at_lines(&[]).unwrap()[0].text,
        document.text
    );
}

#[test]
fn malformed_ambiguous_or_empty_partitions_are_rejected() {
    let document = Document::new("code", "source", "first\n\nthird\n");
    for starts in [
        vec![0],
        vec![1],
        vec![4],
        vec![3, 2],
        vec![3, 3],
        vec![2, 3],
    ] {
        assert_eq!(
            document.chunks_at_lines(&starts),
            Err(ContextError::InvalidInput)
        );
    }
    let mut changed = document.clone();
    changed.id = "x".repeat(101);
    assert_eq!(
        changed.chunks_at_lines(&[]),
        Err(ContextError::InvalidInput)
    );
    changed = document.clone();
    changed.start_line = 0;
    assert_eq!(
        changed.chunks_at_lines(&[]),
        Err(ContextError::InvalidInput)
    );
    for source in ["", "invalid\nsource"] {
        changed = document.clone();
        changed.source = source.into();
        assert_eq!(
            changed.chunks_at_lines(&[]),
            Err(ContextError::InvalidInput)
        );
    }
    changed.text = " \n\t".into();
    changed.source = "source".into();
    assert_eq!(
        changed.chunks_at_lines(&[]),
        Err(ContextError::InvalidInput)
    );
}

#[test]
fn exact_input_chunk_and_line_overflow_limits_apply_before_copying() {
    let document = Document::new("code", "source", "x\n".repeat(4096));
    assert_eq!(
        document
            .chunks_at_lines(&(2..=4096).collect::<Vec<_>>())
            .unwrap()
            .len(),
        4096
    );
    assert_eq!(
        document.chunks_at_lines(&(2..=4097).collect::<Vec<_>>()),
        Err(ContextError::LimitExceeded)
    );
    let max = Document::new("large", "source", "x".repeat(16_777_216));
    assert_eq!(max.chunks_at_lines(&[]).unwrap()[0].text.len(), 16_777_216);
    let oversized = Document {
        text: "x".repeat(16_777_217),
        ..max
    };
    assert_eq!(
        oversized.chunks_at_lines(&[]),
        Err(ContextError::LimitExceeded)
    );
    let mut last = Document::new("last", "source", "one");
    last.start_line = usize::MAX;
    assert_eq!(last.chunks_at_lines(&[]).unwrap()[0].start_line, usize::MAX);
    last.text = "one\ntwo".into();
    assert_eq!(last.chunks_at_lines(&[]), Err(ContextError::LimitExceeded));
}
