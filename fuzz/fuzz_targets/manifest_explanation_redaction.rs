#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cigar_fuzz::manifest_explanation_redaction(data));
