#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cigar_fuzz::policy_parse_evaluate(data));
