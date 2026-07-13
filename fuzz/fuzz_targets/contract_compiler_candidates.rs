#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cigar_fuzz::contract_compiler_candidates(data));
