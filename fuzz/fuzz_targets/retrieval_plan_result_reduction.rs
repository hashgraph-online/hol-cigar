#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cigar_fuzz::retrieval_plan_result_reduction(data));
