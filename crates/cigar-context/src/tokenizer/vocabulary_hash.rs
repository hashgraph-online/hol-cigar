//! Platform-independent lookup hash for a fixed, read-only vocabulary.
//!
//! Hashes are not identities or authentication. Exact bytes decide membership;
//! the generated maximum probe count bounds every lookup, including misses.

pub(super) fn hash(bytes: &[u8]) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}
