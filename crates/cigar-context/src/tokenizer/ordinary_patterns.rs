//! Ordered alternatives of pinned tiktoken-rs 0.12.0's ordinary o200k pattern.
//!
//! The last regular alternative is greedy whitespace. The segmenter restores
//! the upstream negative lookahead by reserving its last scalar before nonspace.

pub(super) const REGULAR: [&str; 6] = [
    r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
    r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
    r"\p{N}{1,3}",
    r" ?[^\s\p{L}\p{N}]+[\r\n/]*",
    r"\s*[\r\n]+",
    r"\s+",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_alternatives_are_exact_pinned_upstream() {
        let mut parts = REGULAR.to_vec();
        parts.pop();
        parts.push(r"\s+(?!\S)");
        parts.push(r"\s+");
        assert_eq!(parts.join("|"), tiktoken_rs::O200K_BASE_PAT_STR);
    }
}
