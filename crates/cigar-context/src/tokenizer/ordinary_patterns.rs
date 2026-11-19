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

// The exact restrictions of REGULAR to entirely ASCII input. Keep every class
// ASCII-bounded so the checked automaton stays small; never use it for Unicode.
// Contraction case pairs avoid expanding Unicode case-fold classes at build time.
pub(super) const ASCII_REGULAR: [&str; 6] = [
    r"[\x00-\x7f&&[^\r\nA-Za-z0-9]]?[A-Z]*[a-z]+(?:'[sStTmMdD]|'[rR][eE]|'[vV][eE]|'[lL][lL])?",
    r"[\x00-\x7f&&[^\r\nA-Za-z0-9]]?[A-Z]+[a-z]*(?:'[sStTmMdD]|'[rR][eE]|'[vV][eE]|'[lL][lL])?",
    r"[0-9]{1,3}",
    r" ?[\x00-\x7f&&[^\t\n\x0B\f\r A-Za-z0-9]]+[\r\n/]*",
    r"[\t\n\x0B\f\r ]*[\r\n]+",
    r"[\t\n\x0B\f\r ]+",
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

    #[test]
    fn ascii_alternatives_cover_ascii_without_unicode_expansion()
    -> Result<(), Box<dyn std::error::Error>> {
        let pattern = fancy_regex::Regex::new(&ASCII_REGULAR.join("|"))?;
        for byte in 0..=127u8 {
            let text = char::from(byte).to_string();
            assert_eq!(
                pattern.find(&text)?.map(|m| m.as_str()),
                Some(text.as_str())
            );
        }
        for text in ["é", "中", "🙂", "ſ", "K", "\u{85}", "\u{a0}", "\u{2028}"] {
            assert!(pattern.find(text)?.is_none());
        }
        Ok(())
    }
}
