//! Precompiled ordinary segmentation with the pinned lookahead boundary semantics.

use crate::ContextError;
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense, sparse},
    util::wire::AlignAs,
};
use std::sync::OnceLock;

const DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ordinary-segmenter.bin"));
static ASCII_DATA: &AlignAs<[u8], u32> = &AlignAs {
    _align: [],
    bytes: *include_bytes!(concat!(env!("OUT_DIR"), "/ordinary-ascii-segmenter.bin")),
};
type Dfa = sparse::DFA<&'static [u8]>;
type AsciiDfa = dense::DFA<&'static [u32]>;
static AUTOMATON: OnceLock<Result<Dfa, ContextError>> = OnceLock::new();
static ASCII_AUTOMATON: OnceLock<Result<AsciiDfa, ContextError>> = OnceLock::new();

pub(super) struct Segmenter(&'static AsciiDfa);

impl Segmenter {
    pub(super) fn new() -> Result<Self, ContextError> {
        let dfa = ASCII_AUTOMATON
            .get_or_init(|| {
                let bytes = &ASCII_DATA.bytes;
                let (dfa, consumed) =
                    dense::DFA::from_bytes(bytes).map_err(|_| ContextError::Tokenizer)?;
                if consumed != bytes.len() || dfa.pattern_len() != 6 || dfa.has_empty() {
                    return Err(ContextError::Tokenizer);
                }
                Ok(dfa)
            })
            .as_ref()
            .map_err(|_| ContextError::Tokenizer)?;
        Ok(Self(dfa))
    }

    pub(super) fn pieces<'text>(&self, text: &'text str) -> Result<Pieces<'text>, ContextError> {
        // Select once for the complete input, never from a prefix or a byte within
        // Unicode. Both tables validate before any transition is searched.
        let dfa = if text.is_ascii() {
            Matcher::Ascii(self.0)
        } else {
            Matcher::Unicode(checked(&AUTOMATON, DATA)?)
        };
        Ok(Pieces {
            dfa,
            text,
            position: 0,
        })
    }
}

fn checked(
    cache: &'static OnceLock<Result<Dfa, ContextError>>,
    bytes: &'static [u8],
) -> Result<&'static Dfa, ContextError> {
    // Use the checked loader. Never use from_bytes_unchecked: every state,
    // transition and start-state list must validate before search is possible.
    cache
        .get_or_init(|| {
            let (dfa, consumed) =
                sparse::DFA::from_bytes(bytes).map_err(|_| ContextError::Tokenizer)?;
            if consumed != bytes.len() || dfa.pattern_len() != 6 || dfa.has_empty() {
                return Err(ContextError::Tokenizer);
            }
            Ok(dfa)
        })
        .as_ref()
        .map_err(|_| ContextError::Tokenizer)
}

pub(super) struct Pieces<'text> {
    dfa: Matcher,
    text: &'text str,
    position: usize,
}

#[derive(Clone, Copy)]
enum Matcher {
    Ascii(&'static AsciiDfa),
    Unicode(&'static Dfa),
}

impl<'text> Iterator for Pieces<'text> {
    type Item = Result<&'text str, ContextError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.text.len() {
            return None;
        }
        let start = self.position;
        let result = (|| {
            let input = Input::new(self.text)
                .span(start..self.text.len())
                .anchored(Anchored::Yes);
            let found = match self.dfa {
                Matcher::Ascii(dfa) => dfa.try_search_fwd(&input),
                Matcher::Unicode(dfa) => dfa.try_search_fwd(&input),
            }
            .map_err(|_| ContextError::Tokenizer)?
            .ok_or(ContextError::Tokenizer)?;
            let mut end = found.offset();
            let matched = self.text.get(start..end).ok_or(ContextError::Tokenizer)?;
            if matched.is_empty() {
                return Err(ContextError::Tokenizer);
            }
            if found.pattern().as_usize() == 5 && end < self.text.len() {
                let last = matched
                    .chars()
                    .next_back()
                    .ok_or(ContextError::Tokenizer)?
                    .len_utf8();
                // Upstream \s+(?!\S) greedily consumes all but the last scalar
                // before a nonspace; a single scalar falls through to \s+.
                if matched.len() > last {
                    end -= last;
                }
            }
            self.position = end;
            self.text.get(start..end).ok_or(ContextError::Tokenizer)
        })();
        if result.is_err() {
            self.position = self.text.len();
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_regex::Regex;

    #[test]
    fn exact_piece_boundaries_match_upstream() -> Result<(), Box<dyn std::error::Error>> {
        let segmenter = Segmenter::new()?;
        let oracle = Regex::new(tiktoken_rs::O200K_BASE_PAT_STR)?;
        let verify = |text: &str| -> Result<(), Box<dyn std::error::Error>> {
            let actual = segmenter.pieces(text)?.collect::<Result<Vec<_>, _>>()?;
            let expected = oracle
                .find_iter(text)
                .map(|m| m.map(|m| m.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(actual, expected, "boundary mismatch: {text:?}");
            assert_eq!(actual.concat(), text);
            Ok(())
        };
        for white in [
            " ", "\t", "\r", "\n", "\r\n", "\u{85}", "\u{a0}", "\u{1680}", "\u{2003}", "\u{2028}",
            "\u{2029}", "\u{3000}",
        ] {
            for length in [1, 2, 3, 17, 1024] {
                let prefix = white.repeat(length);
                for suffix in ["", "a", "ABc", "中", "1234", "!?/", "'RE", "\0", "🙂"] {
                    verify(&(prefix.clone() + suffix))?;
                    verify(&("a!?".to_owned() + &prefix + suffix))?;
                }
            }
        }
        let fragments = [
            "a",
            "abc",
            "XYZ",
            "Abc",
            "中",
            "مرحبا",
            "é",
            "e\u{301}",
            "\u{1c89}",
            "\u{1c8a}",
            "1234",
            "１２３４",
            "¼",
            "Ⅻ",
            " ",
            "  ",
            "\t",
            "\n",
            "\r\n",
            "\u{a0}",
            "\u{2028}",
            "🙂",
            "👩‍💻",
            "'s",
            "'ſ",
            "'RE",
            "'ve",
            "!?/",
            "<|endoftext|>",
            "\0",
        ];
        let mut seed = 0x0142_0005_u64;
        for index in 0..20_000 {
            let mut text = String::new();
            for _ in 0..index % 32 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                text.push_str(
                    fragments
                        .get((seed % fragments.len() as u64) as usize)
                        .ok_or("fragment index")?,
                );
            }
            verify(&text)?;
        }
        Ok(())
    }

    #[test]
    fn every_ascii_byte_pair_matches_upstream_boundaries() -> Result<(), Box<dyn std::error::Error>>
    {
        let segmenter = Segmenter::new()?;
        let oracle = Regex::new(tiktoken_rs::O200K_BASE_PAT_STR)?;
        for first in 0..=127u8 {
            for second in 0..=127u8 {
                let text = format!("a{}{}Z's 1234\r\n", char::from(first), char::from(second));
                let actual = segmenter.pieces(&text)?.collect::<Result<Vec<_>, _>>()?;
                let expected = oracle
                    .find_iter(&text)
                    .map(|m| m.map(|m| m.as_str()))
                    .collect::<Result<Vec<_>, _>>()?;
                assert_eq!(actual, expected, "ASCII boundary mismatch: {text:?}");
                assert_eq!(actual.concat(), text);
            }
        }
        Ok(())
    }

    #[test]
    fn checked_loader_rejects_malformed_automata() {
        assert!(sparse::DFA::from_bytes(&[0u8; 64]).is_err());
        assert!(dense::DFA::from_bytes(&[0u8; 64]).is_err());
    }

    #[test]
    fn dense_ascii_embedding_is_aligned_and_rejects_truncation_and_misalignment()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = &ASCII_DATA.bytes;
        let (dfa, consumed) = dense::DFA::from_bytes(bytes)?;
        assert_eq!(consumed, bytes.len());
        assert_eq!(dfa.pattern_len(), 6);
        for length in [0, 1, bytes.len() - 1] {
            assert!(dense::DFA::from_bytes(&bytes[..length]).is_err());
        }
        let mut unaligned = vec![0u8; bytes.len() + 4];
        let offset = if (unaligned.as_ptr() as usize + 1).is_multiple_of(4) {
            2
        } else {
            1
        };
        let slice = &mut unaligned[offset..offset + bytes.len()];
        slice.copy_from_slice(bytes);
        assert!(dense::DFA::from_bytes(slice).is_err());
        Ok(())
    }
}
