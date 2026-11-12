//! Precompiled ordinary segmentation with the pinned lookahead boundary semantics.

use crate::ContextError;
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, sparse},
};
use std::sync::OnceLock;

const DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ordinary-segmenter.bin"));
type Dfa = sparse::DFA<&'static [u8]>;
static AUTOMATON: OnceLock<Result<Dfa, ContextError>> = OnceLock::new();

pub(super) struct Segmenter(&'static Dfa);

impl Segmenter {
    pub(super) fn new() -> Result<Self, ContextError> {
        // Use the checked loader. Never use from_bytes_unchecked: every state,
        // transition and start-state list must validate before search is possible.
        let dfa = AUTOMATON
            .get_or_init(|| {
                let (dfa, consumed) =
                    sparse::DFA::from_bytes(DATA).map_err(|_| ContextError::Tokenizer)?;
                if consumed != DATA.len() || dfa.pattern_len() != 6 || dfa.has_empty() {
                    return Err(ContextError::Tokenizer);
                }
                Ok(dfa)
            })
            .as_ref()
            .map_err(|_| ContextError::Tokenizer)?;
        Ok(Self(dfa))
    }

    pub(super) fn pieces<'text>(&self, text: &'text str) -> Pieces<'text> {
        Pieces {
            dfa: self.0,
            text,
            position: 0,
        }
    }
}

pub(super) struct Pieces<'text> {
    dfa: &'static Dfa,
    text: &'text str,
    position: usize,
}

impl<'text> Iterator for Pieces<'text> {
    type Item = Result<&'text str, ContextError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.text.len() {
            return None;
        }
        let start = self.position;
        let result = (|| {
            let found = self
                .dfa
                .try_search_fwd(
                    &Input::new(self.text)
                        .span(start..self.text.len())
                        .anchored(Anchored::Yes),
                )
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
            let actual = segmenter.pieces(text).collect::<Result<Vec<_>, _>>()?;
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
    fn checked_loader_rejects_malformed_automata() {
        assert!(sparse::DFA::from_bytes(&[0u8; 64]).is_err());
    }
}
