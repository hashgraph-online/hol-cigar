//! Count-only o200k ordinary encoding, without unused decoder/special-token tables.
//!
//! Uses the exact vocabulary, regex and merge rules from pinned tiktoken-rs 0.12.0.
//! The heap merge below is adapted from that crate's vendor_tiktoken.rs (OpenAI
//! tiktoken, MIT; see LICENSE.tiktoken). Rank/start tie-breaking is unchanged.
//! Long pieces retain the upstream heap algorithm rather than quadratic splitting.

use crate::ContextError;
use base64::{Engine as _, engine::general_purpose};
use fancy_regex::Regex;
use rustc_hash::FxHashMap;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use tiktoken_rs::Rank;

const VOCABULARY: &str = include_str!("o200k_base.tiktoken");
const ORDINARY_TOKENS: usize = 199_998;

pub(super) struct OrdinaryCounter {
    encoder: FxHashMap<Vec<u8>, Rank>,
    regex: Regex,
}

impl OrdinaryCounter {
    pub(super) fn new() -> Result<Self, ContextError> {
        let mut encoder = FxHashMap::with_capacity_and_hasher(ORDINARY_TOKENS, Default::default());
        for (index, line) in VOCABULARY.lines().enumerate() {
            let (encoded, rank) = line.split_once(' ').ok_or(ContextError::Tokenizer)?;
            let rank: Rank = rank.parse().map_err(|_| ContextError::Tokenizer)?;
            if usize::try_from(rank).map_err(|_| ContextError::Tokenizer)? != index {
                return Err(ContextError::Tokenizer);
            }
            let token = general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ContextError::Tokenizer)?;
            if token.is_empty() || encoder.insert(token, rank).is_some() {
                return Err(ContextError::Tokenizer);
            }
        }
        if encoder.len() != ORDINARY_TOKENS
            || !(0..=u8::MAX).all(|b| encoder.contains_key(&[b][..]))
        {
            return Err(ContextError::Tokenizer);
        }
        let regex =
            Regex::new(tiktoken_rs::O200K_BASE_PAT_STR).map_err(|_| ContextError::Tokenizer)?;
        Ok(Self { encoder, regex })
    }

    pub(super) fn count(&self, text: &str) -> Result<usize, ContextError> {
        let mut count = 0usize;
        for matched in self.regex.find_iter(text) {
            let piece = matched
                .map_err(|_| ContextError::Tokenizer)?
                .as_str()
                .as_bytes();
            let tokens = if self.encoder.contains_key(piece) {
                1
            } else if piece.len() < 100 {
                // Same short-piece merge as the upstream encoder. Every byte is in
                // the immutable vocabulary, so a non-token piece has at least 2 bytes.
                tiktoken_rs::byte_pair_split(piece, &self.encoder).len()
            } else {
                count_large(piece, &self.encoder)
            };
            count = count.checked_add(tokens).ok_or(ContextError::Tokenizer)?;
        }
        Ok(count)
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
struct Merge {
    start: usize,
    rank: Rank,
}

impl Ord for Merge {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .rank
            .cmp(&self.rank)
            .then_with(|| other.start.cmp(&self.start))
    }
}

impl PartialOrd for Merge {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct State {
    prev: usize,
    end: usize,
    next_end: usize,
    next_rank: Rank,
}

fn count_large(piece: &[u8], ranks: &FxHashMap<Vec<u8>, Rank>) -> usize {
    let mut state = Vec::with_capacity(piece.len());
    state.push(State {
        prev: usize::MAX,
        end: 1,
        next_end: 2,
        next_rank: Rank::MAX,
    });
    let mut heap = BinaryHeap::with_capacity(piece.len());
    for i in 0..piece.len() - 1 {
        if let Some(&rank) = ranks.get(&piece[i..i + 2]) {
            heap.push(Merge { start: i, rank });
            state[i].next_rank = rank;
        }
        state.push(State {
            prev: i,
            end: i + 2,
            next_end: i + 3,
            next_rank: Rank::MAX,
        });
    }
    let potential_merge =
        |state: &mut Vec<State>, heap: &mut BinaryHeap<Merge>, start: usize, next_end: usize| {
            state[start].next_end = next_end;
            state[start].next_rank = Rank::MAX;
            if next_end <= piece.len()
                && let Some(&rank) = ranks.get(&piece[start..next_end])
            {
                heap.push(Merge { start, rank });
                state[start].next_rank = rank;
            }
        };
    let mut tokens = piece.len();
    while let Some(left) = heap.pop() {
        if left.rank == Rank::MAX {
            break;
        }
        if left.rank != state[left.start].next_rank {
            continue;
        }
        let start = left.start;
        let right_start = state[start].end;
        let right_end = state[start].next_end;
        debug_assert_eq!(right_end, state[right_start].end);
        let right_next_end = state[right_start].next_end;
        state[start].end = right_end;
        potential_merge(&mut state, &mut heap, start, right_next_end);
        if right_end < state.len() {
            state[right_end].prev = start;
        }
        if start > 0 {
            let previous = state[start].prev;
            potential_merge(&mut state, &mut heap, previous, right_end);
        }
        state[right_start].next_rank = Rank::MAX;
        tokens -= 1;
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn vocabulary_is_exact_pinned_o200k() {
        let expected: [u8; 32] = [
            0x44, 0x6a, 0x95, 0x38, 0xcb, 0x6c, 0x34, 0x8e, 0x35, 0x16, 0x12, 0x0d, 0x7c, 0x08,
            0xb0, 0x9f, 0x57, 0xc3, 0x64, 0x95, 0xe2, 0xac, 0xff, 0xfe, 0x59, 0xa5, 0xbf, 0x8b,
            0x0c, 0xfb, 0x1a, 0x2d,
        ];
        assert_eq!(&Sha256::digest(VOCABULARY.as_bytes())[..], &expected);
        assert_eq!(VOCABULARY.lines().count(), ORDINARY_TOKENS);
    }

    #[test]
    fn counts_match_upstream_unicode_special_and_long_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let counter = OrdinaryCounter::new()?;
        let oracle = tiktoken_rs::o200k_base()?;
        let mut texts = vec![
            String::new(),
            "Hello, world!\r\n".into(),
            "<|endoftext|><|endofprompt|>".into(),
            "中文 العربية Русский 🙂👩‍💻 e\u{301} \0\t".into(),
        ];
        for length in [1, 2, 98, 99, 100, 101, 1024, 32_768] {
            texts.push("x".repeat(length));
            texts.push("中文".repeat(length));
            texts.push(" ".repeat(length));
        }
        let alphabet: Vec<char> = "abcXYZ09 _\n\r\t'\"<>|{}[]é中🙂\u{301}\0".chars().collect();
        let mut seed = 0x0142_u64;
        for index in 0..2000 {
            let mut text = String::new();
            for _ in 0..index % 513 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                text.push(alphabet[(seed % alphabet.len() as u64) as usize]);
            }
            texts.push(text);
        }
        // Mixed long ordinary pieces stress stale heap entries and merge ties;
        // short random strings usually split at regex boundaries before the heap.
        for length in [99, 100, 101, 511, 4096, 32_768] {
            for alphabet in ["abcdefghijklmnopqrstuvwxyz", "!?/+=_-.,:;"] {
                let alphabet = alphabet.as_bytes();
                let mut text = String::with_capacity(length);
                for _ in 0..length {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    text.push(alphabet[(seed % alphabet.len() as u64) as usize] as char);
                }
                texts.push(text);
            }
        }
        for text in texts {
            assert_eq!(
                counter.count(&text)?,
                oracle.count_ordinary(&text),
                "mismatch for {} bytes",
                text.len()
            );
        }
        Ok(())
    }

    #[test]
    fn counting_is_safe_to_share_across_threads() -> Result<(), Box<dyn std::error::Error>> {
        let counter = std::sync::Arc::new(OrdinaryCounter::new()?);
        let oracle = tiktoken_rs::o200k_base()?;
        let text = "Concurrency with Unicode 中文 🙂 and ordinary <|endoftext|>.".repeat(30);
        let expected = oracle.count_ordinary(&text);
        let mut threads = Vec::new();
        for _ in 0..8 {
            let counter = std::sync::Arc::clone(&counter);
            let text = text.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..30 {
                    assert_eq!(counter.count(&text), Ok(expected));
                }
            }));
        }
        for thread in threads {
            thread.join().map_err(|_| "counter thread panicked")?;
        }
        Ok(())
    }
}
