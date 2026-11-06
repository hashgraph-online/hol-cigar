//! Count-only o200k ordinary encoding, without unused decoder/special-token tables.
//!
//! Uses the exact vocabulary, regex and merge rules from pinned tiktoken-rs 0.12.0.
//! The heap merge below is adapted from that crate's vendor_tiktoken.rs (OpenAI
//! tiktoken, MIT; see LICENSE.tiktoken). Rank/start tie-breaking is unchanged.
//! Long pieces retain the upstream heap algorithm rather than quadratic splitting.

use super::vocabulary::Encoder;
use crate::ContextError;
use fancy_regex::Regex;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use tiktoken_rs::Rank;

#[cfg(test)]
const VOCABULARY: &str = include_str!("o200k_base.tiktoken");
#[cfg(test)]
const ORDINARY_TOKENS: usize = 199_998;

pub(super) struct OrdinaryCounter {
    encoder: Encoder,
    regex: Regex,
}

impl OrdinaryCounter {
    pub(super) fn new() -> Result<Self, ContextError> {
        // The build validates the pinned source identity and every rank/byte,
        // then embeds a deterministic, read-only table. No text parsing, map
        // construction, cache widening or external vocabulary I/O at startup.
        let encoder = Encoder::new()?;
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
            let tokens = if self.encoder.get(piece)?.is_some() {
                1
            } else if piece.len() < 100 {
                count_short(piece, &self.encoder)?
            } else {
                count_large(piece, &self.encoder)?
            };
            count = count.checked_add(tokens).ok_or(ContextError::Tokenizer)?;
        }
        Ok(count)
    }
}

// Same greedy rank/leftmost ordering as upstream's short-piece merge. It is
// deliberately bounded to fewer than 100 bytes; long input uses the heap.
fn count_short(piece: &[u8], ranks: &Encoder) -> Result<usize, ContextError> {
    if !(2..100).contains(&piece.len()) {
        return Err(ContextError::Tokenizer);
    }
    let mut parts = Vec::with_capacity(piece.len() + 1);
    for (start, pair) in piece.windows(2).enumerate() {
        parts.push((start, ranks.get(pair)?.unwrap_or(Rank::MAX)));
    }
    parts.push((piece.len() - 1, Rank::MAX));
    parts.push((piece.len(), Rank::MAX));
    loop {
        let mut best = (Rank::MAX, usize::MAX);
        for (index, &(_, rank)) in parts.iter().take(parts.len() - 1).enumerate() {
            if rank < best.0 {
                best = (rank, index);
            }
        }
        if best.0 == Rank::MAX {
            break;
        }
        let rank_after_merge = |index: usize| -> Result<Rank, ContextError> {
            let Some(&(end, _)) = parts.get(index + 3) else {
                return Ok(Rank::MAX);
            };
            let start = parts.get(index).ok_or(ContextError::Tokenizer)?.0;
            let span = piece.get(start..end).ok_or(ContextError::Tokenizer)?;
            Ok(ranks.get(span)?.unwrap_or(Rank::MAX))
        };
        let index = best.1;
        let current = rank_after_merge(index)?;
        let previous = if index > 0 {
            Some(rank_after_merge(index - 1)?)
        } else {
            None
        };
        if let Some(rank) = previous {
            parts.get_mut(index - 1).ok_or(ContextError::Tokenizer)?.1 = rank;
        }
        parts.get_mut(index).ok_or(ContextError::Tokenizer)?.1 = current;
        if index + 1 >= parts.len() - 1 {
            return Err(ContextError::Tokenizer);
        }
        parts.remove(index + 1);
    }
    parts.len().checked_sub(1).ok_or(ContextError::Tokenizer)
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

fn count_large(piece: &[u8], ranks: &Encoder) -> Result<usize, ContextError> {
    if piece.len() < 2 {
        return Err(ContextError::Tokenizer);
    }
    let mut state = Vec::with_capacity(piece.len());
    state.push(State {
        prev: usize::MAX,
        end: 1,
        next_end: 2,
        next_rank: Rank::MAX,
    });
    let mut heap = BinaryHeap::with_capacity(piece.len());
    for (i, pair) in piece.windows(2).enumerate() {
        if let Some(rank) = ranks.get(pair)? {
            heap.push(Merge { start: i, rank });
            state.get_mut(i).ok_or(ContextError::Tokenizer)?.next_rank = rank;
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
            let current = state.get_mut(start).ok_or(ContextError::Tokenizer)?;
            current.next_end = next_end;
            current.next_rank = Rank::MAX;
            if next_end <= piece.len() {
                let span = piece.get(start..next_end).ok_or(ContextError::Tokenizer)?;
                if let Some(rank) = ranks.get(span)? {
                    heap.push(Merge { start, rank });
                    current.next_rank = rank;
                }
            }
            Ok::<(), ContextError>(())
        };
    let mut tokens = piece.len();
    while let Some(left) = heap.pop() {
        if left.rank == Rank::MAX {
            break;
        }
        let current = state.get(left.start).ok_or(ContextError::Tokenizer)?;
        if left.rank != current.next_rank {
            continue;
        }
        let start = left.start;
        let previous = current.prev;
        let right_start = current.end;
        let right_end = current.next_end;
        let right = state.get(right_start).ok_or(ContextError::Tokenizer)?;
        if right_end != right.end {
            return Err(ContextError::Tokenizer);
        }
        let right_next_end = right.next_end;
        state.get_mut(start).ok_or(ContextError::Tokenizer)?.end = right_end;
        potential_merge(&mut state, &mut heap, start, right_next_end)?;
        if right_end < state.len() {
            state
                .get_mut(right_end)
                .ok_or(ContextError::Tokenizer)?
                .prev = start;
        }
        if start > 0 {
            potential_merge(&mut state, &mut heap, previous, right_end)?;
        }
        state
            .get_mut(right_start)
            .ok_or(ContextError::Tokenizer)?
            .next_rank = Rank::MAX;
        tokens = tokens.checked_sub(1).ok_or(ContextError::Tokenizer)?;
    }
    Ok(tokens)
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
                text.push(
                    *alphabet
                        .get((seed % alphabet.len() as u64) as usize)
                        .ok_or("alphabet index")?,
                );
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
                    text.push(
                        *alphabet
                            .get((seed % alphabet.len() as u64) as usize)
                            .ok_or("alphabet index")? as char,
                    );
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
