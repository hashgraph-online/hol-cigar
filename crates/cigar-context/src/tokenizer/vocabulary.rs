//! Exact zero-copy lookup in the build-validated immutable ordinary vocabulary.

use super::vocabulary_hash;
use crate::ContextError;
use tiktoken_rs::Rank;

include!(concat!(env!("OUT_DIR"), "/ordinary-vocabulary.rs"));

pub(super) struct Encoder;

fn word(offset: usize) -> Result<u32, ContextError> {
    let end = offset.checked_add(4).ok_or(ContextError::Tokenizer)?;
    let bytes = DATA.get(offset..end).ok_or(ContextError::Tokenizer)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| ContextError::Tokenizer)?,
    ))
}

impl Encoder {
    pub(super) fn new() -> Result<Self, ContextError> {
        if !SLOTS.is_power_of_two()
            || ENTRIES != 199_998
            || MAX_PROBES == 0
            || MAX_PROBES > SLOTS
            || DATA.len() != SLOTS * 4 + (ENTRIES + 1) * 4 + POOL_BYTES
            || word(SLOTS * 4)? != 0
            || word(SLOTS * 4 + ENTRIES * 4)? as usize != POOL_BYTES
        {
            return Err(ContextError::Tokenizer);
        }
        Ok(Self)
    }

    pub(super) fn get(&self, piece: &[u8]) -> Result<Option<Rank>, ContextError> {
        if piece.is_empty() || piece.len() > MAX_TOKEN_BYTES {
            return Ok(None);
        }
        let mut slot = vocabulary_hash::hash(piece) as usize & (SLOTS - 1);
        for _ in 0..MAX_PROBES {
            let rank = word(slot * 4)?;
            if rank == Rank::MAX {
                return Ok(None);
            }
            if rank as usize >= ENTRIES {
                return Err(ContextError::Tokenizer);
            }
            let offset = SLOTS * 4 + rank as usize * 4;
            let pool_start = SLOTS * 4 + (ENTRIES + 1) * 4;
            let start = pool_start
                .checked_add(word(offset)? as usize)
                .ok_or(ContextError::Tokenizer)?;
            let end = pool_start
                .checked_add(word(offset + 4)? as usize)
                .ok_or(ContextError::Tokenizer)?;
            let token = DATA.get(start..end).ok_or(ContextError::Tokenizer)?;
            if token == piece {
                return Ok(Some(rank));
            }
            slot = (slot + 1) & (SLOTS - 1);
        }
        // The generator records the maximum successful probe count. An exact
        // member must have matched by now; misses cannot create longer work.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};

    #[test]
    fn every_pinned_token_resolves_to_its_exact_rank() -> Result<(), Box<dyn std::error::Error>> {
        let encoder = Encoder::new()?;
        for (rank, line) in include_str!("o200k_base.tiktoken").lines().enumerate() {
            let (encoded, _) = line.split_once(' ').ok_or("missing rank")?;
            let bytes = general_purpose::STANDARD.decode(encoded)?;
            assert_eq!(encoder.get(&bytes)?, Some(Rank::try_from(rank)?));
        }
        assert_eq!(encoder.get(&[])?, None);
        assert_eq!(encoder.get(&[b'x'; MAX_TOKEN_BYTES + 1])?, None);
        Ok(())
    }
}
