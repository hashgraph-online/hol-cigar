//! Prepare the pinned ordinary vocabulary at build time; no runtime input or I/O.

use base64::{Engine as _, engine::general_purpose};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

#[path = "src/tokenizer/ordinary_patterns.rs"]
mod ordinary_patterns;
#[path = "src/tokenizer/vocabulary_hash.rs"]
mod vocabulary_hash;

const ENTRIES: usize = 199_998;
const SLOTS: usize = 1 << 19;
const EMPTY: u32 = u32::MAX;
const EXPECTED_SHA256: [u8; 32] = [
    0x44, 0x6a, 0x95, 0x38, 0xcb, 0x6c, 0x34, 0x8e, 0x35, 0x16, 0x12, 0x0d, 0x7c, 0x08, 0xb0, 0x9f,
    0x57, 0xc3, 0x64, 0x95, 0xe2, 0xac, 0xff, 0xfe, 0x59, 0xa5, 0xbf, 0x8b, 0x0c, 0xfb, 0x1a, 0x2d,
];

fn invalid() -> io::Error {
    io::Error::other("ordinary vocabulary does not match its pinned format/identity")
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/tokenizer/o200k_base.tiktoken");
    println!("cargo:rerun-if-changed=src/tokenizer/vocabulary_hash.rs");
    println!("cargo:rerun-if-changed=src/tokenizer/ordinary_patterns.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BPE");
    if std::env::var_os("CARGO_FEATURE_BPE").is_none() {
        return Ok(());
    }
    let source = fs::read("src/tokenizer/o200k_base.tiktoken")?;
    if Sha256::digest(&source).as_slice() != EXPECTED_SHA256 {
        return Err(invalid().into());
    }
    let mut tokens = HashSet::with_capacity(ENTRIES);
    let mut offsets = Vec::with_capacity(ENTRIES + 1);
    let mut pool = Vec::new();
    let mut slots = vec![EMPTY; SLOTS];
    let mut maximum_probes = 0usize;
    let mut maximum_token_bytes = 0usize;
    for (rank, line) in std::str::from_utf8(&source)?.lines().enumerate() {
        let (encoded, declared) = line.split_once(' ').ok_or_else(invalid)?;
        if declared.parse::<usize>()? != rank || rank >= ENTRIES {
            return Err(invalid().into());
        }
        let token = general_purpose::STANDARD.decode(encoded)?;
        if token.is_empty() || !tokens.insert(token.clone()) {
            return Err(invalid().into());
        }
        offsets.push(u32::try_from(pool.len())?);
        pool.extend_from_slice(&token);
        maximum_token_bytes = maximum_token_bytes.max(token.len());
        let mut slot = vocabulary_hash::hash(&token) as usize & (SLOTS - 1);
        let mut inserted = false;
        for probes in 1..=SLOTS {
            let value = slots.get_mut(slot).ok_or_else(invalid)?;
            if *value == EMPTY {
                *value = u32::try_from(rank)?;
                maximum_probes = maximum_probes.max(probes);
                inserted = true;
                break;
            }
            slot = (slot + 1) & (SLOTS - 1);
        }
        if !inserted {
            return Err(invalid().into());
        }
    }
    if offsets.len() != ENTRIES || !(0..=u8::MAX).all(|byte| tokens.contains(&vec![byte])) {
        return Err(invalid().into());
    }
    offsets.push(u32::try_from(pool.len())?);
    let mut data = Vec::with_capacity(SLOTS * 4 + offsets.len() * 4 + pool.len());
    for value in &slots {
        data.extend_from_slice(&value.to_le_bytes());
    }
    for value in &offsets {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.extend_from_slice(&pool);
    let directory = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(invalid)?);
    fs::write(directory.join("ordinary-vocabulary.bin"), &data)?;
    fs::write(
        directory.join("ordinary-vocabulary.rs"),
        format!(
            "const ENTRIES: usize = {ENTRIES};\nconst SLOTS: usize = {SLOTS};\n\
             const MAX_PROBES: usize = {maximum_probes};\n\
             const MAX_TOKEN_BYTES: usize = {maximum_token_bytes};\n\
             const POOL_BYTES: usize = {};\n\
             const DATA: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/ordinary-vocabulary.bin\"));\n",
            pool.len(),
        ),
    )?;
    let dfa = regex_automata::dfa::dense::Builder::new()
        .configure(
            regex_automata::dfa::dense::Config::new()
                .start_kind(regex_automata::dfa::StartKind::Anchored)
                .match_kind(regex_automata::MatchKind::LeftmostFirst)
                .dfa_size_limit(Some(64 * 1024 * 1024))
                .determinize_size_limit(Some(128 * 1024 * 1024)),
        )
        .build_many(&ordinary_patterns::REGULAR)?
        .to_sparse()?;
    let bytes = match std::env::var("CARGO_CFG_TARGET_ENDIAN")?.as_str() {
        "little" => dfa.to_bytes_little_endian(),
        "big" => dfa.to_bytes_big_endian(),
        _ => return Err(invalid().into()),
    };
    fs::write(directory.join("ordinary-segmenter.bin"), bytes)?;
    Ok(())
}
