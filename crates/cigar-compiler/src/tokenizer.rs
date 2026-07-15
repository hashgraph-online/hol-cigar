//! Provider-neutral exact reference tokenizer profiles.

use crate::{ExactTokenizer, MaterializationError};
use cigar_protocol::{ContentDigest, TargetProfile};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Stable identifier for exact strict-UTF-8 byte accounting.
pub const REFERENCE_UTF8_BYTES_V1_ID: &str = "cigar.reference-tokenizer.utf8-bytes.v1";
/// Closed provider identity for every built-in reference tokenizer target.
pub const REFERENCE_TOKENIZER_PROVIDER: &str = "cigar-reference";
/// Stable identifier for exact strict-UTF-8 Unicode-scalar accounting.
pub const REFERENCE_UNICODE_SCALARS_V1_ID: &str = "cigar.reference-tokenizer.unicode-scalars.v1";
/// Locked multihash fingerprint for [`ReferenceTokenizerProfile::Utf8BytesV1`].
pub const REFERENCE_UTF8_BYTES_V1_FINGERPRINT: &str =
    "1220704360550f3e648c66e8333d6f68beccead8c630c31b640385e72bcaf3266657";
/// Locked multihash fingerprint for [`ReferenceTokenizerProfile::UnicodeScalarsV1`].
pub const REFERENCE_UNICODE_SCALARS_V1_FINGERPRINT: &str =
    "122058b866c7331871a2fade5b05daeff49a08003576423570e9d2f2be5f82bb3739";

const TOKENIZER_FINGERPRINT_DOMAIN: &[u8] = b"CIGAR-REFERENCE-TOKENIZER-FINGERPRINT\0v1\0";
const INPUT_ENCODING: &str = "strict-utf8";
const EMPTY_INPUT_BEHAVIOR: &str = "reject-empty";
const OVERFLOW_BEHAVIOR: &str = "reject-u32-overflow";

/// Closed provider-neutral exact reference tokenizer profiles.
///
/// These profiles are accounting references. They are not aliases for any external model or
/// provider tokenizer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReferenceTokenizerProfile {
    /// Validates strict UTF-8 and counts each encoded byte as one exact reference token.
    Utf8BytesV1,
    /// Validates strict UTF-8 and counts each Unicode scalar as one exact reference token.
    UnicodeScalarsV1,
}

impl ReferenceTokenizerProfile {
    /// Every built-in profile in stable identifier order.
    pub const ALL: [Self; 2] = [Self::UnicodeScalarsV1, Self::Utf8BytesV1];

    /// Returns the stable provider-neutral profile identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Utf8BytesV1 => REFERENCE_UTF8_BYTES_V1_ID,
            Self::UnicodeScalarsV1 => REFERENCE_UNICODE_SCALARS_V1_ID,
        }
    }

    /// Returns the immutable algorithm/configuration fingerprint for this profile.
    pub fn fingerprint(self) -> Result<ContentDigest, MaterializationError> {
        reference_fingerprint(self)
    }

    /// Constructs a target whose provider, model family, and tokenizer fingerprint are coherent.
    pub fn target_profile(
        self,
        materializer_fingerprint: ContentDigest,
        max_context_tokens: u32,
    ) -> Result<TargetProfile, MaterializationError> {
        if max_context_tokens == 0 {
            return Err(MaterializationError::InvalidInput);
        }
        Ok(TargetProfile {
            provider: REFERENCE_TOKENIZER_PROVIDER.to_owned(),
            model_family: self.identifier().to_owned(),
            tokenizer_fingerprint: self.fingerprint()?,
            materializer_fingerprint,
            max_context_tokens,
        })
    }

    /// Checks the complete provider/model/tokenizer tuple without considering materialization.
    pub fn matches_target(self, target: &TargetProfile) -> Result<bool, MaterializationError> {
        Ok(target.provider == REFERENCE_TOKENIZER_PROVIDER
            && target.model_family == self.identifier()
            && target.tokenizer_fingerprint == self.fingerprint()?)
    }

    const fn accounting_unit(self) -> &'static str {
        match self {
            Self::Utf8BytesV1 => "encoded-byte",
            Self::UnicodeScalarsV1 => "unicode-scalar-value",
        }
    }
}

/// One exact tokenizer whose algorithm and configuration are fixed by a reference profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceTokenizer {
    profile: ReferenceTokenizerProfile,
    fingerprint: ContentDigest,
}

impl ReferenceTokenizer {
    /// Constructs one built-in tokenizer with its derived immutable fingerprint.
    pub fn new(profile: ReferenceTokenizerProfile) -> Result<Self, MaterializationError> {
        Ok(Self {
            profile,
            fingerprint: profile.fingerprint()?,
        })
    }

    /// Returns the exact built-in profile.
    #[must_use]
    pub const fn profile(&self) -> ReferenceTokenizerProfile {
        self.profile
    }
}

impl ExactTokenizer for ReferenceTokenizer {
    fn fingerprint(&self) -> &ContentDigest {
        &self.fingerprint
    }

    fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError> {
        if bytes.is_empty() {
            return Err(MaterializationError::InvalidInput);
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_error| MaterializationError::InvalidInput)?;
        match self.profile {
            ReferenceTokenizerProfile::Utf8BytesV1 => checked_token_count(bytes.len()),
            ReferenceTokenizerProfile::UnicodeScalarsV1 => {
                checked_token_count(text.chars().count())
            }
        }
    }
}

/// Resolves only built-in reference fingerprints and returns `None` for every unknown fingerprint.
pub fn resolve_reference_tokenizer(
    fingerprint: &ContentDigest,
) -> Result<Option<ReferenceTokenizer>, MaterializationError> {
    for profile in ReferenceTokenizerProfile::ALL {
        let tokenizer = ReferenceTokenizer::new(profile)?;
        if ExactTokenizer::fingerprint(&tokenizer) == fingerprint {
            return Ok(Some(tokenizer));
        }
    }
    Ok(None)
}

/// Resolves only a coherent built-in provider/model/fingerprint target tuple.
pub fn resolve_reference_tokenizer_target(
    target: &TargetProfile,
) -> Result<Option<ReferenceTokenizer>, MaterializationError> {
    for profile in ReferenceTokenizerProfile::ALL {
        if profile.matches_target(target)? {
            return ReferenceTokenizer::new(profile).map(Some);
        }
    }
    Ok(None)
}

fn reference_fingerprint(
    profile: ReferenceTokenizerProfile,
) -> Result<ContentDigest, MaterializationError> {
    let mut hasher = Sha256::new();
    hasher.update(TOKENIZER_FINGERPRINT_DOMAIN);
    for field in [
        profile.identifier(),
        INPUT_ENCODING,
        profile.accounting_unit(),
        EMPTY_INPUT_BEHAVIOR,
        OVERFLOW_BEHAVIOR,
    ] {
        hash_frame(&mut hasher, field.as_bytes())?;
    }
    let mut multihash = String::from("1220");
    for byte in hasher.finalize() {
        write!(&mut multihash, "{byte:02x}")
            .map_err(|_error| MaterializationError::Serialization)?;
    }
    ContentDigest::new(multihash).map_err(|_error| MaterializationError::Serialization)
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) -> Result<(), MaterializationError> {
    let length =
        u64::try_from(value.len()).map_err(|_error| MaterializationError::LimitExceeded)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn checked_token_count(value: usize) -> Result<u32, MaterializationError> {
    u32::try_from(value).map_err(|_error| MaterializationError::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::{
        REFERENCE_UNICODE_SCALARS_V1_FINGERPRINT, REFERENCE_UTF8_BYTES_V1_FINGERPRINT,
        ReferenceTokenizer, ReferenceTokenizerProfile, checked_token_count,
        resolve_reference_tokenizer, resolve_reference_tokenizer_target,
    };
    use crate::{ExactTokenizer, MaterializationError};
    use cigar_protocol::ContentDigest;
    use std::error::Error;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn reference_counts_are_exact_deterministic_and_utf8_strict() -> Result<(), Box<dyn Error>> {
        let bytes = "aé🙂".as_bytes();
        let byte = ReferenceTokenizer::new(ReferenceTokenizerProfile::Utf8BytesV1)?;
        let scalar = ReferenceTokenizer::new(ReferenceTokenizerProfile::UnicodeScalarsV1)?;
        assert_eq!(byte.count_exact(bytes)?, 7);
        assert_eq!(scalar.count_exact(bytes)?, 3);
        for tokenizer in [&byte, &scalar] {
            assert_eq!(
                tokenizer.count_exact(&[]),
                Err(MaterializationError::InvalidInput)
            );
            assert_eq!(
                tokenizer.count_exact(&[0xff, 0xfe]),
                Err(MaterializationError::InvalidInput)
            );
            for _repeat in 0..100 {
                assert_eq!(tokenizer.count_exact(bytes)?, tokenizer.count_exact(bytes)?);
            }
        }
        Ok(())
    }

    #[test]
    fn resolver_accepts_known_fingerprints_and_rejects_unknown() -> Result<(), Box<dyn Error>> {
        for profile in ReferenceTokenizerProfile::ALL {
            let fingerprint = profile.fingerprint()?;
            let resolved = resolve_reference_tokenizer(&fingerprint)?
                .ok_or("known reference tokenizer did not resolve")?;
            assert_eq!(resolved.profile(), profile);
            assert_eq!(resolved.fingerprint(), &fingerprint);
        }
        let unknown = ContentDigest::new(format!("1220{}", "ff".repeat(32)))?;
        assert!(resolve_reference_tokenizer(&unknown)?.is_none());
        Ok(())
    }

    #[test]
    fn algorithm_and_configuration_fingerprints_are_locked() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            ReferenceTokenizerProfile::Utf8BytesV1
                .fingerprint()?
                .as_str(),
            REFERENCE_UTF8_BYTES_V1_FINGERPRINT
        );
        assert_eq!(
            ReferenceTokenizerProfile::UnicodeScalarsV1
                .fingerprint()?
                .as_str(),
            REFERENCE_UNICODE_SCALARS_V1_FINGERPRINT
        );
        Ok(())
    }

    #[test]
    fn target_constructor_binds_provider_model_and_fingerprint_and_rejects_cross_pairs()
    -> Result<(), Box<dyn Error>> {
        let materializer = ContentDigest::new(format!("1220{}", "aa".repeat(32)))?;
        for profile in ReferenceTokenizerProfile::ALL {
            let target = profile.target_profile(materializer.clone(), 4_096)?;
            assert!(profile.matches_target(&target)?);
            assert_eq!(
                resolve_reference_tokenizer_target(&target)?
                    .ok_or("safe reference target did not resolve")?
                    .profile(),
                profile
            );

            let mut external = target.clone();
            external.provider = "anthropic".to_owned();
            assert!(resolve_reference_tokenizer_target(&external)?.is_none());
            external.provider = "openai".to_owned();
            assert!(resolve_reference_tokenizer_target(&external)?.is_none());

            let mut cross_paired = target;
            cross_paired.model_family = match profile {
                ReferenceTokenizerProfile::Utf8BytesV1 => {
                    ReferenceTokenizerProfile::UnicodeScalarsV1.identifier()
                }
                ReferenceTokenizerProfile::UnicodeScalarsV1 => {
                    ReferenceTokenizerProfile::Utf8BytesV1.identifier()
                }
            }
            .to_owned();
            assert!(resolve_reference_tokenizer_target(&cross_paired)?.is_none());
        }
        assert!(
            ReferenceTokenizerProfile::Utf8BytesV1
                .target_profile(materializer, 0)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn fingerprints_and_counts_are_stable_across_concurrent_construction()
    -> Result<(), Box<dyn Error>> {
        let expected = Arc::new(
            ReferenceTokenizerProfile::ALL
                .into_iter()
                .map(|profile| {
                    let tokenizer = ReferenceTokenizer::new(profile)?;
                    Ok::<_, MaterializationError>((
                        profile,
                        tokenizer.fingerprint().clone(),
                        tokenizer.count_exact("CIGAR Δ".as_bytes())?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        let mut workers = Vec::new();
        for _worker in 0..8 {
            let expected = Arc::clone(&expected);
            workers.push(thread::spawn(move || -> Result<(), String> {
                for _repeat in 0..100 {
                    for (profile, fingerprint, count) in expected.iter() {
                        let tokenizer =
                            ReferenceTokenizer::new(*profile).map_err(|error| error.to_string())?;
                        if tokenizer.fingerprint() != fingerprint
                            || tokenizer
                                .count_exact("CIGAR Δ".as_bytes())
                                .map_err(|error| error.to_string())?
                                != *count
                        {
                            return Err("reference tokenizer changed".to_owned());
                        }
                    }
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_panic| "reference tokenizer worker panicked")??;
        }
        Ok(())
    }

    #[test]
    fn synthetic_count_overflow_fails_closed() {
        if let Ok(overflow) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(
                checked_token_count(overflow),
                Err(MaterializationError::LimitExceeded)
            );
        }
    }
}
