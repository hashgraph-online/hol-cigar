//! Validated identities and optimistic-mutation wrappers.

use crate::limits::{MAX_IDEMPOTENCY_KEY_BYTES, UUID_TEXT_BYTES};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;

fn validate_uuid_v7(value: &str, path: &str) -> Result<(), ValidationErrors> {
    let bytes = value.as_bytes();
    let valid_length = bytes.len() == UUID_TEXT_BYTES;
    let valid_hyphens = valid_length
        && [8_usize, 13, 18, 23]
            .into_iter()
            .all(|index| bytes.get(index) == Some(&b'-'));
    let valid_hex = bytes.iter().enumerate().all(|(index, byte)| {
        [8_usize, 13, 18, 23].contains(&index)
            || byte.is_ascii_digit()
            || (b'a'..=b'f').contains(byte)
    });
    let valid_version = bytes.get(14) == Some(&b'7');
    let valid_variant = bytes
        .get(19)
        .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'));
    if valid_length && valid_hyphens && valid_hex && valid_version && valid_variant {
        Ok(())
    } else {
        let mut errors = ValidationErrors::new();
        errors.push(issue(
            ValidationCode::InvalidIdentity,
            path,
            "identity must be a lowercase RFC 9562 UUIDv7",
        ));
        Err(errors)
    }
}

macro_rules! uuid_identifier {
    ($name:ident, $path:literal, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
                let value = value.into();
                validate_uuid_v7(&value, $path)?;
                Ok(Self(value))
            }

            /// Returns the normalized textual identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl From<$name> for String {
            fn from(identifier: $name) -> Self {
                identifier.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValidationErrors;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

uuid_identifier!(
    RecordId,
    "/record_id",
    "Unique identity of one immutable record instance."
);
uuid_identifier!(
    LineageId,
    "/lineage_id",
    "Stable identity shared by versions of one semantic lineage."
);
uuid_identifier!(
    ContextSpaceId,
    "/context_space_id",
    "Identity of a governed context space."
);

fn validate_multihash(value: &str, path: &str) -> Result<(), ValidationErrors> {
    let valid = value.len() == 68
        && value.starts_with("1220")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        let mut errors = ValidationErrors::new();
        errors.push(issue(
            ValidationCode::InvalidIdentity,
            path,
            "digest must be a lowercase SHA-256 multihash hex value",
        ));
        Err(errors)
    }
}

macro_rules! digest_identifier {
    ($name:ident, $path:literal, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
                let value = value.into();
                validate_multihash(&value, $path)?;
                Ok(Self(value))
            }

            /// Returns the multihash hexadecimal representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let Some(prefix) = self.0.get(..12) else {
                    return Err(fmt::Error);
                };
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!("{prefix}…"))
                    .finish()
            }
        }

        impl From<$name> for String {
            fn from(identifier: $name) -> Self {
                identifier.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValidationErrors;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

digest_identifier!(
    ContentDigest,
    "/content_digest",
    "Digest of exact protected content bytes."
);
digest_identifier!(
    VersionId,
    "/version_id",
    "Digest-derived identity of one semantic record version."
);

/// Caller-supplied key that makes a mutation safely repeatable.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

macro_rules! identity_string_schema {
    ($type:ty, $name:literal, $minimum:expr, $maximum:expr, $pattern:literal) => {
        impl JsonSchema for $type {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                $name.into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": $minimum,
                    "maxLength": $maximum,
                    "pattern": $pattern,
                })
            }
        }
    };
}

identity_string_schema!(
    RecordId,
    "RecordId",
    UUID_TEXT_BYTES,
    UUID_TEXT_BYTES,
    "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
identity_string_schema!(
    LineageId,
    "LineageId",
    UUID_TEXT_BYTES,
    UUID_TEXT_BYTES,
    "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
identity_string_schema!(
    ContextSpaceId,
    "ContextSpaceId",
    UUID_TEXT_BYTES,
    UUID_TEXT_BYTES,
    "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
identity_string_schema!(ContentDigest, "ContentDigest", 68, 68, "^1220[0-9a-f]{64}$");
identity_string_schema!(VersionId, "VersionId", 68, 68, "^1220[0-9a-f]{64}$");
identity_string_schema!(
    IdempotencyKey,
    "IdempotencyKey",
    1,
    MAX_IDEMPOTENCY_KEY_BYTES,
    "^[!-~]+$"
);

impl IdempotencyKey {
    /// Creates a bounded printable idempotency key.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        if valid {
            Ok(Self(value))
        } else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidIdentity,
                "/idempotency_key",
                "idempotency key must be non-empty bounded printable ASCII",
            ));
            Err(errors)
        }
    }

    /// Returns the caller-defined key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([REDACTED])")
    }
}

impl From<IdempotencyKey> for String {
    fn from(key: IdempotencyKey) -> Self {
        key.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Optimistic concurrency revision required by public mutations.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct ExpectedRevision(pub u64);

#[cfg(test)]
mod tests {
    use super::{ContentDigest, IdempotencyKey, RecordId};
    use crate::limits::MAX_IDEMPOTENCY_KEY_BYTES;

    #[test]
    fn uuid_v7_accepts_only_version_and_variant() {
        assert!(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890").is_ok());
        assert!(RecordId::new("01890f47-8e7d-4b42-a1d2-3c4d5e6f7890").is_err());
        assert!(RecordId::new("01890F47-8E7D-7B42-A1D2-3C4D5E6F7890").is_err());
    }

    #[test]
    fn multihash_requires_sha256_prefix_and_length() {
        let valid = format!("1220{}", "a".repeat(64));
        assert!(ContentDigest::new(valid).is_ok());
        assert!(ContentDigest::new(format!("1320{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn idempotency_key_checks_minus_exact_plus_one_boundaries() {
        assert!(IdempotencyKey::new("a".repeat(MAX_IDEMPOTENCY_KEY_BYTES - 1)).is_ok());
        assert!(IdempotencyKey::new("a".repeat(MAX_IDEMPOTENCY_KEY_BYTES)).is_ok());
        assert!(IdempotencyKey::new("a".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1)).is_err());
    }

    #[test]
    fn idempotency_key_debug_is_secret_safe() -> Result<(), Box<dyn std::error::Error>> {
        let key = IdempotencyKey::new("sensitive-caller-value")?;
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(key.as_str()));
        Ok(())
    }
}
