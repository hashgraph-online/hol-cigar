//! Bounded semantic primitives used by Context ABI records.

use crate::limits::{MAX_DURATION_NANOS, MAX_MEDIA_TYPE_BYTES, MAX_PATH_BYTES, MAX_URI_BYTES};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

macro_rules! validated_string {
    ($name:ident, $validator:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            /// Returns the validated string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("bytes", &self.0.len())
                    .finish()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
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

fn validate_uri(value: &str) -> Result<(), ValidationErrors> {
    let mut errors = ValidationErrors::new();
    if value.is_empty() || value.len() > MAX_URI_BYTES {
        errors.push(issue(
            ValidationCode::LimitExceeded,
            "/source/uri",
            "source URI length is outside the supported range",
        ));
    }
    let scheme_valid = value.split_once(':').is_some_and(|(scheme, remainder)| {
        let mut bytes = scheme.bytes();
        bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
            && !remainder.is_empty()
    });
    if !scheme_valid
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/source/uri",
            "source URI is not an absolute URI",
        ));
    }
    errors.into_result()
}

fn validate_media_type(value: &str) -> Result<(), ValidationErrors> {
    let valid = !value.is_empty()
        && value.len() <= MAX_MEDIA_TYPE_BYTES
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty()
                && !subtype.is_empty()
                && kind.bytes().chain(subtype.bytes()).all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                        )
                })
        });
    if valid {
        Ok(())
    } else {
        let mut errors = ValidationErrors::new();
        errors.push(issue(
            ValidationCode::InvalidValue,
            "/media_type",
            "media type must be a bounded type/subtype token",
        ));
        Err(errors)
    }
}

validated_string!(SourceUri, validate_uri, "Validated absolute source URI.");
validated_string!(MediaType, validate_media_type, "Validated MIME media type.");

macro_rules! bounded_string_schema {
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

bounded_string_schema!(
    SourceUri,
    "SourceUri",
    1,
    MAX_URI_BYTES,
    "^[A-Za-z][A-Za-z0-9+.-]*:[^\\x00-\\x20]+$"
);
bounded_string_schema!(
    MediaType,
    "MediaType",
    3,
    MAX_MEDIA_TYPE_BYTES,
    "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$"
);

/// Platform-neutral relative path represented by exact bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath(Vec<u8>);

impl JsonSchema for RelativePath {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "RelativePath".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 2,
            "maxLength": 5462,
            "contentEncoding": "base64url",
            "description": "Unpadded base64url encoding of 1..=4096 relative-path bytes; decoded bytes must be non-absolute and NUL-free."
        })
    }
}

impl RelativePath {
    /// Creates a bounded non-absolute, NUL-free relative path.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let invalid_prefix = value
            .first()
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'));
        let valid = !value.is_empty()
            && value.len() <= MAX_PATH_BYTES
            && !invalid_prefix
            && !value.contains(&0);
        if valid {
            Ok(Self(value))
        } else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/source/relative_path",
                "relative path must be bounded, non-absolute, and NUL-free",
            ));
            Err(errors)
        }
    }

    /// Returns the exact path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelativePath")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl TryFrom<Vec<u8>> for RelativePath {
    type Error = ValidationErrors;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RelativePath> for Vec<u8> {
    fn from(value: RelativePath) -> Self {
        value.0
    }
}

impl Serialize for RelativePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        URL_SAFE_NO_PAD.encode(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod base64url {
    use super::{Engine, URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        URL_SAFE_NO_PAD.encode(value).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// UTC instant stored as signed integer nanoseconds from the Unix epoch.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(i128);

impl JsonSchema for UtcTimestamp {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "UtcTimestamp".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date-time",
            "description": "RFC 3339 UTC instant with nanosecond precision."
        })
    }
}

impl UtcTimestamp {
    /// Creates a UTC timestamp from Unix-epoch nanoseconds when representable.
    pub fn from_unix_nanos(value: i128) -> Result<Self, ValidationErrors> {
        OffsetDateTime::from_unix_timestamp_nanos(value).map_err(|_error| timestamp_error())?;
        Ok(Self(value))
    }

    /// Returns signed integer nanoseconds from the Unix epoch.
    #[must_use]
    pub const fn unix_nanos(self) -> i128 {
        self.0
    }

    /// Parses an RFC 3339 timestamp and normalizes it to UTC.
    pub fn parse_rfc3339(value: &str) -> Result<Self, ValidationErrors> {
        let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_error| timestamp_error())?;
        Self::from_unix_nanos(parsed.unix_timestamp_nanos())
    }

    fn to_rfc3339(self) -> Result<String, ValidationErrors> {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(self.0)
            .map_err(|_error| timestamp_error())?;
        timestamp
            .format(&Rfc3339)
            .map_err(|_error| timestamp_error())
    }
}

fn timestamp_error() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.push(issue(
        ValidationCode::InvalidValue,
        "/timestamp",
        "timestamp is not a representable RFC 3339 UTC instant",
    ));
    errors
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UtcTimestamp")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_rfc3339()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_rfc3339(&value).map_err(serde::de::Error::custom)
    }
}

/// Non-negative bounded duration in nanoseconds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct DurationNanos(u64);

impl JsonSchema for DurationNanos {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "DurationNanos".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "format": "uint64",
            "minimum": 0,
            "maximum": MAX_DURATION_NANOS,
        })
    }
}

impl DurationNanos {
    /// Creates a duration within the protocol-wide maximum.
    pub fn new(value: u64) -> Result<Self, ValidationErrors> {
        if value <= MAX_DURATION_NANOS {
            Ok(Self(value))
        } else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/duration_nanos",
                "duration exceeds the protocol maximum",
            ));
            Err(errors)
        }
    }

    /// Returns the duration in nanoseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for DurationNanos {
    type Error = ValidationErrors;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DurationNanos> for u64 {
    fn from(value: DurationNanos) -> Self {
        value.0
    }
}

/// Fixed-point proportion in millionths, avoiding floating point in semantic records.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct FixedPoint(u32);

impl JsonSchema for FixedPoint {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "FixedPoint".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "format": "uint32",
            "minimum": 0,
            "maximum": FixedPoint::ONE,
        })
    }
}

impl FixedPoint {
    /// Maximum inclusive fixed-point value.
    pub const ONE: u32 = 1_000_000;

    /// Creates a value between zero and one million inclusive.
    pub fn new(value: u32) -> Result<Self, ValidationErrors> {
        if value <= Self::ONE {
            Ok(Self(value))
        } else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/fixed_point",
                "fixed-point value must be between zero and one million",
            ));
            Err(errors)
        }
    }

    /// Returns the integer millionths value.
    #[must_use]
    pub const fn millionths(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for FixedPoint {
    type Error = ValidationErrors;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FixedPoint> for u32 {
    fn from(value: FixedPoint) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::{DurationNanos, FixedPoint, MediaType, RelativePath, SourceUri, UtcTimestamp};
    use crate::limits::{MAX_DURATION_NANOS, MAX_PATH_BYTES, MAX_URI_BYTES};

    #[test]
    fn uri_and_path_limits_cover_boundaries() {
        let prefix = "x:";
        assert!(SourceUri::new(format!("{prefix}{}", "a".repeat(MAX_URI_BYTES - 2))).is_ok());
        assert!(SourceUri::new(format!("{prefix}{}", "a".repeat(MAX_URI_BYTES - 1))).is_err());
        assert!(RelativePath::new(vec![b'a'; MAX_PATH_BYTES]).is_ok());
        assert!(RelativePath::new(vec![b'a'; MAX_PATH_BYTES + 1]).is_err());
        assert!(RelativePath::new(b"/absolute".to_vec()).is_err());
    }

    #[test]
    fn timestamps_round_trip_rfc3339_at_nanosecond_precision()
    -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = UtcTimestamp::parse_rfc3339("2026-07-10T12:34:56.123456789Z")?;
        let json = serde_json::to_string(&timestamp)?;
        let decoded: UtcTimestamp = serde_json::from_str(&json)?;
        assert_eq!(decoded, timestamp);
        assert!(json.contains("123456789"));
        Ok(())
    }

    #[test]
    fn fixed_point_and_duration_check_exact_plus_one() {
        assert!(FixedPoint::new(FixedPoint::ONE).is_ok());
        assert!(FixedPoint::new(FixedPoint::ONE + 1).is_err());
        assert!(DurationNanos::new(MAX_DURATION_NANOS).is_ok());
        assert!(DurationNanos::new(MAX_DURATION_NANOS + 1).is_err());
    }

    #[test]
    fn media_type_rejects_parameters_and_missing_subtype() {
        assert!(MediaType::new("text/plain").is_ok());
        assert!(MediaType::new("text/plain; charset=utf-8").is_err());
        assert!(MediaType::new("text").is_err());
    }

    #[test]
    fn path_json_is_unpadded_base64url() -> Result<(), Box<dyn std::error::Error>> {
        let path = RelativePath::new(vec![0xfb, 0xff, b'a'])?;
        let json = serde_json::to_string(&path)?;
        assert_eq!(json, "\"-_9h\"");
        let decoded: RelativePath = serde_json::from_str(&json)?;
        assert_eq!(decoded, path);
        assert!(serde_json::from_str::<RelativePath>("\"-_9h=\"").is_err());
        Ok(())
    }
}
