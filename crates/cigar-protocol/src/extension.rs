//! Stable, bounded extension keys and canonical non-floating-point values.

use crate::limits::{
    MAX_EXTENSION_BYTES, MAX_EXTENSION_COLLECTION_ITEMS, MAX_EXTENSION_DEPTH,
    MAX_EXTENSION_ENTRIES, MAX_EXTENSION_KEY_BYTES, MAX_EXTENSION_TEXT_BYTES,
};
use crate::validation::{ValidationCode, ValidationErrors, issue};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Validated key for an extensible metadata map.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExtensionKey(String);

impl JsonSchema for ExtensionKey {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "ExtensionKey".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EXTENSION_KEY_BYTES,
            "pattern": "^[a-z0-9][a-z0-9._/-]{0,127}$",
        })
    }
}

impl ExtensionKey {
    /// Creates a key matching `[a-z0-9][a-z0-9._/-]{0,127}`.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        });
        if valid_first && valid_rest && value.len() <= MAX_EXTENSION_KEY_BYTES {
            Ok(Self(value))
        } else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidExtensionKey,
                "/extensions",
                "extension key does not match the stable bounded grammar",
            ));
            Err(errors)
        }
    }

    /// Returns the normalized extension key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether an unknown key must cause fail-closed validation.
    #[must_use]
    pub fn is_mandatory(&self) -> bool {
        self.0.starts_with("required/")
    }
}

impl fmt::Debug for ExtensionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExtensionKey")
            .field(&self.0)
            .finish()
    }
}

impl From<ExtensionKey> for String {
    fn from(key: ExtensionKey) -> Self {
        key.0
    }
}

impl TryFrom<String> for ExtensionKey {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Canonical extension value; null and floating-point states are unrepresentable.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CanonicalValue {
    /// Boolean value.
    Boolean(bool),
    /// Signed integer value.
    Integer(i64),
    /// Bounded UTF-8 text.
    Text(#[schemars(length(max = MAX_EXTENSION_TEXT_BYTES))] String),
    /// Bounded byte string. JSON wire generation replaces the derived array form with base64url.
    Bytes(
        #[schemars(with = "String")]
        #[schemars(length(max = 87_382))]
        #[serde(with = "crate::primitive::base64url")]
        Vec<u8>,
    ),
    /// Ordered values.
    Array(#[schemars(length(max = MAX_EXTENSION_COLLECTION_ITEMS))] Vec<Self>),
    /// Deterministically ordered string-keyed values.
    Object(
        #[schemars(extend("maxProperties" = MAX_EXTENSION_COLLECTION_ITEMS))]
        BTreeMap<String, Self>,
    ),
}

impl fmt::Debug for CanonicalValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(_) => formatter.write_str("Boolean([REDACTED])"),
            Self::Integer(_) => formatter.write_str("Integer([REDACTED])"),
            Self::Text(value) => formatter.debug_tuple("Text").field(&value.len()).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(&value.len()).finish(),
            Self::Array(value) => formatter.debug_tuple("Array").field(&value.len()).finish(),
            Self::Object(value) => formatter.debug_tuple("Object").field(&value.len()).finish(),
        }
    }
}

impl CanonicalValue {
    /// Validates decoded structured data against depth, collection, text, and byte limits.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.validate_at(1, "/value", &mut errors);
        errors.into_result()
    }

    fn validate_at(&self, depth: usize, path: &str, errors: &mut ValidationErrors) {
        if depth > MAX_EXTENSION_DEPTH {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                path,
                "extension nesting exceeds the configured maximum",
            ));
            return;
        }
        match self {
            Self::Text(value) if value.len() > MAX_EXTENSION_TEXT_BYTES => errors.push(issue(
                ValidationCode::LimitExceeded,
                path,
                "extension text exceeds the configured byte maximum",
            )),
            Self::Bytes(value) if value.len() > MAX_EXTENSION_BYTES => errors.push(issue(
                ValidationCode::LimitExceeded,
                path,
                "extension bytes exceed the configured maximum",
            )),
            Self::Array(values) => {
                if values.len() > MAX_EXTENSION_COLLECTION_ITEMS {
                    errors.push(issue(
                        ValidationCode::LimitExceeded,
                        path,
                        "extension array exceeds the configured item maximum",
                    ));
                }
                for (index, value) in values.iter().enumerate() {
                    value.validate_at(depth + 1, &format!("{path}/{index}"), errors);
                }
            }
            Self::Object(values) => {
                if values.len() > MAX_EXTENSION_COLLECTION_ITEMS {
                    errors.push(issue(
                        ValidationCode::LimitExceeded,
                        path,
                        "extension object exceeds the configured item maximum",
                    ));
                }
                for (key, value) in values {
                    value.validate_at(depth + 1, &format!("{path}/{key}"), errors);
                }
            }
            Self::Boolean(_) | Self::Integer(_) | Self::Text(_) | Self::Bytes(_) => {}
        }
    }
}

/// Deterministically ordered and bounded extension collection.
#[derive(Clone, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
#[schemars(extend("maxProperties" = MAX_EXTENSION_ENTRIES))]
pub struct ExtensionMap(BTreeMap<ExtensionKey, CanonicalValue>);

impl ExtensionMap {
    /// Validates and creates an extension map.
    pub fn new(
        values: BTreeMap<ExtensionKey, CanonicalValue>,
        known_keys: &BTreeSet<ExtensionKey>,
    ) -> Result<Self, ValidationErrors> {
        let candidate = Self(values);
        candidate.validate_known(known_keys)?;
        Ok(candidate)
    }

    /// Revalidates decoded extensions against the keys understood by a record type.
    pub fn validate_known(
        &self,
        known_keys: &BTreeSet<ExtensionKey>,
    ) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.0.len() > MAX_EXTENSION_ENTRIES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/extensions",
                "extension map exceeds the configured entry maximum",
            ));
        }
        for (key, value) in &self.0 {
            if key.is_mandatory() && !known_keys.contains(key) {
                errors.push(issue(
                    ValidationCode::UnknownMandatoryExtension,
                    "/extensions",
                    "unknown mandatory extension is not supported",
                ));
            }
            value.validate_at(1, &format!("/extensions/{}", key.as_str()), &mut errors);
        }
        errors.into_result()
    }

    /// Returns the number of extension entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether there are no extensions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ExtensionMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionMap")
            .field("entries", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalValue, ExtensionKey, ExtensionMap};
    use crate::ValidationCode;
    use crate::limits::{MAX_EXTENSION_DEPTH, MAX_EXTENSION_KEY_BYTES};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn extension_key_checks_minus_exact_plus_one_boundaries() {
        assert!(ExtensionKey::new("a".repeat(MAX_EXTENSION_KEY_BYTES - 1)).is_ok());
        assert!(ExtensionKey::new("a".repeat(MAX_EXTENSION_KEY_BYTES)).is_ok());
        assert!(ExtensionKey::new("a".repeat(MAX_EXTENSION_KEY_BYTES + 1)).is_err());
        assert!(ExtensionKey::new("Uppercase").is_err());
    }

    #[test]
    fn unknown_optional_extension_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = BTreeMap::new();
        values.insert(
            ExtensionKey::new("vendor.example/value")?,
            CanonicalValue::Integer(7),
        );
        let extensions = ExtensionMap::new(values, &BTreeSet::new())?;
        assert_eq!(extensions.len(), 1);
        Ok(())
    }

    #[test]
    fn unknown_mandatory_extension_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = BTreeMap::new();
        values.insert(
            ExtensionKey::new("required/vendor-feature")?,
            CanonicalValue::Boolean(true),
        );
        let Err(errors) = ExtensionMap::new(values, &BTreeSet::new()) else {
            return Err("unknown mandatory extension unexpectedly passed".into());
        };
        assert!(
            errors
                .iter()
                .any(|issue| { issue.code == ValidationCode::UnknownMandatoryExtension })
        );
        Ok(())
    }

    #[test]
    fn extension_depth_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = CanonicalValue::Boolean(true);
        for _index in 0..=MAX_EXTENSION_DEPTH {
            value = CanonicalValue::Array(vec![value]);
        }
        let mut values = BTreeMap::new();
        values.insert(ExtensionKey::new("vendor/deep")?, value);
        assert!(ExtensionMap::new(values, &BTreeSet::new()).is_err());
        Ok(())
    }
}
