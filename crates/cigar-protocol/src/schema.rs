//! Schema-version syntax and compatibility gates.

use crate::limits::MAX_SCHEMA_FAMILY_BYTES;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

/// Parsed `<family>.v<major>` schema identifier.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SchemaVersion {
    family: String,
    major: u16,
}

impl JsonSchema for SchemaVersion {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "SchemaVersion".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 4,
            "maxLength": MAX_SCHEMA_FAMILY_BYTES + 7,
            "pattern": "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\\.v[1-9][0-9]{0,4}$",
            "description": "Bounded <family>.v<positive-major> schema identifier."
        })
    }
}

impl SchemaVersion {
    /// Creates a validated schema version.
    pub fn new(family: impl Into<String>, major: u16) -> Result<Self, ValidationErrors> {
        let family = family.into();
        let mut errors = ValidationErrors::new();
        if family.is_empty() || family.len() > MAX_SCHEMA_FAMILY_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/schema_version",
                "schema family length is outside the supported range",
            ));
        }
        if !valid_family(&family) {
            errors.push(issue(
                ValidationCode::InvalidSchema,
                "/schema_version",
                "schema family contains an unsupported character or segment",
            ));
        }
        if major == 0 {
            errors.push(issue(
                ValidationCode::InvalidSchema,
                "/schema_version",
                "schema major version must be positive",
            ));
        }
        errors.into_result()?;
        Ok(Self { family, major })
    }

    /// Returns the schema family without its version suffix.
    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    /// Returns the schema major version.
    #[must_use]
    pub const fn major(&self) -> u16 {
        self.major
    }

    /// Fails closed unless this is the v1 form of the expected family.
    pub fn require_v1(&self, expected_family: &str) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.family != expected_family {
            errors.push(issue(
                ValidationCode::InvalidSchema,
                "/schema_version",
                "schema family does not match the record type",
            ));
        }
        if self.major != 1 {
            errors.push(issue(
                ValidationCode::UnsupportedSchema,
                "/schema_version",
                "schema major version is unsupported",
            ));
        }
        errors.into_result()
    }
}

impl fmt::Debug for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.v{}", self.family, self.major)
    }
}

impl From<SchemaVersion> for String {
    fn from(version: SchemaVersion) -> Self {
        version.to_string()
    }
}

impl TryFrom<String> for SchemaVersion {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for SchemaVersion {
    type Err = ValidationErrors;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((family, major)) = value.rsplit_once(".v") else {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidSchema,
                "/schema_version",
                "schema version must end in `.v<major>`",
            ));
            return Err(errors);
        };
        let major = major.parse::<u16>().map_err(|_error| {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::InvalidSchema,
                "/schema_version",
                "schema major version is not an unsigned integer",
            ));
            errors
        })?;
        Self::new(family, major)
    }
}

fn valid_family(family: &str) -> bool {
    !family.starts_with('.')
        && !family.ends_with('.')
        && !family.contains("..")
        && family.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
}

#[cfg(test)]
mod tests {
    use super::SchemaVersion;
    use crate::ValidationCode;

    #[test]
    fn schema_version_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let version: SchemaVersion = "cigar.atom.v1".parse()?;
        assert_eq!(version.family(), "cigar.atom");
        assert_eq!(version.major(), 1);
        assert_eq!(version.to_string(), "cigar.atom.v1");
        Ok(())
    }

    #[test]
    fn unknown_major_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let version: SchemaVersion = "cigar.atom.v2".parse()?;
        let Err(errors) = version.require_v1("cigar.atom") else {
            return Err("unknown major unexpectedly passed".into());
        };
        assert!(
            errors
                .iter()
                .any(|issue| issue.code == ValidationCode::UnsupportedSchema)
        );
        Ok(())
    }
}
