//! Bounded, aggregation-oriented protocol validation results.

use crate::limits::MAX_VALIDATION_ERRORS;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable validation category. WP02 maps these categories into the public error registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationCode {
    /// A named byte, character, entry, depth, or numeric limit was exceeded.
    LimitExceeded,
    /// The schema syntax is malformed.
    InvalidSchema,
    /// The schema major version is not supported by this implementation.
    UnsupportedSchema,
    /// An identifier is malformed or belongs to a different identity domain.
    InvalidIdentity,
    /// An extension key does not match the stable key grammar.
    InvalidExtensionKey,
    /// An unknown extension declares itself mandatory.
    UnknownMandatoryExtension,
    /// A value violates a field-specific structural constraint.
    InvalidValue,
}

/// One safe validation issue that can be returned to an untrusted caller.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationIssue {
    /// Stable issue category.
    pub code: ValidationCode,
    /// JSON-pointer-like field location.
    pub path: String,
    /// Safe message containing no protected field value.
    pub message: String,
}

/// Bounded collection of independently discoverable validation failures.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValidationErrors(Vec<ValidationIssue>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "protocol validation failed with {} issue(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

impl ValidationErrors {
    /// Creates an empty validation result.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Adds an issue if the configured disclosure cap has not been reached.
    pub fn push(&mut self, issue: ValidationIssue) {
        if self.0.len() < MAX_VALIDATION_ERRORS {
            self.0.push(issue);
        }
    }

    /// Returns the number of collected issues.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether validation found no issues.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates through issues in deterministic validation order.
    pub fn iter(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.0.iter()
    }

    /// Appends issues from another validation step while preserving the global cap.
    pub fn merge(&mut self, other: Self) {
        for issue in other.0 {
            self.push(issue);
        }
    }

    /// Converts an empty result to success and a non-empty result to failure.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_empty() { Ok(()) } else { Err(self) }
    }
}

/// Structural validation implemented by every public semantic record.
pub trait Validate {
    /// Validates all safe independent fields up to the global error cap.
    fn validate(&self) -> Result<(), ValidationErrors>;
}

/// Constructs one value-free validation issue.
pub(crate) fn issue(
    code: ValidationCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> ValidationIssue {
    ValidationIssue {
        code,
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidationCode, ValidationErrors, issue};
    use crate::limits::MAX_VALIDATION_ERRORS;

    #[test]
    fn validation_disclosure_is_bounded() {
        let mut errors = ValidationErrors::new();
        for index in 0..(MAX_VALIDATION_ERRORS + 5) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                format!("/field/{index}"),
                "invalid value",
            ));
        }
        assert_eq!(errors.len(), MAX_VALIDATION_ERRORS);
    }
}
