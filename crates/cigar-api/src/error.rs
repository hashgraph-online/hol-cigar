//! Stable, content-safe API error mapping.

use cigar_protocol::{ErrorCode, ExtensionMap, Problem, RecordId, SchemaVersion, ValidationErrors};
use std::fmt;

/// Transport-neutral API failure containing only public catalog metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ApiError {
    code: ErrorCode,
    correlation_id: RecordId,
}

impl ApiError {
    /// Creates a safe error from a stable public code and correlation identity.
    #[must_use]
    pub const fn new(code: ErrorCode, correlation_id: RecordId) -> Self {
        Self {
            code,
            correlation_id,
        }
    }

    /// Returns the stable public error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the correlation identity used for privileged internal diagnosis.
    #[must_use]
    pub const fn correlation_id(&self) -> &RecordId {
        &self.correlation_id
    }

    /// Maps this error to the frozen v1 RFC 9457-style problem contract.
    pub fn into_problem(self) -> Result<Problem, ValidationErrors> {
        let definition = self.code.definition();
        Ok(Problem {
            schema_version: SchemaVersion::new("cigar.problem", 1)?,
            code: self.code,
            http_status: definition.http_status,
            retry: definition.retry,
            message: definition.message.to_owned(),
            remediation: definition.remediation.to_owned(),
            correlation_id: self.correlation_id,
            details: ExtensionMap::default(),
        })
    }
}

impl fmt::Debug for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiError")
            .field("code", &self.code)
            .field("numeric_code", &self.code.numeric())
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.definition().message)
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::ApiError;
    use cigar_protocol::{ErrorCode, RecordId, Validate};

    #[test]
    fn catalog_mapping_is_stable_and_valid() -> Result<(), Box<dyn std::error::Error>> {
        let problem = ApiError::new(
            ErrorCode::RateLimited,
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        )
        .into_problem()?;
        assert_eq!(problem.http_status, 429);
        assert_eq!(problem.message, "request rate limit was reached");
        assert!(problem.validate().is_ok());
        Ok(())
    }

    #[test]
    fn mapping_cannot_reflect_protected_input() -> Result<(), Box<dyn std::error::Error>> {
        let protected = "customer-secret-document";
        let error = ApiError::new(
            ErrorCode::Internal,
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        );
        let rendered = format!("{error:?} {error}");
        let json = serde_json::to_string(&error.into_problem()?)?;
        assert!(!rendered.contains(protected));
        assert!(!json.contains(protected));
        Ok(())
    }
}
