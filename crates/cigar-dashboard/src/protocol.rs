//! Browser-safe projection generated from the frozen operation, payload, and error catalogs.

/// Compile-time handle for the deterministic generated browser projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DashboardProtocolCatalog;

impl DashboardProtocolCatalog {
    /// Returns the exact generated JSON document served to authenticated browsers.
    #[must_use]
    pub const fn generated_json() -> &'static str {
        include_str!("generated/protocol-catalog-v1.json")
    }
}

#[cfg(test)]
mod tests {
    use super::DashboardProtocolCatalog;
    use serde_json::Value;
    use std::collections::BTreeSet;

    #[test]
    fn generated_browser_catalog_covers_operations_payloads_and_error_retry_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let value: Value = serde_json::from_str(DashboardProtocolCatalog::generated_json())?;
        assert_eq!(value.get("service_count"), Some(&Value::from(7)));
        assert_eq!(value.get("operation_count"), Some(&Value::from(45)));
        assert_eq!(value.get("error_count"), Some(&Value::from(34)));
        assert_eq!(
            value.get("source").and_then(Value::as_str),
            Some("cargo-xtask-interface-projection")
        );
        let services = value
            .get("services")
            .and_then(Value::as_array)
            .ok_or("services missing")?;
        let operations = services
            .iter()
            .filter_map(|service| service.get("operations").and_then(Value::as_array))
            .flatten()
            .collect::<Vec<_>>();
        let ids = operations
            .iter()
            .filter_map(|operation| operation.get("operation_id").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 45);
        assert!(ids.contains("getReadiness"));
        assert!(ids.contains("subscribeSpaceEvents"));
        assert!(operations.iter().all(|operation| {
            operation
                .get("payload")
                .and_then(|payload| payload.get("request_schema"))
                .and_then(Value::as_str)
                .is_some()
        }));
        let errors = value
            .get("errors")
            .and_then(Value::as_array)
            .ok_or("errors missing")?;
        assert_eq!(errors.len(), 34);
        assert!(errors.iter().all(|error| {
            error.get("retry").and_then(Value::as_str).is_some()
                && error.get("message").is_none()
                && error.get("remediation").is_none()
        }));
        Ok(())
    }
}
