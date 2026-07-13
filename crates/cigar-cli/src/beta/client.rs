//! Transport-free result type for the initial embedded-local beta.

use serde_json::Value;

pub(crate) struct OperationResponse {
    pub(crate) operation_id: String,
    pub(crate) result: Value,
    pub(crate) semantic_etag: Option<String>,
    pub(crate) next_page_cursor: Option<String>,
}
