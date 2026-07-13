//! Service orchestration, authentication context, API contracts, and client core.

mod context;
mod cursor;
mod error;
mod grpc;
mod handler_registry;
mod http;
mod idempotency;
mod quota;
mod readiness;
mod service;
mod typed;

/// Generated frozen v1 operation contracts.
pub mod generated;

pub use context::*;
pub use cursor::*;
pub use error::*;
pub use grpc::*;
pub use handler_registry::*;
pub use http::*;
pub use idempotency::*;
pub use quota::*;
pub use readiness::*;
pub use service::*;
pub use typed::*;
