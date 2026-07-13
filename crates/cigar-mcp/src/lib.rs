//! Strict bounded MCP 2025-06-18 facade for CIGAR.
//!
//! The crate keeps stdio framing, JSON validation, output pagination, and degradation behavior
//! independent of the daemon transport. Applications can inject a [`Backend`] for a native IPC
//! or authenticated transport; the bundled [`HttpBackend`] is deliberately loopback-only.

mod backend;
mod json;
mod server;

pub use backend::{
    Backend, BackendError, BackendMetadata, BackendRequest, BackendRequestKind, BackendResponse,
    CliBackend, HttpBackend,
};
pub use server::{
    DEFAULT_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS, MAX_REQUEST_BYTES, MCP_PROTOCOL_VERSION,
    MIN_OUTPUT_TOKENS, Server, serve,
};
