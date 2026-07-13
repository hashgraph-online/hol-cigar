//! Production Rust SDK for embedded and remote CIGAR execution.
//!
//! The SDK consumes the frozen `cigar-api` envelopes and reuses `cigar-protocol` semantic
//! records directly. Embedded and remote clients therefore expose the same 45 typed operations.

mod client;
#[cfg(feature = "embedded-daemon")]
mod daemon_embedded;
mod embedded;
mod error;
mod options;
mod remote;
mod transport;
mod verify;

pub use client::*;
#[cfg(feature = "embedded-daemon")]
pub use daemon_embedded::*;
pub use embedded::*;
pub use error::*;
pub use options::*;
pub use remote::*;
pub use transport::*;
pub use verify::*;

/// Frozen API payload and operation types used by typed client methods.
pub use cigar_api as api;
/// Frozen semantic protocol types used without SDK-specific copies.
pub use cigar_protocol as protocol;

/// Exact Protobuf package name of the stable Context ABI implemented by this SDK.
pub const CONTEXT_ABI: &str = "cigar.context.v1";
