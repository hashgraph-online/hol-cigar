//! Optional local CIGAR protocol dashboard sidecar.
//!
//! This initial slice owns strict configuration parsing. Listener, session, gateway, and job
//! modules are added only after their complete security boundaries are available.

mod assets;
mod config;
mod cursor;
mod events;
mod evidence;
mod gateway;
mod history;
mod metrics;
mod profiles;
mod runs;
mod server;
mod session;
mod status;

pub use assets::*;
pub use config::*;
pub use cursor::*;
pub use events::*;
pub use evidence::*;
pub use gateway::*;
pub use history::*;
pub use metrics::*;
pub use profiles::*;
pub use runs::*;
pub use server::*;
pub use session::*;
pub use status::*;
