//! Production-backed CIGARBench v2 raw-observation consumer.

mod assignment;
mod observation;
mod runner;

use assignment::Assignment;
use std::fmt;
use std::io::Write as _;

/// Content-free benchmark consumer failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerError {
    category: &'static str,
    api_code: Option<cigar_protocol::ErrorCode>,
}

impl ConsumerError {
    /// Creates one closed internal failure category.
    #[must_use]
    pub const fn new(category: &'static str) -> Self {
        Self {
            category,
            api_code: None,
        }
    }

    /// Creates one content-safe typed API failure.
    #[must_use]
    pub const fn api(category: &'static str, api_code: cigar_protocol::ErrorCode) -> Self {
        Self {
            category,
            api_code: Some(api_code),
        }
    }
}

impl fmt::Display for ConsumerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.api_code {
            write!(formatter, "{}:api-{}", self.category, code.numeric())
        } else {
            formatter.write_str(self.category)
        }
    }
}

impl std::error::Error for ConsumerError {}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = execute().await {
        let message = format!("cigarbench consumer rejected the observation: {error}\n");
        let _ignored = std::io::stderr().write_all(message.as_bytes());
        std::process::exit(1);
    }
}

async fn execute() -> Result<(), ConsumerError> {
    let (assignment, bytes) = Assignment::read_stdin()?;
    let observation = runner::run(assignment, &bytes).await?;
    let output = observation.canonical_bytes()?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|_error| ConsumerError::new("stdout_write"))?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|_error| ConsumerError::new("stdout_write"))?;
    Ok(())
}
