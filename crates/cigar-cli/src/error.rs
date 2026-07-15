//! Stable content-safe CLI failures.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CliError {
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
    exit_status: u8,
}

impl CliError {
    const fn new(
        code: &'static str,
        message: &'static str,
        remediation: &'static str,
        exit_status: u8,
    ) -> Self {
        Self {
            code,
            message,
            remediation,
            exit_status,
        }
    }

    pub(crate) const fn invalid_command() -> Self {
        Self::new(
            "CLI_INVALID_COMMAND",
            "the command or option is invalid",
            "run 'cigar help' and correct the invocation",
            2,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn invalid_configuration() -> Self {
        Self::new(
            "CLI_INVALID_CONFIGURATION",
            "CLI configuration is invalid",
            "run 'cigar status --explain-config' and correct the reported source",
            78,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn invalid_configuration() -> Self {
        Self::new(
            "CLI_INVALID_CONFIGURATION",
            "embedded-beta configuration is invalid",
            "run 'cigar source list --explain-config' and correct the explicit beta configuration",
            78,
        )
    }

    pub(crate) const fn configuration_io() -> Self {
        Self::new(
            "CLI_CONFIGURATION_UNAVAILABLE",
            "CLI configuration could not be read safely",
            "verify that the configuration is a bounded regular file with safe permissions",
            78,
        )
    }

    pub(crate) const fn confirmation_required() -> Self {
        Self::new(
            "CLI_CONFIRMATION_REQUIRED",
            "the state-changing command was not confirmed",
            "review with --dry-run, then repeat with --yes",
            2,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn input_required() -> Self {
        Self::new(
            "CLI_INPUT_REQUIRED",
            "the operation requires a versioned JSON input document",
            "provide a bounded JSON document with --input <path> according to the operation schema",
            2,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn invalid_input() -> Self {
        Self::new(
            "CLI_INVALID_INPUT",
            "the operation input is malformed or exceeds a published limit",
            "validate the strict JSON document against the operation schema",
            65,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn invalid_input() -> Self {
        Self::new(
            "CLI_INVALID_INPUT",
            "the command argument or embedded state input is malformed",
            "correct the bounded identifier or directory argument shown by 'cigar help'",
            65,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn credential_unavailable() -> Self {
        Self::new(
            "CLI_CREDENTIAL_UNAVAILABLE",
            "authorization material could not be loaded safely",
            "configure a bounded regular authorization file with owner-only permissions",
            77,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn target_unavailable() -> Self {
        Self::new(
            "CLI_TARGET_UNAVAILABLE",
            "the selected CIGAR target is unavailable",
            "start the target, verify its endpoint, and run 'cigar doctor'",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn stale_daemon() -> Self {
        Self::new(
            "CLI_STALE_DAEMON",
            "the target does not support the frozen CLI operation contract",
            "upgrade the daemon or select a compatible target",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn deadline_exceeded() -> Self {
        Self::new(
            "DEADLINE_EXCEEDED",
            "the command deadline elapsed",
            "inspect target health before retrying, especially for effects",
            75,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn deadline_exceeded() -> Self {
        Self::new(
            "DEADLINE_EXCEEDED",
            "the command deadline elapsed",
            "inspect the private embedded state before retrying the command",
            75,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn interrupted() -> Self {
        Self::new(
            "CLI_INTERRUPTED",
            "the command was cancelled",
            "inspect durable status before retrying a state-changing command",
            130,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn interrupted() -> Self {
        Self::new(
            "CLI_INTERRUPTED",
            "the command was cancelled",
            "inspect the private embedded state before retrying a state change",
            130,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn invalid_response() -> Self {
        Self::new(
            "CLI_INVALID_RESPONSE",
            "the target returned an invalid or oversized response",
            "stop using the target and inspect compatibility and integrity diagnostics",
            70,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn invalid_response() -> Self {
        Self::new(
            "CLI_INVALID_RESPONSE",
            "the embedded-beta result could not be rendered safely",
            "stop using this build and report the content-free error code",
            70,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn unsupported_target() -> Self {
        Self::new(
            "CLI_TARGET_UNSUPPORTED",
            "the selected target is not available in this installed CLI",
            "select local or remote, or install a build with embedded composition support",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn unsupported_surface() -> Self {
        Self::new(
            "CLI_UNSUPPORTED_SURFACE",
            "the selected target does not expose this administrative operation",
            "use an embedded or local operator target with its production configuration",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn state_unavailable() -> Self {
        Self::new(
            "CLI_STATE_UNAVAILABLE",
            "the local administrative state is unavailable",
            "run 'cigar init' or restore a verified backup",
            69,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn state_unavailable() -> Self {
        Self::new(
            "CLI_STATE_UNAVAILABLE",
            "the private embedded state is unavailable",
            "run 'cigar init' or provide a valid embedded-beta configuration",
            69,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn state_commit_uncertain() -> Self {
        Self::new(
            "CLI_STATE_COMMIT_UNCERTAIN",
            "the embedded state publish completed but its durable settlement is uncertain",
            "inspect the current state generation before deciding whether to retry",
            75,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    #[cfg(test)]
    pub(crate) fn is_state_commit_uncertain(self) -> bool {
        self.code == "CLI_STATE_COMMIT_UNCERTAIN"
    }

    #[cfg(feature = "full")]
    pub(crate) const fn state_corrupt() -> Self {
        Self::new(
            "CLI_STATE_CORRUPT",
            "local administrative state failed strict integrity validation",
            "stop mutations and restore a verified backup",
            65,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn beta_state_invalid() -> Self {
        Self::new(
            "CLI_BETA_STATE_INVALID",
            "the frozen beta state failed strict read-only validation",
            "keep the input unchanged and inspect its ownership, permissions, and 0.1.0-beta.1 schema",
            65,
        )
    }

    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    pub(crate) const fn state_corrupt() -> Self {
        Self::new(
            "CLI_STATE_CORRUPT",
            "private embedded state failed strict integrity validation",
            "stop mutations and restore state.json from a trusted local copy",
            65,
        )
    }

    pub(crate) const fn state_conflict() -> Self {
        Self::new(
            "CLI_STATE_CONFLICT",
            "the requested administrative state transition conflicts with current state",
            "inspect the current state and repeat with an explicit non-conflicting request",
            65,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn external_command_failed() -> Self {
        Self::new(
            "CLI_EXTERNAL_COMMAND_FAILED",
            "the delegated installed command failed",
            "inspect the delegated component's content-safe diagnostics",
            70,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn plugin_invalid() -> Self {
        Self::new(
            "CLI_PLUGIN_INVALID",
            "the signed adapter package failed strict local validation",
            "reinstall the matching signed CIGAR package before changing Claude Code",
            65,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn plugin_incompatible() -> Self {
        Self::new(
            "CLI_PLUGIN_INCOMPATIBLE",
            "the installed Claude Code version is outside the qualified adapter range",
            "install a version listed by 'cigar plugin doctor claude-code'",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn plugin_handshake_failed() -> Self {
        Self::new(
            "CLI_PLUGIN_HANDSHAKE_FAILED",
            "a required daemon, MCP, hook, or Claude public-surface check failed",
            "run 'cigar plugin doctor claude-code' and correct every failing component",
            69,
        )
    }

    #[cfg(feature = "full")]
    pub(crate) const fn from_public_problem(
        code: &'static str,
        message: &'static str,
        remediation: &'static str,
        status: u16,
    ) -> Self {
        let exit = if status == 401 || status == 403 {
            77
        } else if status == 400 || status == 404 || status == 409 || status == 422 {
            65
        } else if status == 429 || status >= 500 {
            75
        } else {
            70
        };
        Self::new(code, message, remediation, exit)
    }

    pub(crate) const fn code(self) -> &'static str {
        self.code
    }

    pub(crate) const fn message(self) -> &'static str {
        self.message
    }

    pub(crate) const fn remediation(self) -> &'static str {
        self.remediation
    }

    pub(crate) const fn exit_status(self) -> u8 {
        self.exit_status
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}
