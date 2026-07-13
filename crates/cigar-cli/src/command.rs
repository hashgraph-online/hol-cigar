//! Feature-selected closed command catalogs and generated user-facing assets.

#[cfg(feature = "full")]
use crate::error::CliError;
#[cfg(feature = "full")]
use cigar_api::generated::{OperationContract, operation_by_id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandSpec {
    path: &'static str,
    #[cfg(feature = "full")]
    operation_id: Option<&'static str>,
    mutation: bool,
    destructive: bool,
    kind: CommandKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    #[cfg(feature = "full")]
    Operation,
    Help,
    Version,
    #[cfg(feature = "full")]
    Completion,
    #[cfg(feature = "full")]
    Man,
    Administration,
}

impl CommandSpec {
    #[cfg(feature = "full")]
    const fn operation(path: &'static str, operation_id: &'static str, destructive: bool) -> Self {
        Self {
            path,
            #[cfg(feature = "full")]
            operation_id: Some(operation_id),
            mutation: true,
            destructive,
            kind: CommandKind::Operation,
        }
    }

    #[cfg(feature = "full")]
    const fn read(path: &'static str, operation_id: &'static str) -> Self {
        Self {
            path,
            #[cfg(feature = "full")]
            operation_id: Some(operation_id),
            mutation: false,
            destructive: false,
            kind: CommandKind::Operation,
        }
    }

    const fn administration(path: &'static str, mutation: bool, destructive: bool) -> Self {
        Self {
            path,
            #[cfg(feature = "full")]
            operation_id: None,
            mutation,
            destructive,
            kind: CommandKind::Administration,
        }
    }

    pub(crate) const fn path(self) -> &'static str {
        self.path
    }

    pub(crate) const fn mutates(self) -> bool {
        self.mutation
    }

    pub(crate) const fn destructive(self) -> bool {
        self.destructive
    }

    pub(crate) const fn is_help(self) -> bool {
        matches!(self.kind, CommandKind::Help)
    }

    pub(crate) const fn is_version(self) -> bool {
        matches!(self.kind, CommandKind::Version)
    }

    #[cfg(feature = "full")]
    pub(crate) const fn is_completion(self) -> bool {
        matches!(self.kind, CommandKind::Completion)
    }

    #[cfg(feature = "full")]
    pub(crate) const fn is_man(self) -> bool {
        matches!(self.kind, CommandKind::Man)
    }

    #[cfg(feature = "full")]
    pub(crate) const fn is_administration(self) -> bool {
        matches!(self.kind, CommandKind::Administration)
    }

    #[cfg(feature = "full")]
    pub(crate) fn contract(self) -> Result<&'static OperationContract, CliError> {
        self.operation_id
            .and_then(operation_by_id)
            .ok_or_else(CliError::invalid_command)
    }
}

const HELP: CommandSpec = CommandSpec {
    path: "help",
    #[cfg(feature = "full")]
    operation_id: None,
    mutation: false,
    destructive: false,
    kind: CommandKind::Help,
};
const VERSION: CommandSpec = CommandSpec {
    path: "version",
    #[cfg(feature = "full")]
    operation_id: None,
    mutation: false,
    destructive: false,
    kind: CommandKind::Version,
};
#[cfg(feature = "full")]
const COMPLETION: CommandSpec = CommandSpec {
    path: "completion",
    operation_id: None,
    mutation: false,
    destructive: false,
    kind: CommandKind::Completion,
};
#[cfg(feature = "full")]
const MAN: CommandSpec = CommandSpec {
    path: "man",
    operation_id: None,
    mutation: false,
    destructive: false,
    kind: CommandKind::Man,
};
#[cfg(feature = "full")]
const PLUGIN_INSTALL: CommandSpec = CommandSpec::administration("plugin.install", true, false);
#[cfg(feature = "full")]
const PLUGIN_UNINSTALL: CommandSpec = CommandSpec::administration("plugin.uninstall", true, true);
#[cfg(feature = "full")]
const PLUGIN_DOCTOR: CommandSpec = CommandSpec::administration("plugin.doctor", false, false);
#[cfg(feature = "full")]
const MCP_CATALOG_QUERY: CommandSpec = CommandSpec::read("catalog.query", "queryCatalog");

#[cfg(feature = "full")]
pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec::administration("init", true, false),
    CommandSpec::administration("source.add", true, false),
    CommandSpec::administration("source.list", false, false),
    CommandSpec::operation("source.refresh", "discoverSources", false),
    CommandSpec::read("source.inspect", "getSourceStatus"),
    CommandSpec::administration("source.remove", true, true),
    CommandSpec::operation("ingest", "ingestCatalog", false),
    CommandSpec::read("status", "getReadiness"),
    CommandSpec::operation("context.plan", "createContextPlan", false),
    CommandSpec::operation("context.compile", "compileContextBundle", false),
    CommandSpec::operation("context.explain", "explainContextBundle", false),
    CommandSpec::operation("context.diff", "compileContextDelta", false),
    CommandSpec::operation("context.revalidate", "revalidateContextBundle", false),
    CommandSpec::operation("context.materialize", "materializeContextBundle", false),
    CommandSpec::administration("project.list", false, false),
    CommandSpec::administration("project.attach", true, false),
    CommandSpec::administration("project.detach", true, true),
    CommandSpec::administration("project.switch", true, false),
    CommandSpec::administration("project.link", true, false),
    CommandSpec::administration("project.unlink", true, true),
    CommandSpec::operation("focus.new", "createSpace", false),
    CommandSpec::administration("focus.switch", true, false),
    CommandSpec::operation("focus.checkpoint", "createSpaceCheckpoint", false),
    CommandSpec::administration("focus.close", true, true),
    CommandSpec::operation("space.fork", "forkSpace", false),
    CommandSpec::operation("space.publish", "publishSpace", false),
    CommandSpec::read("space.log", "getSpaceLog"),
    CommandSpec::read("space.conflicts", "listSpaceConflicts"),
    CommandSpec::operation("handoff.create", "createHandoff", false),
    CommandSpec::read("handoff.preview", "previewHandoff"),
    CommandSpec::read("handoff.inspect", "previewHandoff"),
    CommandSpec::operation("handoff.accept", "acceptHandoff", false),
    CommandSpec::operation("handoff.revoke", "revokeHandoff", true),
    CommandSpec::operation("handoff.merge", "mergeHandoff", false),
    CommandSpec::operation("effect.prepare", "prepareEffect", false),
    CommandSpec::operation("effect.approve", "authorizeEffect", false),
    CommandSpec::operation("effect.dispatch", "dispatchEffect", true),
    CommandSpec::administration("effect.list", false, false),
    CommandSpec::read("effect.inspect", "getEffectStatus"),
    CommandSpec::operation("effect.reconcile", "reconcileEffect", false),
    CommandSpec::operation("effect.compensate", "compensateEffect", true),
    CommandSpec::operation("replay.reconstruct", "createReplay", false),
    CommandSpec::operation("replay.run", "runObservationalReplay", false),
    CommandSpec::operation("replay.compare", "compareLiveReplay", false),
    CommandSpec::read("replay.completeness", "getReplayCompleteness"),
    CommandSpec::administration("policy.check", false, false),
    CommandSpec::administration("policy.explain", false, false),
    CommandSpec::administration("backup.create", true, false),
    CommandSpec::administration("backup.verify", false, false),
    CommandSpec::administration("backup.restore", true, true),
    CommandSpec::administration("gc.plan", false, false),
    CommandSpec::administration("gc.run", true, true),
    CommandSpec::administration("diagnostics.bundle", true, false),
    CommandSpec::read("doctor", "getDiagnostics"),
    CommandSpec::administration("serve", true, false),
    CommandSpec::administration("mcp.serve", true, false),
    CommandSpec::administration("release.verify", false, false),
];

/// Compile-time closed initial-beta surface. Every command runs in-process against the private
/// embedded administration state; no daemon or transport operation is reachable from this table.
#[cfg(all(feature = "beta-embedded", not(feature = "full")))]
pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec::administration("init", true, false),
    CommandSpec::administration("source.add", true, false),
    CommandSpec::administration("source.list", false, false),
    CommandSpec::administration("source.remove", true, true),
    CommandSpec::administration("project.list", false, false),
    CommandSpec::administration("project.attach", true, false),
    CommandSpec::administration("project.detach", true, true),
    CommandSpec::administration("project.switch", true, false),
    CommandSpec::administration("project.link", true, false),
    CommandSpec::administration("project.unlink", true, true),
    CommandSpec::administration("focus.switch", true, false),
    CommandSpec::administration("focus.close", true, true),
];

pub(crate) fn lookup(path: &str) -> Option<CommandSpec> {
    match path {
        "help" => Some(HELP),
        "version" => Some(VERSION),
        #[cfg(feature = "full")]
        "completion" => Some(COMPLETION),
        #[cfg(feature = "full")]
        "man" => Some(MAN),
        #[cfg(feature = "full")]
        "plugin.install" => Some(PLUGIN_INSTALL),
        #[cfg(feature = "full")]
        "plugin.uninstall" => Some(PLUGIN_UNINSTALL),
        #[cfg(feature = "full")]
        "plugin.doctor" => Some(PLUGIN_DOCTOR),
        #[cfg(feature = "full")]
        "catalog.query" => Some(MCP_CATALOG_QUERY),
        _ => COMMANDS
            .iter()
            .copied()
            .find(|command| command.path == path),
    }
}

pub(crate) fn help_text() -> String {
    #[cfg(feature = "full")]
    {
        include_str!("../assets/cigar-help.txt").to_owned()
    }
    #[cfg(all(feature = "beta-embedded", not(feature = "full")))]
    {
        include_str!("../assets/cigar-help-beta.txt").to_owned()
    }
}

#[cfg(feature = "full")]
pub(crate) fn completion(shell: &str) -> Result<&'static str, CliError> {
    match shell {
        "bash" => Ok(include_str!("../completions/cigar.bash")),
        "zsh" => Ok(include_str!("../completions/_cigar")),
        "fish" => Ok(include_str!("../completions/cigar.fish")),
        _ => Err(CliError::invalid_command()),
    }
}

#[cfg(feature = "full")]
pub(crate) fn man_page() -> &'static str {
    include_str!("../man/cigar.1")
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::{COMMANDS, completion, lookup, man_page};
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn section_fifteen_surface_is_unique_and_contract_backed_where_applicable() {
        let paths = COMMANDS
            .iter()
            .map(|command| command.path())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), COMMANDS.len());
        assert_eq!(paths.len(), 57);
        for command in COMMANDS {
            assert_eq!(lookup(command.path()), Some(*command));
            if !command.is_administration() {
                assert!(command.contract().is_ok());
            }
        }
        assert!(lookup("plugin.install").is_some());
        assert!(lookup("plugin.uninstall").is_some());
        assert!(lookup("plugin.doctor").is_some());
    }

    #[test]
    fn completion_assets_cover_the_closed_catalog_and_pass_available_shell_parsers()
    -> Result<(), Box<dyn std::error::Error>> {
        for shell in ["bash", "zsh", "fish"] {
            let asset = completion(shell)?;
            for command in COMMANDS {
                for word in command.path().split('.') {
                    assert!(asset.contains(word), "{shell} completion omits {word}");
                }
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        check_syntax_if_installed(
            "bash",
            &[
                "-n",
                root.join("completions/cigar.bash").to_str().ok_or("path")?,
            ],
        )?;
        check_syntax_if_installed(
            "zsh",
            &[
                "-n",
                root.join("completions/_cigar").to_str().ok_or("path")?,
            ],
        )?;
        check_syntax_if_installed(
            "fish",
            &[
                "-n",
                root.join("completions/cigar.fish").to_str().ok_or("path")?,
            ],
        )?;
        assert!(man_page().contains("CIGAR"));
        check_syntax_if_installed(
            "mandoc",
            &["-Tlint", root.join("man/cigar.1").to_str().ok_or("path")?],
        )?;
        Ok(())
    }

    fn check_syntax_if_installed(
        program: &str,
        arguments: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        match Command::new(program).args(arguments).status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("{program} syntax check failed with {status}").into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(all(test, feature = "beta-embedded", not(feature = "full")))]
mod beta_tests {
    use super::{COMMANDS, lookup};

    #[test]
    fn beta_command_table_is_exact_and_closed() {
        let expected = [
            "init",
            "source.add",
            "source.list",
            "source.remove",
            "project.list",
            "project.attach",
            "project.detach",
            "project.switch",
            "project.link",
            "project.unlink",
            "focus.switch",
            "focus.close",
        ];
        assert_eq!(
            COMMANDS
                .iter()
                .map(|command| command.path())
                .collect::<Vec<_>>(),
            expected
        );
        for path in expected {
            assert_eq!(lookup(path).map(|command| command.path()), Some(path));
        }
        assert!(lookup("help").is_some());
        assert!(lookup("version").is_some());
    }

    #[test]
    fn beta_command_table_excludes_uncompiled_capabilities() {
        for path in [
            "source.refresh",
            "source.inspect",
            "ingest",
            "status",
            "context.compile",
            "space.publish",
            "handoff.create",
            "effect.prepare",
            "effect.dispatch",
            "replay.run",
            "policy.check",
            "backup.create",
            "gc.run",
            "diagnostics.bundle",
            "doctor",
            "serve",
            "mcp.serve",
            "catalog.query",
            "plugin.install",
            "release.verify",
            "completion",
            "man",
        ] {
            assert_eq!(lookup(path), None, "excluded beta command leaked: {path}");
        }
    }
}
