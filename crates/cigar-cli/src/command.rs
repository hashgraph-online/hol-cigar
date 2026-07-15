//! Feature-selected closed command catalogs and generated user-facing assets.

#[cfg(feature = "full")]
use crate::error::CliError;
#[cfg(feature = "full")]
use crate::operation_mappings::cli_operation_mapping;
#[cfg(feature = "full")]
use cigar_api::generated::{
    HttpMethod, IdempotencyRequirement, OperationContract, RevisionRequirement, operation_by_id,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandSpec {
    path: &'static str,
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
    const fn operation(path: &'static str, mutation: bool, destructive: bool) -> Self {
        Self {
            path,
            mutation,
            destructive,
            kind: CommandKind::Operation,
        }
    }

    const fn administration(path: &'static str, mutation: bool, destructive: bool) -> Self {
        Self {
            path,
            mutation,
            destructive,
            kind: CommandKind::Administration,
        }
    }

    pub(crate) const fn path(self) -> &'static str {
        self.path
    }

    pub(crate) fn mutates(self) -> bool {
        #[cfg(feature = "full")]
        if matches!(self.kind, CommandKind::Operation) {
            return cli_operation_mapping(self.path).is_none_or(|mapping| mapping.mutation);
        }
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
        cli_operation_mapping(self.path)
            .and_then(|mapping| operation_by_id(mapping.operation_id))
            .ok_or_else(CliError::invalid_command)
    }

    /// Returns whether this command consumes an operation request document.
    ///
    /// Keeping this authority beside the closed command table prevents a caller-supplied input
    /// file from being silently ignored by a read or unrelated administration command.
    #[cfg(feature = "full")]
    pub(crate) fn accepts_input(self) -> bool {
        match self.kind {
            CommandKind::Operation => self
                .contract()
                .is_ok_and(|contract| contract.http_method == HttpMethod::Post),
            CommandKind::Administration => {
                matches!(self.path, "policy.check" | "policy.explain" | "gc.plan")
            }
            CommandKind::Help
            | CommandKind::Version
            | CommandKind::Completion
            | CommandKind::Man => false,
        }
    }

    /// Returns whether this command consumes an explicit idempotency key.
    #[cfg(feature = "full")]
    pub(crate) fn accepts_idempotency_key(self) -> bool {
        matches!(self.kind, CommandKind::Operation)
            && self.contract().is_ok_and(|contract| {
                contract.idempotency_requirement == IdempotencyRequirement::Required
            })
    }

    /// Returns whether this command consumes an optimistic expected revision.
    #[cfg(feature = "full")]
    pub(crate) fn accepts_expected_revision(self) -> bool {
        matches!(self.kind, CommandKind::Operation)
            && self.contract().is_ok_and(|contract| {
                contract.revision_requirement == RevisionRequirement::Required
            })
    }

    /// Returns whether this command consumes page or resume metadata.
    #[cfg(feature = "full")]
    pub(crate) fn accepts_pagination(self) -> bool {
        matches!(self.path, "space.log" | "space.conflicts" | "effect.list")
    }
}

const HELP: CommandSpec = CommandSpec {
    path: "help",
    mutation: false,
    destructive: false,
    kind: CommandKind::Help,
};
const VERSION: CommandSpec = CommandSpec {
    path: "version",
    mutation: false,
    destructive: false,
    kind: CommandKind::Version,
};
#[cfg(feature = "full")]
const COMPLETION: CommandSpec = CommandSpec {
    path: "completion",
    mutation: false,
    destructive: false,
    kind: CommandKind::Completion,
};
#[cfg(feature = "full")]
const MAN: CommandSpec = CommandSpec {
    path: "man",
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
const MCP_CATALOG_QUERY: CommandSpec = CommandSpec::operation("catalog.query", false, false);

#[cfg(feature = "full")]
pub(crate) const COMMANDS: &[CommandSpec] = &[
    CommandSpec::administration("init", true, false),
    CommandSpec::administration("source.add", true, false),
    CommandSpec::administration("source.list", false, false),
    CommandSpec::operation("source.refresh", false, false),
    CommandSpec::operation("source.inspect", false, false),
    CommandSpec::administration("source.remove", true, true),
    CommandSpec::operation("ingest", true, false),
    CommandSpec::operation("status", false, false),
    CommandSpec::operation("context.plan", true, false),
    CommandSpec::operation("context.compile", true, false),
    CommandSpec::operation("context.explain", true, false),
    CommandSpec::operation("context.diff", true, false),
    CommandSpec::operation("context.revalidate", true, false),
    CommandSpec::operation("context.materialize", true, false),
    CommandSpec::administration("project.list", false, false),
    CommandSpec::administration("project.attach", true, false),
    CommandSpec::administration("project.detach", true, true),
    CommandSpec::administration("project.switch", true, false),
    CommandSpec::administration("project.link", true, false),
    CommandSpec::administration("project.unlink", true, true),
    CommandSpec::operation("focus.new", true, false),
    CommandSpec::administration("focus.switch", true, false),
    CommandSpec::operation("focus.checkpoint", true, false),
    CommandSpec::administration("focus.close", true, true),
    CommandSpec::operation("space.fork", true, false),
    CommandSpec::operation("space.publish", true, false),
    CommandSpec::operation("space.log", false, false),
    CommandSpec::operation("space.conflicts", false, false),
    CommandSpec::operation("handoff.create", true, false),
    CommandSpec::operation("handoff.preview", false, false),
    CommandSpec::operation("handoff.inspect", false, false),
    CommandSpec::operation("handoff.accept", true, false),
    CommandSpec::operation("handoff.revoke", true, true),
    CommandSpec::operation("handoff.merge", true, false),
    CommandSpec::operation("effect.prepare", true, false),
    CommandSpec::operation("effect.approve", true, false),
    CommandSpec::operation("effect.dispatch", true, true),
    CommandSpec::administration("effect.list", false, false),
    CommandSpec::operation("effect.inspect", false, false),
    CommandSpec::operation("effect.reconcile", true, false),
    CommandSpec::operation("effect.compensate", true, true),
    CommandSpec::operation("replay.reconstruct", true, false),
    CommandSpec::operation("replay.run", true, false),
    CommandSpec::operation("replay.compare", true, false),
    CommandSpec::operation("replay.completeness", false, false),
    CommandSpec::administration("policy.check", false, false),
    CommandSpec::administration("policy.explain", false, false),
    CommandSpec::administration("backup.create", true, false),
    CommandSpec::administration("backup.verify", false, false),
    CommandSpec::administration("backup.restore", true, true),
    CommandSpec::administration("gc.plan", true, false),
    CommandSpec::administration("gc.run", true, true),
    CommandSpec::administration("diagnostics.bundle", true, false),
    CommandSpec::administration("state.inspect-beta", false, false),
    #[cfg(unix)]
    CommandSpec::administration("state.import-beta", true, false),
    #[cfg(unix)]
    CommandSpec::administration("state.restore-beta", true, false),
    CommandSpec::operation("doctor", false, false),
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
    use crate::operation_mappings::CLI_OPERATION_MAPPINGS;
    use cigar_api::generated::operation_by_id;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;
    use std::process::Command;

    const AUXILIARY_COMMANDS: &[&str] = &[
        "catalog.query",
        "plugin.install",
        "plugin.uninstall",
        "plugin.doctor",
        "completion",
        "man",
        "help",
        "version",
    ];

    type CommandGroups = BTreeMap<String, BTreeSet<String>>;
    type CompletionSurface = (BTreeSet<String>, CommandGroups);
    type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn section_fifteen_surface_is_unique_and_contract_backed_where_applicable()
    -> Result<(), Box<dyn std::error::Error>> {
        let paths = COMMANDS
            .iter()
            .map(|command| command.path())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), COMMANDS.len());
        #[cfg(unix)]
        assert_eq!(paths.len(), 60);
        #[cfg(not(unix))]
        assert_eq!(paths.len(), 58);
        for command in COMMANDS {
            assert_eq!(lookup(command.path()), Some(*command));
            if !command.is_administration() {
                assert!(command.contract().is_ok());
                let mapping = CLI_OPERATION_MAPPINGS
                    .iter()
                    .find(|mapping| mapping.exposed_name == command.path())
                    .ok_or("operation command mapping missing")?;
                assert_eq!(command.mutation, mapping.mutation);
                assert_eq!(command.mutates(), mapping.mutation);
            }
        }
        assert!(lookup("plugin.install").is_some());
        assert!(lookup("plugin.uninstall").is_some());
        assert!(lookup("plugin.doctor").is_some());
        let mapped = CLI_OPERATION_MAPPINGS
            .iter()
            .map(|mapping| mapping.exposed_name)
            .collect::<BTreeSet<_>>();
        let exposed = COMMANDS
            .iter()
            .filter(|command| !command.is_administration())
            .map(|command| command.path())
            .chain(["catalog.query"])
            .collect::<BTreeSet<_>>();
        assert_eq!(mapped, exposed);
        assert_eq!(mapped.len(), 34);

        let api_documentation = include_str!("../../../spec/api/operations-v1.md");
        for mapping in CLI_OPERATION_MAPPINGS {
            let contract = operation_by_id(mapping.operation_id)
                .ok_or("CLI mapping references an unknown generated operation")?;
            assert_eq!(mapping.mutation, contract.mutation);
            let documented = format!(
                "| `cigar {}` | `{}` | {} |",
                mapping.exposed_name.replace('.', " "),
                mapping.operation_id,
                if mapping.mutation { "mutation" } else { "read" },
            );
            assert!(
                api_documentation.contains(&documented),
                "generated API documentation omits or changes `{}`",
                mapping.exposed_name,
            );
        }
        Ok(())
    }

    #[test]
    fn generated_user_surfaces_have_exact_commands_options_and_value_domains()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected_groups = expected_command_groups();
        #[cfg(unix)]
        assert_eq!(public_command_paths().len(), 68);
        #[cfg(not(unix))]
        assert_eq!(public_command_paths().len(), 66);
        let help = super::help_text();
        assert_eq!(help_command_groups(&help)?, expected_groups);
        assert_eq!(man_command_groups(man_page())?, expected_groups);

        let bash = completion("bash")?;
        let zsh = completion("zsh")?;
        let fish = completion("fish")?;
        assert_completion_commands(bash_completion_groups(bash)?, &expected_groups);
        assert_completion_commands(zsh_completion_groups(zsh)?, &expected_groups);
        assert_completion_commands(fish_completion_groups(fish)?, &expected_groups);

        let parser_options = parser_long_options()?;
        assert_eq!(long_options(&help), parser_options);
        assert_eq!(long_options(man_page()), parser_options);
        assert_eq!(long_options(bash), parser_options);
        assert_eq!(long_options(zsh), parser_options);
        assert_eq!(fish_long_options(fish), parser_options);

        for required in [
            "--output <text|json>",
            "--target <embedded|local|remote>",
            "--color <auto|always|never>",
            "--unicode <auto|always|never>",
            "cigar completion <bash|zsh|fish>",
        ] {
            assert!(help.contains(required), "help changed `{required}`");
        }
        for required in [
            "--output[output format]:format:(text json)",
            "--target[execution target]:target:(embedded local remote)",
            "--color[color mode]:mode:(auto always never)",
            "--unicode[Unicode mode]:mode:(auto always never)",
            "args:completion) _values 'shell' bash zsh fish",
        ] {
            assert!(
                zsh.contains(required),
                "zsh completion changed `{required}`"
            );
        }
        for required in [
            "--output) words=\"text json\"",
            "--target) words=\"embedded local remote\"",
            "--color|--unicode) words=\"auto always never\"",
            "completion) words=\"bash zsh fish\"",
        ] {
            assert!(
                bash.contains(required),
                "bash completion changed `{required}`"
            );
        }
        for required in [
            "-l output -a 'text json'",
            "-l target -a 'embedded local remote'",
            "-l color -a 'auto always never'",
            "-l unicode -a 'auto always never'",
            "__fish_seen_subcommand_from completion' -a 'bash zsh fish'",
        ] {
            assert!(
                fish.contains(required),
                "fish completion changed `{required}`"
            );
        }
        for (surface, required) in [
            (bash, "--help -h --version -V"),
            (zsh, "'-h[show help]'"),
            (zsh, "'-V[show build metadata]'"),
            (fish, "-l help -s h"),
            (fish, "-l version -s V"),
            (man_page(), ".BI --output \" text|json\""),
            (man_page(), ".BI --target \" embedded|local|remote\""),
            (man_page(), ".BI --color \" auto|always|never\""),
            (man_page(), ".BI --unicode \" auto|always|never\""),
            (man_page(), ".BI \"completion \" \"bash|zsh|fish\""),
        ] {
            assert!(
                surface.contains(required),
                "generated surface changed `{required}`"
            );
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
        check_syntax_if_installed(
            "mandoc",
            &["-Tlint", root.join("man/cigar.1").to_str().ok_or("path")?],
        )?;
        Ok(())
    }

    fn public_command_paths() -> BTreeSet<&'static str> {
        COMMANDS
            .iter()
            .map(|command| command.path())
            .chain(AUXILIARY_COMMANDS.iter().copied())
            .collect()
    }

    fn expected_command_groups() -> CommandGroups {
        let mut groups = BTreeMap::new();
        for path in public_command_paths() {
            if let Some((group, subcommand)) = path.split_once('.') {
                groups
                    .entry(group.to_owned())
                    .or_insert_with(BTreeSet::new)
                    .insert(subcommand.to_owned());
            } else {
                groups.entry(path.to_owned()).or_insert_with(BTreeSet::new);
            }
            assert_eq!(lookup(path).map(|command| command.path()), Some(path));
        }
        groups
    }

    fn insert_command_syntax(
        groups: &mut CommandGroups,
        expected: &CommandGroups,
        syntax: &str,
    ) -> TestResult<()> {
        let normalized = syntax.replace('"', "");
        let top = normalized
            .split_whitespace()
            .next()
            .ok_or("empty command syntax")?;
        let values = groups.entry(top.to_owned()).or_default();
        if expected
            .get(top)
            .is_some_and(|subcommands| !subcommands.is_empty())
        {
            let remainder = normalized
                .strip_prefix(top)
                .ok_or("command syntax lost its top-level command")?
                .trim();
            for alternative in remainder.split('|') {
                let subcommand = alternative
                    .split_whitespace()
                    .next()
                    .ok_or("group command omitted its subcommand")?;
                values.insert(subcommand.to_owned());
            }
        }
        Ok(())
    }

    fn help_command_groups(help: &str) -> TestResult<CommandGroups> {
        let commands = help
            .split_once("Commands:\n")
            .and_then(|(_prefix, remainder)| remainder.split_once("\nGlobal options:"))
            .map(|(commands, _suffix)| commands)
            .ok_or("help command section is malformed")?;
        let expected = expected_command_groups();
        let mut groups = BTreeMap::new();
        for line in commands.lines().map(str::trim) {
            if let Some(syntax) = line.strip_prefix("cigar ") {
                insert_command_syntax(&mut groups, &expected, syntax)?;
            }
        }
        Ok(groups)
    }

    fn man_command_groups(man: &str) -> TestResult<CommandGroups> {
        let commands = man
            .split_once(".SH COMMANDS\n")
            .and_then(|(_prefix, remainder)| remainder.split_once(".SH SECURITY\n"))
            .map(|(commands, _suffix)| commands)
            .ok_or("manual command section is malformed")?;
        let expected = expected_command_groups();
        let mut groups = BTreeMap::new();
        for line in commands.lines() {
            let syntax = line
                .strip_prefix(".BI ")
                .or_else(|| line.strip_prefix(".B "));
            if let Some(syntax) = syntax {
                insert_command_syntax(&mut groups, &expected, syntax)?;
            }
        }
        Ok(groups)
    }

    fn split_words(value: &str) -> BTreeSet<String> {
        value
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    }

    fn bash_completion_groups(asset: &str) -> TestResult<CompletionSurface> {
        let mut top = None;
        let mut groups = BTreeMap::new();
        for line in asset.lines().map(str::trim) {
            let Some((label, remainder)) = line.split_once(") words=\"") else {
                continue;
            };
            let Some((words, _suffix)) = remainder.split_once('"') else {
                return Err("bash completion words are not quoted".into());
            };
            if label == "*" {
                top = Some(split_words(words));
            } else if label.bytes().all(|byte| byte.is_ascii_lowercase()) {
                groups.insert(label.to_owned(), split_words(words));
            }
        }
        Ok((top.ok_or("bash top-level completion is missing")?, groups))
    }

    fn zsh_completion_groups(asset: &str) -> TestResult<CompletionSurface> {
        let command_block = asset
            .split_once("commands=(\n")
            .and_then(|(_prefix, remainder)| remainder.split_once("\n  )"))
            .map(|(commands, _suffix)| commands)
            .ok_or("zsh command block is malformed")?;
        let top = command_block
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix('\''))
            .filter_map(|line| line.split_once(':').map(|(command, _description)| command))
            .map(str::to_owned)
            .collect();
        let mut groups = BTreeMap::new();
        for line in asset.lines().map(str::trim) {
            let Some(remainder) = line.strip_prefix("args:") else {
                continue;
            };
            let Some((group, values)) = remainder.split_once(") _values ") else {
                continue;
            };
            let Some((_label, values)) = values.rsplit_once('\'') else {
                return Err("zsh grouped completion label is malformed".into());
            };
            groups.insert(
                group.to_owned(),
                split_words(values.trim().trim_end_matches(";;")),
            );
        }
        Ok((top, groups))
    }

    fn fish_completion_groups(asset: &str) -> TestResult<CompletionSurface> {
        let top_line = asset
            .lines()
            .find(|line| line.contains("__fish_use_subcommand"))
            .ok_or("fish top-level completion is missing")?;
        let top = quoted_argument(top_line, "-a '")?;
        let mut groups = BTreeMap::new();
        for line in asset.lines() {
            let Some((_prefix, remainder)) = line.split_once("__fish_seen_subcommand_from ") else {
                continue;
            };
            let Some((group, _suffix)) = remainder.split_once('\'') else {
                return Err("fish grouped completion predicate is malformed".into());
            };
            groups.insert(
                group.to_owned(),
                split_words(quoted_argument(line, "-a '")?),
            );
        }
        Ok((split_words(top), groups))
    }

    fn quoted_argument<'a>(line: &'a str, marker: &str) -> TestResult<&'a str> {
        line.split_once(marker)
            .and_then(|(_prefix, remainder)| remainder.split_once('\''))
            .map(|(value, _suffix)| value)
            .ok_or_else(|| "quoted completion argument is malformed".into())
    }

    fn assert_completion_commands(actual: CompletionSurface, expected: &CommandGroups) {
        let expected_top = expected.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(actual.0, expected_top);
        let mut expected_group_values = expected
            .iter()
            .filter(|(_group, subcommands)| !subcommands.is_empty())
            .map(|(group, subcommands)| (group.clone(), subcommands.clone()))
            .collect::<BTreeMap<_, _>>();
        expected_group_values.insert(
            "completion".to_owned(),
            BTreeSet::from(["bash".to_owned(), "fish".to_owned(), "zsh".to_owned()]),
        );
        assert_eq!(actual.1, expected_group_values);
    }

    fn long_options(source: &str) -> BTreeSet<String> {
        let mut options = BTreeSet::new();
        let mut remainder = source;
        while let Some((_prefix, after_marker)) = remainder.split_once("--") {
            let length = after_marker
                .bytes()
                .take_while(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'
                })
                .count();
            if length > 0
                && after_marker
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_lowercase)
                && let Some(name) = after_marker.get(..length)
            {
                options.insert(format!("--{name}"));
            }
            remainder = after_marker.get(length..).unwrap_or_default();
        }
        options
    }

    fn parser_long_options() -> TestResult<BTreeSet<String>> {
        let source = include_str!("arguments.rs");
        let parse_body = source
            .split_once("pub(crate) fn parse(")
            .and_then(|(_prefix, remainder)| {
                remainder.split_once("\n#[cfg(feature = \"full\")]\nfn group_requires_subcommand")
            })
            .map(|(body, _suffix)| body)
            .ok_or("argument parser source boundary changed")?;
        Ok(long_options(parse_body))
    }

    fn fish_long_options(asset: &str) -> BTreeSet<String> {
        asset
            .lines()
            .filter_map(|line| line.split_once(" -l ").map(|(_prefix, suffix)| suffix))
            .filter_map(|suffix| suffix.split_whitespace().next())
            .map(|name| format!("--{name}"))
            .collect()
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
            "state.inspect-beta",
            "state.import-beta",
            "state.restore-beta",
            "completion",
            "man",
        ] {
            assert_eq!(lookup(path), None, "excluded beta command leaked: {path}");
        }
    }
}
