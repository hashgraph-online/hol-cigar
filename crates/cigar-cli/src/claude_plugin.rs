//! User-scoped Claude Code adapter lifecycle through documented public plugin commands.

use crate::arguments::ParsedInvocation;
use crate::error::CliError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt as _;

const ADAPTER: &str = "claude-code";
const PLUGIN_ID: &str = "cigar@cigar-local";
const MARKETPLACE: &str = "cigar-local";
const RECEIPT_SCHEMA: &str = "cigar.claude-plugin-install.v1";
const MAX_FILES: usize = 10_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
// The released, signed CLI embeds this manifest. A package-supplied manifest therefore cannot
// authorize its own modified hook or MCP bytes at installation time.
const TRUSTED_PACKAGE_MANIFEST: &[u8] =
    include_bytes!("../../../adapters/claude-code/package-manifest.json");
const QUALIFIED_HOOKS: [&str; 18] = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "InstructionsLoaded",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "PreCompact",
    "PostCompact",
    "CwdChanged",
    "WorktreeRemove",
    "Stop",
    "StopFailure",
];
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compatibility {
    schema_version: String,
    claude_code: VersionRange,
    platforms: Vec<String>,
    public_surfaces_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRange {
    minimum_inclusive: String,
    maximum_exclusive: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    files: Vec<ManifestFile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug)]
struct Package {
    compatibility: Compatibility,
    files: Vec<FrozenFile>,
    digest: String,
}

#[derive(Clone, Debug)]
struct FrozenFile {
    path: String,
    sha256: String,
    contents: Vec<u8>,
}

#[derive(Debug)]
struct TemporaryMarketplace {
    root: PathBuf,
    plugin: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: String,
    plugin_id: String,
    marketplace_name: String,
    marketplace_root: PathBuf,
    package_digest: String,
    claude_version: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Semver(u64, u64, u64);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct Handshake {
    daemon: bool,
    mcp: bool,
    hook: bool,
    schema_noop: bool,
}

impl Handshake {
    const fn all(self) -> bool {
        self.daemon && self.mcp && self.hook && self.schema_noop
    }
}

pub(crate) async fn install(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    require_adapter(invocation)?;
    let package = validate_package()?;
    let version = claude_version(invocation.options.deadline).await?;
    ensure_compatible(&package.compatibility, version)?;
    let validation_stage = TemporaryMarketplace::new(&package)?;
    validate_with_claude(validation_stage.plugin_root(), invocation.options.deadline).await?;
    let handshake =
        handshake_report(validation_stage.plugin_root(), invocation.options.deadline).await;
    if !handshake.all() {
        return Err(CliError::plugin_handshake_failed());
    }
    let files = package
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if invocation.options.dry_run {
        return Ok(json!({
            "adapter": ADAPTER,
            "planned": true,
            "scope": "user",
            "claude_version": version.to_string(),
            "qualified_range": {
                "minimum_inclusive": package.compatibility.claude_code.minimum_inclusive,
                "maximum_exclusive": package.compatibility.claude_code.maximum_exclusive
            },
            "package_digest": package.digest,
            "files": files,
            "capabilities": {
                "mcp_tools": 10,
                "resource_families": 8,
                "hooks": true,
                "skills": true,
                "agents": true,
                "postinstall_download": false
            },
            "handshake": handshake
        }));
    }

    let home = cigar_home()?;
    let receipt_file = receipt_path(&home);
    if receipt_file.exists() {
        return Err(CliError::state_conflict());
    }
    let marketplace_root = home
        .join("claude-code")
        .join(format!("marketplace-{}", env!("CARGO_PKG_VERSION")));
    guard_managed(&home, &marketplace_root)?;
    if marketplace_root.exists() {
        remove_managed(&home, &marketplace_root)?;
    }
    stage_marketplace(&package, &marketplace_root)?;

    let claude = binary("CIGAR_CLAUDE_BINARY", "claude");
    if run(
        &claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("marketplace"),
            OsStr::new("add"),
            marketplace_root.as_os_str(),
        ],
        invocation.options.deadline,
    )
    .await
    .is_err()
    {
        let _ignored = remove_managed(&home, &marketplace_root);
        return Err(CliError::plugin_handshake_failed());
    }
    if run(
        &claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("install"),
            OsStr::new(PLUGIN_ID),
            OsStr::new("--scope"),
            OsStr::new("user"),
        ],
        invocation.options.deadline,
    )
    .await
    .is_err()
    {
        let _ignored = run(
            &claude,
            &[
                OsStr::new("plugin"),
                OsStr::new("marketplace"),
                OsStr::new("remove"),
                OsStr::new(MARKETPLACE),
            ],
            invocation.options.deadline,
        )
        .await;
        let _ignored = remove_managed(&home, &marketplace_root);
        return Err(CliError::plugin_handshake_failed());
    }

    let receipt = Receipt {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        plugin_id: PLUGIN_ID.to_owned(),
        marketplace_name: MARKETPLACE.to_owned(),
        marketplace_root: marketplace_root.clone(),
        package_digest: package.digest.clone(),
        claude_version: version.to_string(),
    };
    if write_json(&receipt_file, &receipt).is_err() {
        rollback_public_install(&claude, invocation.options.deadline).await;
        let _ignored = remove_managed(&home, &marketplace_root);
        return Err(CliError::state_unavailable());
    }
    Ok(json!({
        "adapter": ADAPTER,
        "installed": true,
        "scope": "user",
        "claude_version": version.to_string(),
        "package_digest": package.digest,
        "public_surface": "claude plugin install",
        "portable_catalog_preserved": true
    }))
}

pub(crate) async fn uninstall(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    require_adapter(invocation)?;
    let home = cigar_home()?;
    let path = receipt_path(&home);
    let receipt: Receipt = read_json(&path, 1024 * 1024)?;
    validate_receipt(&receipt, &home)?;
    if invocation.options.dry_run {
        return Ok(json!({
            "adapter": ADAPTER,
            "planned": true,
            "scope": "user",
            "portable_catalog_preserved": true
        }));
    }
    let claude = binary("CIGAR_CLAUDE_BINARY", "claude");
    run(
        &claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("uninstall"),
            OsStr::new(PLUGIN_ID),
            OsStr::new("--scope"),
            OsStr::new("user"),
        ],
        invocation.options.deadline,
    )
    .await
    .map_err(|_error| CliError::plugin_handshake_failed())?;
    run(
        &claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("marketplace"),
            OsStr::new("remove"),
            OsStr::new(MARKETPLACE),
        ],
        invocation.options.deadline,
    )
    .await
    .map_err(|_error| CliError::plugin_handshake_failed())?;
    remove_managed(&home, &receipt.marketplace_root)?;
    std::fs::remove_file(path).map_err(|_error| CliError::state_unavailable())?;
    Ok(json!({
        "adapter": ADAPTER,
        "uninstalled": true,
        "scope": "user",
        "portable_catalog_preserved": true,
        "public_surface": "claude plugin uninstall"
    }))
}

pub(crate) async fn doctor(invocation: &ParsedInvocation) -> Result<Value, CliError> {
    require_adapter(invocation)?;
    let package = validate_package();
    let version = claude_version(invocation.options.deadline).await;
    let compatible = package
        .as_ref()
        .ok()
        .zip(version.as_ref().ok().copied())
        .is_some_and(|(package, version)| {
            ensure_compatible(&package.compatibility, version).is_ok()
        });
    let validation_stage = package
        .as_ref()
        .ok()
        .and_then(|package| TemporaryMarketplace::new(package).ok());
    let public_validation = if let Some(stage) = &validation_stage {
        validate_with_claude(stage.plugin_root(), invocation.options.deadline)
            .await
            .is_ok()
    } else {
        false
    };
    let handshake = if let Some(stage) = &validation_stage {
        handshake_report(stage.plugin_root(), invocation.options.deadline).await
    } else {
        Handshake::default()
    };
    let installed = cigar_home()
        .map(|home| receipt_path(&home).is_file())
        .unwrap_or(false);
    Ok(json!({
        "adapter": ADAPTER,
        "package_valid": package.is_ok(),
        "claude_version": version.ok().map(|value| value.to_string()),
        "compatible": compatible,
        "public_plugin_validation": public_validation,
        "daemon": handshake.daemon,
        "mcp": handshake.mcp,
        "hook": handshake.hook,
        "schema_noop_compile": handshake.schema_noop,
        "installed": installed,
        "private_provider_files": false,
        "model_calls": 0,
        "next_commands": if compatible && public_validation && handshake.all() {
            vec!["cigar plugin install claude-code --dry-run", "cigar plugin install claude-code --yes"]
        } else {
            vec!["install Claude Code 2.1.207", "start cigard", "reinstall the matching signed CIGAR package"]
        }
    }))
}

async fn rollback_public_install(claude: &OsStr, deadline: Duration) {
    let _ignored = run(
        claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("uninstall"),
            OsStr::new(PLUGIN_ID),
            OsStr::new("--scope"),
            OsStr::new("user"),
        ],
        deadline,
    )
    .await;
    let _ignored = run(
        claude,
        &[
            OsStr::new("plugin"),
            OsStr::new("marketplace"),
            OsStr::new("remove"),
            OsStr::new(MARKETPLACE),
        ],
        deadline,
    )
    .await;
}

async fn handshake_report(root: &Path, deadline: Duration) -> Handshake {
    let daemon = std::env::var_os("CIGAR_CLAUDE_DAEMON_CHECK_BINARY")
        .or_else(|| std::env::current_exe().ok().map(PathBuf::into_os_string))
        .unwrap_or_else(|| OsString::from("cigar"));
    let mcp = binary("CIGAR_MCP_BINARY", "cigar-mcp");
    let hook = binary("CIGAR_CLAUDE_HOOK_BINARY", "cigar-claude-hook");
    Handshake {
        daemon: run(
            &daemon,
            &[
                OsStr::new("status"),
                OsStr::new("--output"),
                OsStr::new("json"),
                OsStr::new("--deadline"),
                OsStr::new("1s"),
            ],
            deadline,
        )
        .await
        .is_ok(),
        mcp: run(&mcp, &[OsStr::new("doctor")], deadline).await.is_ok(),
        hook: run(
            &hook,
            &[
                OsStr::new("doctor"),
                OsStr::new("--plugin-root"),
                root.as_os_str(),
            ],
            deadline,
        )
        .await
        .is_ok(),
        schema_noop: run(&mcp, &[OsStr::new("schema-noop")], deadline)
            .await
            .is_ok(),
    }
}

fn require_adapter(invocation: &ParsedInvocation) -> Result<(), CliError> {
    match invocation.positionals.as_slice() {
        [adapter] if adapter == ADAPTER => Ok(()),
        _ => Err(CliError::invalid_command()),
    }
}

fn validate_package() -> Result<Package, CliError> {
    let root = source_root()?;
    let manifest_bytes = read_regular(&root.join("package-manifest.json"), 4 * 1024 * 1024)?;
    if manifest_bytes.as_slice() != TRUSTED_PACKAGE_MANIFEST {
        return Err(CliError::plugin_invalid());
    }
    cigar_canon::parse_strict_json(&manifest_bytes).map_err(|_error| CliError::plugin_invalid())?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_error| CliError::plugin_invalid())?;
    if manifest.schema_version != "cigar.claude-code-package.v1"
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_FILES
    {
        return Err(CliError::plugin_invalid());
    }
    let mut expected = BTreeSet::new();
    let mut previous = None;
    let mut total = 0_u64;
    let mut aggregate = Sha256::new();
    let mut files = Vec::with_capacity(manifest.files.len());
    for file in manifest.files {
        validate_relative(&file.path)?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &file.path)
            || !expected.insert(file.path.clone())
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CliError::plugin_invalid());
        }
        previous = Some(file.path.clone());
        total = total
            .checked_add(file.bytes)
            .filter(|value| *value <= MAX_BYTES)
            .ok_or_else(CliError::plugin_invalid)?;
        let bytes = read_regular(&root.join(&file.path), MAX_BYTES)?;
        if u64::try_from(bytes.len()).ok() != Some(file.bytes)
            || sha256(&bytes) != file.sha256.to_ascii_lowercase()
        {
            return Err(CliError::plugin_invalid());
        }
        aggregate.update(file.path.as_bytes());
        aggregate.update([0]);
        aggregate.update(file.sha256.as_bytes());
        aggregate.update([0]);
        files.push(FrozenFile {
            path: file.path,
            sha256: file.sha256.to_ascii_lowercase(),
            contents: bytes,
        });
    }
    if collect_files(&root)? != expected {
        return Err(CliError::plugin_invalid());
    }
    let compatibility: Compatibility = frozen_json(&files, "compatibility.json")?;
    if compatibility.schema_version != "cigar.claude-code-compatibility.v1"
        || !compatibility.public_surfaces_only
        || !compatibility.platforms.iter().any(|supported| {
            supported == "all"
                || supported == &platform()
                || supported == &format!("{}-all", std::env::consts::OS)
        })
    {
        return Err(CliError::plugin_invalid());
    }
    validate_public_surface(&files)?;
    Ok(Package {
        compatibility,
        files,
        digest: format!("1220{}", hex(&aggregate.finalize())),
    })
}

fn frozen_json<T>(files: &[FrozenFile], path: &str) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = frozen_bytes(files, path)?;
    cigar_canon::parse_strict_json(bytes).map_err(|_error| CliError::plugin_invalid())?;
    serde_json::from_slice(bytes).map_err(|_error| CliError::plugin_invalid())
}

fn frozen_bytes<'a>(files: &'a [FrozenFile], path: &str) -> Result<&'a [u8], CliError> {
    files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents.as_slice())
        .ok_or_else(CliError::plugin_invalid)
}

fn validate_public_surface(files: &[FrozenFile]) -> Result<(), CliError> {
    let plugin_metadata = files
        .iter()
        .filter(|file| file.path.starts_with(".claude-plugin/"))
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    if plugin_metadata != [".claude-plugin/plugin.json"] {
        return Err(CliError::plugin_invalid());
    }
    let hooks: Value = frozen_json(files, "hooks/hooks.json")?;
    if hooks != expected_hooks() {
        return Err(CliError::plugin_invalid());
    }
    let mcp: Value = frozen_json(files, ".mcp.json")?;
    if mcp != expected_mcp() {
        return Err(CliError::plugin_invalid());
    }
    for relative in [
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "hooks/hooks.json",
    ] {
        let text = std::str::from_utf8(frozen_bytes(files, relative)?)
            .map_err(|_error| CliError::plugin_invalid())?;
        for forbidden in [
            concat!(".claude", "/projects"),
            concat!(".claude", ".json"),
            concat!("read_to_string(", "transcript"),
            concat!("File::open(", "transcript"),
        ] {
            if text.contains(forbidden) {
                return Err(CliError::plugin_invalid());
            }
        }
    }
    Ok(())
}

fn expected_mcp() -> Value {
    json!({
        "mcpServers": {
            "cigar": {
                "command": "cigar-mcp",
                "args": ["serve"],
                "env": {
                    "CIGAR_CLAUDE_PLUGIN_ROOT": "${CLAUDE_PLUGIN_ROOT}",
                    "CIGAR_CLAUDE_PLUGIN_DATA": "${CLAUDE_PLUGIN_DATA}"
                }
            }
        }
    })
}

fn expected_hooks() -> Value {
    let handler = json!({
        "type": "command",
        "command": "cigar-claude-hook",
        "args": [
            "run",
            "--plugin-root",
            "${CLAUDE_PLUGIN_ROOT}",
            "--plugin-data",
            "${CLAUDE_PLUGIN_DATA}"
        ],
        "timeout": 1
    });
    let hooks = QUALIFIED_HOOKS
        .into_iter()
        .map(|event| (event.to_owned(), json!([{"hooks": [handler.clone()]}])))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(serde_json::Map::from_iter([(
        "hooks".to_owned(),
        Value::Object(hooks),
    )]))
}

fn collect_files(root: &Path) -> Result<BTreeSet<String>, CliError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(directory)
            .map_err(|_error| CliError::plugin_invalid())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| CliError::plugin_invalid())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|_error| CliError::plugin_invalid())?;
            if metadata.file_type().is_symlink() {
                return Err(CliError::plugin_invalid());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .ok()
                    .and_then(Path::to_str)
                    .ok_or_else(CliError::plugin_invalid)?
                    .replace('\\', "/");
                if relative != "package-manifest.json" {
                    if files.len() >= MAX_FILES {
                        return Err(CliError::plugin_invalid());
                    }
                    files.insert(relative);
                }
            } else {
                return Err(CliError::plugin_invalid());
            }
        }
    }
    Ok(files)
}

fn source_root() -> Result<PathBuf, CliError> {
    let source = std::env::var_os("CIGAR_CLAUDE_PLUGIN_SOURCE").unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../adapters/claude-code")
            .into_os_string()
    });
    let path = PathBuf::from(source);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_error| CliError::plugin_invalid())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::plugin_invalid());
    }
    std::fs::canonicalize(path).map_err(|_error| CliError::plugin_invalid())
}

async fn claude_version(deadline: Duration) -> Result<Semver, CliError> {
    let capture = run(
        &binary("CIGAR_CLAUDE_BINARY", "claude"),
        &[OsStr::new("--version")],
        deadline,
    )
    .await
    .map_err(|_error| CliError::plugin_handshake_failed())?;
    let output = std::str::from_utf8(&capture.stdout)
        .map_err(|_error| CliError::plugin_handshake_failed())?;
    output
        .split_ascii_whitespace()
        .find_map(|word| {
            Semver::parse(
                word.trim_matches(|character: char| {
                    !character.is_ascii_digit() && character != '.'
                }),
            )
        })
        .ok_or_else(CliError::plugin_handshake_failed)
}

fn ensure_compatible(compatibility: &Compatibility, version: Semver) -> Result<(), CliError> {
    let minimum = Semver::parse(&compatibility.claude_code.minimum_inclusive)
        .ok_or_else(CliError::plugin_invalid)?;
    let maximum = Semver::parse(&compatibility.claude_code.maximum_exclusive)
        .ok_or_else(CliError::plugin_invalid)?;
    if minimum >= maximum {
        return Err(CliError::plugin_invalid());
    }
    if version < minimum || version >= maximum {
        Err(CliError::plugin_incompatible())
    } else {
        Ok(())
    }
}

async fn validate_with_claude(root: &Path, deadline: Duration) -> Result<(), CliError> {
    run(
        &binary("CIGAR_CLAUDE_BINARY", "claude"),
        &[
            OsStr::new("plugin"),
            OsStr::new("validate"),
            root.as_os_str(),
            OsStr::new("--strict"),
        ],
        deadline,
    )
    .await
    .map(|_capture| ())
    .map_err(|_error| CliError::plugin_handshake_failed())
}

impl Semver {
    fn parse(value: &str) -> Option<Self> {
        let core = value.split_once('-').map_or(value, |(core, _suffix)| core);
        let mut parts = core.split('.');
        let version = Self(
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        if parts.next().is_some() {
            None
        } else {
            Some(version)
        }
    }
}

impl std::fmt::Display for Semver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.0, self.1, self.2)
    }
}

fn stage_marketplace(package: &Package, destination: &Path) -> Result<(), CliError> {
    private_directory(destination)?;
    let plugin = destination.join("plugins/cigar");
    private_directory(&plugin)?;
    for file in &package.files {
        let target = plugin.join(&file.path);
        let parent = target.parent().ok_or_else(CliError::plugin_invalid)?;
        private_directory(parent)?;
        write_new(&target, &file.contents)?;
    }
    write_new(
        &plugin.join("package-manifest.json"),
        TRUSTED_PACKAGE_MANIFEST,
    )?;
    verify_staged_package(package, &plugin)?;
    let metadata = destination.join(".claude-plugin");
    private_directory(&metadata)?;
    write_json(
        &metadata.join("marketplace.json"),
        &json!({
            "name": MARKETPLACE,
            "owner": {"name": "CIGAR contributors"},
            "plugins": [{
                "name": "cigar",
                "source": "./plugins/cigar",
                "description": "Deterministic governed CIGAR context for Claude Code",
                "version": env!("CARGO_PKG_VERSION")
            }]
        }),
    )
}

fn verify_staged_package(package: &Package, root: &Path) -> Result<(), CliError> {
    let expected = package
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if collect_files(root)? != expected
        || read_regular(&root.join("package-manifest.json"), 4 * 1024 * 1024)?
            != TRUSTED_PACKAGE_MANIFEST
    {
        return Err(CliError::plugin_invalid());
    }
    for file in &package.files {
        let bytes = read_regular(&root.join(&file.path), MAX_BYTES)?;
        if bytes != file.contents || sha256(&bytes) != file.sha256 {
            return Err(CliError::plugin_invalid());
        }
    }
    validate_public_surface(&package.files)?;
    Ok(())
}

impl TemporaryMarketplace {
    fn new(package: &Package) -> Result<Self, CliError> {
        let parent = validation_stage_parent()?;
        for _attempt in 0..128 {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).map_err(|_error| CliError::state_unavailable())?;
            let root = parent.join(format!("cigar-plugin-validation-{}", hex(&nonce)));
            match create_private_directory(&root) {
                Ok(()) => {
                    let plugin = root.join("plugins/cigar");
                    let stage = Self { root, plugin };
                    if let Err(error) = stage_marketplace(package, &stage.root) {
                        drop(stage);
                        return Err(error);
                    }
                    return Ok(stage);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_error) => return Err(CliError::state_unavailable()),
            }
        }
        Err(CliError::state_unavailable())
    }

    fn plugin_root(&self) -> &Path {
        &self.plugin
    }
}

fn validation_stage_parent() -> Result<PathBuf, CliError> {
    #[cfg(unix)]
    {
        let temporary = std::env::temp_dir();
        let metadata = std::fs::symlink_metadata(&temporary)
            .map_err(|_error| CliError::state_unavailable())?;
        if !metadata.is_dir() {
            return Err(CliError::state_unavailable());
        }
        std::fs::canonicalize(temporary).map_err(|_error| CliError::state_unavailable())
    }
    #[cfg(windows)]
    {
        let parent = cigar_home()?.join("claude-code");
        private_directory(&parent)?;
        Ok(parent)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(CliError::state_unavailable())
    }
}

impl Drop for TemporaryMarketplace {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.root);
    }
}

fn cigar_home() -> Result<PathBuf, CliError> {
    let value = std::env::var_os("CIGAR_HOME").or_else(|| {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| Path::new(&home).join(".cigar").into_os_string())
    });
    let path = PathBuf::from(value.ok_or_else(CliError::state_unavailable)?);
    if !path.is_absolute() {
        return Err(CliError::state_unavailable());
    }
    private_directory(&path)?;
    std::fs::canonicalize(path).map_err(|_error| CliError::state_unavailable())
}

fn receipt_path(home: &Path) -> PathBuf {
    home.join("claude-code/install.json")
}

fn validate_receipt(receipt: &Receipt, home: &Path) -> Result<(), CliError> {
    if receipt.schema_version != RECEIPT_SCHEMA
        || receipt.plugin_id != PLUGIN_ID
        || receipt.marketplace_name != MARKETPLACE
        || receipt.package_digest.len() != 68
        || !receipt.package_digest.starts_with("1220")
    {
        return Err(CliError::state_corrupt());
    }
    guard_managed(home, &receipt.marketplace_root)
}

fn guard_managed(home: &Path, path: &Path) -> Result<(), CliError> {
    if !home.is_absolute()
        || !path.is_absolute()
        || path == home
        || !path.starts_with(home.join("claude-code"))
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn remove_managed(home: &Path, path: &Path) -> Result<(), CliError> {
    guard_managed(home, path)?;
    if !path.exists() {
        return Ok(());
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_corrupt());
    }
    std::fs::remove_dir_all(path).map_err(|_error| CliError::state_unavailable())
}

fn validate_relative(value: &str) -> Result<(), CliError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4_096
        || value.contains('\\')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(CliError::plugin_invalid())
    } else {
        Ok(())
    }
}

fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn binary(variable: &str, fallback: &str) -> OsString {
    std::env::var_os(variable).unwrap_or_else(|| OsString::from(fallback))
}

struct Capture {
    stdout: Vec<u8>,
}

async fn run(
    program: &OsStr,
    arguments: &[&OsStr],
    deadline: Duration,
) -> Result<Capture, CliError> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_error| CliError::plugin_handshake_failed())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(CliError::plugin_handshake_failed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(CliError::plugin_handshake_failed)?;
    let stdout_task = tokio::spawn(read_output(stdout));
    let stderr_task = tokio::spawn(read_output(stderr));
    let status = match tokio::time::timeout(deadline, child.wait()).await {
        Ok(status) => status.map_err(|_error| CliError::plugin_handshake_failed())?,
        Err(_elapsed) => {
            let _ignored = child.kill().await;
            let _ignored = child.wait().await;
            return Err(CliError::deadline_exceeded());
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|_join| CliError::plugin_handshake_failed())??;
    let _stderr = stderr_task
        .await
        .map_err(|_join| CliError::plugin_handshake_failed())??;
    if status.success() {
        Ok(Capture { stdout })
    } else {
        Err(CliError::plugin_handshake_failed())
    }
}

async fn read_output<R>(reader: R) -> Result<Vec<u8>, CliError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let limit = u64::try_from(MAX_OUTPUT)
        .map_err(|_error| CliError::plugin_handshake_failed())?
        .saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_error| CliError::plugin_handshake_failed())?;
    if bytes.len() > MAX_OUTPUT {
        Err(CliError::plugin_handshake_failed())
    } else {
        Ok(bytes)
    }
}

fn read_json<T>(path: &Path, maximum: u64) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = read_regular(path, maximum)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::plugin_invalid())?;
    serde_json::from_slice(&bytes).map_err(|_error| CliError::plugin_invalid())
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| CliError::plugin_invalid())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::plugin_invalid());
    }
    let file = File::open(path).map_err(|_error| CliError::plugin_invalid())?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::plugin_invalid())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        Err(CliError::plugin_invalid())
    } else {
        Ok(bytes)
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn private_directory(path: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(path).map_err(|_error| CliError::state_unavailable())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| CliError::state_unavailable())?;
    }
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let bytes = serde_json::to_vec(value).map_err(|_error| CliError::state_unavailable())?;
    let parent = path.parent().ok_or_else(CliError::state_unavailable)?;
    private_directory(parent)?;
    let temporary = parent.join(format!(
        ".cigar-plugin-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_new(&temporary, &bytes)?;
    let result = std::fs::rename(&temporary, path).map_err(|_error| CliError::state_unavailable());
    if result.is_err() {
        let _ignored = std::fs::remove_file(temporary);
    }
    result
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_error| CliError::state_unavailable())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_error| CliError::state_unavailable())
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Compatibility, Semver, VersionRange, ensure_compatible, validate_relative};

    #[test]
    fn compatibility_range_rejects_old_and_unqualified_future_versions()
    -> Result<(), Box<dyn std::error::Error>> {
        let compatibility = Compatibility {
            schema_version: "cigar.claude-code-compatibility.v1".to_owned(),
            claude_code: VersionRange {
                minimum_inclusive: "2.1.207".to_owned(),
                maximum_exclusive: "2.1.208".to_owned(),
            },
            platforms: vec!["all".to_owned()],
            public_surfaces_only: true,
        };
        assert!(
            ensure_compatible(&compatibility, Semver::parse("2.1.207").ok_or("version")?).is_ok()
        );
        assert!(
            ensure_compatible(&compatibility, Semver::parse("2.0.67").ok_or("version")?).is_err()
        );
        assert!(
            ensure_compatible(&compatibility, Semver::parse("2.1.208").ok_or("version")?).is_err()
        );
        Ok(())
    }

    #[test]
    fn package_paths_cannot_escape_or_use_platform_aliases() {
        assert!(validate_relative("skills/why/SKILL.md").is_ok());
        for invalid in ["", "../escape", "/absolute", "a/./b", "a\\b"] {
            assert!(validate_relative(invalid).is_err(), "{invalid}");
        }
    }
}
