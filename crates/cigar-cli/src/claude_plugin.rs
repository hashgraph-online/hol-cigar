//! User-scoped Claude Code adapter lifecycle through documented public plugin commands.

use crate::arguments::ParsedInvocation;
use crate::error::CliError;
#[cfg(not(unix))]
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
#[cfg(unix)]
use cap_std::fs::{OpenOptionsExt as _, PermissionsExt as _};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
include!(concat!(env!("OUT_DIR"), "/embedded_claude_plugin.rs"));
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
type PackageSource = (Vec<u8>, BTreeMap<String, Vec<u8>>);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compatibility {
    schema_version: String,
    context_abi: String,
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

struct ManagedHome {
    path: PathBuf,
    directory: Dir,
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

    let home = ManagedHome::open()?;
    if entry_exists(&home.directory, receipt_relative())? {
        return Err(CliError::state_conflict());
    }
    let marketplace_relative = marketplace_relative();
    let marketplace_root = home.path.join(&marketplace_relative);
    if entry_exists(&home.directory, &marketplace_relative)? {
        remove_managed(&home, &marketplace_relative)?;
    }
    stage_marketplace_at(&package, &home.directory, &marketplace_relative)?;

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
        let _ignored = remove_managed(&home, &marketplace_relative);
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
        let _ignored = remove_managed(&home, &marketplace_relative);
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
    if write_json_at(&home.directory, receipt_relative(), &receipt).is_err() {
        rollback_public_install(&claude, invocation.options.deadline).await;
        let _ignored = remove_managed(&home, &marketplace_relative);
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
    let home = ManagedHome::open()?;
    let receipt: Receipt = read_json_at(&home.directory, receipt_relative(), 1024 * 1024)?;
    validate_receipt(&receipt, &home.path)?;
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
    remove_managed(&home, &marketplace_relative())?;
    home.directory
        .remove_file(receipt_relative())
        .map_err(|_error| CliError::state_unavailable())?;
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
    let installed = ManagedHome::open()
        .and_then(|home| entry_exists(&home.directory, receipt_relative()))
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
    let mcp = root.join("bin/cigar-mcp").into_os_string();
    let hook = root.join("bin/cigar-claude-hook").into_os_string();
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
    let (manifest_bytes, mut source_files) = package_source()?;
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
        let bytes = source_files
            .remove(&file.path)
            .ok_or_else(CliError::plugin_invalid)?;
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
    if files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(CliError::plugin_invalid());
    }
    let compatibility: Compatibility = frozen_json(&files, "compatibility.json")?;
    if compatibility.schema_version != "cigar.claude-code-compatibility.v1"
        || compatibility.context_abi != "cigar.context.v1"
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
    for (relative, variable, executable) in [
        ("bin/cigar-mcp", "CIGAR_MCP_BINARY", "cigar-mcp"),
        (
            "bin/cigar-claude-hook",
            "CIGAR_CLAUDE_HOOK_BINARY",
            "cigar-claude-hook",
        ),
    ] {
        let payload = freeze_runtime_executable(variable, executable)?;
        if let Some(packaged) = source_files.remove(relative) {
            if packaged != payload {
                return Err(CliError::plugin_invalid());
            }
        }
        let digest = sha256(&payload);
        aggregate.update(relative.as_bytes());
        aggregate.update([0]);
        aggregate.update(digest.as_bytes());
        aggregate.update([0]);
        files.push(FrozenFile {
            path: relative.to_owned(),
            sha256: digest,
            contents: payload,
        });
    }
    if !source_files.is_empty() {
        return Err(CliError::plugin_invalid());
    }
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    Ok(Package {
        compatibility,
        files,
        digest: format!("1220{}", hex(&aggregate.finalize())),
    })
}

fn freeze_runtime_executable(variable: &str, executable: &str) -> Result<Vec<u8>, CliError> {
    let path = if let Some(path) = std::env::var_os(variable) {
        PathBuf::from(path)
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.join(executable)))
            .ok_or_else(CliError::plugin_invalid)?
    };
    read_stable_executable(&path, MAX_BYTES)
}

#[cfg(unix)]
fn read_stable_executable(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute() {
        return Err(CliError::plugin_invalid());
    }
    let canonical = std::fs::canonicalize(path).map_err(|_error| CliError::plugin_invalid())?;
    let names = canonical
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let (name, ancestors) = names.split_last().ok_or_else(CliError::plugin_invalid)?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::plugin_invalid())?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| CliError::plugin_invalid())?;
    }
    let mut file = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::plugin_invalid())?;
    let before = file
        .metadata()
        .map_err(|_error| CliError::plugin_invalid())?;
    let owner = before.uid();
    if !before.is_file()
        || before.nlink() != 1
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || before.mode() & 0o022 != 0
        || before.mode() & 0o111 == 0
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(CliError::plugin_invalid());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_error| CliError::plugin_invalid())?,
    );
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::plugin_invalid())?;
    let after = file
        .metadata()
        .map_err(|_error| CliError::plugin_invalid())?;
    if u64::try_from(bytes.len()).ok() != Some(before.len())
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(CliError::plugin_invalid());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_stable_executable(_path: &Path, _maximum: u64) -> Result<Vec<u8>, CliError> {
    Err(CliError::plugin_incompatible())
}

fn package_source() -> Result<PackageSource, CliError> {
    if let Some(source) = std::env::var_os("CIGAR_CLAUDE_PLUGIN_SOURCE") {
        return external_package_source(PathBuf::from(source));
    }
    let mut files = BTreeMap::new();
    for (path, contents) in EMBEDDED_PACKAGE_FILES {
        validate_relative(path)?;
        if files
            .insert((*path).to_owned(), contents.to_vec())
            .is_some()
        {
            return Err(CliError::plugin_invalid());
        }
    }
    Ok((TRUSTED_PACKAGE_MANIFEST.to_vec(), files))
}

fn external_package_source(path: PathBuf) -> Result<PackageSource, CliError> {
    let metadata = std::fs::symlink_metadata(&path).map_err(|_error| CliError::plugin_invalid())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::plugin_invalid());
    }
    let root = std::fs::canonicalize(path).map_err(|_error| CliError::plugin_invalid())?;
    let manifest = read_regular(&root.join("package-manifest.json"), 4 * 1024 * 1024)?;
    let mut files = BTreeMap::new();
    for relative in collect_files(&root)? {
        validate_relative(&relative)?;
        let contents = read_regular(&root.join(&relative), MAX_BYTES)?;
        if files.insert(relative, contents).is_some() {
            return Err(CliError::plugin_invalid());
        }
    }
    Ok((manifest, files))
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
                "command": "${CLAUDE_PLUGIN_ROOT}/bin/cigar-mcp",
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
        "command": "${CLAUDE_PLUGIN_ROOT}/bin/cigar-claude-hook",
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
        write_new_mode(
            &target,
            &file.contents,
            if file.path.starts_with("bin/") {
                0o700
            } else {
                0o600
            },
        )?;
    }
    write_new(
        &plugin.join("package-manifest.json"),
        &installed_manifest_bytes(package)?,
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

fn stage_marketplace_at(package: &Package, home: &Dir, destination: &Path) -> Result<(), CliError> {
    validate_capability_relative(destination)?;
    private_directory_at(home, destination)?;
    let plugin_relative = destination.join("plugins/cigar");
    private_directory_at(home, &plugin_relative)?;
    for file in &package.files {
        validate_relative(&file.path)?;
        let target = plugin_relative.join(&file.path);
        let parent = target.parent().ok_or_else(CliError::plugin_invalid)?;
        private_directory_at(home, parent)?;
        write_new_at(
            home,
            &target,
            &file.contents,
            if file.path.starts_with("bin/") {
                0o700
            } else {
                0o600
            },
        )?;
    }
    write_new_at(
        home,
        &plugin_relative.join("package-manifest.json"),
        &installed_manifest_bytes(package)?,
        0o600,
    )?;
    let plugin = home
        .open_dir(&plugin_relative)
        .map_err(|_error| CliError::state_unavailable())?;
    verify_staged_package_at(package, &plugin)?;
    let metadata = destination.join(".claude-plugin");
    private_directory_at(home, &metadata)?;
    write_json_at(
        home,
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
            != installed_manifest_bytes(package)?
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

fn verify_staged_package_at(package: &Package, root: &Dir) -> Result<(), CliError> {
    let expected = package
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if collect_files_at(root)? != expected
        || read_regular_at(root, Path::new("package-manifest.json"), 4 * 1024 * 1024)?
            != installed_manifest_bytes(package)?
    {
        return Err(CliError::plugin_invalid());
    }
    for file in &package.files {
        let bytes = read_regular_at(root, Path::new(&file.path), MAX_BYTES)?;
        if bytes != file.contents || sha256(&bytes) != file.sha256 {
            return Err(CliError::plugin_invalid());
        }
    }
    validate_public_surface(&package.files)
}

fn collect_files_at(root: &Dir) -> Result<BTreeSet<String>, CliError> {
    fn visit(directory: &Dir, prefix: &Path, files: &mut BTreeSet<String>) -> Result<(), CliError> {
        let mut entries = directory
            .entries()
            .map_err(|_error| CliError::plugin_invalid())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| CliError::plugin_invalid())?;
        entries.sort_by_key(cap_std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry
                .file_type()
                .map_err(|_error| CliError::plugin_invalid())?;
            if file_type.is_symlink() {
                return Err(CliError::plugin_invalid());
            }
            let relative = prefix.join(entry.file_name());
            if file_type.is_dir() {
                let child = entry
                    .open_dir()
                    .map_err(|_error| CliError::plugin_invalid())?;
                visit(&child, &relative, files)?;
            } else if file_type.is_file() {
                let relative = relative
                    .to_str()
                    .ok_or_else(CliError::plugin_invalid)?
                    .replace('\\', "/");
                if relative != "package-manifest.json" {
                    if files.len() >= MAX_FILES || !files.insert(relative) {
                        return Err(CliError::plugin_invalid());
                    }
                }
            } else {
                return Err(CliError::plugin_invalid());
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    visit(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn installed_manifest_bytes(package: &Package) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec(&json!({
        "schema_version": "cigar.claude-code-package.v1",
        "files": package.files.iter().map(|file| json!({
            "path": file.path,
            "sha256": file.sha256,
            "bytes": file.contents.len(),
        })).collect::<Vec<_>>()
    }))
    .map_err(|_error| CliError::plugin_invalid())
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

#[cfg(not(unix))]
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
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(CliError::state_unavailable());
        }
    }
    private_directory(&path)?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_error| CliError::state_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_unavailable());
    }
    std::fs::canonicalize(path).map_err(|_error| CliError::state_unavailable())
}

impl ManagedHome {
    fn open() -> Result<Self, CliError> {
        let requested = requested_cigar_home()?;
        #[cfg(unix)]
        let (path, directory) = open_or_create_managed_home(&requested)?;
        #[cfg(not(unix))]
        let (path, directory) = {
            let path = cigar_home()?;
            let directory = Dir::open_ambient_dir(&path, ambient_authority())
                .map_err(|_error| CliError::state_unavailable())?;
            (path, directory)
        };
        private_directory_at(&directory, Path::new("claude-code"))?;
        Ok(Self { path, directory })
    }
}

fn requested_cigar_home() -> Result<PathBuf, CliError> {
    let value = std::env::var_os("CIGAR_HOME").or_else(|| {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| Path::new(&home).join(".cigar").into_os_string())
    });
    let path = PathBuf::from(value.ok_or_else(CliError::state_unavailable)?);
    if !path.is_absolute()
        || !path
            .components()
            .any(|component| matches!(component, Component::Normal(_)))
    {
        return Err(CliError::state_unavailable());
    }
    Ok(path)
}

#[cfg(unix)]
fn open_or_create_managed_home(requested: &Path) -> Result<(PathBuf, Dir), CliError> {
    use cap_std::fs::MetadataExt as _;
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::os::unix::fs::MetadataExt as _;

    let mut existing = PathBuf::from("/");
    let mut missing = PathBuf::new();
    let mut saw_missing = false;
    for component in requested.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        if saw_missing {
            missing.push(name);
            continue;
        }
        let candidate = existing.join(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() && metadata.uid() != 0 {
                    return Err(CliError::state_unavailable());
                }
                if !metadata.is_dir() && !metadata.file_type().is_symlink() {
                    return Err(CliError::state_unavailable());
                }
                existing = candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                saw_missing = true;
                missing.push(name);
            }
            Err(_error) => return Err(CliError::state_unavailable()),
        }
    }
    let canonical =
        std::fs::canonicalize(&existing).map_err(|_error| CliError::state_unavailable())?;
    let mut opened = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_error| CliError::state_unavailable())?;
    for component in canonical.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        opened = openat(
            &opened,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_error| CliError::state_unavailable())?;
    }
    let ancestor = Dir::from_std_file(opened);
    let path = canonical.join(&missing);
    let directory = if missing.as_os_str().is_empty() {
        ancestor
    } else {
        private_directory_at(&ancestor, &missing)?;
        ancestor
            .open_dir(&missing)
            .map_err(|_error| CliError::state_unavailable())?
    };
    let metadata = directory
        .metadata(".")
        .map_err(|_error| CliError::state_unavailable())?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(CliError::state_unavailable());
    }
    Ok((path, directory))
}

fn receipt_relative() -> &'static Path {
    Path::new("claude-code/install.json")
}

fn marketplace_relative() -> PathBuf {
    Path::new("claude-code").join(format!("marketplace-{}", env!("CARGO_PKG_VERSION")))
}

fn validate_receipt(receipt: &Receipt, home: &Path) -> Result<(), CliError> {
    if receipt.schema_version != RECEIPT_SCHEMA
        || receipt.plugin_id != PLUGIN_ID
        || receipt.marketplace_name != MARKETPLACE
        || receipt.package_digest.len() != 68
        || !receipt.package_digest.starts_with("1220")
        || receipt.marketplace_root != home.join(marketplace_relative())
    {
        return Err(CliError::state_corrupt());
    }
    Ok(())
}

fn validate_capability_relative(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(CliError::state_corrupt())
    } else {
        Ok(())
    }
}

fn entry_exists(directory: &Dir, path: &Path) -> Result<bool, CliError> {
    match directory.symlink_metadata(path) {
        Ok(_metadata) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_error) => Err(CliError::state_unavailable()),
    }
}

fn remove_managed(home: &ManagedHome, relative: &Path) -> Result<(), CliError> {
    if relative != marketplace_relative() {
        return Err(CliError::state_corrupt());
    }
    validate_capability_relative(relative)?;
    let metadata = match home.directory.symlink_metadata(relative) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_error) => return Err(CliError::state_unavailable()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::state_corrupt());
    }
    home.directory
        .remove_dir_all(relative)
        .map_err(|_error| CliError::state_unavailable())
}

fn private_directory_at(directory: &Dir, relative: &Path) -> Result<(), CliError> {
    validate_capability_relative(relative)?;
    let mut current = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(CliError::state_corrupt());
        };
        current.push(name);
        match directory.symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(CliError::state_corrupt());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                directory
                    .create_dir(&current)
                    .map_err(|_error| CliError::state_unavailable())?;
            }
            Err(_error) => return Err(CliError::state_unavailable()),
        }
        #[cfg(unix)]
        directory
            .set_permissions(&current, cap_std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| CliError::state_unavailable())?;
    }
    Ok(())
}

fn write_new_at(directory: &Dir, path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
    validate_capability_relative(path)?;
    let parent = path.parent().ok_or_else(CliError::state_unavailable)?;
    if !parent.as_os_str().is_empty() {
        private_directory_at(directory, parent)?;
    }
    let mut options = CapOpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = directory
        .open_with(path, &options)
        .map_err(|_error| CliError::state_unavailable())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_error| CliError::state_unavailable())
}

fn write_json_at<T: Serialize>(directory: &Dir, path: &Path, value: &T) -> Result<(), CliError> {
    validate_capability_relative(path)?;
    let bytes = serde_json::to_vec(value).map_err(|_error| CliError::state_unavailable())?;
    let parent = path.parent().ok_or_else(CliError::state_unavailable)?;
    private_directory_at(directory, parent)?;
    let temporary = parent.join(format!(
        ".cigar-plugin-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_new_at(directory, &temporary, &bytes, 0o600)?;
    let publication = directory
        .hard_link(&temporary, directory, path)
        .map_err(|_error| CliError::state_unavailable());
    if publication.is_err() {
        let _ignored = directory.remove_file(&temporary);
        return publication;
    }
    if directory.remove_file(&temporary).is_err() {
        let _ignored = directory.remove_file(path);
        return Err(CliError::state_unavailable());
    }
    Ok(())
}

fn read_json_at<T>(directory: &Dir, path: &Path, maximum: u64) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = read_regular_at(directory, path, maximum)?;
    cigar_canon::parse_strict_json(&bytes).map_err(|_error| CliError::plugin_invalid())?;
    serde_json::from_slice(&bytes).map_err(|_error| CliError::plugin_invalid())
}

fn read_regular_at(directory: &Dir, path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    validate_capability_relative(path)?;
    let metadata = directory
        .symlink_metadata(path)
        .map_err(|_error| CliError::plugin_invalid())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(CliError::plugin_invalid());
    }
    let mut file = directory
        .open(path)
        .map_err(|_error| CliError::plugin_invalid())?;
    let opened = file
        .metadata()
        .map_err(|_error| CliError::plugin_invalid())?;
    if !opened.is_file() || opened.len() > maximum {
        return Err(CliError::plugin_invalid());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| CliError::plugin_invalid())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        Err(CliError::plugin_invalid())
    } else {
        Ok(bytes)
    }
}

// Every destructive managed-path operation is relative to an already-open
// CIGAR_HOME directory capability. cap-std recursively opens children without
// following symlinks, so ancestor substitution cannot redirect deletion outside it.

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
    write_new_mode(path, bytes, 0o600)
}

fn write_new_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
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
            context_abi: "cigar.context.v1".to_owned(),
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
