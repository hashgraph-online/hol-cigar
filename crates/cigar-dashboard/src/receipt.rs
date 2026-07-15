//! Independent, bounded verification for dashboard-controlled machine receipts.

use crate::{EvidenceCategory, EvidenceDescriptor, EvidenceStatus, RunProfile};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 200_000;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
const MAX_JSON_ITEMS: usize = 100_000;

/// Stable content-free receipt verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// The reviewed profile has no deterministic receipt contract.
    UnsupportedSchema,
    /// The expected receipt does not exist.
    Missing,
    /// Filesystem confinement or ownership verification failed.
    UnsafePath,
    /// A byte, node, depth, string, or collection limit was exceeded.
    LimitExceeded,
    /// JSON syntax, duplicate keys, canonical encoding, or schema shape was invalid.
    InvalidReceipt,
    /// Source, platform, matrix, or exact receipt binding was inconsistent.
    BindingMismatch,
    /// Process outcome and receipt outcome contradicted one another.
    OutcomeMismatch,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "dashboard receipt schema is unsupported",
            Self::Missing => "dashboard receipt is missing",
            Self::UnsafePath => "dashboard receipt path is unsafe",
            Self::LimitExceeded => "dashboard receipt limit was exceeded",
            Self::InvalidReceipt => "dashboard receipt is invalid",
            Self::BindingMismatch => "dashboard receipt binding is invalid",
            Self::OutcomeMismatch => "dashboard receipt outcome is inconsistent",
        })
    }
}

impl std::error::Error for ReceiptError {}

/// Strict receipt result that can be reduced to browser-safe persisted metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReceipt {
    schema_id: String,
    digest: String,
    receipt_id: String,
    passed: bool,
}

impl VerifiedReceipt {
    /// Returns the allowlisted receipt schema identity.
    #[must_use]
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the exact receipt SHA-256.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns a bounded opaque receipt identifier derived from the exact digest.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Returns the independently checked product outcome.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Produces only a sanitized descriptor; receipt bytes and paths never enter history.
    pub fn descriptor(
        &self,
        run_id: &str,
        source_revision: &str,
    ) -> Result<EvidenceDescriptor, crate::EvidenceError> {
        EvidenceDescriptor::verified(
            run_id,
            &self.schema_id,
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            &self.digest,
            source_revision,
            None,
        )
    }
}

/// Receipt verifier pinned to one supervisor-created run root and source checkout.
#[derive(Clone, Debug)]
pub struct ReceiptVerifier {
    evidence_root: PathBuf,
    workspace_root: PathBuf,
    maximum_bytes: u64,
}

impl ReceiptVerifier {
    /// Captures canonical roots before any child receipt is opened.
    pub fn new(
        evidence_root: &Path,
        workspace_root: &Path,
        maximum_bytes: u64,
    ) -> Result<Self, ReceiptError> {
        if !evidence_root.is_absolute()
            || !workspace_root.is_absolute()
            || maximum_bytes == 0
            || maximum_bytes > 10_737_418_240
        {
            return Err(ReceiptError::UnsafePath);
        }
        let evidence_root = evidence_root
            .canonicalize()
            .map_err(|_error| ReceiptError::UnsafePath)?;
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|_error| ReceiptError::UnsafePath)?;
        validate_private_directory(&evidence_root)?;
        if evidence_root.starts_with(&workspace_root) || workspace_root.starts_with(&evidence_root)
        {
            return Err(ReceiptError::UnsafePath);
        }
        Ok(Self {
            evidence_root,
            workspace_root,
            maximum_bytes,
        })
    }

    /// Opens the one exact profile receipt, validates it independently, and binds process status.
    pub fn verify(
        &self,
        profile: &RunProfile,
        source_revision: &str,
        process_succeeded: bool,
    ) -> Result<VerifiedReceipt, ReceiptError> {
        let relative = profile
            .receipt_relative_path()
            .ok_or(ReceiptError::UnsupportedSchema)?;
        let source = self.read_confined(relative)?;
        let value = strict_canonical_json(&source)?;
        let passed = match profile.receipt_schema() {
            "cigar.test-matrix-result.v1" => {
                self.validate_matrix(profile, source_revision, &value)?
            }
            "cigar.dashboard-schema-check.v1" => {
                self.validate_schema_check(source_revision, &value)?
            }
            _ => return Err(ReceiptError::UnsupportedSchema),
        };
        if passed != process_succeeded {
            return Err(ReceiptError::OutcomeMismatch);
        }
        let digest = hex_digest(&source);
        Ok(VerifiedReceipt {
            schema_id: profile.receipt_schema().to_owned(),
            receipt_id: format!("receipt-{}", &digest[..32]),
            digest,
            passed,
        })
    }

    fn read_confined(&self, relative: &str) -> Result<Vec<u8>, ReceiptError> {
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative.contains(['\\', '%', '\0'])
            || relative_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ReceiptError::UnsafePath);
        }
        let mut current = self.evidence_root.clone();
        let components = relative_path.components().collect::<Vec<_>>();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            let Component::Normal(name) = component else {
                return Err(ReceiptError::UnsafePath);
            };
            current.push(name);
            let metadata =
                fs::symlink_metadata(&current).map_err(|_error| ReceiptError::Missing)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ReceiptError::UnsafePath);
            }
        }
        let path = self.evidence_root.join(relative_path);
        let before = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReceiptError::Missing
            } else {
                ReceiptError::UnsafePath
            }
        })?;
        validate_private_regular(&before, self.maximum_bytes)?;
        let mut file = File::open(&path).map_err(|_error| ReceiptError::UnsafePath)?;
        let opened = file.metadata().map_err(|_error| ReceiptError::UnsafePath)?;
        validate_private_regular(&opened, self.maximum_bytes)?;
        if !same_file(&before, &opened) {
            return Err(ReceiptError::UnsafePath);
        }
        let maximum =
            usize::try_from(self.maximum_bytes).map_err(|_error| ReceiptError::LimitExceeded)?;
        let mut source = Vec::with_capacity(maximum.min(64 * 1024));
        file.by_ref()
            .take(self.maximum_bytes.saturating_add(1))
            .read_to_end(&mut source)
            .map_err(|_error| ReceiptError::UnsafePath)?;
        if source.is_empty() || source.len() > maximum {
            return Err(ReceiptError::LimitExceeded);
        }
        let after = fs::symlink_metadata(&path).map_err(|_error| ReceiptError::UnsafePath)?;
        let opened_after = file.metadata().map_err(|_error| ReceiptError::UnsafePath)?;
        if !same_file(&before, &after)
            || !same_file(&opened, &opened_after)
            || after.len() != opened_after.len()
        {
            return Err(ReceiptError::UnsafePath);
        }
        Ok(source)
    }

    fn validate_matrix(
        &self,
        profile: &RunProfile,
        source_revision: &str,
        value: &Value,
    ) -> Result<bool, ReceiptError> {
        let object = exact_object(
            value,
            &[
                "cases",
                "failed_case_count",
                "finished_at",
                "host",
                "matrix",
                "passed_case_count",
                "profile",
                "release_eligible",
                "schema_version",
                "selected_case_count",
                "source",
                "started_at",
                "status",
                "suite",
            ],
        )?;
        if string(object, "schema_version")? != "cigar.test-matrix-result.v1"
            || string(object, "profile")? != "local"
            || object.get("release_eligible").and_then(Value::as_bool) != Some(false)
        {
            return Err(ReceiptError::InvalidReceipt);
        }
        validate_native_macos(object.get("host").ok_or(ReceiptError::InvalidReceipt)?)?;
        let source = exact_object(
            object.get("source").ok_or(ReceiptError::InvalidReceipt)?,
            &["clean", "committed", "kind", "revision"],
        )?;
        if string(source, "revision")? != source_revision
            || source.get("committed").and_then(Value::as_bool) != Some(true)
            || source.get("clean").and_then(Value::as_bool) != Some(true)
        {
            return Err(ReceiptError::BindingMismatch);
        }
        let matrix = exact_object(
            object.get("matrix").ok_or(ReceiptError::InvalidReceipt)?,
            &["path", "sha256"],
        )?;
        let expected_path = profile
            .argv()
            .windows(2)
            .find(|arguments| arguments.first().is_some_and(|value| value == "--matrix"))
            .and_then(|arguments| arguments.get(1))
            .ok_or(ReceiptError::BindingMismatch)?;
        if string(matrix, "path")? != expected_path {
            return Err(ReceiptError::BindingMismatch);
        }
        let matrix_source = fs::read(self.workspace_root.join(expected_path))
            .map_err(|_error| ReceiptError::BindingMismatch)?;
        if string(matrix, "sha256")? != hex_digest(&matrix_source) {
            return Err(ReceiptError::BindingMismatch);
        }
        let cases = object
            .get("cases")
            .and_then(Value::as_array)
            .ok_or(ReceiptError::InvalidReceipt)?;
        let selected = integer(object, "selected_case_count")?;
        let passed_count = integer(object, "passed_case_count")?;
        let failed_count = integer(object, "failed_case_count")?;
        if selected != u64::try_from(cases.len()).map_err(|_error| ReceiptError::LimitExceeded)?
            || passed_count.checked_add(failed_count) != Some(selected)
            || selected == 0
        {
            return Err(ReceiptError::InvalidReceipt);
        }
        let mut observed_passed = 0_u64;
        let mut observed_failed = 0_u64;
        for case in cases {
            let case = case.as_object().ok_or(ReceiptError::InvalidReceipt)?;
            let status = string(case, "status")?;
            let exit_code = case
                .get("exit_code")
                .and_then(Value::as_i64)
                .ok_or(ReceiptError::InvalidReceipt)?;
            if case.get("canary_scan").and_then(Value::as_str) != Some("passed") {
                return Err(ReceiptError::InvalidReceipt);
            }
            match status {
                "passed" if exit_code == 0 => observed_passed += 1,
                "failed" if exit_code != 0 => observed_failed += 1,
                _ => return Err(ReceiptError::InvalidReceipt),
            }
        }
        if observed_passed != passed_count || observed_failed != failed_count {
            return Err(ReceiptError::InvalidReceipt);
        }
        match string(object, "status")? {
            "passed" if failed_count == 0 => Ok(true),
            "failed" if failed_count > 0 => Ok(false),
            _ => Err(ReceiptError::InvalidReceipt),
        }
    }

    fn validate_schema_check(
        &self,
        source_revision: &str,
        value: &Value,
    ) -> Result<bool, ReceiptError> {
        let object = exact_object(
            value,
            &[
                "host",
                "reference_count",
                "schema_count",
                "schema_set_sha256",
                "schema_version",
                "source_revision",
                "status",
            ],
        )?;
        if string(object, "schema_version")? != "cigar.dashboard-schema-check.v1"
            || string(object, "source_revision")? != source_revision
            || string(object, "status")? != "passed"
            || integer(object, "schema_count")? == 0
            || integer(object, "reference_count")? == 0
        {
            return Err(ReceiptError::BindingMismatch);
        }
        validate_native_macos(object.get("host").ok_or(ReceiptError::InvalidReceipt)?)?;
        let declared_digest = string(object, "schema_set_sha256")?;
        if declared_digest != self.dashboard_schema_digest()? {
            return Err(ReceiptError::BindingMismatch);
        }
        Ok(true)
    }

    fn dashboard_schema_digest(&self) -> Result<String, ReceiptError> {
        let root = self.workspace_root.join("schemas/dashboard");
        let mut paths = fs::read_dir(&root)
            .map_err(|_error| ReceiptError::BindingMismatch)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| ReceiptError::BindingMismatch)?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".schema.json"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        if paths.is_empty() || paths.len() > 1000 {
            return Err(ReceiptError::LimitExceeded);
        }
        let mut digest = Sha256::new();
        for path in paths {
            let relative = path
                .strip_prefix(&self.workspace_root)
                .map_err(|_error| ReceiptError::BindingMismatch)?
                .to_str()
                .ok_or(ReceiptError::BindingMismatch)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let source = fs::read(&path).map_err(|_error| ReceiptError::BindingMismatch)?;
            let path_len =
                u32::try_from(relative.len()).map_err(|_error| ReceiptError::LimitExceeded)?;
            let source_len =
                u64::try_from(source.len()).map_err(|_error| ReceiptError::LimitExceeded)?;
            digest.update(path_len.to_be_bytes());
            digest.update(relative.as_bytes());
            digest.update(source_len.to_be_bytes());
            digest.update(&source);
        }
        Ok(hex_bytes(&digest.finalize()))
    }
}

fn validate_native_macos(value: &Value) -> Result<(), ReceiptError> {
    let host = exact_object(value, &["architecture", "platform"])?;
    if string(host, "platform")? == "macos" && string(host, "architecture")? == "arm64" {
        Ok(())
    } else {
        Err(ReceiptError::BindingMismatch)
    }
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ReceiptError> {
    let object = value.as_object().ok_or(ReceiptError::InvalidReceipt)?;
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(object)
    } else {
        Err(ReceiptError::InvalidReceipt)
    }
}

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReceiptError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_JSON_STRING_BYTES)
        .ok_or(ReceiptError::InvalidReceipt)
}

fn integer(object: &Map<String, Value>, key: &str) -> Result<u64, ReceiptError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(ReceiptError::InvalidReceipt)
}

pub(crate) fn strict_canonical_json(source: &[u8]) -> Result<Value, ReceiptError> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_error| ReceiptError::InvalidReceipt)?
        .0;
    deserializer
        .end()
        .map_err(|_error| ReceiptError::InvalidReceipt)?;
    validate_json_bounds(&value, 0, &mut 0)?;
    let canonical =
        serde_json::to_string_pretty(&value).map_err(|_error| ReceiptError::InvalidReceipt)? + "\n";
    if canonical.as_bytes() != source {
        return Err(ReceiptError::InvalidReceipt);
    }
    Ok(value)
}

fn validate_json_bounds(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ReceiptError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ReceiptError::LimitExceeded);
    }
    *nodes = nodes.checked_add(1).ok_or(ReceiptError::LimitExceeded)?;
    if *nodes > MAX_JSON_NODES {
        return Err(ReceiptError::LimitExceeded);
    }
    match value {
        Value::String(text) if text.len() > MAX_JSON_STRING_BYTES => {
            Err(ReceiptError::LimitExceeded)
        }
        Value::Array(items) => {
            if items.len() > MAX_JSON_ITEMS {
                return Err(ReceiptError::LimitExceeded);
            }
            for item in items {
                validate_json_bounds(item, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(fields) => {
            if fields.len() > MAX_JSON_ITEMS {
                return Err(ReceiptError::LimitExceeded);
            }
            for (key, item) in fields {
                if key.len() > MAX_JSON_STRING_BYTES {
                    return Err(ReceiptError::LimitExceeded);
                }
                validate_json_bounds(item, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one strict JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            items.push(value.0);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A>(self, mut fields: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = fields.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = fields.next_value::<StrictValue>()?;
            object.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

fn hex_digest(source: &[u8]) -> String {
    hex_bytes(&Sha256::digest(source))
}

fn hex_bytes(source: &[u8]) -> String {
    source.iter().fold(
        String::with_capacity(source.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            if write!(output, "{byte:02x}").is_err() {
                return String::new();
            }
            output
        },
    )
}

#[cfg(unix)]
fn validate_private_directory(path: &Path) -> Result<(), ReceiptError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = fs::symlink_metadata(path).map_err(|_error| ReceiptError::UnsafePath)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ReceiptError::UnsafePath);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(_path: &Path) -> Result<(), ReceiptError> {
    Err(ReceiptError::UnsafePath)
}

#[cfg(unix)]
fn validate_private_regular(
    metadata: &fs::Metadata,
    maximum_bytes: u64,
) -> Result<(), ReceiptError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(ReceiptError::UnsafePath);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_regular(
    _metadata: &fs::Metadata,
    _maximum_bytes: u64,
) -> Result<(), ReceiptError> {
    Err(ReceiptError::UnsafePath)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{ReceiptError, ReceiptVerifier, strict_canonical_json};
    use crate::RunProfileRegistry;
    use serde_json::json;

    #[test]
    fn strict_json_rejects_duplicate_and_noncanonical_receipts() {
        assert_eq!(
            strict_canonical_json(b"{\"a\": 1, \"a\": 2}\n").err(),
            Some(ReceiptError::InvalidReceipt)
        );
        assert_eq!(
            strict_canonical_json(b"{\"a\":1}\n").err(),
            Some(ReceiptError::InvalidReceipt)
        );
        assert!(strict_canonical_json(b"{\n  \"a\": 1\n}\n").is_ok());
    }

    #[test]
    fn matrix_receipt_cannot_forge_a_clean_source_binding() -> Result<(), Box<dyn std::error::Error>>
    {
        const REVISION: &str = "0123456789012345678901234567890123456789";
        const REGISTRY: &[u8] = include_bytes!("../../../tests/dashboard/run-profiles-v1.json");
        let profile = RunProfileRegistry::from_json(REGISTRY)?
            .profiles()
            .iter()
            .find(|profile| profile.id() == "compatibility-matrix")
            .cloned()
            .ok_or("compatibility profile unavailable")?;
        let directory = tempfile::tempdir()?;
        let verifier = ReceiptVerifier {
            evidence_root: directory.path().join("evidence"),
            workspace_root: directory.path().join("workspace"),
            maximum_bytes: 1024,
        };
        let receipt = json!({
            "cases": [],
            "failed_case_count": 0,
            "finished_at": "2026-01-01T00:00:01Z",
            "host": {"architecture": "arm64", "platform": "macos"},
            "matrix": {"path": "tests/compatibility/matrix-v1.json", "sha256": "0".repeat(64)},
            "passed_case_count": 0,
            "profile": "local",
            "release_eligible": false,
            "schema_version": "cigar.test-matrix-result.v1",
            "selected_case_count": 0,
            "source": {"clean": false, "committed": true, "kind": "git", "revision": REVISION},
            "started_at": "2026-01-01T00:00:00Z",
            "status": "passed",
            "suite": "compatibility"
        });
        assert_eq!(
            verifier.validate_matrix(&profile, REVISION, &receipt).err(),
            Some(ReceiptError::BindingMismatch)
        );
        Ok(())
    }
}
