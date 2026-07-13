//! Deterministic source atomizers and language-aware symbol extraction.

use cigar_protocol::{ContentDigest, RelativePath};
use cigar_store::CancellationToken;
use std::fmt;

mod atomizer;
mod capsules;
mod tree_sitter_adapter;

pub use atomizer::{AtomizationProfile, BuiltinAtomizer, BuiltinAtomizerKind};
pub use capsules::{
    CapsuleBudget, CheckpointCapsule, DecisionCapsule, DiffCapsule, build_checkpoint_capsule,
    build_decision_capsule, build_diff_capsule, build_symbol_capsule,
};
pub use tree_sitter_adapter::BuiltinLanguageAdapter;

/// Maximum source bytes accepted by one language adapter invocation.
pub const MAX_CODE_INPUT_BYTES: usize = 67_108_864;
/// Maximum symbols emitted for one source record.
pub const MAX_SYMBOLS_PER_FILE: usize = 100_000;
/// Maximum parse error regions emitted for one source record.
pub const MAX_PARSE_ERRORS_PER_FILE: usize = 10_000;

/// Stable content-free code-intelligence failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeIntelErrorCode {
    /// Language, path, range, adapter, or state metadata is invalid.
    InvalidMetadata,
    /// Source or result limits were exceeded.
    LimitExceeded,
    /// Cooperative cancellation was requested.
    Cancelled,
    /// Adapter or parser state was unavailable.
    Unavailable,
    /// Adapter output is nondeterministic, overlapping, or otherwise inconsistent.
    InvalidOutput,
}

/// Content-free code-intelligence error safe for diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CodeIntelError {
    code: CodeIntelErrorCode,
}

impl CodeIntelError {
    const fn new(code: CodeIntelErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(self) -> CodeIntelErrorCode {
        self.code
    }
}

impl fmt::Debug for CodeIntelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodeIntelError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CodeIntelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "code intelligence failed: {:?}", self.code)
    }
}

impl std::error::Error for CodeIntelError {}

/// Frozen v1 source-language registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Language {
    /// Rust.
    Rust,
    /// TypeScript.
    TypeScript,
    /// JavaScript.
    JavaScript,
    /// Python.
    Python,
    /// Go.
    Go,
    /// Java.
    Java,
    /// C.
    C,
    /// C++.
    Cpp,
}

/// Language-neutral structural symbol kinds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SymbolKind {
    /// Package or crate.
    Package,
    /// Module or namespace.
    Module,
    /// Class, struct, enum, trait, interface, or type alias.
    Type,
    /// Free function.
    Function,
    /// Type-associated method.
    Method,
    /// Field, property, constant, or variable declaration.
    Field,
    /// Import, include, or dependency declaration.
    Import,
    /// Test declaration.
    Test,
}

/// Exact half-open byte and line/column range in one immutable source record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceRange {
    /// Inclusive UTF-8 byte offset.
    pub start_byte: u64,
    /// Exclusive UTF-8 byte offset.
    pub end_byte: u64,
    /// Zero-based start line.
    pub start_line: u32,
    /// Zero-based start column in bytes.
    pub start_column: u32,
    /// Zero-based end line.
    pub end_line: u32,
    /// Zero-based end column in bytes.
    pub end_column: u32,
}

impl SourceRange {
    /// Validates a non-empty forward range within one source length.
    pub fn validate(self, source_bytes: usize) -> Result<(), CodeIntelError> {
        let source_bytes = u64::try_from(source_bytes)
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
        if self.start_byte >= self.end_byte
            || self.end_byte > source_bytes
            || self.start_line > self.end_line
            || (self.start_line == self.end_line && self.start_column >= self.end_column)
        {
            Err(CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata))
        } else {
            Ok(())
        }
    }
}

/// Explicit parser error region that is never silently omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseErrorRegion {
    /// Exact affected source range.
    pub range: SourceRange,
    /// Stable parser-independent reason code.
    pub reason_code: String,
}

/// Language-neutral immutable symbol extracted from one source revision.
#[derive(Clone, Eq, PartialEq)]
pub struct Symbol {
    /// Stable project/language/name/kind/source-lineage identity digest.
    pub symbol_id: ContentDigest,
    /// Version digest including signature and implementation bytes.
    pub symbol_version: ContentDigest,
    /// Source language.
    pub language: Language,
    /// Structural kind.
    pub kind: SymbolKind,
    /// Fully qualified semantic name.
    pub qualified_name: String,
    /// Entire declaration/implementation range.
    pub range: SourceRange,
    /// Exact signature range when present.
    pub signature_range: Option<SourceRange>,
    /// Documentation/contract range when present.
    pub documentation_range: Option<SourceRange>,
    /// Sorted direct qualified-name dependencies.
    pub direct_dependencies: Vec<String>,
}

impl fmt::Debug for Symbol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Symbol")
            .field("symbol_id", &self.symbol_id)
            .field("symbol_version", &self.symbol_version)
            .field("language", &self.language)
            .field("kind", &self.kind)
            .field("qualified_name_bytes", &self.qualified_name.len())
            .field("range", &self.range)
            .field("has_signature", &self.signature_range.is_some())
            .field("has_documentation", &self.documentation_range.is_some())
            .field("dependency_count", &self.direct_dependencies.len())
            .finish()
    }
}

/// Opaque deterministic incremental parse state fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalParseState {
    /// Adapter version that produced the state.
    pub adapter_version: String,
    /// Digest of exact source bytes.
    pub source_digest: ContentDigest,
    /// Digest of opaque parser state stored behind the adapter boundary.
    pub state_digest: ContentDigest,
}

/// Complete deterministic parse result for one source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedFile {
    /// Sorted extracted symbols.
    pub symbols: Vec<Symbol>,
    /// Sorted explicit parse error regions.
    pub error_regions: Vec<ParseErrorRegion>,
    /// State for a subsequent incremental parse.
    pub incremental_state: IncrementalParseState,
}

impl ParsedFile {
    /// Validates bounds and strict deterministic ordering without reading source content.
    pub fn validate(&self, source_bytes: usize) -> Result<(), CodeIntelError> {
        if self.symbols.len() > MAX_SYMBOLS_PER_FILE
            || self.error_regions.len() > MAX_PARSE_ERRORS_PER_FILE
        {
            return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
        }
        for symbol in &self.symbols {
            symbol.range.validate(source_bytes)?;
            if let Some(range) = symbol.signature_range {
                range.validate(source_bytes)?;
            }
            if let Some(range) = symbol.documentation_range {
                range.validate(source_bytes)?;
            }
            if symbol.qualified_name.is_empty()
                || !strictly_sorted_unique(&symbol.direct_dependencies)
            {
                return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidOutput));
            }
        }
        for error in &self.error_regions {
            error.range.validate(source_bytes)?;
            if error.reason_code.is_empty() || error.reason_code.len() > 128 {
                return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidOutput));
            }
        }
        if !self.symbols.windows(2).all(|window| {
            window.first().map(|symbol| &symbol.symbol_id)
                < window.get(1).map(|symbol| &symbol.symbol_id)
        }) || !self.error_regions.windows(2).all(|window| {
            window.first().map(|region| region.range) < window.get(1).map(|region| region.range)
        }) {
            return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidOutput));
        }
        Ok(())
    }
}

/// Static language adapter capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageAdapterDescriptor {
    /// Source language.
    pub language: Language,
    /// Deterministic adapter and grammar version.
    pub version: String,
    /// Supported filename extensions without dots.
    pub extensions: Vec<String>,
    /// Maximum accepted source bytes.
    pub max_input_bytes: usize,
    /// Whether incremental prior state is supported.
    pub incremental: bool,
}

/// Exact parse request retaining a platform-neutral source identity.
#[derive(Clone, Copy)]
pub struct ParseRequest<'a> {
    /// Exact source-relative path.
    pub path: &'a RelativePath,
    /// Exact immutable source bytes.
    pub bytes: &'a [u8],
    /// Prior incremental state, if compatible.
    pub previous: Option<&'a IncrementalParseState>,
}

impl fmt::Debug for ParseRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParseRequest")
            .field("path_bytes", &self.path.as_bytes().len())
            .field("input_bytes", &self.bytes.len())
            .field("has_previous", &self.previous.is_some())
            .finish()
    }
}

/// Deterministic Tree-sitter or equivalent language adapter boundary.
pub trait LanguageAdapter: Send + Sync {
    /// Declares language, grammar version, extensions, bounds, and incremental support.
    fn descriptor(&self) -> LanguageAdapterDescriptor;
    /// Parses exact bytes and explicitly returns every error region.
    fn parse(
        &self,
        request: ParseRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<ParsedFile, CodeIntelError>;
}

/// Deterministic token-budget-aware symbol capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolCapsule {
    /// Exact symbol version represented.
    pub symbol_version: ContentDigest,
    /// Ordered signature/contract/implementation/test source ranges.
    pub selected_ranges: Vec<SourceRange>,
    /// Sorted dependency symbol identities.
    pub dependency_ids: Vec<ContentDigest>,
    /// Digest of the current diff evidence when present.
    pub diff_digest: Option<ContentDigest>,
    /// Exact deterministic token estimate under the declared tokenizer.
    pub token_count: u64,
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| window.first() < window.get(1))
}

#[cfg(test)]
mod tests {
    use super::{
        CodeIntelErrorCode, IncrementalParseState, Language, ParseErrorRegion, ParsedFile,
        SourceRange, Symbol, SymbolKind,
    };
    use cigar_protocol::ContentDigest;

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    #[test]
    fn source_ranges_and_parse_errors_are_explicit_and_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let range = SourceRange {
            start_byte: 0,
            end_byte: 3,
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 3,
        };
        let parsed = ParsedFile {
            symbols: vec![Symbol {
                symbol_id: digest('a')?,
                symbol_version: digest('b')?,
                language: Language::Rust,
                kind: SymbolKind::Function,
                qualified_name: "crate::function".to_owned(),
                range,
                signature_range: Some(range),
                documentation_range: None,
                direct_dependencies: vec!["crate::dependency".to_owned()],
            }],
            error_regions: vec![ParseErrorRegion {
                range,
                reason_code: "syntax_error".to_owned(),
            }],
            incremental_state: IncrementalParseState {
                adapter_version: "rust-v1".to_owned(),
                source_digest: digest('c')?,
                state_digest: digest('d')?,
            },
        };
        parsed.validate(3)?;
        assert_eq!(
            range.validate(2).map_err(|error| error.code()),
            Err(CodeIntelErrorCode::InvalidMetadata)
        );
        assert!(!format!("{:?}", parsed.symbols.first()).contains("crate::function"));
        Ok(())
    }

    #[test]
    fn duplicate_or_unsorted_symbol_dependencies_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let range = SourceRange {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 1,
        };
        let symbol = Symbol {
            symbol_id: digest('a')?,
            symbol_version: digest('b')?,
            language: Language::Python,
            kind: SymbolKind::Function,
            qualified_name: "function".to_owned(),
            range,
            signature_range: None,
            documentation_range: None,
            direct_dependencies: vec!["same".to_owned(), "same".to_owned()],
        };
        let parsed = ParsedFile {
            symbols: vec![symbol],
            error_regions: Vec::new(),
            incremental_state: IncrementalParseState {
                adapter_version: "python-v1".to_owned(),
                source_digest: digest('c')?,
                state_digest: digest('d')?,
            },
        };
        assert_eq!(
            parsed.validate(1).map_err(|error| error.code()),
            Err(CodeIntelErrorCode::InvalidOutput)
        );
        Ok(())
    }
}
