//! Required bounded Tree-sitter adapters behind the frozen language-neutral contract.

use crate::{
    CodeIntelError, CodeIntelErrorCode, IncrementalParseState, Language, LanguageAdapter,
    LanguageAdapterDescriptor, MAX_CODE_INPUT_BYTES, MAX_PARSE_ERRORS_PER_FILE,
    MAX_SYMBOLS_PER_FILE, ParseErrorRegion, ParseRequest, ParsedFile, SourceRange, Symbol,
    SymbolKind,
};
use cigar_protocol::ContentDigest;
use cigar_store::CancellationToken;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use tree_sitter::{InputEdit, Language as TreeSitterLanguage, Node, Parser, Point, Tree};

const MAX_VISITED_NODES: usize = 1_000_000;
const MAX_CACHED_TREES: usize = 32;

/// One of the required built-in Tree-sitter language adapters.
#[derive(Clone)]
pub struct BuiltinLanguageAdapter {
    language: Language,
    cache: Arc<Mutex<BTreeMap<ContentDigest, CachedTree>>>,
}

struct CachedTree {
    tree: Tree,
    source: Vec<u8>,
    source_digest: ContentDigest,
}

impl Drop for CachedTree {
    fn drop(&mut self) {
        self.source.fill(0);
    }
}

impl BuiltinLanguageAdapter {
    /// Creates the required adapter for one frozen language registry entry.
    #[must_use]
    pub fn new(language: Language) -> Self {
        Self {
            language,
            cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Returns all required v1 adapters in registry order.
    #[must_use]
    pub fn required_v1() -> Vec<Self> {
        vec![
            Self::new(Language::Rust),
            Self::new(Language::TypeScript),
            Self::new(Language::JavaScript),
            Self::new(Language::Python),
            Self::new(Language::Go),
            Self::new(Language::Java),
            Self::new(Language::C),
            Self::new(Language::Cpp),
        ]
    }

    fn grammar(&self) -> TreeSitterLanguage {
        match self.language {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        }
    }

    const fn version(&self) -> &'static str {
        match self.language {
            Language::Rust => "tree-sitter-rust-0.24.2",
            Language::TypeScript => "tree-sitter-typescript-0.23.2",
            Language::JavaScript => "tree-sitter-javascript-0.25.0",
            Language::Python => "tree-sitter-python-0.25.0",
            Language::Go => "tree-sitter-go-0.25.0",
            Language::Java => "tree-sitter-java-0.23.5",
            Language::C => "tree-sitter-c-0.24.2",
            Language::Cpp => "tree-sitter-cpp-0.23.4",
        }
    }

    fn extensions(&self) -> Vec<String> {
        let extensions: &[&str] = match self.language {
            Language::Rust => &["rs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::JavaScript => &["js", "jsx", "mjs"],
            Language::Python => &["py"],
            Language::Go => &["go"],
            Language::Java => &["java"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cc", "cpp", "cxx", "hpp"],
        };
        extensions.iter().map(|value| (*value).to_owned()).collect()
    }
}

impl fmt::Debug for BuiltinLanguageAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinLanguageAdapter")
            .field("language", &self.language)
            .finish_non_exhaustive()
    }
}

impl LanguageAdapter for BuiltinLanguageAdapter {
    fn descriptor(&self) -> LanguageAdapterDescriptor {
        LanguageAdapterDescriptor {
            language: self.language,
            version: self.version().to_owned(),
            extensions: self.extensions(),
            max_input_bytes: MAX_CODE_INPUT_BYTES,
            incremental: true,
        }
    }

    fn parse(
        &self,
        request: ParseRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<ParsedFile, CodeIntelError> {
        check_cancelled(cancellation)?;
        if request.bytes.is_empty() || request.bytes.len() > MAX_CODE_INPUT_BYTES {
            return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
        }
        let previous_tree = self.previous_tree(request.previous, request.bytes)?;
        let mut parser = Parser::new();
        parser
            .set_language(&self.grammar())
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
        let tree = parser
            .parse(request.bytes, previous_tree.as_ref())
            .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
        check_cancelled(cancellation)?;
        let mut symbols = Vec::new();
        let mut error_regions = Vec::new();
        let mut stack = vec![tree.root_node()];
        let mut visited = 0_usize;
        while let Some(node) = stack.pop() {
            visited = visited
                .checked_add(1)
                .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
            if visited > MAX_VISITED_NODES {
                return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
            }
            if visited.is_multiple_of(1_024) {
                check_cancelled(cancellation)?;
            }
            if node.is_error() || node.is_missing() {
                if error_regions.len() == MAX_PARSE_ERRORS_PER_FILE {
                    return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
                }
                error_regions.push(ParseErrorRegion {
                    range: range_for_error(node, request.bytes.len())?,
                    reason_code: if node.is_missing() {
                        "missing_node".to_owned()
                    } else {
                        "syntax_error".to_owned()
                    },
                });
            }
            if let Some(kind) = symbol_kind(self.language, node.kind()) {
                if symbols.len() == MAX_SYMBOLS_PER_FILE {
                    return Err(CodeIntelError::new(CodeIntelErrorCode::LimitExceeded));
                }
                if let Some(symbol) =
                    build_symbol(self.language, self.version(), kind, node, request.bytes)?
                {
                    symbols.push(symbol);
                }
            }
            for index in (0..node.child_count()).rev() {
                let index = u32::try_from(index)
                    .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?;
                if let Some(child) = node.child(index) {
                    stack.push(child);
                }
            }
        }
        symbols.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
        symbols.dedup_by(|left, right| left.symbol_id == right.symbol_id);
        error_regions.sort_by_key(|region| region.range);
        error_regions.dedup_by(|left, right| left.range == right.range);
        let source_digest = content_digest(request.bytes)?;
        let state_digest = framed_digest(&[
            b"CIGAR-TREE-SITTER-STATE\0v1\0",
            self.version().as_bytes(),
            source_digest.as_str().as_bytes(),
        ])?;
        let parsed = ParsedFile {
            symbols,
            error_regions,
            incremental_state: IncrementalParseState {
                adapter_version: self.version().to_owned(),
                source_digest,
                state_digest,
            },
        };
        parsed.validate(request.bytes.len())?;
        self.cache_tree(
            parsed.incremental_state.state_digest.clone(),
            parsed.incremental_state.source_digest.clone(),
            tree,
            request.bytes,
        )?;
        Ok(parsed)
    }
}

impl BuiltinLanguageAdapter {
    fn previous_tree(
        &self,
        previous: Option<&crate::IncrementalParseState>,
        source: &[u8],
    ) -> Result<Option<Tree>, CodeIntelError> {
        let Some(previous) = previous else {
            return Ok(None);
        };
        if previous.adapter_version != self.version() {
            return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata));
        }
        let cache = self
            .cache
            .lock()
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
        let cached = cache
            .get(&previous.state_digest)
            .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
        if cached.source_digest != previous.source_digest {
            return Err(CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata));
        }
        let mut tree = cached.tree.clone();
        tree.edit(&single_edit(&cached.source, source));
        Ok(Some(tree))
    }

    fn cache_tree(
        &self,
        state_digest: ContentDigest,
        source_digest: ContentDigest,
        tree: Tree,
        source: &[u8],
    ) -> Result<(), CodeIntelError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
        if !cache.contains_key(&state_digest) && cache.len() == MAX_CACHED_TREES {
            let _evicted = cache.pop_first();
        }
        cache.insert(
            state_digest,
            CachedTree {
                tree,
                source: source.to_vec(),
                source_digest,
            },
        );
        Ok(())
    }
}

fn single_edit(old: &[u8], new: &[u8]) -> InputEdit {
    let prefix = old
        .iter()
        .zip(new)
        .take_while(|(left, right)| left == right)
        .count();
    let maximum_suffix = old.len().min(new.len()).saturating_sub(prefix);
    let suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(maximum_suffix)
        .take_while(|(left, right)| left == right)
        .count();
    let old_end_byte = old.len().saturating_sub(suffix);
    let new_end_byte = new.len().saturating_sub(suffix);
    InputEdit {
        start_byte: prefix,
        old_end_byte,
        new_end_byte,
        start_position: point_at(old, prefix),
        old_end_position: point_at(old, old_end_byte),
        new_end_position: point_at(new, new_end_byte),
    }
}

fn point_at(bytes: &[u8], offset: usize) -> Point {
    let bounded = offset.min(bytes.len());
    let prefix = bytes.get(..bounded).unwrap_or(bytes);
    let row = prefix.iter().filter(|byte| **byte == b'\n').count();
    let column = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(prefix.len(), |position| {
            prefix.len().saturating_sub(position.saturating_add(1))
        });
    Point::new(row, column)
}

fn build_symbol(
    language: Language,
    adapter_version: &str,
    kind: SymbolKind,
    node: Node<'_>,
    source: &[u8],
) -> Result<Option<Symbol>, CodeIntelError> {
    let Some(name_node) = node
        .child_by_field_name("name")
        .or_else(|| first_identifier_child(node))
    else {
        return Ok(None);
    };
    let name_bytes = source
        .get(name_node.byte_range())
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))?;
    let qualified_name = std::str::from_utf8(name_bytes)
        .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))?
        .to_owned();
    if qualified_name.is_empty() || qualified_name.len() > 4_096 {
        return Ok(None);
    }
    let range = node_range(node)?;
    let identity = framed_digest(&[
        b"CIGAR-SYMBOL-IDENTITY\0v1\0",
        format!("{language:?}").as_bytes(),
        format!("{kind:?}").as_bytes(),
        qualified_name.as_bytes(),
        &range.start_byte.to_be_bytes(),
    ])?;
    let implementation = source
        .get(node.byte_range())
        .ok_or_else(|| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))?;
    let version = framed_digest(&[
        b"CIGAR-SYMBOL-VERSION\0v1\0",
        identity.as_str().as_bytes(),
        adapter_version.as_bytes(),
        implementation,
    ])?;
    Ok(Some(Symbol {
        symbol_id: identity,
        symbol_version: version,
        language,
        kind,
        qualified_name,
        range,
        signature_range: signature_range(node)?,
        documentation_range: None,
        direct_dependencies: Vec::new(),
    }))
}

fn first_identifier_child(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.child_count()).find_map(|index| {
        u32::try_from(index)
            .ok()
            .and_then(|index| node.child(index))
            .filter(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "field_identifier" | "property_identifier"
                )
            })
    })
}

fn signature_range(node: Node<'_>) -> Result<Option<SourceRange>, CodeIntelError> {
    let Some(body) = node.child_by_field_name("body") else {
        return Ok(None);
    };
    if body.start_byte() <= node.start_byte() {
        return Ok(None);
    }
    Ok(Some(SourceRange {
        start_byte: u64::try_from(node.start_byte())
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?,
        end_byte: u64::try_from(body.start_byte())
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?,
        start_line: point_component(node.start_position().row)?,
        start_column: point_component(node.start_position().column)?,
        end_line: point_component(body.start_position().row)?,
        end_column: point_component(body.start_position().column)?,
    }))
}

fn node_range(node: Node<'_>) -> Result<SourceRange, CodeIntelError> {
    range_from_points(
        node.start_byte(),
        node.end_byte(),
        node.start_position(),
        node.end_position(),
    )
}

fn range_for_error(node: Node<'_>, source_bytes: usize) -> Result<SourceRange, CodeIntelError> {
    if node.start_byte() < node.end_byte() {
        return node_range(node);
    }
    let start = node.start_byte().min(source_bytes.saturating_sub(1));
    let end = start.saturating_add(1).min(source_bytes);
    let start_point = node.start_position();
    let end_point = Point::new(start_point.row, start_point.column.saturating_add(1));
    range_from_points(start, end, start_point, end_point)
}

fn range_from_points(
    start: usize,
    end: usize,
    start_point: Point,
    end_point: Point,
) -> Result<SourceRange, CodeIntelError> {
    Ok(SourceRange {
        start_byte: u64::try_from(start)
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?,
        end_byte: u64::try_from(end)
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))?,
        start_line: point_component(start_point.row)?,
        start_column: point_component(start_point.column)?,
        end_line: point_component(end_point.row)?,
        end_column: point_component(end_point.column)?,
    })
}

fn point_component(value: usize) -> Result<u32, CodeIntelError> {
    u32::try_from(value).map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::LimitExceeded))
}

fn symbol_kind(language: Language, node_kind: &str) -> Option<SymbolKind> {
    if is_test_node(language, node_kind) {
        Some(SymbolKind::Test)
    } else if node_kind.contains("method") {
        Some(SymbolKind::Method)
    } else if node_kind.contains("function")
        || matches!(node_kind, "function_item" | "function_definition")
    {
        Some(SymbolKind::Function)
    } else if node_kind.contains("class")
        || node_kind.contains("struct")
        || node_kind.contains("enum")
        || node_kind.contains("interface")
        || node_kind.contains("trait")
        || node_kind.contains("type_declaration")
    {
        Some(SymbolKind::Type)
    } else if node_kind.contains("import") || node_kind.contains("include") {
        Some(SymbolKind::Import)
    } else if matches!(node_kind, "module" | "mod_item" | "namespace_definition") {
        Some(SymbolKind::Module)
    } else {
        None
    }
}

const fn is_test_node(_language: Language, _node_kind: &str) -> bool {
    false
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), CodeIntelError> {
    if cancellation.is_cancelled() {
        Err(CodeIntelError::new(CodeIntelErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn content_digest(bytes: &[u8]) -> Result<ContentDigest, CodeIntelError> {
    framed_digest(&[b"CIGAR-SOURCE-CONTENT\0v1\0", bytes])
}

fn framed_digest(parts: &[&[u8]]) -> Result<ContentDigest, CodeIntelError> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update((part.len() as u64).to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::Unavailable))?;
    }
    ContentDigest::new(value)
        .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::InvalidOutput))
}

#[cfg(test)]
mod tests {
    use super::BuiltinLanguageAdapter;
    use crate::{Language, LanguageAdapter, ParseRequest};
    use cigar_protocol::RelativePath;
    use cigar_store::CancellationToken;

    #[test]
    fn every_required_language_extracts_a_symbol() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = [
            (Language::Rust, "sample.rs", b"fn sample() {}".as_slice()),
            (
                Language::TypeScript,
                "sample.ts",
                b"function sample(): void {}".as_slice(),
            ),
            (
                Language::JavaScript,
                "sample.js",
                b"function sample() {}".as_slice(),
            ),
            (
                Language::Python,
                "sample.py",
                b"def sample():\n    pass\n".as_slice(),
            ),
            (
                Language::Go,
                "sample.go",
                b"package p\nfunc sample() {}".as_slice(),
            ),
            (
                Language::Java,
                "Sample.java",
                b"class Sample { void sample() {} }".as_slice(),
            ),
            (Language::C, "sample.c", b"void sample(void) {}".as_slice()),
            (Language::Cpp, "sample.cpp", b"void sample() {}".as_slice()),
        ];
        for (language, path, bytes) in fixtures {
            let adapter = BuiltinLanguageAdapter::new(language);
            let path = RelativePath::new(path.as_bytes().to_vec())?;
            let parsed = adapter.parse(
                ParseRequest {
                    path: &path,
                    bytes,
                    previous: None,
                },
                &CancellationToken::default(),
            )?;
            assert!(!parsed.symbols.is_empty(), "missing {language:?} symbol");
        }
        Ok(())
    }

    #[test]
    fn malformed_source_returns_explicit_error_regions() -> Result<(), Box<dyn std::error::Error>> {
        let adapter = BuiltinLanguageAdapter::new(Language::Rust);
        let path = RelativePath::new(b"broken.rs".to_vec())?;
        let parsed = adapter.parse(
            ParseRequest {
                path: &path,
                bytes: b"fn broken( {",
                previous: None,
            },
            &CancellationToken::default(),
        )?;
        assert!(!parsed.error_regions.is_empty());
        Ok(())
    }

    #[test]
    fn ranges_track_line_endings_and_remain_stable_across_rename()
    -> Result<(), Box<dyn std::error::Error>> {
        let adapter = BuiltinLanguageAdapter::new(Language::Rust);
        let old_path = RelativePath::new(b"old.rs".to_vec())?;
        let new_path = RelativePath::new(b"renamed.rs".to_vec())?;
        let lf = b"fn one() {}\nfn two() {}\n";
        let crlf = b"fn one() {}\r\nfn two() {}\r\n";
        let parse = |path: &RelativePath, bytes: &[u8]| {
            adapter.parse(
                ParseRequest {
                    path,
                    bytes,
                    previous: None,
                },
                &CancellationToken::default(),
            )
        };
        let before = parse(&old_path, lf)?;
        let renamed = parse(&new_path, lf)?;
        assert_eq!(before.symbols, renamed.symbols);
        let crlf_parsed = parse(&new_path, crlf)?;
        let lf_second = before
            .symbols
            .iter()
            .find(|symbol| symbol.qualified_name == "two")
            .ok_or("missing LF symbol")?;
        let crlf_second = crlf_parsed
            .symbols
            .iter()
            .find(|symbol| symbol.qualified_name == "two")
            .ok_or("missing CRLF symbol")?;
        assert_eq!(lf_second.range.start_line, 1);
        assert_eq!(crlf_second.range.start_line, 1);
        assert_eq!(crlf_second.range.start_byte, lf_second.range.start_byte + 1);
        Ok(())
    }

    #[test]
    fn compatible_prior_state_reuses_bounded_incremental_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let adapter = BuiltinLanguageAdapter::new(Language::Rust);
        assert!(adapter.descriptor().incremental);
        let path = RelativePath::new(b"incremental.rs".to_vec())?;
        let first = adapter.parse(
            ParseRequest {
                path: &path,
                bytes: b"fn first() {}\n",
                previous: None,
            },
            &CancellationToken::default(),
        )?;
        let second = adapter.parse(
            ParseRequest {
                path: &path,
                bytes: b"fn first() {}\nfn second() {}\n",
                previous: Some(&first.incremental_state),
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(second.symbols.len(), 2);
        assert_ne!(
            first.incremental_state.source_digest,
            second.incremental_state.source_digest
        );
        Ok(())
    }
}
