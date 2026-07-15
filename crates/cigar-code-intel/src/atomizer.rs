//! Deterministic built-in text, Markdown, structured, Git, interaction, and code atomizers.

use crate::{
    BuiltinLanguageAdapter, CodeIntelError, CodeIntelErrorCode, Language, LanguageAdapter,
    ParseRequest,
};
use cigar_canon::{
    CanonicalNode, SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1,
};
use cigar_catalog::{
    AtomizationOutput, AtomizationRequest, Atomizer, AtomizerDescriptor, AtomizerInvalidation,
    CatalogError, CatalogErrorCode, ConnectorContext, MAX_ATOMIZATION_BYTES,
    atomizer_configuration_digest,
};
use cigar_protocol::limits::MAX_INLINE_TEXT_BYTES;
use cigar_protocol::{
    AtomKind, AtomPayload, CanonicalValue, ContentDigest, ContextAtomV1, ContextEdge, EdgeKind,
    ExtensionMap, GovernanceEnvelope, Lifecycle, LineageId, MediaType, QualityEnvelope, RecordId,
    RetrievalEnvelope, ScopeEnvelope, SourceDescriptor, TemporalEnvelope, VersionId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

const TEXT_CHUNK_BYTES: usize = 4_096;
const MAX_INCREMENTAL_FILES: usize = 10_000;

/// Shared governance and scope applied to atoms produced by one ingestion profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomizationProfile {
    /// Tenant and sorted projects authorized to own the source.
    pub scope: ScopeEnvelope,
    /// Classification, purpose, processor, and instruction-authority gates.
    pub governance: GovernanceEnvelope,
    /// Deterministic quality metadata.
    pub quality: QualityEnvelope,
    /// Whether protected lexical indexing is policy-eligible.
    pub lexical_enabled: bool,
    /// Whether a later policy decision may request embeddings.
    pub embedding_eligible: bool,
}

/// Closed built-in atomizer families.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuiltinAtomizerKind {
    /// Bounded plain UTF-8 text chunks.
    Text,
    /// Heading-aligned Markdown sections.
    Markdown,
    /// Strict canonical JSON structured data.
    StructuredJson,
    /// YAML structured data converted through the canonical value profile.
    StructuredYaml,
    /// TOML structured data converted through the canonical value profile.
    StructuredToml,
    /// Well-formed XML retained as exact schema text.
    StructuredXml,
    /// Bounded Protocol Buffers schema source.
    StructuredProtobuf,
    /// Immutable Git commit or diff material.
    Git,
    /// Interaction, observation, or tool transcript material.
    Interaction,
    /// CIGAR-native manifest, decision, handoff, effect, or replay record.
    CigarNative,
    /// Tree-sitter symbol-aware source code.
    Code(Language),
}

/// One configured deterministic built-in atomizer.
#[derive(Clone)]
pub struct BuiltinAtomizer {
    kind: BuiltinAtomizerKind,
    profile: AtomizationProfile,
    descriptor: AtomizerDescriptor,
    language_adapter: Option<BuiltinLanguageAdapter>,
    incremental_states: Arc<Mutex<BTreeMap<String, crate::IncrementalParseState>>>,
}

impl BuiltinAtomizer {
    /// Creates one built-in atomizer and validates its static media registry.
    pub fn new(
        kind: BuiltinAtomizerKind,
        profile: AtomizationProfile,
    ) -> Result<Self, CodeIntelError> {
        let media_types = media_types(kind)?;
        let produced_kinds = [atom_kind(kind)].into_iter().collect();
        let id = format!("cigar.builtin.{}.v1", atomizer_name(kind));
        let version = "1.0.0".to_owned();
        let configuration_digest = atomizer_configuration_digest(
            &id,
            &version,
            &profile.scope,
            &profile.governance,
            profile.quality,
            profile.lexical_enabled,
            profile.embedding_eligible,
        )
        .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata))?;
        let descriptor = AtomizerDescriptor {
            id,
            version,
            media_types,
            max_input_bytes: match kind {
                BuiltinAtomizerKind::StructuredJson
                | BuiltinAtomizerKind::StructuredYaml
                | BuiltinAtomizerKind::StructuredToml
                | BuiltinAtomizerKind::StructuredXml
                | BuiltinAtomizerKind::StructuredProtobuf
                | BuiltinAtomizerKind::CigarNative => MAX_INLINE_TEXT_BYTES,
                BuiltinAtomizerKind::Text
                | BuiltinAtomizerKind::Markdown
                | BuiltinAtomizerKind::Git
                | BuiltinAtomizerKind::Interaction
                | BuiltinAtomizerKind::Code(_) => MAX_ATOMIZATION_BYTES,
            },
            produced_kinds,
            authority_ceiling: profile.governance.instruction_authority,
            configuration_digest,
            scope: profile.scope.clone(),
            governance: profile.governance.clone(),
            quality: profile.quality,
            lexical_enabled: profile.lexical_enabled,
            embedding_eligible: profile.embedding_eligible,
            invalidation: AtomizerInvalidation {
                source_bytes: true,
                source_metadata: true,
                adapter_version: true,
            },
        };
        Ok(Self {
            kind,
            profile,
            descriptor,
            language_adapter: match kind {
                BuiltinAtomizerKind::Code(language) => Some(BuiltinLanguageAdapter::new(language)),
                BuiltinAtomizerKind::Text
                | BuiltinAtomizerKind::Markdown
                | BuiltinAtomizerKind::StructuredJson
                | BuiltinAtomizerKind::StructuredYaml
                | BuiltinAtomizerKind::StructuredToml
                | BuiltinAtomizerKind::StructuredXml
                | BuiltinAtomizerKind::StructuredProtobuf
                | BuiltinAtomizerKind::Git
                | BuiltinAtomizerKind::Interaction
                | BuiltinAtomizerKind::CigarNative => None,
            },
            incremental_states: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Creates the complete required v1 atomizer family.
    pub fn required_v1(profile: AtomizationProfile) -> Result<Vec<Self>, CodeIntelError> {
        let mut kinds = vec![
            BuiltinAtomizerKind::Text,
            BuiltinAtomizerKind::Markdown,
            BuiltinAtomizerKind::StructuredJson,
            BuiltinAtomizerKind::StructuredYaml,
            BuiltinAtomizerKind::StructuredToml,
            BuiltinAtomizerKind::StructuredXml,
            BuiltinAtomizerKind::StructuredProtobuf,
            BuiltinAtomizerKind::Git,
            BuiltinAtomizerKind::Interaction,
            BuiltinAtomizerKind::CigarNative,
        ];
        kinds.extend(
            BuiltinLanguageAdapter::required_v1()
                .into_iter()
                .map(|adapter| BuiltinAtomizerKind::Code(adapter.descriptor().language)),
        );
        kinds
            .into_iter()
            .map(|kind| Self::new(kind, profile.clone()))
            .collect()
    }
}

impl fmt::Debug for BuiltinAtomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinAtomizer")
            .field("kind", &self.kind)
            .field("profile", &self.profile)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl Atomizer for BuiltinAtomizer {
    fn descriptor(&self) -> AtomizerDescriptor {
        self.descriptor.clone()
    }

    fn atomize(
        &self,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        context.check()?;
        if request.bytes.len() > self.descriptor.max_input_bytes {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        match self.kind {
            BuiltinAtomizerKind::StructuredJson
            | BuiltinAtomizerKind::StructuredYaml
            | BuiltinAtomizerKind::StructuredToml
            | BuiltinAtomizerKind::CigarNative => self.atomize_structured(request, context),
            BuiltinAtomizerKind::StructuredXml => self.atomize_xml(request, context),
            BuiltinAtomizerKind::StructuredProtobuf => self.atomize_protobuf(request, context),
            BuiltinAtomizerKind::Code(language) => self.atomize_code(language, request, context),
            BuiltinAtomizerKind::Markdown => self.atomize_textual(request, true, context),
            BuiltinAtomizerKind::Text
            | BuiltinAtomizerKind::Git
            | BuiltinAtomizerKind::Interaction => self.atomize_textual(request, false, context),
        }
    }
}

impl BuiltinAtomizer {
    fn atomize_textual(
        &self,
        request: AtomizationRequest<'_>,
        markdown_sections: bool,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        let text = std::str::from_utf8(request.bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let ranges = if markdown_sections {
            markdown_ranges(text)
        } else {
            utf8_chunk_ranges(text)
        };
        let mut atoms = Vec::with_capacity(ranges.len());
        for (ordinal, (start, end)) in ranges.into_iter().enumerate() {
            context.check()?;
            let selected = text
                .get(start..end)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            if selected.is_empty() {
                continue;
            }
            atoms.push(self.build_atom(
                &request,
                atom_kind(self.kind),
                format!("chunk:{ordinal}"),
                AtomPayload::InlineText(selected.to_owned()),
                selected.as_bytes(),
            )?);
        }
        atoms.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        Ok(AtomizationOutput {
            atoms,
            edges: Vec::new(),
        })
    }

    fn atomize_structured(
        &self,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        context.check()?;
        let normalized;
        let input = match self.kind {
            BuiltinAtomizerKind::StructuredJson => request.bytes,
            BuiltinAtomizerKind::CigarNative => request.bytes,
            BuiltinAtomizerKind::StructuredYaml => {
                let value: serde_json::Value = yaml_serde::from_slice(request.bytes)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                normalized = serde_json::to_vec(&value)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                &normalized
            }
            BuiltinAtomizerKind::StructuredToml => {
                let source = std::str::from_utf8(request.bytes)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                let value: toml::Table = toml::from_str(source)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                normalized = serde_json::to_vec(&value)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                &normalized
            }
            BuiltinAtomizerKind::Text
            | BuiltinAtomizerKind::Markdown
            | BuiltinAtomizerKind::StructuredXml
            | BuiltinAtomizerKind::StructuredProtobuf
            | BuiltinAtomizerKind::Git
            | BuiltinAtomizerKind::Interaction
            | BuiltinAtomizerKind::Code(_) => {
                return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
            }
        };
        let node = parse_strict_json(input)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let payload = canonical_value(node)?;
        payload
            .validate()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let atom = self.build_atom(
            &request,
            AtomKind::Schema,
            "structured-root".to_owned(),
            AtomPayload::Structured(payload),
            request.bytes,
        )?;
        Ok(AtomizationOutput {
            atoms: vec![atom],
            edges: Vec::new(),
        })
    }

    fn atomize_xml(
        &self,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        use quick_xml::events::Event;
        context.check()?;
        let text = std::str::from_utf8(request.bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut reader = quick_xml::Reader::from_reader(request.bytes);
        let mut depth = 0_usize;
        let mut saw_root = false;
        loop {
            match reader
                .read_event()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?
            {
                Event::Start(_start) => {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                    saw_root = true;
                }
                Event::End(_end) => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                }
                Event::DocType(_doctype) => {
                    return Err(CatalogError::new(CatalogErrorCode::Denied));
                }
                Event::Eof => break,
                Event::Empty(_empty) => saw_root = true,
                Event::Text(_)
                | Event::CData(_)
                | Event::Comment(_)
                | Event::Decl(_)
                | Event::PI(_)
                | Event::GeneralRef(_) => {}
            }
        }
        if !saw_root || depth != 0 {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        let atom = self.build_atom(
            &request,
            AtomKind::Schema,
            "xml-root".to_owned(),
            AtomPayload::InlineText(text.to_owned()),
            request.bytes,
        )?;
        Ok(AtomizationOutput {
            atoms: vec![atom],
            edges: Vec::new(),
        })
    }

    fn atomize_protobuf(
        &self,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        context.check()?;
        let text = std::str::from_utf8(request.bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        if !balanced_schema_braces(text) || !text.contains("syntax") {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        let atom = self.build_atom(
            &request,
            AtomKind::Schema,
            "protobuf-schema".to_owned(),
            AtomPayload::InlineText(text.to_owned()),
            request.bytes,
        )?;
        Ok(AtomizationOutput {
            atoms: vec![atom],
            edges: Vec::new(),
        })
    }

    fn atomize_code(
        &self,
        language: Language,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError> {
        let adapter = self
            .language_adapter
            .as_ref()
            .filter(|adapter| adapter.descriptor().language == language)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        let previous = self
            .incremental_states
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
            .get(&request.record.record_id)
            .cloned();
        let parsed = adapter
            .parse(
                ParseRequest {
                    path: &request.record.relative_path,
                    bytes: request.bytes,
                    previous: previous.as_ref(),
                },
                &context.cancellation(),
            )
            .map_err(map_code_error)?;
        let mut states = self
            .incremental_states
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        if !states.contains_key(&request.record.record_id) && states.len() == MAX_INCREMENTAL_FILES
        {
            let _evicted = states.pop_first();
        }
        states.insert(
            request.record.record_id.clone(),
            parsed.incremental_state.clone(),
        );
        drop(states);
        let full_text = std::str::from_utf8(request.bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut base_atoms = Vec::new();
        for (ordinal, (start, end)) in utf8_chunk_ranges(full_text).into_iter().enumerate() {
            let chunk = full_text
                .get(start..end)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            base_atoms.push(self.build_atom(
                &request,
                AtomKind::SourceCode,
                format!("file:{ordinal}"),
                AtomPayload::InlineText(chunk.to_owned()),
                chunk.as_bytes(),
            )?);
        }
        let provenance_base = base_atoms
            .first()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?
            .version_id
            .clone();
        let mut atoms = base_atoms;
        let mut edges = Vec::new();
        for symbol in parsed.symbols {
            context.check()?;
            let start = usize::try_from(symbol.range.start_byte)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
            let end = usize::try_from(symbol.range.end_byte)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
            let source = request
                .bytes
                .get(start..end)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            let text = std::str::from_utf8(source)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            for (ordinal, (chunk_start, chunk_end)) in
                utf8_chunk_ranges(text).into_iter().enumerate()
            {
                let chunk = text
                    .get(chunk_start..chunk_end)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                let atom = self.build_atom(
                    &request,
                    AtomKind::SourceCode,
                    format!("symbol:{}:{ordinal}", symbol.symbol_id.as_str()),
                    AtomPayload::InlineText(chunk.to_owned()),
                    chunk.as_bytes(),
                )?;
                edges.push(derived_edge(
                    &atom.version_id,
                    &provenance_base,
                    &request.snapshot.manifest_digest,
                )?);
                atoms.push(atom);
            }
        }
        atoms.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        Ok(AtomizationOutput { atoms, edges })
    }

    fn build_atom(
        &self,
        request: &AtomizationRequest<'_>,
        kind: AtomKind,
        logical_key: String,
        payload: AtomPayload,
        exact_content: &[u8],
    ) -> Result<ContextAtomV1, CatalogError> {
        let path = request.record.relative_path.as_bytes();
        let source_uri = request.snapshot.source_uri.as_str().as_bytes();
        let lineage_id = LineageId::new(deterministic_uuid(&[
            b"CIGAR-ATOM-LINEAGE\0v1\0",
            source_uri,
            path,
            logical_key.as_bytes(),
        ]))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let placeholder = VersionId::new(format!("1220{}", "0".repeat(64)))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut atom = ContextAtomV1 {
            schema_version: "cigar.atom.v1"
                .parse()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            atom_id: RecordId::new(deterministic_uuid(&[
                b"CIGAR-ATOM-RECORD\0v1\0",
                source_uri,
                path,
                logical_key.as_bytes(),
                request.record.revision.as_bytes(),
            ]))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            lineage_id,
            version_id: placeholder,
            content_digest: raw_digest(exact_content)?,
            kind,
            payload,
            source: SourceDescriptor {
                uri: request.snapshot.source_uri.clone(),
                relative_path: Some(request.record.relative_path.clone()),
                revision: request.record.revision.clone(),
                snapshot_digest: request.snapshot.manifest_digest.clone(),
            },
            scope: self.profile.scope.clone(),
            temporal: TemporalEnvelope {
                valid_from: request.snapshot.captured_at,
                valid_until: None,
                observed_at: request.snapshot.captured_at,
            },
            governance: self.profile.governance.clone(),
            quality: self.profile.quality,
            retrieval: RetrievalEnvelope {
                exact_terms: Vec::new(),
                lexical_enabled: self.profile.lexical_enabled,
                embedding_eligible: self.profile.embedding_eligible,
            },
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        };
        atom.version_id = VersionId::new(
            semantic_multihash_v1(SemanticEnvelopeProfile::Atom, &atom)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
        )
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        Ok(atom)
    }
}

fn media_types(kind: BuiltinAtomizerKind) -> Result<BTreeSet<MediaType>, CodeIntelError> {
    let values: &[&str] = match kind {
        BuiltinAtomizerKind::Text => &["text/plain"],
        BuiltinAtomizerKind::Markdown => &["text/markdown"],
        BuiltinAtomizerKind::StructuredJson => &["application/json"],
        BuiltinAtomizerKind::StructuredYaml => &["application/yaml"],
        BuiltinAtomizerKind::StructuredToml => &["application/toml"],
        BuiltinAtomizerKind::StructuredXml => &["application/xml", "text/xml"],
        BuiltinAtomizerKind::StructuredProtobuf => &["text/x-protobuf"],
        BuiltinAtomizerKind::Git => &["application/x-git-commit", "application/x-git-diff"],
        BuiltinAtomizerKind::Interaction => &["application/x-cigar-interaction"],
        BuiltinAtomizerKind::CigarNative => &["application/vnd.cigar.record+json"],
        BuiltinAtomizerKind::Code(Language::Rust) => &["text/x-rust"],
        BuiltinAtomizerKind::Code(Language::TypeScript) => &["text/typescript"],
        BuiltinAtomizerKind::Code(Language::JavaScript) => &["text/javascript"],
        BuiltinAtomizerKind::Code(Language::Python) => &["text/x-python"],
        BuiltinAtomizerKind::Code(Language::Go) => &["text/x-go"],
        BuiltinAtomizerKind::Code(Language::Java) => &["text/x-java"],
        BuiltinAtomizerKind::Code(Language::C) => &["text/x-c"],
        BuiltinAtomizerKind::Code(Language::Cpp) => &["text/x-c++"],
    };
    values
        .iter()
        .map(|value| {
            MediaType::new(*value)
                .map_err(|_error| CodeIntelError::new(CodeIntelErrorCode::InvalidMetadata))
        })
        .collect()
}

const fn atomizer_name(kind: BuiltinAtomizerKind) -> &'static str {
    match kind {
        BuiltinAtomizerKind::Text => "text",
        BuiltinAtomizerKind::Markdown => "markdown",
        BuiltinAtomizerKind::StructuredJson => "structured-json",
        BuiltinAtomizerKind::StructuredYaml => "structured-yaml",
        BuiltinAtomizerKind::StructuredToml => "structured-toml",
        BuiltinAtomizerKind::StructuredXml => "structured-xml",
        BuiltinAtomizerKind::StructuredProtobuf => "structured-protobuf",
        BuiltinAtomizerKind::Git => "git",
        BuiltinAtomizerKind::Interaction => "interaction",
        BuiltinAtomizerKind::CigarNative => "cigar-native",
        BuiltinAtomizerKind::Code(Language::Rust) => "code-rust",
        BuiltinAtomizerKind::Code(Language::TypeScript) => "code-typescript",
        BuiltinAtomizerKind::Code(Language::JavaScript) => "code-javascript",
        BuiltinAtomizerKind::Code(Language::Python) => "code-python",
        BuiltinAtomizerKind::Code(Language::Go) => "code-go",
        BuiltinAtomizerKind::Code(Language::Java) => "code-java",
        BuiltinAtomizerKind::Code(Language::C) => "code-c",
        BuiltinAtomizerKind::Code(Language::Cpp) => "code-cpp",
    }
}

const fn atom_kind(kind: BuiltinAtomizerKind) -> AtomKind {
    match kind {
        BuiltinAtomizerKind::Text | BuiltinAtomizerKind::Markdown => AtomKind::Documentation,
        BuiltinAtomizerKind::StructuredJson
        | BuiltinAtomizerKind::StructuredYaml
        | BuiltinAtomizerKind::StructuredToml
        | BuiltinAtomizerKind::StructuredXml
        | BuiltinAtomizerKind::StructuredProtobuf => AtomKind::Schema,
        BuiltinAtomizerKind::Git => AtomKind::Artifact,
        BuiltinAtomizerKind::Interaction => AtomKind::Conversation,
        BuiltinAtomizerKind::CigarNative => AtomKind::Artifact,
        BuiltinAtomizerKind::Code(_language) => AtomKind::SourceCode,
    }
}

fn balanced_schema_braces(source: &str) -> bool {
    let mut depth = 0_u64;
    let mut quoted = false;
    let mut escaped = false;
    for character in source.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '{' => {
                let Some(next) = depth.checked_add(1) else {
                    return false;
                };
                depth = next;
            }
            '}' => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            _other => {}
        }
    }
    depth == 0 && !quoted && !escaped
}

fn markdown_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut starts = vec![0_usize];
    let mut offset = 0_usize;
    for line in text.split_inclusive('\n') {
        if offset != 0 && line.trim_start().starts_with('#') {
            starts.push(offset);
        }
        offset = offset.saturating_add(line.len());
    }
    starts.push(text.len());
    starts
        .windows(2)
        .filter_map(|window| Some((*window.first()?, *window.get(1)?)))
        .flat_map(|(start, end)| {
            text.get(start..end)
                .map(utf8_chunk_ranges)
                .unwrap_or_default()
                .into_iter()
                .map(move |(inner_start, inner_end)| (start + inner_start, start + inner_end))
        })
        .collect()
}

fn utf8_chunk_ranges(text: &str) -> Vec<(usize, usize)> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while start < text.len() {
        let mut end = start.saturating_add(TEXT_CHUNK_BYTES).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            break;
        }
        ranges.push((start, end));
        start = end;
    }
    ranges
}

fn canonical_value(node: CanonicalNode) -> Result<CanonicalValue, CatalogError> {
    match node {
        CanonicalNode::Boolean(value) => Ok(CanonicalValue::Boolean(value)),
        CanonicalNode::Unsigned(value) => i64::try_from(value)
            .map(CanonicalValue::Integer)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded)),
        CanonicalNode::Negative(value) => Ok(CanonicalValue::Integer(value)),
        CanonicalNode::Bytes(value) => Ok(CanonicalValue::Bytes(value)),
        CanonicalNode::Text(value) => Ok(CanonicalValue::Text(value)),
        CanonicalNode::Array(values) => values
            .into_iter()
            .map(canonical_value)
            .collect::<Result<Vec<_>, _>>()
            .map(CanonicalValue::Array),
        CanonicalNode::Map(values) => values
            .into_iter()
            .map(|(key, value)| canonical_value(value).map(|value| (key, value)))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(CanonicalValue::Object),
    }
}

fn derived_edge(
    from: &VersionId,
    to: &VersionId,
    provenance: &ContentDigest,
) -> Result<ContextEdge, CatalogError> {
    Ok(ContextEdge {
        schema_version: "cigar.edge.v1"
            .parse()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
        edge_id: RecordId::new(deterministic_uuid(&[
            b"CIGAR-DERIVATION-EDGE\0v1\0",
            from.as_str().as_bytes(),
            to.as_str().as_bytes(),
        ]))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
        from_version: from.clone(),
        to_version: to.clone(),
        kind: EdgeKind::DerivedFrom,
        provenance_digest: provenance.clone(),
        lifecycle: Lifecycle::Active,
        superseded_by: None,
        extensions: ExtensionMap::default(),
    })
}

fn raw_digest(bytes: &[u8]) -> Result<ContentDigest, CatalogError> {
    let digest = Sha256::digest(bytes);
    ContentDigest::new(multihash(&digest))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn deterministic_uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update((part.len() as u64).to_be_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
        b8,
        b9,
        b10,
        b11,
        b12,
        b13,
        b14,
        b15,
        ..,
    ] = digest;
    let version = (b6 & 0x0f) | 0x70;
    let variant = (b8 & 0x3f) | 0x80;
    format!(
        "{b0:02x}{b1:02x}{b2:02x}{b3:02x}-{b4:02x}{b5:02x}-{version:02x}{b7:02x}-{variant:02x}{b9:02x}-{b10:02x}{b11:02x}{b12:02x}{b13:02x}{b14:02x}{b15:02x}"
    )
}

fn multihash(digest: &[u8]) -> String {
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn map_code_error(error: CodeIntelError) -> CatalogError {
    let code = match error.code() {
        CodeIntelErrorCode::InvalidMetadata | CodeIntelErrorCode::InvalidOutput => {
            CatalogErrorCode::InvalidRecord
        }
        CodeIntelErrorCode::LimitExceeded => CatalogErrorCode::LimitExceeded,
        CodeIntelErrorCode::Cancelled => CatalogErrorCode::Cancelled,
        CodeIntelErrorCode::Unavailable => CatalogErrorCode::Unavailable,
    };
    CatalogError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{
        AtomizationProfile, BuiltinAtomizer, BuiltinAtomizerKind, GovernanceEnvelope,
        QualityEnvelope,
    };
    use cigar_catalog::{AtomizationRequest, Atomizer, ConnectorContext, SourceRecord};
    use cigar_protocol::{
        Classification, ContentDigest, FixedPoint, InstructionAuthority, MediaType, RecordId,
        RelativePath, ScopeEnvelope, SourceSnapshot, SourceUri, UtcTimestamp, Validate,
    };
    use cigar_store::CancellationToken;
    use std::time::{Duration, Instant};

    fn profile() -> Result<AtomizationProfile, Box<dyn std::error::Error>> {
        Ok(AtomizationProfile {
            scope: ScopeEnvelope {
                tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
                project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?],
            },
            governance: GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            },
            quality: QualityEnvelope {
                confidence: FixedPoint::new(1_000_000)?,
                coverage: FixedPoint::new(1_000_000)?,
                authority: 1,
            },
            lexical_enabled: true,
            embedding_eligible: false,
        })
    }

    #[test]
    fn descriptor_binds_scope_governance_quality_and_retrieval_features()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = profile()?;
        let baseline_digest =
            BuiltinAtomizer::new(BuiltinAtomizerKind::Markdown, baseline.clone())?
                .descriptor()
                .configuration_digest;

        let mut scope = baseline.clone();
        scope.scope.project_ids = vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7893")?];
        let mut governance = baseline.clone();
        governance.governance.classification = Classification::Confidential;
        let mut quality = baseline.clone();
        quality.quality.authority = 2;
        let mut lexical = baseline.clone();
        lexical.lexical_enabled = false;
        let mut embedding = baseline;
        embedding.embedding_eligible = true;

        for changed in [scope, governance, quality, lexical, embedding] {
            let digest = BuiltinAtomizer::new(BuiltinAtomizerKind::Markdown, changed)?
                .descriptor()
                .configuration_digest;
            assert_ne!(digest, baseline_digest);
        }
        Ok(())
    }

    #[test]
    fn code_atomizer_emits_valid_file_symbols_and_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"fn one() {}\nfn two() {}\n";
        let digest = ContentDigest::new(format!("1220{}", "a".repeat(64)))?;
        let record = SourceRecord {
            record_id: "fs:1:2".to_owned(),
            relative_path: RelativePath::new(b"src/lib.rs".to_vec())?,
            revision: digest.as_str().to_owned(),
            size_bytes: u64::try_from(bytes.len())?,
            executable: false,
            media_type: MediaType::new("text/x-rust")?,
            content_digest: Some(digest.clone()),
        };
        let snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1".parse()?,
            snapshot_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
            source_uri: SourceUri::new("file:///fixture")?,
            source_revision: digest.as_str().to_owned(),
            captured_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            manifest_digest: digest,
            entry_count: 1,
            total_bytes: u64::try_from(bytes.len())?,
            complete: true,
            extensions: Default::default(),
        };
        let atomizer =
            BuiltinAtomizer::new(BuiltinAtomizerKind::Code(crate::Language::Rust), profile()?)?;
        let output = atomizer.atomize(
            AtomizationRequest {
                record: &record,
                bytes,
                snapshot: &snapshot,
            },
            &ConnectorContext::new(
                CancellationToken::default(),
                Instant::now() + Duration::from_secs(1),
            ),
        )?;
        assert_eq!(output.atoms.len(), 3);
        assert_eq!(output.edges.len(), 2);
        for atom in output.atoms {
            atom.validate()?;
        }
        for edge in output.edges {
            edge.validate()?;
        }
        Ok(())
    }

    #[test]
    fn every_non_code_atomizer_family_emits_valid_atoms() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixtures = [
            (BuiltinAtomizerKind::Text, b"plain text".as_slice()),
            (
                BuiltinAtomizerKind::Markdown,
                b"# First\nbody\n# Second\nbody\n".as_slice(),
            ),
            (
                BuiltinAtomizerKind::StructuredJson,
                br#"{"count":1,"enabled":true}"#.as_slice(),
            ),
            (
                BuiltinAtomizerKind::StructuredYaml,
                b"count: 1\nenabled: true\n".as_slice(),
            ),
            (
                BuiltinAtomizerKind::StructuredToml,
                b"count = 1\nenabled = true\n".as_slice(),
            ),
            (
                BuiltinAtomizerKind::StructuredXml,
                b"<schema><field name=\"count\"/></schema>".as_slice(),
            ),
            (
                BuiltinAtomizerKind::StructuredProtobuf,
                b"syntax = \"proto3\"; message Fixture { string value = 1; }".as_slice(),
            ),
            (BuiltinAtomizerKind::Git, b"commit fixture".as_slice()),
            (
                BuiltinAtomizerKind::Interaction,
                b"user: fixture\nassistant: response".as_slice(),
            ),
            (
                BuiltinAtomizerKind::CigarNative,
                br#"{"schema_version":"cigar.fixture.v1","sequence":1}"#.as_slice(),
            ),
        ];
        let digest = ContentDigest::new(format!("1220{}", "a".repeat(64)))?;
        let snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1".parse()?,
            snapshot_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
            source_uri: SourceUri::new("file:///fixture")?,
            source_revision: digest.as_str().to_owned(),
            captured_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            manifest_digest: digest.clone(),
            entry_count: 1,
            total_bytes: 1,
            complete: true,
            extensions: Default::default(),
        };
        for (ordinal, (kind, bytes)) in fixtures.into_iter().enumerate() {
            let atomizer = BuiltinAtomizer::new(kind, profile()?)?;
            let media_type = atomizer
                .descriptor()
                .media_types
                .into_iter()
                .next()
                .ok_or("missing media type")?;
            let record = SourceRecord {
                record_id: format!("fixture:{ordinal}"),
                relative_path: RelativePath::new(format!("fixture-{ordinal}").into_bytes())?,
                revision: digest.as_str().to_owned(),
                size_bytes: u64::try_from(bytes.len())?,
                executable: false,
                media_type,
                content_digest: Some(digest.clone()),
            };
            let output = atomizer
                .atomize(
                    AtomizationRequest {
                        record: &record,
                        bytes,
                        snapshot: &snapshot,
                    },
                    &ConnectorContext::new(
                        CancellationToken::default(),
                        Instant::now() + Duration::from_secs(1),
                    ),
                )
                .map_err(|error| format!("{kind:?}: {error}"))?;
            assert!(!output.atoms.is_empty(), "missing output for {kind:?}");
            for atom in output.atoms {
                atom.validate()?;
            }
        }
        Ok(())
    }

    #[test]
    fn atom_identity_binds_source_and_path_while_lineage_survives_record_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_bytes = b"first revision";
        let second_bytes = b"second revision";
        let first_digest = ContentDigest::new(format!("1220{}", "a".repeat(64)))?;
        let second_digest = ContentDigest::new(format!("1220{}", "b".repeat(64)))?;
        let mut record = SourceRecord {
            record_id: "git:path:first".to_owned(),
            relative_path: RelativePath::new(b"README.md".to_vec())?,
            revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:100644".to_owned(),
            size_bytes: u64::try_from(first_bytes.len())?,
            executable: false,
            media_type: MediaType::new("text/plain")?,
            content_digest: Some(first_digest.clone()),
        };
        let mut snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1".parse()?,
            snapshot_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
            source_uri: SourceUri::new("git+file:///first")?,
            source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            captured_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            manifest_digest: first_digest,
            entry_count: 1,
            total_bytes: u64::try_from(first_bytes.len())?,
            complete: true,
            extensions: Default::default(),
        };
        let atomizer = BuiltinAtomizer::new(BuiltinAtomizerKind::Text, profile()?)?;
        let operation_context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(1),
        );
        let first = atomizer
            .atomize(
                AtomizationRequest {
                    record: &record,
                    bytes: first_bytes,
                    snapshot: &snapshot,
                },
                &operation_context,
            )?
            .atoms
            .into_iter()
            .next()
            .ok_or("missing first atom")?;

        record.record_id = "git:path:second".to_owned();
        record.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:100644".to_owned();
        record.size_bytes = u64::try_from(second_bytes.len())?;
        record.content_digest = Some(second_digest.clone());
        snapshot.source_revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
        snapshot.manifest_digest = second_digest;
        snapshot.captured_at = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:01Z")?;
        snapshot.total_bytes = u64::try_from(second_bytes.len())?;
        let replacement = atomizer
            .atomize(
                AtomizationRequest {
                    record: &record,
                    bytes: second_bytes,
                    snapshot: &snapshot,
                },
                &operation_context,
            )?
            .atoms
            .into_iter()
            .next()
            .ok_or("missing replacement atom")?;
        assert_eq!(first.lineage_id, replacement.lineage_id);
        assert_ne!(first.atom_id, replacement.atom_id);

        snapshot.source_uri = SourceUri::new("git+file:///second")?;
        let other_source = atomizer
            .atomize(
                AtomizationRequest {
                    record: &record,
                    bytes: second_bytes,
                    snapshot: &snapshot,
                },
                &operation_context,
            )?
            .atoms
            .into_iter()
            .next()
            .ok_or("missing other-source atom")?;
        assert_ne!(replacement.lineage_id, other_source.lineage_id);
        assert_ne!(replacement.atom_id, other_source.atom_id);
        Ok(())
    }
}
