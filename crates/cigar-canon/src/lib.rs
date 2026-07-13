//! Deterministic canonicalization, semantic envelopes, and digest domains.

use serde::Serialize;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use unicode_normalization::UnicodeNormalization;

/// Maximum accepted JSON or CBOR input bytes for one canonical operation.
pub const MAX_CANONICAL_INPUT_BYTES: usize = 67_108_864;
/// Maximum canonical output bytes for one value.
pub const MAX_CANONICAL_OUTPUT_BYTES: usize = 67_108_864;
/// Maximum nested containers in canonical data.
pub const MAX_CANONICAL_DEPTH: usize = 64;
/// Maximum entries in one canonical array.
pub const MAX_CANONICAL_ARRAY_ITEMS: usize = 100_000;
/// Maximum entries in one canonical map.
pub const MAX_CANONICAL_MAP_ENTRIES: usize = 100_000;

/// Stable safe canonicalization failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalErrorCode {
    /// Input is not structurally valid JSON or supported CBOR.
    InvalidInput,
    /// A JSON or CBOR map repeats a key.
    DuplicateKey,
    /// Null is not representable in canonical semantic data.
    NullForbidden,
    /// Floating point is not representable in canonical semantic data.
    FloatForbidden,
    /// A configured byte, depth, entry, or integer limit was exceeded.
    LimitExceeded,
    /// CBOR used an indefinite, non-shortest, misordered, tagged, or otherwise noncanonical form.
    NonCanonical,
    /// A byte-string node cannot be rendered as untyped JSON.
    BytesNotJson,
}

/// Content-free canonicalization error safe for public diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalError {
    code: CanonicalErrorCode,
}

impl CanonicalError {
    const fn new(code: CanonicalErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> CanonicalErrorCode {
        self.code
    }
}

impl fmt::Debug for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "canonicalization failed: {:?}", self.code)
    }
}

impl std::error::Error for CanonicalError {}

/// Semantic tree accepted by the deterministic JSON and CBOR profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalNode {
    /// Boolean value.
    Boolean(bool),
    /// Unsigned integer value.
    Unsigned(u64),
    /// Negative integer value.
    Negative(i64),
    /// Exact byte string, available only in the CBOR semantic model.
    Bytes(Vec<u8>),
    /// Exact valid UTF-8 text.
    Text(String),
    /// Ordered semantic values.
    Array(Vec<Self>),
    /// Unique string-keyed semantic values.
    Map(BTreeMap<String, Self>),
}

const DUPLICATE_MARKER: &str = "CIGAR_DUPLICATE_KEY";
const NULL_MARKER: &str = "CIGAR_NULL_FORBIDDEN";
const FLOAT_MARKER: &str = "CIGAR_FLOAT_FORBIDDEN";
const LIMIT_MARKER: &str = "CIGAR_LIMIT_EXCEEDED";

struct NodeSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for NodeSeed {
    type Value = CanonicalNode;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_CANONICAL_DEPTH {
            return Err(D::Error::custom(LIMIT_MARKER));
        }
        deserializer.deserialize_any(NodeVisitor { depth: self.depth })
    }
}

struct NodeVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = CanonicalNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded canonical semantic value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Boolean(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Unsigned(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        if value < 0 {
            Ok(CanonicalNode::Negative(value))
        } else {
            Ok(CanonicalNode::Unsigned(value.cast_unsigned()))
        }
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(FLOAT_MARKER))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CanonicalNode::Text(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Text(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(NodeSeed {
            depth: self.depth + 1,
        })? {
            if values.len() == MAX_CANONICAL_ARRAY_ITEMS {
                return Err(A::Error::custom(LIMIT_MARKER));
            }
            values.push(value);
        }
        Ok(CanonicalNode::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() == MAX_CANONICAL_MAP_ENTRIES {
                return Err(A::Error::custom(LIMIT_MARKER));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom(DUPLICATE_MARKER));
            }
            let value = map.next_value_seed(NodeSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(CanonicalNode::Map(values))
    }
}

/// Parses JSON without accepting duplicate keys, null, floating point, trailing data, or excess limits.
pub fn parse_strict_json(input: &[u8]) -> Result<CanonicalNode, CanonicalError> {
    if input.len() > MAX_CANONICAL_INPUT_BYTES {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = NodeSeed { depth: 1 }
        .deserialize(&mut deserializer)
        .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(error: serde_json::Error) -> CanonicalError {
    let rendered = error.to_string();
    let code = if rendered.contains(DUPLICATE_MARKER) {
        CanonicalErrorCode::DuplicateKey
    } else if rendered.contains(NULL_MARKER) {
        CanonicalErrorCode::NullForbidden
    } else if rendered.contains(FLOAT_MARKER) {
        CanonicalErrorCode::FloatForbidden
    } else if rendered.contains(LIMIT_MARKER) {
        CanonicalErrorCode::LimitExceeded
    } else {
        CanonicalErrorCode::InvalidInput
    };
    CanonicalError::new(code)
}

/// Renders deterministic compact JSON with lexicographically ordered map keys.
pub fn to_normalized_json(value: &CanonicalNode) -> Result<Vec<u8>, CanonicalError> {
    let mut output = Vec::new();
    write_json(value, &mut output, 1)?;
    Ok(output)
}

fn write_json(
    value: &CanonicalNode,
    output: &mut Vec<u8>,
    depth: usize,
) -> Result<(), CanonicalError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    match value {
        CanonicalNode::Boolean(value) => append(output, if *value { b"true" } else { b"false" })?,
        CanonicalNode::Unsigned(value) => append(output, value.to_string().as_bytes())?,
        CanonicalNode::Negative(value) => append(output, value.to_string().as_bytes())?,
        CanonicalNode::Bytes(_) => {
            return Err(CanonicalError::new(CanonicalErrorCode::BytesNotJson));
        }
        CanonicalNode::Text(value) => {
            let rendered = serde_json::to_string(value)
                .map_err(|_error| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
            append(output, rendered.as_bytes())?;
        }
        CanonicalNode::Array(values) => {
            if values.len() > MAX_CANONICAL_ARRAY_ITEMS {
                return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
            }
            push(output, b'[')?;
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    push(output, b',')?;
                }
                write_json(child, output, depth + 1)?;
            }
            push(output, b']')?;
        }
        CanonicalNode::Map(values) => {
            if values.len() > MAX_CANONICAL_MAP_ENTRIES {
                return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
            }
            push(output, b'{')?;
            for (index, (key, child)) in values.iter().enumerate() {
                if index != 0 {
                    push(output, b',')?;
                }
                let rendered = serde_json::to_string(key)
                    .map_err(|_error| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
                append(output, rendered.as_bytes())?;
                push(output, b':')?;
                write_json(child, output, depth + 1)?;
            }
            push(output, b'}')?;
        }
    }
    Ok(())
}

/// Encodes one value using the CIGAR deterministic RFC 8949 profile.
pub fn to_deterministic_cbor(value: &CanonicalNode) -> Result<Vec<u8>, CanonicalError> {
    let mut output = Vec::new();
    encode_cbor(value, &mut output, 1)?;
    Ok(output)
}

fn encode_cbor(
    value: &CanonicalNode,
    output: &mut Vec<u8>,
    depth: usize,
) -> Result<(), CanonicalError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    match value {
        CanonicalNode::Boolean(false) => push(output, 0xf4)?,
        CanonicalNode::Boolean(true) => push(output, 0xf5)?,
        CanonicalNode::Unsigned(value) => encode_head(0, *value, output)?,
        CanonicalNode::Negative(value) => {
            let argument = i128::from(-1_i8)
                .checked_sub(i128::from(*value))
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
            encode_head(1, argument, output)?;
        }
        CanonicalNode::Bytes(value) => {
            encode_length(2, value.len(), output)?;
            append(output, value)?;
        }
        CanonicalNode::Text(value) => {
            encode_length(3, value.len(), output)?;
            append(output, value.as_bytes())?;
        }
        CanonicalNode::Array(values) => {
            if values.len() > MAX_CANONICAL_ARRAY_ITEMS {
                return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
            }
            encode_length(4, values.len(), output)?;
            for child in values {
                encode_cbor(child, output, depth + 1)?;
            }
        }
        CanonicalNode::Map(values) => {
            if values.len() > MAX_CANONICAL_MAP_ENTRIES {
                return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
            }
            encode_length(5, values.len(), output)?;
            let mut entries = Vec::with_capacity(values.len());
            for (key, child) in values {
                let mut encoded_key = Vec::new();
                encode_length(3, key.len(), &mut encoded_key)?;
                append(&mut encoded_key, key.as_bytes())?;
                entries.push((encoded_key, child));
            }
            entries.sort_by(|first, second| first.0.cmp(&second.0));
            for (encoded_key, child) in entries {
                append(output, &encoded_key)?;
                encode_cbor(child, output, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn encode_length(major: u8, length: usize, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    let length = u64::try_from(length)
        .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
    encode_head(major, length, output)
}

fn encode_head(major: u8, argument: u64, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    let prefix = major << 5;
    match argument {
        0..=23 => push(
            output,
            prefix
                .checked_add(
                    u8::try_from(argument)
                        .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
                )
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
        ),
        24..=0xff => {
            push(
                output,
                prefix
                    .checked_add(24)
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
            )?;
            push(
                output,
                u8::try_from(argument)
                    .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
            )
        }
        0x100..=0xffff => {
            push(
                output,
                prefix
                    .checked_add(25)
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
            )?;
            let value = u16::try_from(argument)
                .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
            append(output, &value.to_be_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            push(
                output,
                prefix
                    .checked_add(26)
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
            )?;
            let value = u32::try_from(argument)
                .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
            append(output, &value.to_be_bytes())
        }
        _ => {
            push(
                output,
                prefix
                    .checked_add(27)
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?,
            )?;
            append(output, &argument.to_be_bytes())
        }
    }
}

fn push(output: &mut Vec<u8>, value: u8) -> Result<(), CanonicalError> {
    if output.len() == MAX_CANONICAL_OUTPUT_BYTES {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    output.push(value);
    Ok(())
}

fn append(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CanonicalError> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > MAX_CANONICAL_OUTPUT_BYTES)
    {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    output.extend_from_slice(value);
    Ok(())
}

/// Decodes CBOR only when it already uses the deterministic CIGAR encoding.
pub fn from_deterministic_cbor(input: &[u8]) -> Result<CanonicalNode, CanonicalError> {
    if input.len() > MAX_CANONICAL_INPUT_BYTES {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    let mut parser = CborParser { input, position: 0 };
    let value = parser.parse(1)?;
    if parser.position != input.len() {
        return Err(CanonicalError::new(CanonicalErrorCode::NonCanonical));
    }
    let encoded = to_deterministic_cbor(&value)?;
    if encoded != input {
        return Err(CanonicalError::new(CanonicalErrorCode::NonCanonical));
    }
    Ok(value)
}

struct CborParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl CborParser<'_> {
    fn parse(&mut self, depth: usize) -> Result<CanonicalNode, CanonicalError> {
        if depth > MAX_CANONICAL_DEPTH {
            return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
        }
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CanonicalNode::Unsigned(self.read_argument(additional)?)),
            1 => {
                let argument = self.read_argument(additional)?;
                let value = i128::from(-1_i8) - i128::from(argument);
                let value = i64::try_from(value)
                    .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
                Ok(CanonicalNode::Negative(value))
            }
            2 => {
                let length = self.read_length(additional, MAX_CANONICAL_OUTPUT_BYTES)?;
                Ok(CanonicalNode::Bytes(self.read_exact(length)?.to_vec()))
            }
            3 => {
                let length = self.read_length(additional, MAX_CANONICAL_OUTPUT_BYTES)?;
                let bytes = self.read_exact(length)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|_error| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
                Ok(CanonicalNode::Text(value.to_owned()))
            }
            4 => {
                let length = self.read_length(additional, MAX_CANONICAL_ARRAY_ITEMS)?;
                let mut values = Vec::with_capacity(length);
                for _index in 0..length {
                    values.push(self.parse(depth + 1)?);
                }
                Ok(CanonicalNode::Array(values))
            }
            5 => self.parse_map(additional, depth),
            6 => Err(CanonicalError::new(CanonicalErrorCode::NonCanonical)),
            7 if additional == 20 => Ok(CanonicalNode::Boolean(false)),
            7 if additional == 21 => Ok(CanonicalNode::Boolean(true)),
            7 if additional == 22 => Err(CanonicalError::new(CanonicalErrorCode::NullForbidden)),
            7 if matches!(additional, 25..=27) => {
                Err(CanonicalError::new(CanonicalErrorCode::FloatForbidden))
            }
            _ => Err(CanonicalError::new(CanonicalErrorCode::NonCanonical)),
        }
    }

    fn parse_map(&mut self, additional: u8, depth: usize) -> Result<CanonicalNode, CanonicalError> {
        let length = self.read_length(additional, MAX_CANONICAL_MAP_ENTRIES)?;
        let mut values = BTreeMap::new();
        let mut previous_key_bytes: Option<Vec<u8>> = None;
        for _index in 0..length {
            let key_start = self.position;
            let key = self.parse(depth + 1)?;
            let key_end = self.position;
            let CanonicalNode::Text(key) = key else {
                return Err(CanonicalError::new(CanonicalErrorCode::NonCanonical));
            };
            let encoded_key = self
                .input
                .get(key_start..key_end)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
            if previous_key_bytes
                .as_deref()
                .is_some_and(|previous| previous >= encoded_key)
            {
                return Err(CanonicalError::new(CanonicalErrorCode::NonCanonical));
            }
            previous_key_bytes = Some(encoded_key.to_vec());
            let value = self.parse(depth + 1)?;
            if values.insert(key, value).is_some() {
                return Err(CanonicalError::new(CanonicalErrorCode::DuplicateKey));
            }
        }
        Ok(CanonicalNode::Map(values))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CanonicalError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    Err(CanonicalError::new(CanonicalErrorCode::NonCanonical))
                } else {
                    Ok(value)
                }
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.read_array()?));
                if value <= 0xff {
                    Err(CanonicalError::new(CanonicalErrorCode::NonCanonical))
                } else {
                    Ok(value)
                }
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.read_array()?));
                if value <= 0xffff {
                    Err(CanonicalError::new(CanonicalErrorCode::NonCanonical))
                } else {
                    Ok(value)
                }
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array()?);
                if value <= 0xffff_ffff {
                    Err(CanonicalError::new(CanonicalErrorCode::NonCanonical))
                } else {
                    Ok(value)
                }
            }
            _ => Err(CanonicalError::new(CanonicalErrorCode::NonCanonical)),
        }
    }

    fn read_length(&mut self, additional: u8, maximum: usize) -> Result<usize, CanonicalError> {
        let value = self.read_argument(additional)?;
        let value = usize::try_from(value)
            .map_err(|_error| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
        if value > maximum {
            Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded))
        } else {
            Ok(value)
        }
    }

    fn read_byte(&mut self) -> Result<u8, CanonicalError> {
        let value = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
        self.position += 1;
        Ok(value)
    }

    fn read_exact(&mut self, length: usize) -> Result<&[u8], CanonicalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_error| CanonicalError::new(CanonicalErrorCode::InvalidInput))
    }
}

/// Fields that declare human-text normalization use this NFC transform before hashing.
#[must_use]
pub fn normalize_nfc(value: &str) -> String {
    value.nfc().collect()
}

/// Frozen v1 semantic digest domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestDomain {
    /// Context atom semantic envelope.
    Atom,
    /// Ordered context bundle.
    Bundle,
    /// Selection manifest.
    Manifest,
    /// Signed handoff capsule.
    Handoff,
    /// Effect intent.
    Effect,
    /// Effect or verification receipt.
    Receipt,
    /// Signature-excluded extension manifest.
    ExtensionManifest,
}

/// Frozen v1 semantic envelope profiles and their unsigned discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum SemanticEnvelopeProfile {
    /// Atom content identity; record and self-derived version identities are excluded.
    Atom = 1,
    /// Bundle content identity; the self-derived bundle identity is excluded.
    Bundle = 2,
    /// Manifest content identity; the self-derived manifest identity is excluded.
    Manifest = 3,
    /// Handoff signing identity; the signature bytes are excluded.
    Handoff = 4,
    /// Effect-intent identity; every serialized field is semantic.
    Effect = 5,
    /// Receipt content identity; the receipt identity is excluded.
    Receipt = 6,
    /// Extension-manifest signing identity; only the signature bytes are excluded.
    ExtensionManifest = 7,
}

impl SemanticEnvelopeProfile {
    /// Digest domain bound to this envelope profile.
    #[must_use]
    pub const fn digest_domain(self) -> DigestDomain {
        match self {
            Self::Atom => DigestDomain::Atom,
            Self::Bundle => DigestDomain::Bundle,
            Self::Manifest => DigestDomain::Manifest,
            Self::Handoff => DigestDomain::Handoff,
            Self::Effect => DigestDomain::Effect,
            Self::Receipt => DigestDomain::Receipt,
            Self::ExtensionManifest => DigestDomain::ExtensionManifest,
        }
    }

    /// Exact top-level fields excluded from the semantic envelope.
    #[must_use]
    pub const fn excluded_fields(self) -> &'static [&'static str] {
        match self {
            Self::Atom => &["atom_id", "version_id"],
            Self::Bundle => &["bundle_id"],
            Self::Manifest => &["manifest_id"],
            Self::Handoff => &["signature"],
            Self::Effect => &[],
            Self::Receipt => &["receipt_id"],
            Self::ExtensionManifest => &["signature"],
        }
    }
}

/// Builds a schema-tagged semantic envelope after removing only profile-documented fields.
pub fn semantic_envelope_v1<T: Serialize>(
    profile: SemanticEnvelopeProfile,
    record: &T,
) -> Result<CanonicalNode, CanonicalError> {
    let json = serde_json::to_vec(record)
        .map_err(|_error| CanonicalError::new(CanonicalErrorCode::InvalidInput))?;
    let CanonicalNode::Map(mut fields) = parse_strict_json(&json)? else {
        return Err(CanonicalError::new(CanonicalErrorCode::InvalidInput));
    };
    for field in profile.excluded_fields() {
        fields.remove(*field);
    }
    Ok(CanonicalNode::Array(vec![
        CanonicalNode::Unsigned(profile as u64),
        CanonicalNode::Map(fields),
    ]))
}

/// Encodes and hashes a frozen v1 semantic envelope using its bound digest domain.
pub fn semantic_multihash_v1<T: Serialize>(
    profile: SemanticEnvelopeProfile,
    record: &T,
) -> Result<String, CanonicalError> {
    let envelope = semantic_envelope_v1(profile, record)?;
    let cbor = to_deterministic_cbor(&envelope)?;
    Ok(multihash_v1(profile.digest_domain(), &cbor))
}

/// Builds the exact domain-separated bytes signed for one semantic envelope.
///
/// This is intentionally distinct from a content digest: Ed25519 signs the complete canonical
/// envelope with an explicit CIGAR domain and version prefix. Callers must use a profile whose
/// documented exclusions match the signature field of their record.
pub fn semantic_signing_bytes_v1<T: Serialize>(
    profile: SemanticEnvelopeProfile,
    record: &T,
) -> Result<Vec<u8>, CanonicalError> {
    let envelope = semantic_envelope_v1(profile, record)?;
    let canonical = to_deterministic_cbor(&envelope)?;
    let separator = profile.digest_domain().separator();
    let capacity = separator
        .len()
        .checked_add(canonical.len())
        .and_then(|length| length.checked_add(5))
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::LimitExceeded))?;
    if capacity > MAX_CANONICAL_OUTPUT_BYTES {
        return Err(CanonicalError::new(CanonicalErrorCode::LimitExceeded));
    }
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(separator);
    message.push(0);
    message.extend_from_slice(b"v1");
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(message)
}

impl DigestDomain {
    const fn separator(self) -> &'static [u8] {
        match self {
            Self::Atom => b"CIGAR-ATOM",
            Self::Bundle => b"CIGAR-BUNDLE",
            Self::Manifest => b"CIGAR-MANIFEST",
            Self::Handoff => b"CIGAR-HANDOFF",
            Self::Effect => b"CIGAR-EFFECT",
            Self::Receipt => b"CIGAR-RECEIPT",
            Self::ExtensionManifest => b"CIGAR-EXTENSION-MANIFEST",
        }
    }
}

/// Computes the domain-separated v1 SHA-256 digest bytes.
#[must_use]
pub fn digest_v1(domain: DigestDomain, canonical_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.separator());
    hasher.update([0]);
    hasher.update(b"v1");
    hasher.update([0]);
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

/// Computes the lowercase SHA-256 multihash representation used by protocol identities.
#[must_use]
pub fn multihash_v1(domain: DigestDomain, canonical_payload: &[u8]) -> String {
    let digest = digest_v1(domain, canonical_payload);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalErrorCode, CanonicalNode, DigestDomain, MAX_CANONICAL_INPUT_BYTES,
        SemanticEnvelopeProfile, from_deterministic_cbor, multihash_v1, normalize_nfc,
        parse_strict_json, semantic_envelope_v1, semantic_multihash_v1, semantic_signing_bytes_v1,
        to_deterministic_cbor, to_normalized_json,
    };
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn strict_json_rejects_duplicates_float_null_and_trailing_data()
    -> Result<(), Box<dyn std::error::Error>> {
        for (input, code) in [
            (
                br#"{"a":1,"a":2}"#.as_slice(),
                CanonicalErrorCode::DuplicateKey,
            ),
            (
                br#"{"a":1.5}"#.as_slice(),
                CanonicalErrorCode::FloatForbidden,
            ),
            (
                br#"{"a":null}"#.as_slice(),
                CanonicalErrorCode::NullForbidden,
            ),
            (br#"{} {}"#.as_slice(), CanonicalErrorCode::InvalidInput),
        ] {
            let Err(error) = parse_strict_json(input) else {
                return Err("invalid fixture unexpectedly passed".into());
            };
            assert_eq!(error.code(), code);
        }
        Ok(())
    }

    #[test]
    fn normalized_json_is_compact_and_map_order_independent()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = parse_strict_json(br#"{ "b": 2, "a": [true, -1] }"#)?;
        let second = parse_strict_json(br#"{"a":[true,-1],"b":2}"#)?;
        assert_eq!(first, second);
        assert_eq!(to_normalized_json(&first)?, br#"{"a":[true,-1],"b":2}"#);
        Ok(())
    }

    #[test]
    fn deterministic_cbor_matches_known_vectors_and_encoded_key_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = parse_strict_json(br#"{"aa":2,"b":1}"#)?;
        let encoded = to_deterministic_cbor(&value)?;
        assert_eq!(hex(&encoded), "a261620162616102");
        assert_eq!(from_deterministic_cbor(&encoded)?, value);
        assert_eq!(
            hex(&to_deterministic_cbor(&CanonicalNode::Negative(-25))?),
            "3818"
        );
        Ok(())
    }

    #[test]
    fn deterministic_cbor_integer_head_boundaries_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        for (value, expected) in [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (0xff, "18ff"),
            (0x100, "190100"),
            (0xffff, "19ffff"),
            (0x1_0000, "1a00010000"),
            (0xffff_ffff, "1affffffff"),
            (0x1_0000_0000, "1b0000000100000000"),
            (u64::MAX, "1bffffffffffffffff"),
        ] {
            let node = CanonicalNode::Unsigned(value);
            let encoded = to_deterministic_cbor(&node)?;
            assert_eq!(hex(&encoded), expected, "unsigned integer {value}");
            assert_eq!(from_deterministic_cbor(&encoded)?, node);
        }

        for (value, expected) in [
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65_536, "39ffff"),
            (-65_537, "3a00010000"),
            (i64::MIN, "3b7fffffffffffffff"),
        ] {
            let node = CanonicalNode::Negative(value);
            let encoded = to_deterministic_cbor(&node)?;
            assert_eq!(hex(&encoded), expected, "negative integer {value}");
            assert_eq!(from_deterministic_cbor(&encoded)?, node);
        }
        Ok(())
    }

    #[test]
    fn deterministic_cbor_length_head_boundaries_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        for (length, expected_prefix) in [
            (23, &[0x57][..]),
            (24, &[0x58, 0x18][..]),
            (0xff, &[0x58, 0xff][..]),
            (0x100, &[0x59, 0x01, 0x00][..]),
            (0xffff, &[0x59, 0xff, 0xff][..]),
            (0x1_0000, &[0x5a, 0x00, 0x01, 0x00, 0x00][..]),
        ] {
            let encoded = to_deterministic_cbor(&CanonicalNode::Bytes(vec![0; length]))?;
            assert!(encoded.starts_with(expected_prefix), "byte length {length}");
            assert_eq!(encoded.len(), expected_prefix.len() + length);
        }

        for (length, expected_prefix) in [
            (23, &[0x77][..]),
            (24, &[0x78, 0x18][..]),
            (0xff, &[0x78, 0xff][..]),
            (0x100, &[0x79, 0x01, 0x00][..]),
            (0xffff, &[0x79, 0xff, 0xff][..]),
            (0x1_0000, &[0x7a, 0x00, 0x01, 0x00, 0x00][..]),
        ] {
            let encoded = to_deterministic_cbor(&CanonicalNode::Text("a".repeat(length)))?;
            assert!(encoded.starts_with(expected_prefix), "text length {length}");
            assert_eq!(encoded.len(), expected_prefix.len() + length);
        }

        for (length, expected_prefix) in [
            (23, &[0x97][..]),
            (24, &[0x98, 0x18][..]),
            (0xff, &[0x98, 0xff][..]),
            (0x100, &[0x99, 0x01, 0x00][..]),
            (0xffff, &[0x99, 0xff, 0xff][..]),
            (0x1_0000, &[0x9a, 0x00, 0x01, 0x00, 0x00][..]),
        ] {
            let encoded =
                to_deterministic_cbor(&CanonicalNode::Array(vec![
                    CanonicalNode::Boolean(false);
                    length
                ]))?;
            assert!(
                encoded.starts_with(expected_prefix),
                "array length {length}"
            );
            assert_eq!(encoded.len(), expected_prefix.len() + length);
        }
        Ok(())
    }

    #[test]
    fn deterministic_cbor_rejects_each_non_shortest_integer_width()
    -> Result<(), Box<dyn std::error::Error>> {
        for input in [
            &[0x18, 0x17][..],
            &[0x19, 0x00, 0xff][..],
            &[0x1a, 0x00, 0x00, 0xff, 0xff][..],
            &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff][..],
        ] {
            let Err(error) = from_deterministic_cbor(input) else {
                return Err("non-shortest integer width unexpectedly passed".into());
            };
            assert_eq!(error.code(), CanonicalErrorCode::NonCanonical);
        }
        Ok(())
    }

    #[test]
    fn deterministic_cbor_input_limit_boundary_is_exact() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut input = vec![0_u8; MAX_CANONICAL_INPUT_BYTES];
        let Err(exact_error) = from_deterministic_cbor(&input) else {
            return Err("trailing bytes unexpectedly formed a canonical value".into());
        };
        assert_eq!(exact_error.code(), CanonicalErrorCode::NonCanonical);

        input.push(0);
        let Err(oversized_error) = from_deterministic_cbor(&input) else {
            return Err("oversized deterministic CBOR unexpectedly passed".into());
        };
        assert_eq!(oversized_error.code(), CanonicalErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn noncanonical_cbor_forms_fail_closed() {
        for input in [
            &[0x18, 0x00][..],
            &[0x9f, 0x01, 0xff][..],
            &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02][..],
            &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02][..],
            &[0xf9, 0x3c, 0x00][..],
        ] {
            assert!(from_deterministic_cbor(input).is_err());
        }
    }

    #[test]
    fn bytes_round_trip_in_cbor_and_are_not_untyped_json() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = CanonicalNode::Bytes(vec![0, 1, 255]);
        let encoded = to_deterministic_cbor(&value)?;
        assert_eq!(hex(&encoded), "430001ff");
        assert_eq!(from_deterministic_cbor(&encoded)?, value);
        let Err(error) = to_normalized_json(&value) else {
            return Err("bytes rendered as untyped JSON".into());
        };
        assert_eq!(error.code(), CanonicalErrorCode::BytesNotJson);
        Ok(())
    }

    #[test]
    fn nfc_is_field_explicit_and_exact_text_remains_distinct() {
        let decomposed = "e\u{301}";
        let composed = "é";
        assert_ne!(decomposed.as_bytes(), composed.as_bytes());
        assert_eq!(normalize_nfc(decomposed), composed);
        assert_ne!(
            to_deterministic_cbor(&CanonicalNode::Text(decomposed.to_owned())),
            to_deterministic_cbor(&CanonicalNode::Text(composed.to_owned()))
        );
    }

    #[test]
    fn domains_separate_equal_payloads_and_multihash_is_stable() {
        let payload = b"fixture";
        let atom = multihash_v1(DigestDomain::Atom, payload);
        let bundle = multihash_v1(DigestDomain::Bundle, payload);
        assert_ne!(atom, bundle);
        assert_eq!(atom.len(), 68);
        assert!(atom.starts_with("1220"));
        assert_eq!(atom, multihash_v1(DigestDomain::Atom, payload));
    }

    #[test]
    fn map_permutations_have_identical_canonical_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut expected = None;
        for input in [
            br#"{"a":1,"b":2,"c":3}"#.as_slice(),
            br#"{"c":3,"a":1,"b":2}"#.as_slice(),
            br#"{"b":2,"c":3,"a":1}"#.as_slice(),
        ] {
            let encoded = to_deterministic_cbor(&parse_strict_json(input)?)?;
            if let Some(expected) = &expected {
                assert_eq!(expected, &encoded);
            } else {
                expected = Some(encoded);
            }
        }
        let empty = CanonicalNode::Map(BTreeMap::new());
        assert_eq!(to_deterministic_cbor(&empty)?, vec![0xa0]);
        Ok(())
    }

    #[test]
    fn randomized_map_permutations_are_byte_identical() -> Result<(), Box<dyn std::error::Error>> {
        let mut expected = None;
        let mut state = 0x9e37_79b9_u32;
        for _round in 0..256 {
            let mut entries: Vec<u32> = (0..32).collect();
            for upper in (1..entries.len()).rev() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let target = usize::try_from(state)? % (upper + 1);
                entries.swap(upper, target);
            }
            let body = entries
                .iter()
                .map(|entry| format!("\"key-{entry:02}\":{entry}"))
                .collect::<Vec<_>>()
                .join(",");
            let input = format!("{{{body}}}");
            let encoded = to_deterministic_cbor(&parse_strict_json(input.as_bytes())?)?;
            if let Some(expected) = &expected {
                assert_eq!(expected, &encoded);
            } else {
                expected = Some(encoded);
            }
        }
        Ok(())
    }

    #[test]
    fn semantic_digest_changes_when_included_content_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = to_deterministic_cbor(&parse_strict_json(br#"{"value":"a"}"#)?)?;
        let second = to_deterministic_cbor(&parse_strict_json(br#"{"value":"b"}"#)?)?;
        assert_ne!(
            multihash_v1(DigestDomain::Atom, &first),
            multihash_v1(DigestDomain::Atom, &second)
        );
        Ok(())
    }

    #[test]
    fn semantic_profiles_exclude_only_documented_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = serde_json::json!({
            "schema_version": "cigar.atom.v1",
            "atom_id": "record-a",
            "version_id": "self-a",
            "lineage_id": "stable-lineage",
            "payload": "same"
        });
        let excluded_changed = serde_json::json!({
            "schema_version": "cigar.atom.v1",
            "atom_id": "record-b",
            "version_id": "self-b",
            "lineage_id": "stable-lineage",
            "payload": "same"
        });
        let semantic_changed = serde_json::json!({
            "schema_version": "cigar.atom.v1",
            "atom_id": "record-b",
            "version_id": "self-b",
            "lineage_id": "stable-lineage",
            "payload": "changed"
        });
        let first_digest = semantic_multihash_v1(SemanticEnvelopeProfile::Atom, &first)?;
        assert_eq!(
            first_digest,
            semantic_multihash_v1(SemanticEnvelopeProfile::Atom, &excluded_changed)?
        );
        assert_ne!(
            first_digest,
            semantic_multihash_v1(SemanticEnvelopeProfile::Atom, &semantic_changed)?
        );
        Ok(())
    }

    #[test]
    fn extension_manifest_signing_excludes_only_signature_and_is_domain_separated()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = serde_json::json!({"extension_id": "dev.example", "signature": "first"});
        let signature_changed =
            serde_json::json!({"extension_id": "dev.example", "signature": "second"});
        let identity_changed =
            serde_json::json!({"extension_id": "dev.other", "signature": "first"});
        let first_bytes =
            semantic_signing_bytes_v1(SemanticEnvelopeProfile::ExtensionManifest, &first)?;
        assert_eq!(
            first_bytes,
            semantic_signing_bytes_v1(
                SemanticEnvelopeProfile::ExtensionManifest,
                &signature_changed,
            )?
        );
        assert_ne!(
            first_bytes,
            semantic_signing_bytes_v1(
                SemanticEnvelopeProfile::ExtensionManifest,
                &identity_changed,
            )?
        );
        assert!(first_bytes.starts_with(b"CIGAR-EXTENSION-MANIFEST\0v1\0"));
        Ok(())
    }

    #[test]
    fn semantic_envelope_discriminants_are_frozen() -> Result<(), Box<dyn std::error::Error>> {
        for (profile, discriminant) in [
            (SemanticEnvelopeProfile::Atom, 1),
            (SemanticEnvelopeProfile::Bundle, 2),
            (SemanticEnvelopeProfile::Manifest, 3),
            (SemanticEnvelopeProfile::Handoff, 4),
            (SemanticEnvelopeProfile::Effect, 5),
            (SemanticEnvelopeProfile::Receipt, 6),
            (SemanticEnvelopeProfile::ExtensionManifest, 7),
        ] {
            let envelope = semantic_envelope_v1(profile, &serde_json::json!({"value": true}))?;
            let CanonicalNode::Array(fields) = envelope else {
                return Err("semantic envelope is not an array".into());
            };
            assert_eq!(fields.first(), Some(&CanonicalNode::Unsigned(discriminant)));
        }
        Ok(())
    }
}
