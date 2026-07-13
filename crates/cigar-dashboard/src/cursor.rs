//! Short-lived collection-bound pagination cursors with integrity protection.

use crate::events::{bounded_identifier, uuid_v7_is_valid};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

const CURSOR_VERSION: u8 = 1;
const MAC_BYTES: usize = 32;
const HEADER_BYTES: usize = 12;
const MAX_CURSOR_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ID_BYTES: usize = 128;
const CURSOR_TTL_SECONDS: u64 = 15 * 60;
const MAX_FUTURE_SKEW_SECONDS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

/// Stable content-free cursor failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorError {
    /// The cursor was malformed, expired, modified, or bound to another collection.
    InvalidCursor,
    /// The operating system could not provide cursor-signing entropy or time.
    AuthorityUnavailable,
}

impl fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCursor => "dashboard cursor is invalid",
            Self::AuthorityUnavailable => "dashboard cursor authority is unavailable",
        })
    }
}

impl std::error::Error for CursorError {}

/// Closed cursor namespace preventing cross-endpoint cursor reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CursorKind {
    Runs,
    Evidence,
}

impl CursorKind {
    const fn code(self) -> u8 {
        match self {
            Self::Runs => 1,
            Self::Evidence => 2,
        }
    }

    fn from_code(value: u8) -> Result<Self, CursorError> {
        match value {
            1 => Ok(Self::Runs),
            2 => Ok(Self::Evidence),
            _ => Err(CursorError::InvalidCursor),
        }
    }

    fn validates_id(self, value: &str) -> bool {
        match self {
            Self::Runs => uuid_v7_is_valid(value),
            Self::Evidence => bounded_identifier(value) && value.starts_with("evidence-"),
        }
    }
}

/// Validated descending-order tuple stored inside one cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PagePosition {
    sort_at: String,
    id: String,
}

impl PagePosition {
    pub(crate) fn new(kind: CursorKind, sort_at: &str, id: &str) -> Result<Self, CursorError> {
        if sort_at.is_empty()
            || sort_at.len() > MAX_TIMESTAMP_BYTES
            || OffsetDateTime::parse(sort_at, &Rfc3339).is_err()
            || id.is_empty()
            || id.len() > MAX_ID_BYTES
            || !kind.validates_id(id)
        {
            return Err(CursorError::InvalidCursor);
        }
        Ok(Self {
            sort_at: sort_at.to_owned(),
            id: id.to_owned(),
        })
    }

    pub(crate) fn sort_at(&self) -> &str {
        &self.sort_at
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

/// Per-process secret authority for bounded short-lived pagination cursors.
#[derive(Clone)]
pub(crate) struct CursorAuthority {
    key: Zeroizing<[u8; MAC_BYTES]>,
}

impl CursorAuthority {
    pub(crate) fn generate() -> Result<Self, CursorError> {
        let mut key = Zeroizing::new([0_u8; MAC_BYTES]);
        getrandom::fill(key.as_mut()).map_err(|_error| CursorError::AuthorityUnavailable)?;
        Ok(Self { key })
    }

    pub(crate) fn encode(
        &self,
        kind: CursorKind,
        position: &PagePosition,
    ) -> Result<String, CursorError> {
        self.encode_at(kind, position, unix_seconds()?)
    }

    pub(crate) fn decode(
        &self,
        expected_kind: CursorKind,
        source: &str,
    ) -> Result<PagePosition, CursorError> {
        self.decode_at(expected_kind, source, unix_seconds()?)
    }

    fn encode_at(
        &self,
        kind: CursorKind,
        position: &PagePosition,
        issued_at: u64,
    ) -> Result<String, CursorError> {
        let position = PagePosition::new(kind, position.sort_at(), position.id())?;
        let timestamp_bytes = position.sort_at.as_bytes();
        let id_bytes = position.id.as_bytes();
        let timestamp_length =
            u8::try_from(timestamp_bytes.len()).map_err(|_error| CursorError::InvalidCursor)?;
        let id_length =
            u8::try_from(id_bytes.len()).map_err(|_error| CursorError::InvalidCursor)?;
        let capacity = HEADER_BYTES
            .checked_add(timestamp_bytes.len())
            .and_then(|value| value.checked_add(id_bytes.len()))
            .and_then(|value| value.checked_add(MAC_BYTES))
            .ok_or(CursorError::InvalidCursor)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.push(CURSOR_VERSION);
        bytes.push(kind.code());
        bytes.push(timestamp_length);
        bytes.push(id_length);
        bytes.extend_from_slice(&issued_at.to_be_bytes());
        bytes.extend_from_slice(timestamp_bytes);
        bytes.extend_from_slice(id_bytes);
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_error| CursorError::AuthorityUnavailable)?;
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > MAX_CURSOR_TEXT_BYTES {
            return Err(CursorError::InvalidCursor);
        }
        Ok(encoded)
    }

    fn decode_at(
        &self,
        expected_kind: CursorKind,
        source: &str,
        now: u64,
    ) -> Result<PagePosition, CursorError> {
        if source.is_empty()
            || source.len() > MAX_CURSOR_TEXT_BYTES
            || !source
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CursorError::InvalidCursor);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(source)
            .map_err(|_error| CursorError::InvalidCursor)?;
        let signed_length = bytes
            .len()
            .checked_sub(MAC_BYTES)
            .ok_or(CursorError::InvalidCursor)?;
        let signed = bytes
            .get(..signed_length)
            .ok_or(CursorError::InvalidCursor)?;
        let signature = bytes
            .get(signed_length..)
            .ok_or(CursorError::InvalidCursor)?;
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_error| CursorError::AuthorityUnavailable)?;
        mac.update(signed);
        mac.verify_slice(signature)
            .map_err(|_error| CursorError::InvalidCursor)?;
        if signed.len() < HEADER_BYTES {
            return Err(CursorError::InvalidCursor);
        }
        let version = signed.first().copied().ok_or(CursorError::InvalidCursor)?;
        let kind =
            CursorKind::from_code(signed.get(1).copied().ok_or(CursorError::InvalidCursor)?)?;
        let timestamp_length =
            usize::from(signed.get(2).copied().ok_or(CursorError::InvalidCursor)?);
        let id_length = usize::from(signed.get(3).copied().ok_or(CursorError::InvalidCursor)?);
        if version != CURSOR_VERSION
            || kind != expected_kind
            || timestamp_length == 0
            || timestamp_length > MAX_TIMESTAMP_BYTES
            || id_length == 0
            || id_length > MAX_ID_BYTES
        {
            return Err(CursorError::InvalidCursor);
        }
        let issued_source = signed
            .get(4..HEADER_BYTES)
            .ok_or(CursorError::InvalidCursor)?;
        let issued_bytes: [u8; 8] = issued_source
            .try_into()
            .map_err(|_error| CursorError::InvalidCursor)?;
        let issued_at = u64::from_be_bytes(issued_bytes);
        if issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || now.saturating_sub(issued_at) > CURSOR_TTL_SECONDS
        {
            return Err(CursorError::InvalidCursor);
        }
        let body = signed
            .get(HEADER_BYTES..)
            .ok_or(CursorError::InvalidCursor)?;
        let expected_body_length = timestamp_length
            .checked_add(id_length)
            .ok_or(CursorError::InvalidCursor)?;
        if body.len() != expected_body_length {
            return Err(CursorError::InvalidCursor);
        }
        let timestamp_source = body
            .get(..timestamp_length)
            .ok_or(CursorError::InvalidCursor)?;
        let id_source = body
            .get(timestamp_length..)
            .ok_or(CursorError::InvalidCursor)?;
        let timestamp =
            std::str::from_utf8(timestamp_source).map_err(|_error| CursorError::InvalidCursor)?;
        let id = std::str::from_utf8(id_source).map_err(|_error| CursorError::InvalidCursor)?;
        PagePosition::new(kind, timestamp, id)
    }
}

impl fmt::Debug for CursorAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorAuthority")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

fn unix_seconds() -> Result<u64, CursorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_error| CursorError::AuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{CursorAuthority, CursorError, CursorKind, PagePosition};

    const RUN_ID: &str = "01980c69-9d00-7000-8000-000000000001";
    const AT: &str = "2026-07-13T12:00:00Z";

    #[test]
    fn cursor_round_trips_and_is_collection_bound() -> Result<(), Box<dyn std::error::Error>> {
        let authority = CursorAuthority::generate()?;
        let position = PagePosition::new(CursorKind::Runs, AT, RUN_ID)?;
        let cursor = authority.encode_at(CursorKind::Runs, &position, 1000)?;
        assert_eq!(
            authority.decode_at(CursorKind::Runs, &cursor, 1001)?,
            position
        );
        assert_eq!(
            authority.decode_at(CursorKind::Evidence, &cursor, 1001),
            Err(CursorError::InvalidCursor)
        );
        Ok(())
    }

    #[test]
    fn cursor_tampering_and_expiry_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let authority = CursorAuthority::generate()?;
        let position = PagePosition::new(CursorKind::Runs, AT, RUN_ID)?;
        let cursor = authority.encode_at(CursorKind::Runs, &position, 1000)?;
        let mut tampered = cursor.clone();
        let replacement = if tampered.ends_with('A') { "B" } else { "A" };
        tampered.replace_range(tampered.len().saturating_sub(1).., replacement);
        assert_eq!(
            authority.decode_at(CursorKind::Runs, &tampered, 1001),
            Err(CursorError::InvalidCursor)
        );
        assert_eq!(
            authority.decode_at(CursorKind::Runs, &cursor, 2000),
            Err(CursorError::InvalidCursor)
        );
        Ok(())
    }
}
