//! Opaque, authenticated, snapshot-pinned pagination cursors.

use crate::context::{OperationId, PrincipalId, RequestContextError, TenantId};
use cigar_protocol::{ContentDigest, PageCursor, UtcTimestamp};
use sha2::{Digest, Sha256};
use std::fmt;

const CURSOR_VERSION: u8 = 1;
const HMAC_BLOCK_BYTES: usize = 64;
const HMAC_TAG_BYTES: usize = 32;
const MIN_SIGNING_KEY_BYTES: usize = 32;
const MAX_SIGNING_KEY_BYTES: usize = 64;
const MAX_POSITION_BYTES: usize = 256;

/// Failure to issue or verify an opaque page cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorError {
    /// The signing key or cursor position exceeded a strict bound.
    LimitExceeded,
    /// The cursor was malformed, forged, trailing, or bound to another scope.
    Invalid,
    /// The authenticated cursor has expired.
    Expired,
}

impl fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::LimitExceeded => "cursor input exceeds a configured limit",
            Self::Invalid => "cursor is invalid for this request",
            Self::Expired => "cursor has expired",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CursorError {}

/// Secret HMAC key used only for issuing and verifying page cursors.
pub struct CursorSigningKey(Vec<u8>);

impl CursorSigningKey {
    /// Creates a bounded key with at least 256 bits of key material.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CursorError> {
        let bytes = bytes.into();
        if (MIN_SIGNING_KEY_BYTES..=MAX_SIGNING_KEY_BYTES).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(CursorError::LimitExceeded)
        }
    }
}

impl fmt::Debug for CursorSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorSigningKey([REDACTED])")
    }
}

/// Exact request and snapshot scope to which a cursor is cryptographically bound.
#[derive(Clone, Eq, PartialEq)]
pub struct CursorScope {
    tenant: TenantId,
    principal: PrincipalId,
    operation: OperationId,
    query_digest: ContentDigest,
    snapshot_digest: ContentDigest,
}

impl CursorScope {
    /// Creates an exact cursor binding.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        principal: PrincipalId,
        operation: OperationId,
        query_digest: ContentDigest,
        snapshot_digest: ContentDigest,
    ) -> Self {
        Self {
            tenant,
            principal,
            operation,
            query_digest,
            snapshot_digest,
        }
    }

    /// Returns the tenant binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the principal binding.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the operation binding.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the normalized query digest binding.
    #[must_use]
    pub const fn query_digest(&self) -> &ContentDigest {
        &self.query_digest
    }

    /// Returns the immutable snapshot digest binding.
    #[must_use]
    pub const fn snapshot_digest(&self) -> &ContentDigest {
        &self.snapshot_digest
    }
}

impl fmt::Debug for CursorScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorScope")
            .field("tenant", &self.tenant)
            .field("principal", &self.principal)
            .field("operation", &self.operation)
            .field("query_digest", &self.query_digest)
            .field("snapshot_digest", &self.snapshot_digest)
            .finish()
    }
}

/// Authenticated continuation state returned after successful cursor verification.
#[derive(Clone, Eq, PartialEq)]
pub struct CursorClaims {
    scope: CursorScope,
    position: Vec<u8>,
    expires_at: UtcTimestamp,
}

impl CursorClaims {
    /// Returns the authenticated cursor scope.
    #[must_use]
    pub const fn scope(&self) -> &CursorScope {
        &self.scope
    }

    /// Returns the opaque repository continuation position.
    #[must_use]
    pub fn position(&self) -> &[u8] {
        &self.position
    }

    /// Returns the authenticated expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UtcTimestamp {
        self.expires_at
    }
}

impl fmt::Debug for CursorClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorClaims")
            .field("scope", &self.scope)
            .field("position_bytes", &self.position.len())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Issues and verifies v1 opaque page cursors using HMAC-SHA256.
pub struct CursorCodec {
    key: CursorSigningKey,
}

impl CursorCodec {
    /// Creates a codec from a validated secret signing key.
    #[must_use]
    pub const fn new(key: CursorSigningKey) -> Self {
        Self { key }
    }

    /// Issues a cursor bound to the exact scope, position, and expiration.
    pub fn seal(
        &self,
        scope: &CursorScope,
        position: &[u8],
        expires_at: UtcTimestamp,
    ) -> Result<PageCursor, CursorError> {
        if position.len() > MAX_POSITION_BYTES {
            return Err(CursorError::LimitExceeded);
        }
        let mut payload = Vec::with_capacity(512);
        payload.push(CURSOR_VERSION);
        write_field(&mut payload, scope.tenant.as_str().as_bytes())?;
        write_field(&mut payload, scope.principal.as_str().as_bytes())?;
        write_field(&mut payload, scope.operation.as_str().as_bytes())?;
        write_field(&mut payload, scope.query_digest.as_str().as_bytes())?;
        write_field(&mut payload, scope.snapshot_digest.as_str().as_bytes())?;
        write_field(&mut payload, position)?;
        payload.extend_from_slice(&expires_at.unix_nanos().to_be_bytes());
        let tag = hmac_sha256(&self.key.0, &payload);
        payload.extend_from_slice(&tag);
        PageCursor::new(payload).map_err(|_error| CursorError::LimitExceeded)
    }

    /// Authenticates a cursor, enforces exact request scope, and checks expiration.
    pub fn open(
        &self,
        cursor: &PageCursor,
        expected_scope: &CursorScope,
        now: UtcTimestamp,
    ) -> Result<CursorClaims, CursorError> {
        let bytes = cursor.as_bytes();
        if bytes.len() <= HMAC_TAG_BYTES {
            return Err(CursorError::Invalid);
        }
        let payload_length = bytes.len().saturating_sub(HMAC_TAG_BYTES);
        let (payload, supplied_tag) = bytes.split_at(payload_length);
        let expected_tag = hmac_sha256(&self.key.0, payload);
        if !constant_time_equal(supplied_tag, &expected_tag) {
            return Err(CursorError::Invalid);
        }
        let claims = decode_claims(payload)?;
        if claims.scope != *expected_scope {
            return Err(CursorError::Invalid);
        }
        if now >= claims.expires_at {
            return Err(CursorError::Expired);
        }
        Ok(claims)
    }
}

impl fmt::Debug for CursorCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorCodec([REDACTED])")
    }
}

fn write_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CursorError> {
    let length = u16::try_from(value.len()).map_err(|_error| CursorError::LimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_TAG_BYTES] {
    let mut padded_key = [0_u8; HMAC_BLOCK_BYTES];
    for (destination, source) in padded_key.iter_mut().zip(key.iter().copied()) {
        *destination = source;
    }
    let mut inner_pad = [0_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0_u8; HMAC_BLOCK_BYTES];
    for ((inner, outer), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(padded_key)
    {
        *inner = key_byte ^ 0x36;
        *outer = key_byte ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |accumulator, (left_byte, right_byte)| {
            accumulator | (left_byte ^ right_byte)
        });
    difference == 0
}

fn decode_claims(payload: &[u8]) -> Result<CursorClaims, CursorError> {
    let mut reader = CursorReader::new(payload);
    if reader.read_byte()? != CURSOR_VERSION {
        return Err(CursorError::Invalid);
    }
    let tenant = TenantId::new(reader.read_text()?).map_err(map_context_error)?;
    let principal = PrincipalId::new(reader.read_text()?).map_err(map_context_error)?;
    let operation = OperationId::new(reader.read_text()?).map_err(map_context_error)?;
    let query_digest =
        ContentDigest::new(reader.read_text()?).map_err(|_error| CursorError::Invalid)?;
    let snapshot_digest =
        ContentDigest::new(reader.read_text()?).map_err(|_error| CursorError::Invalid)?;
    let position = reader.read_field()?.to_vec();
    if position.len() > MAX_POSITION_BYTES {
        return Err(CursorError::Invalid);
    }
    let expires_at = UtcTimestamp::from_unix_nanos(reader.read_i128()?)
        .map_err(|_error| CursorError::Invalid)?;
    if !reader.is_empty() {
        return Err(CursorError::Invalid);
    }
    Ok(CursorClaims {
        scope: CursorScope::new(tenant, principal, operation, query_digest, snapshot_digest),
        position,
        expires_at,
    })
}

const fn map_context_error(_error: RequestContextError) -> CursorError {
    CursorError::Invalid
}

struct CursorReader<'a> {
    remaining: &'a [u8],
}

impl<'a> CursorReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CursorError> {
        if length > self.remaining.len() {
            return Err(CursorError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8, CursorError> {
        self.take(1)?.first().copied().ok_or(CursorError::Invalid)
    }

    fn read_field(&mut self) -> Result<&'a [u8], CursorError> {
        let encoded_length: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_error| CursorError::Invalid)?;
        self.take(usize::from(u16::from_be_bytes(encoded_length)))
    }

    fn read_text(&mut self) -> Result<String, CursorError> {
        let text =
            std::str::from_utf8(self.read_field()?).map_err(|_error| CursorError::Invalid)?;
        Ok(text.to_owned())
    }

    fn read_i128(&mut self) -> Result<i128, CursorError> {
        let bytes: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_error| CursorError::Invalid)?;
        Ok(i128::from_be_bytes(bytes))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{CursorCodec, CursorError, CursorScope, CursorSigningKey, hmac_sha256};
    use crate::context::{OperationId, PrincipalId, TenantId};
    use cigar_protocol::{ContentDigest, PageCursor, UtcTimestamp};

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn scope() -> Result<CursorScope, Box<dyn std::error::Error>> {
        Ok(CursorScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            OperationId::new("queryCatalog")?,
            digest('a')?,
            digest('b')?,
        ))
    }

    fn time(value: i128) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
        Ok(UtcTimestamp::from_unix_nanos(value)?)
    }

    #[test]
    fn cursor_round_trips_exact_position() -> Result<(), Box<dyn std::error::Error>> {
        let codec = CursorCodec::new(CursorSigningKey::new(vec![7_u8; 32])?);
        let scope = scope()?;
        let cursor = codec.seal(&scope, b"page-17", time(30)?)?;
        let claims = codec.open(&cursor, &scope, time(20)?)?;
        assert_eq!(claims.position(), b"page-17");
        assert_eq!(claims.scope(), &scope);
        Ok(())
    }

    #[test]
    fn cursor_rejects_forgery_and_wrong_scope() -> Result<(), Box<dyn std::error::Error>> {
        let codec = CursorCodec::new(CursorSigningKey::new(vec![7_u8; 32])?);
        let scope = scope()?;
        let cursor = codec.seal(&scope, b"page-17", time(30)?)?;
        let mut forged = cursor.as_bytes().to_vec();
        let Some(byte) = forged.get_mut(5) else {
            return Err("test cursor was unexpectedly short".into());
        };
        *byte ^= 1;
        let forged = PageCursor::new(forged)?;
        assert_eq!(
            codec.open(&forged, &scope, time(20)?),
            Err(CursorError::Invalid)
        );

        let wrong_scope = CursorScope::new(
            TenantId::new("tenant-b")?,
            PrincipalId::new("principal-a")?,
            OperationId::new("queryCatalog")?,
            digest('a')?,
            digest('b')?,
        );
        assert_eq!(
            codec.open(&cursor, &wrong_scope, time(20)?),
            Err(CursorError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn cursor_rejects_expiry_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let codec = CursorCodec::new(CursorSigningKey::new(vec![7_u8; 32])?);
        let scope = scope()?;
        let cursor = codec.seal(&scope, b"position", time(30)?)?;
        assert_eq!(
            codec.open(&cursor, &scope, time(30)?),
            Err(CursorError::Expired)
        );
        Ok(())
    }

    #[test]
    fn signing_key_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let secret = vec![7_u8; 32];
        let key = CursorSigningKey::new(secret.clone())?;
        assert!(!format!("{key:?}").contains(&format!("{secret:?}")));
        assert!(!format!("{:?}", CursorCodec::new(key)).contains('7'));
        Ok(())
    }

    #[test]
    fn hmac_matches_rfc_4231_sha256_vector() {
        let actual = hmac_sha256(&[0x0b_u8; 20], b"Hi There");
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(actual, expected);
    }
}
