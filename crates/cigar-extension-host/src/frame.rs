//! Length-delimited canonical-CBOR framing for third-party extension processes.

use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use cigar_canon::{
    from_deterministic_cbor, parse_strict_json, to_deterministic_cbor, to_normalized_json,
};
use cigar_protocol::Validate;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::Read;

const LENGTH_PREFIX_BYTES: usize = 4;

/// Exact bounded codec used on isolated standard-I/O and remote logical ABI boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCodec {
    maximum_payload_bytes: usize,
}

impl FrameCodec {
    /// Creates a codec with a nonzero payload ceiling representable by the v1 prefix.
    pub fn new(maximum_payload_bytes: usize) -> Result<Self, ExtensionHostError> {
        if maximum_payload_bytes == 0 || u32::try_from(maximum_payload_bytes).is_err() {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        Ok(Self {
            maximum_payload_bytes,
        })
    }

    /// Returns the configured canonical-CBOR payload ceiling.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> usize {
        self.maximum_payload_bytes
    }

    /// Encodes exactly one validated record with a four-byte network-order length prefix.
    pub fn encode<T: Serialize + Validate>(
        self,
        record: &T,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        record
            .validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        self.encode_value(record)
    }

    pub(crate) fn encode_value<T: Serialize>(
        self,
        record: &T,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        let json = serde_json::to_vec(record)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        let node = parse_strict_json(&json)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let payload = to_deterministic_cbor(&node)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        self.frame_payload(payload)
    }

    /// Decodes exactly one complete frame, rejects trailing bytes, and validates its record.
    pub fn decode<T: DeserializeOwned + Validate>(
        self,
        framed: &[u8],
    ) -> Result<T, ExtensionHostError> {
        if framed.len() < LENGTH_PREFIX_BYTES {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        let prefix: [u8; LENGTH_PREFIX_BYTES] = framed
            .get(..LENGTH_PREFIX_BYTES)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?
            .try_into()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let expected = LENGTH_PREFIX_BYTES
            .checked_add(length)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?;
        if length == 0 || length > self.maximum_payload_bytes || framed.len() != expected {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        self.decode_payload(
            framed
                .get(LENGTH_PREFIX_BYTES..)
                .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?,
        )
    }

    pub(crate) fn decode_value<T: DeserializeOwned>(
        self,
        framed: &[u8],
    ) -> Result<T, ExtensionHostError> {
        if framed.len() < LENGTH_PREFIX_BYTES {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        let prefix: [u8; LENGTH_PREFIX_BYTES] = framed
            .get(..LENGTH_PREFIX_BYTES)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?
            .try_into()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let expected = LENGTH_PREFIX_BYTES
            .checked_add(length)
            .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?;
        if length == 0 || length > self.maximum_payload_bytes || framed.len() != expected {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        self.decode_payload_value(
            framed
                .get(LENGTH_PREFIX_BYTES..)
                .ok_or_else(|| error(ExtensionHostErrorCode::InvalidFrame))?,
        )
    }

    pub(crate) fn read_value<T: DeserializeOwned>(
        self,
        reader: &mut impl Read,
    ) -> Result<T, ExtensionHostError> {
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        reader
            .read_exact(&mut prefix)
            .map_err(|_error| error(ExtensionHostErrorCode::ExtensionCrashed))?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        if length == 0 || length > self.maximum_payload_bytes {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        let mut payload = vec![0_u8; length];
        reader
            .read_exact(&mut payload)
            .map_err(|_error| error(ExtensionHostErrorCode::ExtensionCrashed))?;
        self.decode_payload_value(&payload)
    }

    fn frame_payload(self, payload: Vec<u8>) -> Result<Vec<u8>, ExtensionHostError> {
        if payload.is_empty() || payload.len() > self.maximum_payload_bytes {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        let length = u32::try_from(payload.len())
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    fn decode_payload<T: DeserializeOwned + Validate>(
        self,
        payload: &[u8],
    ) -> Result<T, ExtensionHostError> {
        if payload.is_empty() || payload.len() > self.maximum_payload_bytes {
            return Err(error(ExtensionHostErrorCode::InvalidFrame));
        }
        let record: T = self.decode_payload_value(payload)?;
        record
            .validate()
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        Ok(record)
    }

    fn decode_payload_value<T: DeserializeOwned>(
        self,
        payload: &[u8],
    ) -> Result<T, ExtensionHostError> {
        let node = from_deterministic_cbor(payload)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        let json = to_normalized_json(&node)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))?;
        serde_json::from_slice(&json).map_err(|_error| error(ExtensionHostErrorCode::InvalidFrame))
    }
}
