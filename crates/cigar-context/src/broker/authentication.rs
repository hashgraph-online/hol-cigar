//! Mutual per-connection proof of the host-distributed grant secret.
//!
//! Client and server use fresh challenges and separate HMAC-SHA256 domains. Clients verify the
//! server before sending any context/command bytes; the server verifies the client before reading
//! a command body. The secret is never transmitted on the loopback connection. This authenticates
//! the local peer, not evidence truth, and is not encryption or a multi-host TLS replacement.

use super::protocol::BROKER_PROTOCOL;
use super::{BrokerCredential, BrokerError, hex, random_id};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Maximum encoded size of each handshake message, checked before allocation.
pub const MAX_HANDSHAKE_FRAME: usize = 1024;

/// Public grant routing identity plus a fresh client challenge. Contains no credential secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// Exact broker protocol.
    pub protocol: String,
    /// Expected current broker epoch.
    pub epoch: String,
    /// Domain-separated digest of this specific grant credential.
    pub grant_id: String,
    /// Fresh random 256-bit client challenge, lowercase hex.
    pub nonce: String,
}

/// Server proof bound to both fresh challenges and this exact grant/epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerProof {
    /// Exact broker protocol.
    pub protocol: String,
    /// Expected current broker epoch.
    pub epoch: String,
    /// Exact grant routing identity.
    pub grant_id: String,
    /// Echo of the exact fresh client challenge.
    pub client_nonce: String,
    /// Fresh random 256-bit server challenge, lowercase hex.
    pub server_nonce: String,
    /// HMAC-SHA256 server proof, lowercase hex. It cannot serve as a client proof.
    pub proof: String,
}

/// Client's response to this connection's verified server challenge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProof {
    /// Exact broker protocol.
    pub protocol: String,
    /// HMAC-SHA256 under the distinct client-proof domain, lowercase hex.
    pub proof: String,
}

impl ClientHello {
    /// Create a fresh handshake. Never reuse it for another connection or retry.
    pub fn new(credential: &BrokerCredential) -> Result<Self, BrokerError> {
        Ok(Self {
            protocol: BROKER_PROTOCOL.into(),
            epoch: credential.epoch.clone(),
            grant_id: grant_id(credential)?,
            nonce: random_id()?,
        })
    }

    /// Authenticate the peer before transmitting any context/command, then answer its challenge.
    pub fn verify_server(
        &self,
        credential: &BrokerCredential,
        server: &ServerProof,
    ) -> Result<ClientProof, BrokerError> {
        if self.epoch != credential.epoch
            || self.grant_id != grant_id(credential)?
            || !self.matches(server)
        {
            return Err(BrokerError::AccessDenied);
        }
        let key = ServerKey::new(credential)?;
        key.mac(b"cigar.broker-server-proof.v1\0", server)?
            .verify_slice(&unhex(&server.proof)?)
            .map_err(|_| BrokerError::AccessDenied)?;
        let proof = key
            .mac(b"cigar.broker-client-proof.v1\0", server)?
            .finalize()
            .into_bytes();
        Ok(ClientProof {
            protocol: BROKER_PROTOCOL.into(),
            proof: hex(&proof),
        })
    }

    pub(super) fn valid(&self) -> bool {
        self.protocol == BROKER_PROTOCOL
            && canonical_hex(&self.epoch)
            && canonical_hex(&self.grant_id)
            && canonical_hex(&self.nonce)
    }

    fn matches(&self, server: &ServerProof) -> bool {
        self.valid()
            && server.protocol == BROKER_PROTOCOL
            && server.epoch == self.epoch
            && server.grant_id == self.grant_id
            && server.client_nonce == self.nonce
            && canonical_hex(&server.server_nonce)
            && canonical_hex(&server.proof)
    }
}

/// Public, non-secret routing identity. Knowing it alone grants no client or host authority.
pub fn grant_id(credential: &BrokerCredential) -> Result<String, BrokerError> {
    if !canonical_hex(&credential.epoch) || !canonical_hex(&credential.secret) {
        return Err(BrokerError::AccessDenied);
    }
    let mut hash = Sha256::new();
    hash.update(b"cigar.broker-grant-id.v1\0");
    hash.update(credential.epoch.as_bytes());
    hash.update(credential.secret.as_bytes());
    Ok(hex(&hash.finalize()))
}

// Kept only in the current admission registry; never serialized, logged or restored as authority.
pub(super) struct ServerKey(Zeroizing<[u8; 32]>);

impl ServerKey {
    pub(super) fn new(credential: &BrokerCredential) -> Result<Self, BrokerError> {
        Ok(Self(Zeroizing::new(unhex(&credential.secret)?)))
    }

    pub(super) fn prove(&self, hello: &ClientHello) -> Result<ServerProof, BrokerError> {
        if !hello.valid() {
            return Err(BrokerError::AccessDenied);
        }
        let mut proof = ServerProof {
            protocol: BROKER_PROTOCOL.into(),
            epoch: hello.epoch.clone(),
            grant_id: hello.grant_id.clone(),
            client_nonce: hello.nonce.clone(),
            server_nonce: random_id()?,
            proof: String::new(),
        };
        proof.proof = hex(&self
            .mac(b"cigar.broker-server-proof.v1\0", &proof)?
            .finalize()
            .into_bytes());
        Ok(proof)
    }

    pub(super) fn verify_client(
        &self,
        hello: &ClientHello,
        server: &ServerProof,
        client: &ClientProof,
    ) -> Result<BrokerCredential, BrokerError> {
        if !hello.matches(server) || client.protocol != BROKER_PROTOCOL {
            return Err(BrokerError::AccessDenied);
        }
        self.mac(b"cigar.broker-client-proof.v1\0", server)?
            .verify_slice(&unhex(&client.proof)?)
            .map_err(|_| BrokerError::AccessDenied)?;
        Ok(BrokerCredential {
            epoch: hello.epoch.clone(),
            secret: hex(self.0.as_ref()),
        })
    }

    fn mac(&self, domain: &[u8], proof: &ServerProof) -> Result<Hmac<Sha256>, BrokerError> {
        // Every variable component is exactly 64 ASCII hex bytes. Role-specific domains make
        // client/server reflection invalid; both challenges make cross-connection replay invalid.
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| BrokerError::Unavailable)?;
        mac.update(domain);
        mac.update(proof.epoch.as_bytes());
        mac.update(proof.grant_id.as_bytes());
        mac.update(proof.client_nonce.as_bytes());
        mac.update(proof.server_nonce.as_bytes());
        Ok(mac)
    }
}

fn canonical_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unhex(text: &str) -> Result<[u8; 32], BrokerError> {
    if !canonical_hex(text) {
        return Err(BrokerError::AccessDenied);
    }
    let mut value = [0_u8; 32];
    for (out, pair) in value.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digits = std::str::from_utf8(pair).map_err(|_| BrokerError::AccessDenied)?;
        *out = u8::from_str_radix(digits, 16).map_err(|_| BrokerError::AccessDenied)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn credential() -> BrokerCredential {
        BrokerCredential {
            epoch: "e".repeat(64),
            secret: "a".repeat(64),
        }
    }

    #[test]
    fn python_and_node_hmac_vector_agrees_with_native_handshake() {
        let vector: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("../../fixtures/broker-authentication.v1.json"))
                .unwrap();
        let field = |name: &str| vector.get(name).unwrap().clone();
        let credential = BrokerCredential {
            epoch: field("epoch"),
            secret: field("secret"),
        };
        assert_eq!(grant_id(&credential).unwrap(), field("grant_id"));
        let hello = ClientHello {
            protocol: BROKER_PROTOCOL.into(),
            epoch: credential.epoch.clone(),
            grant_id: field("grant_id"),
            nonce: field("client_nonce"),
        };
        let server = ServerProof {
            protocol: BROKER_PROTOCOL.into(),
            epoch: credential.epoch.clone(),
            grant_id: field("grant_id"),
            client_nonce: field("client_nonce"),
            server_nonce: field("server_nonce"),
            proof: field("server_proof"),
        };
        let client = hello.verify_server(&credential, &server).unwrap();
        assert_eq!(client.proof, field("client_proof"));
        let key = ServerKey::new(&credential).unwrap();
        assert_eq!(
            key.verify_client(&hello, &server, &client).unwrap().secret,
            credential.secret
        );
    }

    #[test]
    fn fresh_mutual_proof_never_puts_the_secret_on_the_wire() {
        let credential = credential();
        let key = ServerKey::new(&credential).unwrap();
        let hello = ClientHello::new(&credential).unwrap();
        let server = key.prove(&hello).unwrap();
        let client = hello.verify_server(&credential, &server).unwrap();
        let authorized = key.verify_client(&hello, &server, &client).unwrap();
        assert_eq!(authorized.epoch, credential.epoch);
        assert_eq!(authorized.secret, credential.secret);
        for wire in [
            serde_json::to_string(&hello).unwrap(),
            serde_json::to_string(&server).unwrap(),
            serde_json::to_string(&client).unwrap(),
        ] {
            assert!(!wire.contains(&credential.secret));
        }
    }

    #[test]
    fn old_connection_and_reflected_proofs_never_authenticate() {
        let credential = credential();
        let key = ServerKey::new(&credential).unwrap();
        let hello = ClientHello::new(&credential).unwrap();
        let first = key.prove(&hello).unwrap();
        let client = hello.verify_server(&credential, &first).unwrap();
        let second = key.prove(&hello).unwrap();
        assert!(key.verify_client(&hello, &second, &client).is_err());
        let next = ClientHello::new(&credential).unwrap();
        assert!(next.verify_server(&credential, &first).is_err());
        let reflected = ClientProof {
            protocol: BROKER_PROTOCOL.into(),
            proof: first.proof.clone(),
        };
        assert!(key.verify_client(&hello, &first, &reflected).is_err());
    }

    #[test]
    fn wrong_server_grant_epoch_and_challenge_are_rejected() {
        let credential = credential();
        let hello = ClientHello::new(&credential).unwrap();
        let other = BrokerCredential {
            epoch: credential.epoch.clone(),
            secret: "b".repeat(64),
        };
        let fake = ServerKey::new(&other).unwrap().prove(&hello).unwrap();
        assert!(hello.verify_server(&credential, &fake).is_err());
        let valid = ServerKey::new(&credential).unwrap().prove(&hello).unwrap();
        let mut changed = valid.clone();
        changed.epoch = "0".repeat(64);
        assert!(hello.verify_server(&credential, &changed).is_err());
        let mut changed = valid.clone();
        changed.grant_id = "0".repeat(64);
        assert!(hello.verify_server(&credential, &changed).is_err());
        let mut changed = valid;
        changed.server_nonce = "0".repeat(64);
        assert!(hello.verify_server(&credential, &changed).is_err());
    }
}
