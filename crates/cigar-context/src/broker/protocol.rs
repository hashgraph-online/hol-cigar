//! Closed, separately authorized host/agent commands and bounded length framing.
//!
//! Decoding an agent frame cannot produce a host command. The caller must still authenticate,
//! enforce admission limits and recheck current broker authority immediately before dispatch.
//! These helpers perform no socket discovery, connection, retries or background work.

use super::scheduler::{AgentQueueLimits, QueueLimits};
use super::{AgentGrantSpec, BrokerError, BrokerLimits, SourceProvenance, SourceRevision};
use crate::{
    AnswerDraft, AnswerPolicy, ClaimReview, ContextError, ContextRequest, Document, EdgeKind,
    GraphLimits, TokenCacheLimits,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};

/// Independent protocol identity; ordinary `cigar.context-worker.v1` remains unchanged.
pub const BROKER_PROTOCOL: &str = "cigar.context-broker.v1";
/// Agent encoded-frame ceiling, checked before allocation and decode.
pub const MAX_AGENT_FRAME: usize = 2 * 1024 * 1024;
/// Agent response ceiling. A disconnected/oversized response never implies a safe write retry.
pub const MAX_AGENT_RESPONSE: usize = 8 * 1024 * 1024;
/// Private host frame ceiling, matching ordinary worker ingestion bounds.
pub const MAX_HOST_FRAME: usize = 32 * 1024 * 1024;
/// Private host response ceiling.
pub const MAX_HOST_RESPONSE: usize = 64 * 1024 * 1024;

/// Explicit local transport resource bounds; there is never a configurable non-loopback bind.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportLimits {
    /// Concurrent connection handlers, including unauthenticated frame readers.
    pub max_connections: usize,
    /// Authenticated connections per grant, across all of its agent processes.
    pub max_connections_per_agent: usize,
    /// Aggregate raw frame bytes being read/decoded before queue transfer.
    pub max_inbound_bytes: usize,
    /// Aggregate encoded agent replies awaiting/performing writes.
    pub max_outbound_bytes: usize,
    /// Total handshake-and-command receive deadline; not renewed by a slow stream.
    pub frame_timeout_ms: u64,
    /// Total response-write deadline, including prefix and body.
    pub write_timeout_ms: u64,
    /// Total owner response wait, including queue and service. Expiry never implies write failure.
    pub response_timeout_ms: u64,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_connections_per_agent: 4,
            max_inbound_bytes: 32 * 1024 * 1024,
            max_outbound_bytes: 32 * 1024 * 1024,
            frame_timeout_ms: 5000,
            write_timeout_ms: 5000,
            response_timeout_ms: 60_000,
        }
    }
}

impl TransportLimits {
    /// Validate resource bounds before opening any listener.
    pub fn validate(&self) -> Result<(), BrokerError> {
        if self.max_connections == 0
            || self.max_connections > 128
            || self.max_connections_per_agent == 0
            || self.max_connections_per_agent > 128
            || self.max_inbound_bytes < MAX_AGENT_FRAME
            || self.max_inbound_bytes > 256 * 1024 * 1024
            || self.max_outbound_bytes < MAX_AGENT_RESPONSE
            || self.max_outbound_bytes > 256 * 1024 * 1024
            || self.frame_timeout_ms == 0
            || self.frame_timeout_ms > 30_000
            || self.write_timeout_ms == 0
            || self.write_timeout_ms > 30_000
            || self.response_timeout_ms == 0
            || self.response_timeout_ms > 300_000
        {
            return Err(BrokerError::InvalidInput);
        }
        Ok(())
    }
}

/// Host-only native graph/cache options. Omitted values use existing graph defaults.
#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphOptions {
    /// Maximum live documents.
    pub max_documents: Option<usize>,
    /// Maximum UTF-8 source bytes per document.
    pub max_document_bytes: Option<usize>,
    /// Maximum live source bytes.
    pub max_total_bytes: Option<usize>,
    /// Maximum outgoing edges per document.
    pub max_edges_per_document: Option<usize>,
    /// Maximum retained directed edges, including dangling edges.
    pub max_edges: Option<usize>,
    /// Token-cache entry ceiling.
    pub cache_entries: Option<usize>,
    /// Token-cache retained-text ceiling.
    pub cache_text_bytes: Option<usize>,
}

impl GraphOptions {
    /// Resolve options without changing validation in the existing graph constructor.
    #[must_use]
    pub fn graph_limits(&self) -> GraphLimits {
        let defaults = GraphLimits::default();
        GraphLimits {
            max_documents: self.max_documents.unwrap_or(defaults.max_documents),
            max_document_bytes: self
                .max_document_bytes
                .unwrap_or(defaults.max_document_bytes),
            max_total_bytes: self.max_total_bytes.unwrap_or(defaults.max_total_bytes),
            max_edges_per_document: self
                .max_edges_per_document
                .unwrap_or(defaults.max_edges_per_document),
            max_edges: self.max_edges.unwrap_or(defaults.max_edges),
        }
    }

    /// Resolve existing tokenizer-cache options.
    #[must_use]
    pub fn cache_limits(&self) -> TokenCacheLimits {
        let defaults = TokenCacheLimits::default();
        TokenCacheLimits {
            max_entries: self.cache_entries.unwrap_or(defaults.max_entries),
            max_text_bytes: self.cache_text_bytes.unwrap_or(defaults.max_text_bytes),
        }
    }
}

/// Commands accepted only on the private host control channel.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostCommand {
    /// First command; no listener should be created before successful initialization.
    Init {
        /// Host-owned privacy domain.
        domain: String,
        /// Existing native graph/cache limits.
        #[serde(default)]
        graph: GraphOptions,
        /// Broker retention limits.
        #[serde(default)]
        retention: BrokerLimits,
        /// Queue admission limits.
        #[serde(default)]
        queues: QueueLimits,
        /// Explicit socket/frame/reply resource bounds.
        #[serde(default)]
        transport: TransportLimits,
        /// Explicit host-owned local storage; absent means no persistence.
        #[serde(default)]
        storage: Option<super::BrokerStorageOptions>,
    },
    /// Issue/replace one agent's authority and queue allowance.
    Grant {
        /// Host-owned view, lease and resource bounds.
        spec: AgentGrantSpec,
        /// Per-grant queue allowance shared by every connection.
        #[serde(default)]
        queue: AgentQueueLimits,
    },
    /// Revoke current authority and pending queue admission.
    Revoke {
        /// Exact host-assigned agent name.
        agent: String,
    },
    /// Read a source's current authority without exposing it to another agent.
    SourceRevision {
        /// Host-selected source locator.
        source: String,
    },
    /// Ingest authoritative source evidence with CAS.
    ReplaceSource {
        /// Exact source locator.
        source: String,
        /// Expected current epoch/version.
        expected: SourceRevision,
        /// Complete atomic replacement, or empty withdrawal.
        documents: Vec<Document>,
        /// Host-declared acquisition and derivation records.
        provenance: SourceProvenance,
    },
    /// Inspect host provenance, including possibly hidden dependency locators.
    Provenance {
        /// Host-selected source locator.
        source: String,
    },
    /// Change an explicit relationship, preserving identity through withdrawal.
    SetEdge {
        /// Source node ID.
        from: String,
        /// Target node ID.
        to: String,
        /// Existing relationship semantics.
        kind: EdgeKind,
        /// True adds, false removes the relation.
        present: bool,
        /// Exact affected source versions.
        expected: BTreeMap<String, SourceRevision>,
    },
    /// Read unverified agent material before deciding whether to admit it.
    Proposal {
        /// Exact pending proposal ID.
        proposal_id: String,
    },
    /// Host admission with fresh source authority checks.
    AdmitProposal {
        /// Exact pending proposal ID.
        proposal_id: String,
        /// Must identify the reviewed-proposal admission path.
        provenance: SourceProvenance,
    },
    /// Reject pending material and retain its terminal receipt.
    RejectProposal {
        /// Exact pending proposal ID.
        proposal_id: String,
    },
    /// Read exact submitted claims through the host reviewer port.
    Submission {
        /// Exact context ticket.
        ticket: String,
    },
    /// Apply trusted reviews to the current exact submission; does not grant effect authority.
    CheckAnswer {
        /// Exact current context ticket.
        ticket: String,
        /// Exact current claim-set identity.
        submission_id: String,
        /// Independently supplied trusted verdicts.
        reviews: Vec<ClaimReview>,
        /// Host release policy.
        #[serde(default)]
        policy: AnswerPolicy,
    },
    /// Gracefully terminate the explicit broker, invalidating all agent clients.
    Close {},
}

/// The entire model-facing surface. No grant, source-admission, reviewer or root-operation variant.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentCommand {
    /// Compile within the server-selected view. Caller `allowed` only narrows it.
    Compile {
        /// Ordinary context request; caller policy cannot override the host's policy.
        request: ContextRequest,
    },
    /// Revalidate a current own ticket.
    Revalidate {
        /// Own ticket ID.
        ticket: String,
    },
    /// Resolve an exact selected node only after current authority validation.
    Citations {
        /// Own ticket ID.
        ticket: String,
        /// Node ID in that selected evidence.
        node_id: String,
    },
    /// Read a version only for an assigned source.
    SourceRevision {
        /// Assigned source locator.
        source: String,
    },
    /// Submit unverified material; never changes the evidence graph itself.
    ProposeSource {
        /// Unique caller key for explicit lost-response reconciliation.
        request_key: String,
        /// Writable assigned source.
        source: String,
        /// Source version used when producing the proposal.
        expected: SourceRevision,
        /// Complete proposed replacement, including empty withdrawal.
        documents: Vec<Document>,
    },
    /// Reconcile an own proposal without automatically retrying it.
    ProposalStatus {
        /// Original caller-supplied request key.
        request_key: String,
    },
    /// Release/cancel an own retained proposal or completion receipt.
    ForgetProposal {
        /// Original caller-supplied request key.
        request_key: String,
    },
    /// Release an own context ticket and any draft bound to it.
    ForgetTicket {
        /// Own ticket ID.
        ticket: String,
    },
    /// Submit the complete displayed claims. Reviewer judgments are not accepted here.
    SubmitAnswer {
        /// Own current ticket ID.
        ticket: String,
        /// Existing exact claim-set format, without arbitrary unreviewed prose.
        draft: AnswerDraft,
    },
}

/// Private stdio request envelope, independent of agent authentication material.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequest {
    /// Positive u32 request identifier, exactly representable in every SDK.
    pub id: u32,
    /// A host-only command.
    pub command: HostCommand,
}

/// One length-framed request per mutually authenticated connection. The transport supplies the
/// authenticated identity internally; a request cannot select or override its credential/view.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequest {
    /// Must equal `BROKER_PROTOCOL`.
    pub protocol: String,
    /// Positive u32 request identifier.
    pub id: u32,
    /// Requested maximum queue wait. The host scheduler imposes an independent upper bound.
    pub wait_ms: u64,
    /// Closed agent surface.
    pub command: AgentCommand,
}

/// Content-free wire failures. They never serialize OS errors, credentials or input fragments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Wrong, expired, revoked or other-owner authority.
    AccessDenied,
    /// A context, dependency or exact answer is stale.
    Stale,
    /// Source CAS or request-key conflict.
    Conflict,
    /// A bounded admission/retention quota was reached.
    Quota,
    /// Malformed command.
    InvalidInput,
    /// Local secure randomness/clock/runtime is unavailable.
    Unavailable,
    /// Existing graph input/work bound.
    LimitExceeded,
    /// Required evidence is absent or unauthorized.
    RequiredUnavailable,
    /// Required evidence cannot fit the budget.
    BudgetUnsatisfiable,
    /// Tokenizer failed.
    Tokenizer,
    /// Context integrity failed.
    Integrity,
    /// Existing context base/policy mismatch.
    BaseMismatch,
    /// Queue deadline expired before dispatch.
    Expired,
    /// Definitive cancellation before dispatch.
    Cancelled,
    /// Host closed the broker before dispatch.
    Closed,
}

impl From<BrokerError> for ErrorCode {
    fn from(error: BrokerError) -> Self {
        match error {
            BrokerError::AccessDenied => Self::AccessDenied,
            BrokerError::Stale => Self::Stale,
            BrokerError::Conflict => Self::Conflict,
            BrokerError::Quota => Self::Quota,
            BrokerError::InvalidInput => Self::InvalidInput,
            BrokerError::Unavailable => Self::Unavailable,
            BrokerError::Context(error) => match error {
                ContextError::InvalidInput => Self::InvalidInput,
                ContextError::LimitExceeded => Self::LimitExceeded,
                ContextError::RequiredUnavailable => Self::RequiredUnavailable,
                ContextError::BudgetUnsatisfiable => Self::BudgetUnsatisfiable,
                ContextError::Tokenizer => Self::Tokenizer,
                ContextError::Integrity => Self::Integrity,
                ContextError::BaseMismatch => Self::BaseMismatch,
            },
        }
    }
}

/// Request timing measured by the owner; request repetitions are not independent benchmark units.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    /// Queue residence in integer microseconds.
    pub queue_us: u64,
    /// Owner service time in integer microseconds.
    pub service_us: u64,
}

/// A correlated successful reply or a content-free definitive failure reply.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome<T> {
    /// The owner completed the operation.
    Ok {
        /// Typed result for the corresponding operation.
        result: T,
    },
    /// A known failure. Missing/invalid replies still leave post-send mutation outcome unknown.
    Error {
        /// Stable allowlisted error.
        error: ErrorCode,
        /// Whether owner dispatch began; false proves the operation handler never ran.
        dispatched: bool,
    },
}

/// Closed, correlated broker reply envelope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply<T> {
    /// Must equal `BROKER_PROTOCOL`.
    pub protocol: String,
    /// Exact request identifier.
    pub id: u32,
    /// Explicit status/result or allowlisted failure.
    pub outcome: Outcome<T>,
    /// Content-free owner timing.
    pub timing: Timing,
}

/// A framing failure invalidates the connection. Never scan for a new frame after one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Missing/truncated prefix/body, timeout or other I/O failure.
    Transport,
    /// Zero-length or over-limit frame; checked before allocating its declared body.
    Limit,
    /// Serialization failed within the permitted frame size.
    Encoding,
}

/// Read one big-endian u32 length and its exact body, bounded before allocation.
/// A socket implementation must additionally enforce a total deadline, not renewable per-read timeouts.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| FrameError::Transport)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > limit {
        return Err(FrameError::Limit);
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| FrameError::Transport)?;
    Ok(body)
}

/// Serialize with a hard output bound, then emit the prefix/body without retrying an operation.
pub fn write_frame(
    writer: &mut impl Write,
    value: &impl Serialize,
    limit: usize,
) -> Result<(), FrameError> {
    let body = encode(value, limit)?;
    let length = u32::try_from(body.len()).map_err(|_| FrameError::Limit)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&body))
        .and_then(|()| writer.flush())
        .map_err(|_| FrameError::Transport)
}

/// Bounded JSON encoding, shared by the host JSONL and agent length-framed transports.
pub fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, FrameError> {
    struct Output {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }
    impl Write for Output {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(std::io::Error::other("frame limit"));
            }
            self.bytes.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Output {
        bytes: Vec::new(),
        limit: limit.min(u32::MAX as usize),
        exceeded: false,
    };
    if serde_json::to_writer(&mut output, value).is_err() {
        return Err(if output.exceeded {
            FrameError::Limit
        } else {
            FrameError::Encoding
        });
    }
    if output.bytes.is_empty() {
        return Err(FrameError::Limit);
    }
    Ok(output.bytes)
}

/// Decode only the closed agent surface, after bounded framing. Does not authenticate a grant.
pub fn decode_agent(frame: &[u8]) -> Result<AgentRequest, ErrorCode> {
    if frame.is_empty() || frame.len() > MAX_AGENT_FRAME {
        return Err(ErrorCode::LimitExceeded);
    }
    let request: AgentRequest =
        serde_json::from_slice(frame).map_err(|_| ErrorCode::InvalidInput)?;
    if request.protocol != BROKER_PROTOCOL
        || request.id == 0
        || request.wait_ms == 0
        || request.wait_ms > super::MAX_LIFETIME_MS
    {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(request)
}

/// Decode only the host control surface after bounded private-channel input.
pub fn decode_host(frame: &[u8]) -> Result<HostRequest, ErrorCode> {
    if frame.is_empty() || frame.len() > MAX_HOST_FRAME {
        return Err(ErrorCode::LimitExceeded);
    }
    let request: HostRequest =
        serde_json::from_slice(frame).map_err(|_| ErrorCode::InvalidInput)?;
    if request.id == 0 {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use serde_json::{Value, json};

    fn envelope(command: Value) -> Value {
        json!({"protocol": BROKER_PROTOCOL, "id": 1, "wait_ms": 1000, "command": command})
    }

    #[test]
    fn agent_wire_cannot_represent_host_mutation_authority_or_reviewer_verdicts() {
        for command in [
            json!({"op":"init", "domain":"root"}),
            json!({"op":"grant"}),
            json!({"op":"revoke", "agent":"other"}),
            json!({"op":"replace_source", "source":"docs", "documents":[]}),
            json!({"op":"admit_proposal", "proposal_id":"fake"}),
            json!({"op":"set_edge"}),
            json!({"op":"check_answer"}),
            json!({"op":"close"}),
            json!({"op":"compile", "request":{}, "view":"root"}),
            json!({"op":"submit_answer", "ticket":"own", "draft":{"snapshot_id":"0".repeat(64),"claims":[],"abstain":true},"reviews":[]}),
        ] {
            assert!(matches!(
                decode_agent(&serde_json::to_vec(&envelope(command)).unwrap()),
                Err(ErrorCode::InvalidInput)
            ));
        }
        let valid = serde_json::to_vec(&envelope(json!({"op":"compile", "request":{}}))).unwrap();
        assert!(matches!(
            decode_agent(&valid).unwrap().command,
            AgentCommand::Compile { .. }
        ));
    }

    #[test]
    fn duplicate_members_wrong_protocol_and_unknown_envelopes_are_rejected() {
        let valid =
            serde_json::to_string(&envelope(json!({"op":"revalidate","ticket":"own"}))).unwrap();
        let duplicate = valid.replacen("\"id\":1", "\"id\":1,\"id\":2", 1);
        assert!(matches!(
            decode_agent(duplicate.as_bytes()),
            Err(ErrorCode::InvalidInput)
        ));
        let mut changed = envelope(json!({"op":"revalidate","ticket":"own"}));
        changed["protocol"] = json!("other");
        assert!(decode_agent(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed["protocol"] = json!(BROKER_PROTOCOL);
        changed["agent"] = json!("administrator");
        assert!(decode_agent(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut command = envelope(json!({"op":"compile","request":{}}));
        command["credential"] = json!({"epoch":"e".repeat(64),"secret":"a".repeat(64)});
        assert!(decode_agent(&serde_json::to_vec(&command).unwrap()).is_err());
    }

    #[test]
    fn source_revisions_round_trip_beyond_javascript_integer_precision() {
        for version in [
            0,
            1,
            (1_u64 << 53) - 1,
            1_u64 << 53,
            (1_u64 << 53) + 1,
            u64::MAX,
        ] {
            let revision = SourceRevision {
                epoch: "e".repeat(64),
                version,
            };
            let wire = serde_json::to_value(&revision).unwrap();
            assert_eq!(wire["version"], json!(version.to_string()));
            assert_eq!(
                serde_json::from_value::<SourceRevision>(wire).unwrap(),
                revision
            );
        }
        for version in [
            json!(1),
            json!("01"),
            json!("+1"),
            json!(" 1"),
            json!("-1"),
            json!(""),
            json!("18446744073709551616"),
        ] {
            assert!(
                serde_json::from_value::<SourceRevision>(
                    json!({"epoch":"e".repeat(64),"version":version})
                )
                .is_err()
            );
        }
    }

    #[test]
    fn prefix_limits_truncation_and_exact_frame_boundaries() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &json!({"a":1}), 7).unwrap();
        assert_eq!(read_frame(&mut wire.as_slice(), 7).unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut wire.as_slice(), 6), Err(FrameError::Limit));
        assert_eq!(
            write_frame(&mut Vec::new(), &json!({"a":1}), 6),
            Err(FrameError::Limit)
        );
        for end in 0..wire.len() {
            assert_eq!(read_frame(&mut &wire[..end], 7), Err(FrameError::Transport));
        }
        assert_eq!(
            read_frame(&mut u32::MAX.to_be_bytes().as_slice(), MAX_AGENT_FRAME),
            Err(FrameError::Limit)
        );
        assert_eq!(
            read_frame(&mut 0_u32.to_be_bytes().as_slice(), MAX_AGENT_FRAME),
            Err(FrameError::Limit)
        );
        let value = "x".repeat(MAX_AGENT_FRAME - 2);
        let encoded = encode(&value, MAX_AGENT_FRAME).unwrap();
        assert_eq!(encoded.len(), MAX_AGENT_FRAME);
        assert_eq!(
            encode(&(value + "x"), MAX_AGENT_FRAME),
            Err(FrameError::Limit)
        );
    }

    #[test]
    fn large_declared_frame_is_rejected_without_requesting_its_body() {
        struct PrefixOnly {
            prefix: std::io::Cursor<[u8; 4]>,
            calls: usize,
        }
        impl Read for PrefixOnly {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                self.prefix.read(bytes)
            }
        }
        let mut reader = PrefixOnly {
            prefix: std::io::Cursor::new(u32::MAX.to_be_bytes()),
            calls: 0,
        };
        assert_eq!(
            read_frame(&mut reader, MAX_AGENT_FRAME),
            Err(FrameError::Limit)
        );
        assert_eq!(reader.calls, 1);
    }

    #[test]
    fn reply_has_only_allowlisted_errors_and_an_explicit_dispatch_boundary() {
        let reply = Reply::<Value> {
            protocol: BROKER_PROTOCOL.into(),
            id: 1,
            outcome: Outcome::Error {
                error: ErrorCode::Cancelled,
                dispatched: false,
            },
            timing: Timing::default(),
        };
        let value = serde_json::to_value(reply).unwrap();
        assert_eq!(value["outcome"]["dispatched"], false);
        let mut forged = value;
        forged["outcome"]["result"] = json!("unreviewed success");
        assert!(serde_json::from_value::<Reply<Value>>(forged).is_err());
        let bad = json!({"protocol":BROKER_PROTOCOL,"id":1,"timing":{"queue_us":0,"service_us":0},"outcome":{"status":"error","error":"SECRET_INPUT","dispatched":false}});
        assert!(serde_json::from_value::<Reply<Value>>(bad).is_err());
    }
}
