import type { LocalAnswerDraft, LocalContextLimits, LocalDocument, LocalViewContext } from "./context-types.js";

export type LocalBrokerLimits = Readonly<Partial<{
  max_agents: number; max_sources: number; max_tickets: number; max_proposals: number;
  max_retained_bytes: number; max_provenance_bytes: number; max_relation_bytes: number;
}>>;
export type LocalBrokerQueueLimits = Readonly<Partial<{
  max_agents: number; max_agent_jobs: number; max_agent_bytes: number;
  max_host_jobs: number; max_host_bytes: number; max_wait_ms: number;
}>>;
export type LocalBrokerTransportLimits = Readonly<Partial<{
  max_connections: number; max_connections_per_agent: number; max_inbound_bytes: number;
  max_outbound_bytes: number; frame_timeout_ms: number; write_timeout_ms: number; response_timeout_ms: number;
}>>;
export type LocalBrokerAgentLimits = Readonly<Partial<{
  max_tokens: number; max_tickets: number; max_proposals: number; max_retained_bytes: number;
  max_proposal_bytes: number; max_proposal_documents: number; ticket_lifetime_ms: number; proposal_lifetime_ms: number;
}>>;
export type LocalBrokerAgentQueueLimits = Readonly<Partial<{max_jobs: number; max_bytes: number}>>;
/** Existing private host directory; only evidence is retained across restarts. */
export type LocalBrokerStorageOptions = Readonly<{
  directory: string; create_directory?: boolean; max_checkpoint_bytes?: number; max_database_bytes?: number; max_journal_records?: number;
}>;
export type LocalBrokerStorageStatus = Readonly<{mode: "memory" | "sqlite-checkpoint.v1"; restored: boolean}>;
export type LocalBrokerOptions = Readonly<{
  workerPath?: string; timeoutMs?: number; maxPending?: number;
  graph?: LocalContextLimits; retention?: LocalBrokerLimits; queues?: LocalBrokerQueueLimits;
  transport?: LocalBrokerTransportLimits;
  storage?: LocalBrokerStorageOptions;
}>;
/** Sensitive export for protected IPC. Never log or put in argv/environment. */
export type LocalBrokerConnectionConfig = Readonly<{
  schema: "cigar.broker-client.v1"; host: "127.0.0.1"; port: number; epoch: string; secret: string;
}>;
/** Canonical decimal string preserves every native u64 revision. */
export type LocalBrokerSourceRevision = Readonly<{epoch: string; version: string}>;
export type LocalBrokerSourceDependency = Readonly<{source: string; revision: LocalBrokerSourceRevision}>;
/** Host declarations, not signatures or semantic truth guarantees. */
export type LocalBrokerSourceProvenance = Readonly<{
  authority: string; upstream_revision: string; observed_at_ms: number; valid_until_ms: number | null;
  origin: "host" | "reviewed_proposal"; derived_from: readonly LocalBrokerSourceDependency[];
}>;
export type LocalBrokerSourceReceipt = Readonly<{
  revision: LocalBrokerSourceRevision; inserted: number; replaced: number; removed: number; unchanged: number;
}>;
export type LocalBrokerContext = Readonly<{ticket: string; context: LocalViewContext; rendered: string}>;
export type LocalBrokerProposalStatus = Readonly<{
  proposal_id: string; request_key: string;
  outcome: {status: "pending"} | {status: "admitted"; receipt: LocalBrokerSourceReceipt} | {status: "rejected"};
}>;
/** Unverified agent material, available only to host admission. */
export type LocalBrokerProposal = Readonly<{
  source: string; expected: LocalBrokerSourceRevision; documents: readonly LocalDocument[];
}>;
export type LocalBrokerSubmission = Readonly<{
  submission_id: string; draft: LocalAnswerDraft; review_keys: readonly string[];
}>;
export type LocalBrokerCapabilities = Readonly<{
  protocol: "cigar.context-broker.v1"; core_version: string; epoch: string; host: "127.0.0.1"; port: number;
  tokenizer: string; max_frame_bytes: number; max_response_bytes: number;
  host_max_frame_bytes: number; host_max_response_bytes: number;
  execution: "single-owner-fair-dispatch"; requires_hol_services: false;
  capabilities: readonly string[]; transport_limits: LocalBrokerTransportLimits;
  storage?: LocalBrokerStorageStatus;
}>;
