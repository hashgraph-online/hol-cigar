/** Copy-safe high-level HTTP wire records. */

export interface PathParameter {
  readonly name: string;
  readonly value: string;
}

export interface OperationRequest {
  readonly payloadCbor?: Uint8Array;
  readonly pathParameters?: readonly PathParameter[];
  readonly idempotencyKey?: string;
  readonly expectedRevision?: string;
  readonly dryRun?: boolean;
  readonly pageCursor?: string;
  readonly pageSize?: number;
}

export interface TypedOperationRequest<T> {
  readonly payload: T;
  readonly idempotencyKey?: string;
  readonly expectedRevision?: string;
  readonly dryRun?: boolean;
  readonly pageCursor?: string;
  readonly pageSize?: number;
}

export interface OperationResponse {
  readonly operationId: string;
  readonly payloadCbor: Uint8Array;
  readonly semanticEtag?: string;
  readonly nextPageCursor?: string;
}

export interface TypedOperationResponse<T> {
  readonly operationId: string;
  readonly payload: Readonly<T>;
  readonly payloadCbor: Uint8Array;
  readonly semanticEtag?: string;
  readonly nextPageCursor?: string;
}

export interface OperationEvent {
  readonly operationId: string;
  readonly eventId: string;
  readonly payloadCbor: Uint8Array;
}

export interface TypedOperationEvent<T> {
  readonly operationId: string;
  readonly eventId: string;
  readonly payload: Readonly<T>;
  readonly payloadCbor: Uint8Array;
}

export type BearerTokenProvider = string | ((signal?: AbortSignal) => string | Promise<string>);

export interface CallOptions {
  /** End-to-end deadline in milliseconds. The SDK caps this at five minutes. */
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  /** Maximum total attempts, including the first. Dispatch is always one attempt. */
  readonly maxAttempts?: number;
  /** Exact Last-Event-ID for a server stream; distinct from opaque pagination cursors. */
  readonly resumeFrom?: string;
}

export interface ClientOptions {
  readonly baseUrl: string | URL;
  /** Mandatory for remote HTTPS; no ambient or inherited credential source is consulted. */
  readonly bearerToken?: BearerTokenProvider;
  readonly defaultTimeoutMs?: number;
  readonly maxAttempts?: number;
  readonly fetch?: typeof globalThis.fetch;
  /** Required when injecting a custom fetch implementation with caller-owned proxy/redirect policy. */
  readonly trustCustomFetch?: boolean;
  readonly apiVersion?: "1";
  /** Allows cleartext only for localhost/loopback development endpoints. */
  readonly allowInsecureLoopback?: boolean;
}

export interface EventStream extends AsyncIterable<OperationEvent>, AsyncDisposable {
  readonly lastEventId: string | undefined;
  close(): void;
}

export interface TypedEventStream<T> extends AsyncIterable<TypedOperationEvent<T>>, AsyncDisposable {
  readonly lastEventId: string | undefined;
  close(): void;
}

export interface Compatibility {
  readonly apiVersion: "1";
  readonly version: OperationResponse;
  readonly capabilities: OperationResponse;
}

interface SemanticBundleBlockBase {
  readonly block_id: string;
  readonly lane: "rules" | "task" | "evidence" | "history" | "tools";
  readonly content_digest: string;
  readonly token_count: number;
  readonly provenance: readonly string[];
}

export type SemanticBundleBlock = SemanticBundleBlockBase & (
  | {
    readonly representation: "exact" | "redacted";
    readonly transform_receipt?: never;
  }
  | {
    readonly representation: "extracted" | "summarized";
    readonly transform_receipt: string;
  }
);

export interface SemanticContextBundle {
  readonly schema_version: "cigar.context-bundle.v1";
  readonly bundle_id: string;
  readonly contract_digest: string;
  readonly manifest_digest: string;
  readonly blocks: readonly SemanticBundleBlock[];
  readonly total_tokens: number;
  readonly extensions: Readonly<Record<string, unknown>>;
}

export interface SemanticContextDelta {
  readonly schema_version: "cigar.context-delta.v1";
  readonly base_bundle_id: string;
  readonly target_bundle_id: string;
  readonly added_blocks: readonly SemanticBundleBlock[];
  readonly removed_block_ids: readonly string[];
  readonly resulting_tokens: number;
}
