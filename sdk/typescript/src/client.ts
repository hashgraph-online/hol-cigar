import { setTimeout as delay } from "node:timers/promises";

import {
  CigarApiError,
  CigarTimeoutError,
  CompatibilityError,
  TransportError,
  ValidationError,
  isRetryable,
  type ProblemDetails,
} from "./errors.js";
import { OPERATIONS, type GeneratedOperations, type OperationId } from "./generated/operations.js";
import { ERROR_CATALOG, type ErrorCode } from "./generated/errors.js";
import * as models from "./generated/models.js";
import { validateIdempotencyKey } from "./idempotency.js";
import { decodeOperationPayload, encodeOperationPayload } from "./digest.js";
import type {
  CallOptions,
  ClientOptions,
  Compatibility,
  EventStream,
  OperationEvent,
  OperationRequest,
  OperationResponse,
  PathParameter,
  TypedEventStream,
  TypedOperationEvent,
  TypedOperationRequest,
  TypedOperationResponse,
} from "./types.js";
import type { PayloadModel } from "./generated/models.js";

const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_EVENT_BYTES = 1024 * 1024;
const MAX_PROBLEM_BYTES = 64 * 1024;
const MAX_TIMEOUT_MS = 300_000;
const MAX_CURSOR_BYTES = 4096;
const PATH_NAME = /^[a-z][a-z0-9_]{0,63}$/u;
const PATH_VALUE = /^[A-Za-z0-9._~-]{1,256}$/u;

function exactBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function decodeBase64url(value: unknown, maximum: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new TransportError("server returned invalid base64url payload");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length > maximum || decoded.toString("base64url") !== value) {
    throw new TransportError("server returned non-canonical or oversized payload");
  }
  return Uint8Array.from(decoded);
}

function boundedText(value: unknown, maximum: number, field: string, required = false): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || (required && value.length === 0) || Buffer.byteLength(value) > maximum) {
    throw new TransportError(`server returned invalid ${field}`);
  }
  return value;
}

function parseResponse(operationId: OperationId, value: unknown, maximum = MAX_PAYLOAD_BYTES): OperationResponse {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TransportError("server returned a non-object response");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  const allowed = ["next_page_cursor", "operation_id", "payload_cbor", "semantic_etag"];
  if (Object.keys(record).some((key) => !allowed.includes(key))) {
    throw new TransportError(`server returned unknown response fields: ${keys}`);
  }
  if (record.operation_id !== operationId) throw new TransportError("server operation identity mismatch");
  const semanticEtag = boundedText(record.semantic_etag, 256, "semantic_etag");
  const nextPageCursor = boundedText(record.next_page_cursor, MAX_CURSOR_BYTES, "next_page_cursor");
  return {
    operationId,
    payloadCbor: decodeBase64url(record.payload_cbor, maximum),
    ...(semanticEtag === undefined ? {} : { semanticEtag }),
    ...(nextPageCursor === undefined ? {} : { nextPageCursor }),
  };
}

async function boundedBytes(response: Response, maximum: number, field: string): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(declared) || Number(declared) > maximum)) {
    throw new TransportError(`${field} content length exceeds its bound`);
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maximum) {
      await reader.cancel();
      throw new TransportError(`${field} exceeds its bound`);
    }
    chunks.push(value);
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function parseJson(bytes: Uint8Array, field: string): unknown {
  try {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    assertUniqueJsonKeys(source);
    return JSON.parse(source);
  } catch (cause) {
    throw new TransportError(`${field} is not valid UTF-8 JSON`, { cause });
  }
}

function assertUniqueJsonKeys(source: string): void {
  let position = 0;
  let nodes = 0;
  const whitespace = /[\u0009\u000a\u000d\u0020]/u;
  const skipWhitespace = (): void => {
    while (position < source.length && whitespace.test(source[position] ?? "")) position += 1;
  };
  const stringToken = (): string => {
    if (source[position] !== '"') throw new Error("expected JSON string");
    const start = position;
    position += 1;
    for (;;) {
      const character = source[position];
      if (character === undefined || character.charCodeAt(0) < 0x20) throw new Error("invalid JSON string");
      position += 1;
      if (character === '"') return JSON.parse(source.slice(start, position)) as string;
      if (character !== "\\") continue;
      const escape = source[position];
      if (escape === undefined || !'"\\/bfnrtu'.includes(escape)) throw new Error("invalid JSON escape");
      position += 1;
      if (escape === "u") {
        const scalar = source.slice(position, position + 4);
        if (!/^[0-9a-fA-F]{4}$/u.test(scalar)) throw new Error("invalid JSON Unicode escape");
        position += 4;
      }
    }
  };
  const value = (depth: number): void => {
    nodes += 1;
    if (depth > 64 || nodes > 100_000) throw new Error("JSON exceeds nesting or node bounds");
    skipWhitespace();
    const initial = source[position];
    if (initial === '"') {
      stringToken();
      return;
    }
    if (initial === "{") {
      position += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (source[position] === "}") {
        position += 1;
        return;
      }
      for (;;) {
        skipWhitespace();
        const key = stringToken();
        if (keys.has(key)) throw new Error("JSON object contains a duplicate key");
        keys.add(key);
        skipWhitespace();
        if (source[position] !== ":") throw new Error("JSON object lacks a colon");
        position += 1;
        value(depth + 1);
        skipWhitespace();
        if (source[position] === "}") {
          position += 1;
          return;
        }
        if (source[position] !== ",") throw new Error("JSON object lacks a separator");
        position += 1;
      }
    }
    if (initial === "[") {
      position += 1;
      skipWhitespace();
      if (source[position] === "]") {
        position += 1;
        return;
      }
      for (;;) {
        value(depth + 1);
        skipWhitespace();
        if (source[position] === "]") {
          position += 1;
          return;
        }
        if (source[position] !== ",") throw new Error("JSON array lacks a separator");
        position += 1;
      }
    }
    const start = position;
    while (position < source.length && !/[\u0009\u000a\u000d\u0020,\]}]/u.test(source[position] ?? "")) position += 1;
    if (position === start) throw new Error("JSON value is missing");
    JSON.parse(source.slice(start, position));
  };
  value(0);
  skipWhitespace();
  if (position !== source.length) throw new Error("JSON contains trailing data");
}

async function problem(response: Response): Promise<CigarApiError> {
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/problem+json") {
    throw new TransportError(`HTTP ${response.status} did not use application/problem+json`);
  }
  const value = parseJson(
    await boundedBytes(response, MAX_PROBLEM_BYTES, `HTTP ${response.status} problem`),
    `HTTP ${response.status} problem`,
  );
  return decodeProblem(response.status, value);
}

function decodeProblem(status: number, value: unknown): CigarApiError {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TransportError(`HTTP ${status} contained an invalid CIGAR problem`);
  }
  const candidate = value as Record<string, unknown>;
  const expected = ["code", "correlation_id", "details", "http_status", "message", "remediation", "retry", "schema_version"].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TransportError(`HTTP ${status} contained unknown or missing problem fields`);
  }
  if (candidate.schema_version !== "cigar.problem.v1" || typeof candidate.code !== "string" || !(candidate.code in ERROR_CATALOG)) {
    throw new TransportError(`HTTP ${status} contained an unsupported CIGAR problem`);
  }
  const code = candidate.code as ErrorCode;
  const definition = ERROR_CATALOG[code];
  if (candidate.http_status !== status || candidate.http_status !== definition.httpStatus || candidate.retry !== definition.retry) {
    throw new TransportError(`HTTP ${status} problem disagrees with the frozen error catalog`);
  }
  if (
    typeof candidate.message !== "string" || candidate.message.length === 0 || Buffer.byteLength(candidate.message) > 4096
    || typeof candidate.remediation !== "string" || candidate.remediation.length === 0 || Buffer.byteLength(candidate.remediation) > 4096
    || typeof candidate.correlation_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(candidate.correlation_id)
    || typeof candidate.details !== "object" || candidate.details === null || Array.isArray(candidate.details)
    || Object.keys(candidate.details).length > 256
  ) {
    throw new TransportError(`HTTP ${status} contained an invalid bounded CIGAR problem`);
  }
  return new CigarApiError(status, candidate as unknown as ProblemDetails);
}

function validateTimeout(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS) {
    throw new ValidationError(`timeout must be an integer in 1..${MAX_TIMEOUT_MS} milliseconds`);
  }
  return value;
}

function pathParameters(parameters: readonly PathParameter[] | undefined): readonly PathParameter[] {
  const sorted = [...(parameters ?? [])].sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  if (sorted.length > 8) throw new ValidationError("at most eight path parameters are allowed");
  for (let index = 0; index < sorted.length; index += 1) {
    const item = sorted[index];
    if (item === undefined || !PATH_NAME.test(item.name) || !PATH_VALUE.test(item.value)) {
      throw new ValidationError("path parameters must use the frozen name/value alphabets");
    }
    if (index > 0 && sorted[index - 1]?.name === item.name) {
      throw new ValidationError("path parameter names must be unique");
    }
  }
  return sorted;
}

function bindPath(template: string, parameters: readonly PathParameter[]): string {
  const expected = [...template.matchAll(/\{([a-z][a-z0-9_]*)\}/gu)].map((match) => match[1]);
  if (expected.length !== parameters.length || expected.some((name) => !parameters.some((item) => item.name === name))) {
    throw new ValidationError("request path parameters do not exactly match the operation path");
  }
  return parameters.reduce((path, item) => path.replace(`{${item.name}}`, item.value), template);
}

class HttpEventStream implements EventStream {
  #closed = false;
  #lastEventId?: string;
  readonly #controller = new AbortController();
  readonly #iterate: () => AsyncGenerator<OperationEvent>;
  #iterator?: AsyncGenerator<OperationEvent>;

  constructor(iterate: () => AsyncGenerator<OperationEvent>) {
    this.#iterate = iterate;
  }

  get lastEventId(): string | undefined {
    return this.#lastEventId;
  }

  remember(eventId: string): void {
    this.#lastEventId = eventId;
  }

  get closed(): boolean {
    return this.#closed;
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#controller.abort(new DOMException("CIGAR event stream closed", "AbortError"));
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
  }

  [Symbol.asyncIterator](): AsyncIterator<OperationEvent> {
    this.#iterator ??= this.#iterate();
    return this.#iterator;
  }
}

class TypedHttpEventStream<T> implements TypedEventStream<T> {
  readonly #raw: EventStream;
  readonly #model: PayloadModel<T>;

  constructor(raw: EventStream, model: PayloadModel<T>) {
    this.#raw = raw;
    this.#model = model;
  }

  get lastEventId(): string | undefined {
    return this.#raw.lastEventId;
  }

  close(): void {
    this.#raw.close();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
  }

  async *[Symbol.asyncIterator](): AsyncIterator<TypedOperationEvent<T>> {
    for await (const event of this.#raw) {
      const decoded = decodeOperationPayload(event.payloadCbor) as T;
      yield {
        operationId: event.operationId,
        eventId: event.eventId,
        payload: this.#model.create(decoded),
        payloadCbor: Uint8Array.from(event.payloadCbor),
      };
    }
  }
}

export class CigarClient {
  readonly #baseUrl: URL;
  readonly #token?: ClientOptions["bearerToken"];
  readonly #timeoutMs: number;
  readonly #maxAttempts: number;
  readonly #fetch: typeof globalThis.fetch;
  readonly #apiVersion: "1";

  constructor(options: ClientOptions) {
    try {
      this.#baseUrl = new URL(options.baseUrl);
    } catch (cause) {
      throw new ValidationError("baseUrl must be an absolute HTTP(S) origin", { cause });
    }
    if (!new Set(["http:", "https:"]).has(this.#baseUrl.protocol)) {
      throw new ValidationError("baseUrl must use HTTP or HTTPS");
    }
    if (this.#baseUrl.username !== "" || this.#baseUrl.password !== "" || this.#baseUrl.search !== "" || this.#baseUrl.hash !== "") {
      throw new ValidationError("baseUrl must not contain credentials, query, or fragment");
    }
    if (this.#baseUrl.pathname !== "/" && this.#baseUrl.pathname !== "") {
      throw new ValidationError("baseUrl must be an origin with no path prefix");
    }
    const loopback = this.#baseUrl.hostname === "localhost"
      || this.#baseUrl.hostname === "127.0.0.1"
      || this.#baseUrl.hostname === "::1"
      || this.#baseUrl.hostname === "[::1]";
    if (this.#baseUrl.protocol === "http:" && (!loopback || options.allowInsecureLoopback !== true)) {
      throw new ValidationError("cleartext HTTP requires explicit allowInsecureLoopback for a loopback host");
    }
    this.#baseUrl.pathname = "";
    this.#token = options.bearerToken;
    this.#timeoutMs = validateTimeout(options.defaultTimeoutMs ?? 30_000);
    this.#maxAttempts = options.maxAttempts ?? 3;
    if (!Number.isInteger(this.#maxAttempts) || this.#maxAttempts < 1 || this.#maxAttempts > 8) {
      throw new ValidationError("maxAttempts must be in 1..8");
    }
    if (options.fetch !== undefined && options.trustCustomFetch !== true) {
      throw new ValidationError("custom fetch requires explicit trustCustomFetch acknowledgement");
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (options.apiVersion !== undefined && options.apiVersion !== "1") {
      throw new ValidationError("apiVersion must be the frozen v1 line");
    }
    this.#apiVersion = options.apiVersion ?? "1";
  }

  async negotiate(options?: CallOptions): Promise<Compatibility> {
    const empty = { payloadCbor: new Uint8Array() } satisfies OperationRequest;
    const version = await this.invokeOperation("getVersion", empty, options);
    const capabilities = await this.invokeOperation("getCapabilities", empty, options);
    return { apiVersion: this.#apiVersion, version, capabilities };
  }

  async invokeTypedOperation<RequestPayload, ResponsePayload>(
    operationId: OperationId,
    request: TypedOperationRequest<RequestPayload>,
    responseModel: PayloadModel<ResponsePayload>,
    options?: CallOptions,
  ): Promise<TypedOperationResponse<ResponsePayload>> {
    const raw = await this.invokeOperation(operationId, this.#typedRequest(operationId, request), options);
    const decoded = decodeOperationPayload(raw.payloadCbor) as ResponsePayload;
    return {
      operationId: raw.operationId,
      payload: responseModel.create(decoded),
      payloadCbor: Uint8Array.from(raw.payloadCbor),
      ...(raw.semanticEtag === undefined ? {} : { semanticEtag: raw.semanticEtag }),
      ...(raw.nextPageCursor === undefined ? {} : { nextPageCursor: raw.nextPageCursor }),
    };
  }

  streamTypedOperation<RequestPayload, EventPayload>(
    operationId: OperationId,
    request: TypedOperationRequest<RequestPayload>,
    eventModel: PayloadModel<EventPayload>,
    options?: CallOptions,
  ): TypedEventStream<EventPayload> {
    return new TypedHttpEventStream(
      this.streamOperation(operationId, this.#typedRequest(operationId, request), options),
      eventModel,
    );
  }

  #typedRequest<T>(operationId: OperationId, request: TypedOperationRequest<T>): OperationRequest {
    const definition = OPERATIONS[operationId];
    if (definition.stream && request.pageCursor !== undefined) {
      throw new ValidationError("SSE resume uses CallOptions.resumeFrom, not a pagination cursor");
    }
    const validatedPayload = payloadModel(definition.requestType).create(request.payload);
    if (typeof validatedPayload !== "object" || validatedPayload === null) {
      throw new ValidationError(`${definition.requestType} payload must be an object`);
    }
    const record = validatedPayload as Record<string, unknown>;
    const pathParameters = definition.pathFields.map((name) => {
      const value = record[name];
      if (typeof value !== "string") throw new ValidationError(`${definition.requestType}.${name} must be a path string`);
      return { name, value };
    });
    return {
      payloadCbor: definition.httpMethod === "GET" ? new Uint8Array() : encodeOperationPayload(validatedPayload),
      pathParameters,
      ...(request.idempotencyKey === undefined ? {} : { idempotencyKey: request.idempotencyKey }),
      ...(request.expectedRevision === undefined ? {} : { expectedRevision: request.expectedRevision }),
      ...(request.dryRun === undefined ? {} : { dryRun: request.dryRun }),
      ...(request.pageCursor === undefined ? {} : { pageCursor: request.pageCursor }),
      ...(request.pageSize === undefined ? {} : { pageSize: request.pageSize }),
    };
  }

  async *paginate(
    operationId: OperationId,
    request: OperationRequest,
    options?: CallOptions,
  ): AsyncGenerator<OperationResponse> {
    if (OPERATIONS[operationId].stream) throw new ValidationError("stream operations cannot be paginated");
    let cursor = request.pageCursor;
    const seen = new Set<string>();
    for (;;) {
      const pageRequest: OperationRequest = cursor === undefined
        ? { ...request }
        : { ...request, pageCursor: cursor };
      const response = await this.invokeOperation(operationId, pageRequest, options);
      yield response;
      if (response.nextPageCursor === undefined) return;
      if (seen.has(response.nextPageCursor)) throw new TransportError("pagination cursor cycle detected");
      seen.add(response.nextPageCursor);
      cursor = response.nextPageCursor;
    }
  }

  async invokeOperation(
    operationId: OperationId,
    request: OperationRequest,
    options?: CallOptions,
  ): Promise<OperationResponse> {
    const definition = OPERATIONS[operationId];
    if (definition.stream) throw new ValidationError("use streamOperation for streaming operations");
    const attempts = this.#attempts(operationId, request, options);
    const timeoutMs = validateTimeout(options?.timeoutMs ?? this.#timeoutMs);
    const deadline = Date.now() + timeoutMs;
    let lastError: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      if (deadline <= Date.now()) throw new CigarTimeoutError("CIGAR request deadline elapsed");
      try {
        return await this.#unary(operationId, request, deadline, options);
      } catch (error) {
        lastError = error;
        if (attempt === attempts || !isRetryable(error)) throw error;
        const backoff = Math.min(100 * 2 ** (attempt - 1), 1_000);
        const remaining = deadline - Date.now();
        if (remaining <= backoff) throw new CigarTimeoutError("CIGAR request deadline elapsed", { cause: error });
        await delay(backoff, undefined, { signal: options?.signal });
      }
    }
    throw lastError;
  }

  streamOperation(operationId: OperationId, request: OperationRequest, options?: CallOptions): EventStream {
    if (!OPERATIONS[operationId].stream) throw new ValidationError("operation is not a stream");
    if (request.pageCursor !== undefined) throw new ValidationError("SSE resume uses CallOptions.resumeFrom, not pageCursor");
    let stream: HttpEventStream;
    stream = new HttpEventStream(() => this.#events(stream, operationId, request, options));
    return stream;
  }

  #attempts(operationId: OperationId, request: OperationRequest, options: CallOptions | undefined): number {
    const requested = options?.maxAttempts ?? this.#maxAttempts;
    if (!Number.isInteger(requested) || requested < 1 || requested > 8) {
      throw new ValidationError("maxAttempts must be in 1..8");
    }
    if (operationId === "dispatchEffect") return 1;
    const definition = OPERATIONS[operationId];
    if (!definition.mutation) return requested;
    return request.idempotencyKey === undefined ? 1 : requested;
  }

  async #headers(
    operationId: OperationId,
    timeoutMs: number,
    signal?: AbortSignal,
    externalSignal?: AbortSignal,
  ): Promise<Headers> {
    const headers = new Headers({
      accept: "application/json, application/problem+json",
      "x-cigar-api-version": this.#apiVersion,
      "x-cigar-operation-id": operationId,
      "x-cigar-timeout-ms": String(timeoutMs),
    });
    if (this.#token !== undefined) {
      let token: string;
      try {
        if (typeof this.#token !== "function") token = this.#token;
        else if (signal === undefined) token = await this.#token();
        else {
          const provider = Promise.resolve(this.#token(signal));
          token = await new Promise<string>((resolve, reject) => {
            const aborted = (): void => reject(signal.reason);
            signal.addEventListener("abort", aborted, { once: true });
            provider.then(resolve, reject).finally(() => signal.removeEventListener("abort", aborted)).catch(() => undefined);
          });
        }
      } catch (cause) {
        if (externalSignal?.aborted === true) throw cause;
        if (signal?.aborted === true) throw new CigarTimeoutError("CIGAR request deadline elapsed", { cause });
        throw new TransportError("bearer token provider failed", { cause });
      }
      if (!/^[\x21-\x7e]{1,8192}$/u.test(token)) throw new ValidationError("bearer token must be 1..8192 visible ASCII bytes");
      headers.set("authorization", `Bearer ${token}`);
    }
    return headers;
  }

  #signal(options: CallOptions | undefined, timeoutMs: number, internal?: AbortSignal): AbortSignal {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signals = [timeout];
    if (options?.signal !== undefined) signals.push(options.signal);
    if (internal !== undefined) signals.push(internal);
    return signals.length === 1 ? timeout : AbortSignal.any(signals);
  }

  async #unary(
    operationId: OperationId,
    request: OperationRequest,
    deadline: number,
    options?: CallOptions,
  ): Promise<OperationResponse> {
    const definition = OPERATIONS[operationId];
    const timeoutMs = Math.max(1, deadline - Date.now());
    const parameters = pathParameters(request.pathParameters);
    let path = bindPath(definition.httpPath, parameters);
    const requestSignal = this.#signal(options, timeoutMs);
    const headers = await this.#headers(operationId, timeoutMs, requestSignal, options?.signal);
    const payload = Uint8Array.from(request.payloadCbor ?? []);
    if (payload.length > definition.requestMaxBytes) throw new ValidationError("request payload exceeds operation bound");
    let body: string | undefined;
    if (definition.httpMethod === "GET") {
      if (payload.length !== 0 || request.idempotencyKey !== undefined || request.expectedRevision !== undefined || request.dryRun === true) {
        throw new ValidationError("GET operations do not carry payload or mutation metadata");
      }
      const query = new URLSearchParams();
      if (request.pageCursor !== undefined) {
        if (Buffer.byteLength(request.pageCursor) > MAX_CURSOR_BYTES) throw new ValidationError("page cursor exceeds bound");
        query.set("page_cursor", request.pageCursor);
      }
      if (request.pageSize !== undefined) {
        if (!Number.isInteger(request.pageSize) || request.pageSize < 1 || request.pageSize > 1000) throw new ValidationError("pageSize must be in 1..1000");
        query.set("page_size", String(request.pageSize));
      }
      const encoded = query.toString();
      if (encoded !== "") path += `?${encoded}`;
    } else {
      if (definition.idempotencyRequired) {
        if (request.idempotencyKey === undefined) throw new ValidationError(`${operationId} requires an idempotency key`);
        headers.set("idempotency-key", validateIdempotencyKey(request.idempotencyKey));
      } else if (request.idempotencyKey !== undefined) {
        throw new ValidationError(`${operationId} does not accept an idempotency key`);
      }
      if (definition.revisionRequired) {
        if (request.expectedRevision === undefined || request.expectedRevision.length === 0 || request.expectedRevision.length > 256) {
          throw new ValidationError(`${operationId} requires a bounded expected revision`);
        }
        headers.set("if-match", request.expectedRevision);
      } else if (request.expectedRevision !== undefined) {
        throw new ValidationError(`${operationId} does not accept an expected revision`);
      }
      headers.set("content-type", "application/json");
      body = JSON.stringify({
        operation_id: operationId,
        payload_cbor: exactBase64url(payload),
        dry_run: request.dryRun ?? false,
        ...(request.idempotencyKey === undefined ? {} : { idempotency_key: request.idempotencyKey }),
        ...(request.expectedRevision === undefined ? {} : { expected_revision: request.expectedRevision }),
        ...(request.pageCursor === undefined ? {} : { page_cursor: request.pageCursor }),
        ...(request.pageSize === undefined ? {} : { page_size: request.pageSize }),
        path_parameters: parameters,
      });
    }
    let response: Response;
    try {
      const init: RequestInit = {
        method: definition.httpMethod,
        headers,
        signal: requestSignal,
        redirect: "error",
        ...(body === undefined ? {} : { body }),
      };
      response = await this.#fetch(new URL(path, `${this.#baseUrl.toString()}/`), init);
    } catch (cause) {
      if (options?.signal?.aborted === true) throw cause;
      if (cause instanceof DOMException && cause.name === "TimeoutError") throw new CigarTimeoutError("CIGAR request deadline elapsed", { cause });
      throw new TransportError("CIGAR transport failed", { cause });
    }
    if (!response.ok) throw await problem(response);
    const serverVersion = response.headers.get("x-cigar-api-version");
    if (serverVersion !== null && serverVersion !== this.#apiVersion) {
      throw new CompatibilityError(`server API version ${serverVersion} is incompatible with ${this.#apiVersion}`);
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType === "application/openmetrics-text") {
      return {
        operationId,
        payloadCbor: await boundedBytes(response, definition.responseMaxBytes, "metrics response"),
      };
    }
    if (contentType !== "application/json") {
      throw new TransportError(`unexpected response content type ${contentType}`);
    }
    const wrapperMaximum = Math.ceil(definition.responseMaxBytes * 4 / 3) + 16_384;
    return parseResponse(
      operationId,
      parseJson(await boundedBytes(response, wrapperMaximum, "operation response"), "operation response"),
      definition.responseMaxBytes,
    );
  }

  async *#events(
    stream: HttpEventStream,
    operationId: OperationId,
    request: OperationRequest,
    options?: CallOptions,
  ): AsyncGenerator<OperationEvent> {
    const timeoutMs = validateTimeout(options?.timeoutMs ?? this.#timeoutMs);
    const deadline = Date.now() + timeoutMs;
    const parameters = pathParameters(request.pathParameters);
    const definition = OPERATIONS[operationId];
    const path = bindPath(definition.httpPath, parameters);
    let resume = options?.resumeFrom;
    if (resume !== undefined && !/^[\x21-\x7e]{1,256}$/u.test(resume)) {
      throw new ValidationError("resumeFrom must be a bounded visible-ASCII event ID");
    }
    const attempts = options?.maxAttempts ?? this.#maxAttempts;
    if (!Number.isInteger(attempts) || attempts < 1 || attempts > 8) {
      throw new ValidationError("maxAttempts must be in 1..8");
    }
    const seen = new Set<string>(resume === undefined ? [] : [resume]);
    for (let attempt = 1; attempt <= attempts && !stream.closed; attempt += 1) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new CigarTimeoutError("CIGAR stream deadline elapsed");
      const requestSignal = this.#signal(options, remaining, stream.signal);
      let headers: Headers;
      try {
        headers = await this.#headers(operationId, remaining, requestSignal, options?.signal);
      } catch (error) {
        if (stream.closed) return;
        throw error;
      }
      headers.set("accept", "text/event-stream, application/problem+json");
      if (resume !== undefined) headers.set("last-event-id", resume);
      let retryCause: unknown = new TransportError("CIGAR event stream ended before close");
      let cleanEnd = false;
      let response: Response | undefined;
      try {
        response = await this.#fetch(new URL(path, `${this.#baseUrl.toString()}/`), {
          method: "GET",
          headers,
          signal: requestSignal,
          redirect: "error",
        });
      } catch (cause) {
        if (stream.closed || options?.signal?.aborted === true) return;
        retryCause = new TransportError("CIGAR event stream failed", { cause });
      }
      if (response !== undefined) {
        if (!response.ok) {
          retryCause = await problem(response);
          if (!isRetryable(retryCause)) throw retryCause;
        } else {
          const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
          if (contentType !== "text/event-stream") throw new TransportError("stream response must use text/event-stream");
          if (response.body === null) throw new TransportError("event stream response has no body");
          const iterator = response.body.pipeThrough(new TextDecoderStream("utf-8", { fatal: true }))[Symbol.asyncIterator]();
          let pending = "";
          for (;;) {
            let next: IteratorResult<string>;
            try {
              next = await iterator.next();
            } catch (cause) {
              retryCause = new TransportError("event stream body read failed", { cause });
              break;
            }
            if (next.done) {
              cleanEnd = true;
              break;
            }
            if (stream.closed) return;
            pending += next.value.replace(/\r\n/gu, "\n");
            if (Buffer.byteLength(pending) > MAX_EVENT_BYTES * 2) throw new TransportError("event frame exceeds bound");
            let boundary: number;
            while ((boundary = pending.indexOf("\n\n")) >= 0) {
              const frame = pending.slice(0, boundary);
              pending = pending.slice(boundary + 2);
              const parsed = this.#event(operationId, frame);
              if (parsed === undefined) continue;
              if (parsed instanceof CigarApiError) throw parsed;
              if (seen.has(parsed.eventId)) continue;
              if (seen.size >= 100_000) throw new TransportError("event identity set exceeds its bound");
              seen.add(parsed.eventId);
              resume = parsed.eventId;
              stream.remember(parsed.eventId);
              yield parsed;
            }
          }
        }
      }
      if (stream.closed) return;
      if (attempt === attempts) {
        if (cleanEnd) return;
        throw retryCause;
      }
      const backoff = Math.min(100 * 2 ** (attempt - 1), 1_000);
      if (deadline - Date.now() <= backoff) {
        throw new CigarTimeoutError("CIGAR stream deadline elapsed", { cause: retryCause });
      }
      await delay(backoff, undefined, { signal: options?.signal });
    }
  }

  #event(operationId: OperationId, frame: string): OperationEvent | CigarApiError | undefined {
    let eventType = "message";
    let id: string | undefined;
    const data: string[] = [];
    for (const line of frame.split("\n")) {
      if (line === "" || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon < 0 ? line : line.slice(0, colon);
      const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /u, "");
      if (field === "event") eventType = value;
      else if (field === "id") id = value;
      else if (field === "data") data.push(value);
    }
    if (data.length === 0) return undefined;
    let decoded: unknown;
    try {
      decoded = parseJson(new TextEncoder().encode(data.join("\n")), "event data");
    } catch (cause) {
      throw new TransportError("event data is not valid JSON", { cause });
    }
    if (eventType === "problem") {
      if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new TransportError("problem event is not an object");
      }
      const status = (decoded as Record<string, unknown>).http_status;
      if (!Number.isInteger(status)) throw new TransportError("problem event lacks its HTTP status");
      return decodeProblem(status as number, decoded);
    }
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new TransportError("event is not an object");
    const record = decoded as Record<string, unknown>;
    const eventFields = Object.keys(record).sort();
    if (eventFields.join(",") !== "event_id,operation_id,payload_cbor") {
      throw new TransportError("event contains unknown or missing fields");
    }
    if (
      record.operation_id !== operationId
      || typeof record.event_id !== "string"
      || !/^[\x21-\x7e]{1,256}$/u.test(record.event_id)
      || record.event_id !== id
    ) {
      throw new TransportError("event identity mismatch");
    }
    return { operationId, eventId: record.event_id, payloadCbor: decodeBase64url(record.payload_cbor, MAX_EVENT_BYTES) };
  }
}

export interface CigarClient extends GeneratedOperations {}

function payloadModel(name: string): PayloadModel<unknown> {
  const candidate = (models as unknown as Record<string, unknown>)[name];
  if (typeof candidate !== "object" || candidate === null || !("create" in candidate)) {
    throw new Error(`generated payload model ${name} is missing`);
  }
  return candidate as PayloadModel<unknown>;
}

for (const operationId of Object.keys(OPERATIONS) as OperationId[]) {
  Object.defineProperty(CigarClient.prototype, operationId, {
    configurable: false,
    enumerable: false,
    value(
      this: CigarClient,
      request: TypedOperationRequest<unknown>,
      options?: CallOptions,
    ): Promise<TypedOperationResponse<unknown>> | TypedEventStream<unknown> {
      return OPERATIONS[operationId].stream
        ? this.streamTypedOperation(operationId, request, payloadModel(OPERATIONS[operationId].eventType ?? ""), options)
        : this.invokeTypedOperation(operationId, request, payloadModel(OPERATIONS[operationId].responseType), options);
    },
    writable: false,
  });
}
