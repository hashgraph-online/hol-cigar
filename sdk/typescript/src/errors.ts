export type RetryClass =
  | "never"
  | "safe"
  | "after_backoff"
  | "after_reauthorization"
  | "after_reconciliation";

import { ERROR_CATALOG, type ErrorCode } from "./generated/errors.js";

export interface ProblemDetails {
  readonly schema_version: "cigar.problem.v1";
  readonly code: ErrorCode;
  readonly http_status: number;
  readonly retry: RetryClass;
  readonly message: string;
  readonly remediation: string;
  readonly correlation_id: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export class CigarError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class ValidationError extends CigarError {}
export class CompatibilityError extends CigarError {}
export class CigarTimeoutError extends CigarError {}
export class TransportError extends CigarError {}

function immutableJson(value: unknown, depth = 0, budget = { nodes: 0 }): unknown {
  budget.nodes += 1;
  if (depth > 64 || budget.nodes > 100_000) throw new TransportError("problem details exceed nesting or node bounds");
  if (Array.isArray(value)) return Object.freeze(value.map((child) => immutableJson(child, depth + 1, budget)));
  if (typeof value === "object" && value !== null) {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, immutableJson(child, depth + 1, budget)]),
    ));
  }
  if (value === null || ["boolean", "number", "string"].includes(typeof value)) return value;
  throw new TransportError("problem details contain a non-JSON value");
}

export class CigarApiError extends CigarError {
  readonly status: number;
  readonly code: ErrorCode;
  readonly numericCode: number;
  readonly retry: RetryClass;
  readonly correlationId: string;
  readonly remediation: string;
  readonly details: Readonly<Record<string, unknown>>;

  constructor(status: number, problem: ProblemDetails) {
    super(`${problem.message} (CIGAR ${problem.code})`);
    this.status = status;
    this.code = problem.code;
    this.numericCode = ERROR_CATALOG[problem.code].numericCode;
    this.retry = problem.retry;
    this.correlationId = problem.correlation_id;
    this.remediation = problem.remediation;
    this.details = immutableJson(structuredClone(problem.details)) as Readonly<Record<string, unknown>>;
  }
}

export function isRetryable(error: unknown): boolean {
  if (error instanceof CigarApiError) {
    return error.retry === "safe" || error.retry === "after_backoff";
  }
  return error instanceof TransportError || error instanceof CigarTimeoutError;
}
