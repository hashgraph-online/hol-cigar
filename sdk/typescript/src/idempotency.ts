import { randomUUID } from "node:crypto";

import { ValidationError } from "./errors.js";

const KEY_PATTERN = /^[\x21-\x7e]{1,256}$/u;

export function createIdempotencyKey(prefix = "cigar"): string {
  if (!/^[A-Za-z0-9._~-]{1,32}$/u.test(prefix)) {
    throw new ValidationError("idempotency prefix must be 1..32 unreserved ASCII characters");
  }
  return `${prefix}-${randomUUID()}`;
}

export function validateIdempotencyKey(value: string): string {
  if (!KEY_PATTERN.test(value)) {
    throw new ValidationError("idempotency key must be 1..256 visible ASCII characters");
  }
  return value;
}

