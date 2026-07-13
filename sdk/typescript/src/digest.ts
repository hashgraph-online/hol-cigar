import { createHash } from "node:crypto";

import { ValidationError } from "./errors.js";
import type { SemanticBundleBlock, SemanticContextBundle, SemanticContextDelta } from "./types.js";

type Canonical = boolean | bigint | number | string | Uint8Array | readonly Canonical[] | { readonly [key: string]: Canonical };

const DIGEST = /^1220[0-9a-f]{64}$/u;
const LANE_ORDER = new Map([
  ["rules", 0],
  ["task", 1],
  ["evidence", 2],
  ["history", 3],
  ["tools", 4],
]);

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function head(major: number, argument: bigint): Uint8Array {
  if (argument < 0n || argument > 0xffff_ffff_ffff_ffffn) throw new ValidationError("canonical integer exceeds u64");
  const prefix = major << 5;
  if (argument < 24n) return Uint8Array.of(prefix | Number(argument));
  const widths: readonly [bigint, number, number][] = [
    [0xffn, 24, 1],
    [0xffffn, 25, 2],
    [0xffff_ffffn, 26, 4],
    [0xffff_ffff_ffff_ffffn, 27, 8],
  ];
  for (const [maximum, additional, width] of widths) {
    if (argument <= maximum) {
      const output = new Uint8Array(width + 1);
      output[0] = prefix | additional;
      let remainder = argument;
      for (let index = width; index > 0; index -= 1) {
        output[index] = Number(remainder & 0xffn);
        remainder >>= 8n;
      }
      return output;
    }
  }
  throw new ValidationError("canonical integer exceeds u64");
}

/** Encode the frozen CIGAR deterministic-CBOR subset. */
export function deterministicCbor(value: Canonical): Uint8Array {
  return encodeCanonical(value, 0, { nodes: 0 });
}

function encodeCanonical(value: Canonical, depth: number, budget: { nodes: number }): Uint8Array {
  budget.nodes += 1;
  if (depth > 64 || budget.nodes > 100_000) throw new ValidationError("canonical value exceeds nesting or node bounds");
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new ValidationError("canonical numbers must be safe integers; use bigint for wider values");
    return encodeCanonical(BigInt(value), depth, budget);
  }
  if (typeof value === "bigint") {
    if (value < -(1n << 63n)) throw new ValidationError("canonical signed integer is below i64");
    return value >= 0n ? head(0, value) : head(1, -1n - value);
  }
  if (typeof value === "string") {
    const encoded = new TextEncoder().encode(value.normalize("NFC"));
    return concatenate([head(3, BigInt(encoded.length)), encoded]);
  }
  if (value instanceof Uint8Array) return concatenate([head(2, BigInt(value.length)), value]);
  if (Array.isArray(value)) {
    return concatenate([head(4, BigInt(value.length)), ...value.map((child) => encodeCanonical(child, depth + 1, budget))]);
  }
  if (typeof value !== "object" || value === null) throw new ValidationError("null is not canonical");
  const entries = Object.entries(value).map(([key, child]) => {
    if (child === undefined || child === null) throw new ValidationError("undefined and null are not canonical");
    return { key: encodeCanonical(key, depth + 1, budget), child };
  });
  entries.sort((left, right) => Buffer.compare(left.key, right.key));
  for (let index = 1; index < entries.length; index += 1) {
    if (Buffer.compare(entries[index - 1]?.key ?? new Uint8Array(), entries[index]?.key ?? new Uint8Array()) === 0) {
      throw new ValidationError("canonical map contains a duplicate key");
    }
  }
  return concatenate([
    head(5, BigInt(entries.length)),
    ...entries.flatMap(({ key, child }) => [key, encodeCanonical(child, depth + 1, budget)]),
  ]);
}

function canonicalPayload(value: unknown, depth = 0, budget = { nodes: 0 }): Canonical {
  budget.nodes += 1;
  if (depth > 64 || budget.nodes > 100_000) throw new ValidationError("operation payload exceeds nesting or node bounds");
  if (typeof value === "boolean" || typeof value === "string" || typeof value === "bigint" || value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new ValidationError("payload numbers must be safe integers; use bigint for int64/uint64");
    return value;
  }
  if (Array.isArray(value)) return value.map((child) => canonicalPayload(child, depth + 1, budget));
  if (typeof value === "object" && value !== null) {
    const result: Record<string, Canonical> = {};
    for (const [key, child] of Object.entries(value)) {
      if (child !== undefined) result[key] = canonicalPayload(child, depth + 1, budget);
    }
    return result;
  }
  throw new ValidationError("operation payload contains null, undefined, or a non-canonical value");
}

/** Encode one schema-derived operation payload exactly like cigar-api. */
export function encodeOperationPayload(value: unknown): Uint8Array {
  return deterministicCbor(canonicalPayload(value));
}

class PayloadCborParser {
  #position = 0;
  #nodes = 0;
  readonly #source: Uint8Array;

  constructor(source: Uint8Array) {
    this.#source = source;
  }

  get done(): boolean {
    return this.#position === this.#source.length;
  }

  #exact(length: number): Uint8Array {
    const end = this.#position + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.#source.length) throw new ValidationError("payload CBOR is truncated");
    const value = this.#source.slice(this.#position, end);
    this.#position = end;
    return value;
  }

  #byte(): number {
    const value = this.#exact(1)[0];
    if (value === undefined) throw new ValidationError("payload CBOR is truncated");
    return value;
  }

  #argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const widths = new Map([[24, 1], [25, 2], [26, 4], [27, 8]]);
    const width = widths.get(additional);
    if (width === undefined) throw new ValidationError("payload CBOR uses an indefinite or reserved form");
    let value = 0n;
    for (const byte of this.#exact(width)) value = (value << 8n) | BigInt(byte);
    const minimum = new Map([[1, 24n], [2, 0x100n], [4, 0x1_0000n], [8, 0x1_0000_0000n]]).get(width);
    if (minimum === undefined || value < minimum) throw new ValidationError("payload CBOR integer is non-canonical");
    return value;
  }

  parse(depth = 0): Canonical {
    this.#nodes += 1;
    if (depth > 64 || this.#nodes > 100_000) throw new ValidationError("payload CBOR exceeds nesting or node bounds");
    const initial = this.#byte();
    const major = initial >> 5;
    const additional = initial & 31;
    if (major === 0 || major === 1) {
      const argument = this.#argument(additional);
      const value = major === 0 ? argument : -1n - argument;
      if (value < -(1n << 63n)) throw new ValidationError("payload CBOR integer exceeds i64");
      return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    }
    if (major === 2 || major === 3) {
      const length = Number(this.#argument(additional));
      const bytes = this.#exact(length);
      if (major === 2) return bytes;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes).normalize("NFC");
      } catch (cause) {
        throw new ValidationError("payload CBOR text is invalid UTF-8", { cause });
      }
    }
    if (major === 4) {
      const length = Number(this.#argument(additional));
      if (!Number.isSafeInteger(length) || length > 100_000) throw new ValidationError("payload CBOR collection exceeds its node bound");
      return Array.from({ length }, () => this.parse(depth + 1));
    }
    if (major === 5) {
      const length = Number(this.#argument(additional));
      if (!Number.isSafeInteger(length) || length > 100_000) throw new ValidationError("payload CBOR collection exceeds its node bound");
      const result: Record<string, Canonical> = {};
      let previous: Uint8Array | undefined;
      for (let index = 0; index < length; index += 1) {
        const start = this.#position;
        const key = this.parse(depth + 1);
        const encoded = this.#source.slice(start, this.#position);
        if (typeof key !== "string" || (previous !== undefined && Buffer.compare(previous, encoded) >= 0) || key in result) {
          throw new ValidationError("payload CBOR map keys are not canonical and unique");
        }
        previous = encoded;
        result[key] = this.parse(depth + 1);
      }
      return result;
    }
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    throw new ValidationError("payload CBOR contains a forbidden tag, null, float, or simple value");
  }
}

/** Strictly decode one canonical typed operation payload. */
export function decodeOperationPayload(source: Uint8Array): unknown {
  const parser = new PayloadCborParser(source);
  const value = parser.parse();
  if (!parser.done || Buffer.compare(deterministicCbor(value), source) !== 0) {
    throw new ValidationError("payload CBOR is not deterministic");
  }
  return value;
}

function multihash(domain: string, canonical: Uint8Array): string {
  const digest = createHash("sha256")
    .update(domain)
    .update(Uint8Array.of(0))
    .update("v1")
    .update(Uint8Array.of(0))
    .update(canonical)
    .digest("hex");
  return `1220${digest}`;
}

/** Compute an ordinary raw SHA-256 multihash (used for sealed delta JSON). */
export function rawMultihash(bytes: Uint8Array): string {
  return `1220${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertDigest(value: string, field: string): void {
  if (!DIGEST.test(value)) throw new ValidationError(`${field} must be a lowercase SHA-256 multihash`);
}

function exactKeys(value: object, expected: readonly string[], context: string): void {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  if (actual.length !== sorted.length || actual.some((key, index) => key !== sorted[index])) {
    throw new ValidationError(`${context} has unknown or missing fields`);
  }
}

function validateBlock(block: SemanticBundleBlock, index: number): void {
  const expected = ["block_id", "lane", "representation", "content_digest", "token_count", "provenance"];
  const receiptPresent = Object.hasOwn(block, "transform_receipt");
  if (receiptPresent) expected.push("transform_receipt");
  exactKeys(block, expected, `block ${index}`);
  assertDigest(block.block_id, `block ${index} id`);
  assertDigest(block.content_digest, `block ${index} content digest`);
  if (!LANE_ORDER.has(block.lane)) throw new ValidationError(`block ${index} has an unknown lane`);
  if (!["exact", "extracted", "summarized", "redacted"].includes(block.representation)) {
    throw new ValidationError(`block ${index} has an unknown representation`);
  }
  if (!Number.isInteger(block.token_count) || block.token_count < 1 || block.token_count > 0xffff_ffff) {
    throw new ValidationError(`block ${index} token count is invalid`);
  }
  if (block.provenance.length < 1 || block.provenance.length > 10_000) {
    throw new ValidationError(`block ${index} provenance count is invalid`);
  }
  block.provenance.forEach((item) => assertDigest(item, `block ${index} provenance`));
  if (!block.provenance.every((item, ordinal) => ordinal === 0 || (block.provenance[ordinal - 1] ?? "") < item)) {
    throw new ValidationError(`block ${index} provenance must be sorted and unique`);
  }
  const receiptRequired = block.representation === "extracted" || block.representation === "summarized";
  if (receiptRequired !== receiptPresent) {
    throw new ValidationError(`block ${index} extracted and summarized representations require exactly one transform receipt`);
  }
  if (receiptPresent) {
    assertDigest(block.transform_receipt as string, `block ${index} transform receipt`);
  }
}

function canonicalBlock(block: SemanticBundleBlock): Record<string, Canonical> {
  return {
    block_id: block.block_id,
    lane: block.lane,
    representation: block.representation,
    content_digest: block.content_digest,
    token_count: block.token_count,
    provenance: block.provenance,
    ...(block.transform_receipt === undefined ? {} : { transform_receipt: block.transform_receipt }),
  };
}

function canonicalExtensions(value: Readonly<Record<string, unknown>>): Record<string, Canonical> {
  return value as Record<string, Canonical>;
}

/** Compute the semantic v1 bundle identity, excluding the self-derived bundle_id. */
export function bundleId(bundle: SemanticContextBundle): string {
  bundle.blocks.forEach((block, index) => validateBlock(block, index));
  const fields: Record<string, Canonical> = {
    schema_version: bundle.schema_version,
    contract_digest: bundle.contract_digest,
    manifest_digest: bundle.manifest_digest,
    blocks: bundle.blocks.map(canonicalBlock),
    total_tokens: bundle.total_tokens,
    extensions: canonicalExtensions(bundle.extensions),
  };
  return multihash("CIGAR-BUNDLE", deterministicCbor([2, fields]));
}

/** Validate structural invariants and prove the content-derived bundle identity. */
export function verifyBundle(bundle: SemanticContextBundle): void {
  exactKeys(
    bundle,
    ["schema_version", "bundle_id", "contract_digest", "manifest_digest", "blocks", "total_tokens", "extensions"],
    "bundle",
  );
  if (bundle.schema_version !== "cigar.context-bundle.v1") throw new ValidationError("unsupported bundle schema");
  assertDigest(bundle.bundle_id, "bundle id");
  assertDigest(bundle.contract_digest, "contract digest");
  assertDigest(bundle.manifest_digest, "manifest digest");
  if (bundle.blocks.length > 10_000) throw new ValidationError("bundle has too many blocks");
  let total = 0;
  let previous: SemanticBundleBlock | undefined;
  for (const [index, block] of bundle.blocks.entries()) {
    validateBlock(block, index);
    const order = LANE_ORDER.get(block.lane) ?? -1;
    const previousOrder = previous === undefined ? -1 : (LANE_ORDER.get(previous.lane) ?? -1);
    if (previous !== undefined && (order < previousOrder || (order === previousOrder && block.block_id <= previous.block_id))) {
      throw new ValidationError("bundle blocks must be lane/id sorted and unique");
    }
    total += block.token_count;
    if (total > 0xffff_ffff) throw new ValidationError("bundle token sum exceeds u32");
    previous = block;
  }
  if (!Number.isInteger(bundle.total_tokens) || bundle.total_tokens !== total) {
    throw new ValidationError("bundle token total is not exact");
  }
  if (bundleId(bundle) !== bundle.bundle_id) throw new ValidationError("bundle identity verification failed");
}

function deltaJson(delta: SemanticContextDelta): Uint8Array {
  const blocks = delta.added_blocks.map((block) => ({
    block_id: block.block_id,
    lane: block.lane,
    representation: block.representation,
    content_digest: block.content_digest,
    token_count: block.token_count,
    provenance: [...block.provenance],
    ...(block.transform_receipt === undefined ? {} : { transform_receipt: block.transform_receipt }),
  }));
  return new TextEncoder().encode(JSON.stringify({
    schema_version: delta.schema_version,
    base_bundle_id: delta.base_bundle_id,
    target_bundle_id: delta.target_bundle_id,
    added_blocks: blocks,
    removed_block_ids: [...delta.removed_block_ids],
    resulting_tokens: delta.resulting_tokens,
  }));
}

export function deltaDigest(delta: SemanticContextDelta): string {
  delta.added_blocks.forEach((block, index) => validateBlock(block, index));
  return rawMultihash(deltaJson(delta));
}

/** Apply and verify a sealed delta against an exact expected target bundle. */
export function applyContextDelta(
  base: SemanticContextBundle,
  expectedTarget: SemanticContextBundle,
  delta: SemanticContextDelta,
  sealedDigest: string,
): SemanticContextBundle {
  verifyBundle(base);
  verifyBundle(expectedTarget);
  exactKeys(delta, ["schema_version", "base_bundle_id", "target_bundle_id", "added_blocks", "removed_block_ids", "resulting_tokens"], "delta");
  if (delta.schema_version !== "cigar.context-delta.v1") throw new ValidationError("unsupported delta schema");
  if (delta.base_bundle_id !== base.bundle_id) throw new ValidationError("delta base does not match");
  if (delta.target_bundle_id !== expectedTarget.bundle_id) throw new ValidationError("delta target does not match");
  if (deltaDigest(delta) !== sealedDigest) throw new ValidationError("sealed delta digest does not match");
  const blocks = new Map(base.blocks.map((block) => [block.block_id, block]));
  let previousRemoved = "";
  for (const id of delta.removed_block_ids) {
    assertDigest(id, "removed block id");
    if (id <= previousRemoved || !blocks.delete(id)) throw new ValidationError("delta removal set is invalid for the base");
    previousRemoved = id;
  }
  let previousAdded = "";
  for (const [index, block] of delta.added_blocks.entries()) {
    validateBlock(block, index);
    if (block.block_id <= previousAdded || blocks.has(block.block_id)) throw new ValidationError("delta addition set is invalid");
    if (delta.removed_block_ids.includes(block.block_id)) throw new ValidationError("delta both adds and removes a block");
    blocks.set(block.block_id, block);
    previousAdded = block.block_id;
  }
  if (delta.resulting_tokens !== expectedTarget.total_tokens || blocks.size !== expectedTarget.blocks.length) {
    throw new ValidationError("delta result does not match target accounting");
  }
  for (const target of expectedTarget.blocks) {
    const actual = blocks.get(target.block_id);
    if (actual === undefined || JSON.stringify(actual) !== JSON.stringify(target)) {
      throw new ValidationError("delta result does not reproduce the target");
    }
  }
  return structuredClone(expectedTarget);
}
