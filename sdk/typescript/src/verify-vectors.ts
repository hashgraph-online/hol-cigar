/** Independent TypeScript verifier for CIGAR canonicalization vectors. */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

type CanonicalNode = boolean | bigint | string | Uint8Array | CanonicalNode[] | Map<string, CanonicalNode>;

class CanonicalFailure extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

class JsonParser {
  private position = 0;
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  parse(): CanonicalNode {
    const value = this.value();
    this.whitespace();
    if (this.position !== this.source.length) throw new CanonicalFailure("invalid_input");
    return value;
  }

  private whitespace(): void {
    while (/[ \t\r\n]/u.test(this.source[this.position] ?? "")) this.position += 1;
  }

  private value(): CanonicalNode {
    this.whitespace();
    const current = this.source[this.position];
    if (current === '"') return this.string();
    if (current === "[") return this.array();
    if (current === "{") return this.object();
    if (this.source.startsWith("true", this.position)) {
      this.position += 4;
      return true;
    }
    if (this.source.startsWith("false", this.position)) {
      this.position += 5;
      return false;
    }
    if (this.source.startsWith("null", this.position)) throw new CanonicalFailure("null_forbidden");
    return this.number();
  }

  private string(): string {
    const start = this.position;
    this.position += 1;
    let escaped = false;
    while (this.position < this.source.length) {
      const current = this.source[this.position];
      this.position += 1;
      if (escaped) {
        escaped = false;
      } else if (current === "\\") {
        escaped = true;
      } else if (current === '"') {
        try {
          const parsed: unknown = JSON.parse(this.source.slice(start, this.position));
          if (typeof parsed !== "string") throw new CanonicalFailure("invalid_input");
          return parsed;
        } catch (error) {
          if (error instanceof CanonicalFailure) throw error;
          throw new CanonicalFailure("invalid_input");
        }
      }
    }
    throw new CanonicalFailure("invalid_input");
  }

  private array(): CanonicalNode[] {
    this.position += 1;
    const result: CanonicalNode[] = [];
    this.whitespace();
    if (this.source[this.position] === "]") {
      this.position += 1;
      return result;
    }
    for (;;) {
      result.push(this.value());
      this.whitespace();
      const current = this.source[this.position];
      this.position += 1;
      if (current === "]") return result;
      if (current !== ",") throw new CanonicalFailure("invalid_input");
    }
  }

  private object(): Map<string, CanonicalNode> {
    this.position += 1;
    const result = new Map<string, CanonicalNode>();
    this.whitespace();
    if (this.source[this.position] === "}") {
      this.position += 1;
      return result;
    }
    for (;;) {
      this.whitespace();
      if (this.source[this.position] !== '"') throw new CanonicalFailure("invalid_input");
      const key = this.string();
      if (result.has(key)) throw new CanonicalFailure("duplicate_key");
      this.whitespace();
      if (this.source[this.position] !== ":") throw new CanonicalFailure("invalid_input");
      this.position += 1;
      result.set(key, this.value());
      this.whitespace();
      const current = this.source[this.position];
      this.position += 1;
      if (current === "}") return result;
      if (current !== ",") throw new CanonicalFailure("invalid_input");
    }
  }

  private number(): bigint {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(this.source.slice(this.position));
    if (match === null) throw new CanonicalFailure("invalid_input");
    this.position += match[0].length;
    if (/[.eE]/u.test(match[0])) throw new CanonicalFailure("float_forbidden");
    const value = BigInt(match[0]);
    if (value < -(1n << 63n) || value > (1n << 64n) - 1n) throw new CanonicalFailure("float_forbidden");
    return value;
  }
}

function parseStrictJson(source: string): CanonicalNode {
  return new JsonParser(source).parse();
}

function normalizedJson(value: CanonicalNode): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return JSON.stringify(value);
  if (value instanceof Uint8Array) throw new CanonicalFailure("bytes_not_json");
  if (Array.isArray(value)) return `[${value.map(normalizedJson).join(",")}]`;
  const encoder = new TextEncoder();
  const entries = [...value.entries()].sort(([first], [second]) =>
    Buffer.compare(encoder.encode(first), encoder.encode(second)),
  );
  return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${normalizedJson(child)}`).join(",")}}`;
}

function head(major: number, argument: bigint): Uint8Array {
  const prefix = major << 5;
  if (argument < 24n) return Uint8Array.of(prefix | Number(argument));
  const sizes: Array<[bigint, number, number]> = [
    [0xffn, 24, 1], [0xffffn, 25, 2], [0xffffffffn, 26, 4], [0xffffffffffffffffn, 27, 8],
  ];
  for (const [maximum, additional, size] of sizes) {
    if (argument <= maximum) {
      const output = new Uint8Array(size + 1);
      output[0] = prefix | additional;
      let remainder = argument;
      for (let index = size; index > 0; index -= 1) {
        output[index] = Number(remainder & 0xffn);
        remainder >>= 8n;
      }
      return output;
    }
  }
  throw new CanonicalFailure("limit_exceeded");
}

function concatenate(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function deterministicCbor(value: CanonicalNode): Uint8Array {
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (typeof value === "bigint") return value >= 0n ? head(0, value) : head(1, -1n - value);
  if (value instanceof Uint8Array) return concatenate([head(2, BigInt(value.length)), value]);
  if (typeof value === "string") {
    const encoded = new TextEncoder().encode(value);
    return concatenate([head(3, BigInt(encoded.length)), encoded]);
  }
  if (Array.isArray(value)) return concatenate([head(4, BigInt(value.length)), ...value.map(deterministicCbor)]);
  const entries = [...value.entries()].map(([key, child]) => ({ key: deterministicCbor(key), child }));
  entries.sort((first, second) => Buffer.compare(first.key, second.key));
  return concatenate([head(5, BigInt(entries.length)), ...entries.flatMap(({ key, child }) => [key, deterministicCbor(child)])]);
}

class CborParser {
  position = 0;
  private readonly source: Uint8Array;

  constructor(source: Uint8Array) {
    this.source = source;
  }

  private exact(length: number): Uint8Array {
    const end = this.position + length;
    if (!Number.isSafeInteger(length) || end > this.source.length) throw new CanonicalFailure("invalid_input");
    const value = this.source.slice(this.position, end);
    this.position = end;
    return value;
  }

  private byte(): number {
    const value = this.exact(1)[0];
    if (value === undefined) throw new CanonicalFailure("invalid_input");
    return value;
  }

  private argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const sizes = new Map([[24, 1], [25, 2], [26, 4], [27, 8]]);
    const size = sizes.get(additional);
    if (size === undefined) throw new CanonicalFailure("non_canonical");
    let value = 0n;
    for (const current of this.exact(size)) value = (value << 8n) | BigInt(current);
    const minimum = new Map([[1, 24n], [2, 0x100n], [4, 0x10000n], [8, 0x100000000n]]).get(size);
    if (minimum === undefined || value < minimum) throw new CanonicalFailure("non_canonical");
    return value;
  }

  parse(): CanonicalNode {
    const initial = this.byte();
    const major = initial >> 5;
    const additional = initial & 31;
    if (major === 0) return this.argument(additional);
    if (major === 1) {
      const value = -1n - this.argument(additional);
      if (value < -(1n << 63n)) throw new CanonicalFailure("limit_exceeded");
      return value;
    }
    if (major === 2 || major === 3) {
      const length = Number(this.argument(additional));
      const data = this.exact(length);
      if (major === 2) return data;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(data);
      } catch {
        throw new CanonicalFailure("invalid_input");
      }
    }
    if (major === 4) {
      const length = Number(this.argument(additional));
      return Array.from({ length }, () => this.parse());
    }
    if (major === 5) {
      const length = Number(this.argument(additional));
      const result = new Map<string, CanonicalNode>();
      let previous: Uint8Array | undefined;
      for (let index = 0; index < length; index += 1) {
        const start = this.position;
        const key = this.parse();
        const encoded = this.source.slice(start, this.position);
        if (typeof key !== "string" || (previous !== undefined && Buffer.compare(previous, encoded) >= 0)) {
          throw new CanonicalFailure("non_canonical");
        }
        previous = encoded;
        if (result.has(key)) throw new CanonicalFailure("duplicate_key");
        result.set(key, this.parse());
      }
      return result;
    }
    if (major === 6) throw new CanonicalFailure("non_canonical");
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    if (major === 7 && additional === 22) throw new CanonicalFailure("null_forbidden");
    if (major === 7 && additional >= 25 && additional <= 27) throw new CanonicalFailure("float_forbidden");
    throw new CanonicalFailure("non_canonical");
  }
}

function strictCbor(source: Uint8Array): CanonicalNode {
  const parser = new CborParser(source);
  const value = parser.parse();
  if (parser.position !== source.length || Buffer.compare(deterministicCbor(value), source) !== 0) {
    throw new CanonicalFailure("non_canonical");
  }
  return value;
}

const domains = new Map([
  ["atom", "CIGAR-ATOM"], ["bundle", "CIGAR-BUNDLE"], ["manifest", "CIGAR-MANIFEST"],
  ["handoff", "CIGAR-HANDOFF"], ["effect", "CIGAR-EFFECT"], ["receipt", "CIGAR-RECEIPT"],
  ["extension_manifest", "CIGAR-EXTENSION-MANIFEST"],
]);

function digest(domain: string, cbor: Uint8Array): Buffer {
  const separator = domains.get(domain);
  if (separator === undefined) throw new Error(`unknown digest domain ${domain}`);
  return createHash("sha256").update(separator).update(Uint8Array.of(0)).update("v1").update(Uint8Array.of(0)).update(cbor).digest();
}

interface ValidVector {
  id: string; domain: string; normalization: string; json_input: string; normalized_json: string; cbor_hex: string;
  digest_hex: string; multihash: string; signature_input_hex: string;
}
interface InvalidVector { id: string; encoding: string; input: string; error: string }
interface DifferentialVector { algorithm: string; count: number; domain: string; digest_accumulator_hex: string }
interface Manifest {
  schema_version: number; profile: string; valid_count: number; invalid_count: number;
  valid: ValidVector[]; invalid: InvalidVector[]; differential: DifferentialVector;
}

function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function differentialRecord(index: number): Map<string, CanonicalNode> {
  const entries: Array<[string, CanonicalNode]> = [
    ["active", index % 2 === 0], ["index", BigInt(index)], ["label", `record-${index % 997}`],
    ["values", [BigInt(index % 17), BigInt(-(index % 19) - 1)]],
  ];
  return new Map(entries);
}

function verify(path: string): [number, number] {
  const manifest = JSON.parse(readFileSync(path, "utf8")) as Manifest;
  check(manifest.schema_version === 1 && manifest.profile === "cigar-canonical-v1", "invalid manifest profile");
  check(manifest.valid_count === manifest.valid.length && manifest.invalid_count === manifest.invalid.length && manifest.valid.length >= 200, "invalid manifest counts");
  for (const vector of manifest.valid) {
    const value = parseStrictJson(vector.json_input);
    if (vector.normalization === "nfc:/human_text") {
      if (!(value instanceof Map) || typeof value.get("human_text") !== "string") throw new Error(`${vector.id}: invalid NFC target`);
      value.set("human_text", (value.get("human_text") as string).normalize("NFC"));
    } else if (vector.normalization !== "none") {
      throw new Error(`${vector.id}: unknown normalization profile`);
    }
    const cbor = deterministicCbor(value);
    const expectedDigest = digest(vector.domain, cbor);
    check(normalizedJson(value) === vector.normalized_json, `${vector.id}: normalized JSON mismatch`);
    check(Buffer.from(cbor).toString("hex") === vector.cbor_hex, `${vector.id}: CBOR mismatch`);
    strictCbor(cbor);
    check(expectedDigest.toString("hex") === vector.digest_hex && `1220${expectedDigest.toString("hex")}` === vector.multihash, `${vector.id}: digest mismatch`);
    check(Buffer.concat([Buffer.from("CIGAR-SIGNATURE\0v1\0"), cbor]).toString("hex") === vector.signature_input_hex, `${vector.id}: signature input mismatch`);
  }
  for (const vector of manifest.invalid) {
    let actual: string | undefined;
    try {
      if (vector.encoding === "json") parseStrictJson(vector.input);
      else if (vector.encoding === "cbor_hex") strictCbor(Buffer.from(vector.input, "hex"));
      else if (vector.encoding === "semantic") throw new CanonicalFailure("invalid_argument");
      else if (vector.encoding === "signature_hex" && Buffer.from(vector.input, "hex").length !== 64) throw new CanonicalFailure("invalid_argument");
    } catch (error) {
      if (error instanceof CanonicalFailure) actual = error.code;
      else throw error;
    }
    check(actual === vector.error, `${vector.id}: expected ${vector.error}, found ${actual ?? "accepted"}`);
  }
  const differential = manifest.differential;
  check(differential.algorithm === "cigar-differential-record-v1" && differential.count >= 100_000, "invalid differential metadata");
  const accumulator = createHash("sha256");
  for (let index = 0; index < differential.count; index += 1) accumulator.update(digest(differential.domain, deterministicCbor(differentialRecord(index))));
  check(accumulator.digest("hex") === differential.digest_accumulator_hex, "100,000-record differential accumulator mismatch");
  return [manifest.valid.length + manifest.invalid.length, differential.count];
}

const path = process.argv[2] ?? "schemas/vectors/canonical-v1.json";
const [vectorCount, differentialCount] = verify(path);
console.log(`verified ${vectorCount} canonical vectors and ${differentialCount} differential records`);
