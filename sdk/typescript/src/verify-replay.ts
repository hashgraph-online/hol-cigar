/** Independently verifies the bounded CIGAR replay reproduction vector. */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const MAX_FIXTURE_BYTES = 1_048_576;
const MAX_RETAINED_BYTES = 1_048_576;
const MAX_ENCODED_RETAINED_BYTES = 1_398_104;
const MAX_ARTIFACTS = 64;
const MAX_OBSERVATIONS = 1_024;
const MAX_JSON_DEPTH = 64;
const DEPENDENCY_ORDER = [
  "source",
  "blob",
  "policy",
  "index",
  "manifest",
  "bundle",
  "tokenizer",
  "adapter",
  "consumer",
  "tool_schema",
  "environment",
] as const;

type JsonObject = Record<string, unknown>;
type RetainedArtifact = {
  kind: string;
  bytesBase64url: string;
  digestMultihash: string;
};
type ArtifactVerification = {
  verifiedBytes: Map<string, Buffer>;
  missing: string[];
};

function fail(message: string): never {
  throw new Error(`replay vector verification failed: ${message}`);
}

function strictObject(value: unknown, keys: readonly string[], context: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${context} must be an object`);
  }
  const record = value as JsonObject;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${context} has unknown or missing fields`);
  }
  return record;
}

function stringField(
  record: JsonObject,
  key: string,
  context: string,
  maximum = 256,
  allowEmpty = false,
): string {
  const value = record[key];
  if (typeof value !== "string" || (!allowEmpty && value.length === 0) || value.length > maximum) {
    fail(`${context}.${key} must be a bounded string`);
  }
  return value;
}

function booleanField(record: JsonObject, key: string, context: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") fail(`${context}.${key} must be a boolean`);
  return value;
}

function stringArray(value: unknown, context: string, maximum = 64): string[] {
  if (!Array.isArray(value) || value.length > maximum) fail(`${context} must be a bounded array`);
  return value.map((item, index) => {
    if (typeof item !== "string" || item.length === 0 || item.length > 256) {
      fail(`${context}[${index}] must be a bounded string`);
    }
    return item;
  });
}

function sameStrings(actual: readonly string[], expected: readonly string[], context: string): void {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail(`${context} differs`);
  }
}

function decodeExactBase64url(value: string, context: string, allowEmpty: boolean): Buffer {
  if (value.length === 0) {
    if (allowEmpty) return Buffer.alloc(0);
    fail(`${context} must not be empty`);
  }
  if (value.length > MAX_ENCODED_RETAINED_BYTES || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail(`${context} is not bounded unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length > MAX_RETAINED_BYTES || decoded.toString("base64url") !== value) {
    fail(`${context} is non-canonical or exceeds its bound`);
  }
  return decoded;
}

function multihash(bytes: Uint8Array): string {
  return `1220${createHash("sha256").update(bytes).digest("hex")}`;
}

function observationMultihash(observations: readonly Buffer[]): string {
  const hash = createHash("sha256");
  for (const observation of observations) {
    if (observation.length > 0xffff_ffff) fail("recorded observation exceeds u32 framing");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(observation.length);
    hash.update(length);
    hash.update(observation);
  }
  return `1220${hash.digest("hex")}`;
}

function verifyDigest(value: string, context: string): void {
  if (!/^1220[0-9a-f]{64}$/u.test(value)) fail(`${context} is not a lowercase SHA-256 multihash`);
}

function parseArtifacts(required: readonly string[], value: unknown): RetainedArtifact[] {
  if (!Array.isArray(value) || value.length > MAX_ARTIFACTS) {
    fail("retained artifact table must be a bounded array");
  }
  const seen = new Set<string>();
  return value.map((raw, index) => {
    const entry = strictObject(
      raw,
      ["kind", "bytes_base64url", "digest_multihash"],
      `retained artifact ${index}`,
    );
    const kind = stringField(entry, "kind", `retained artifact ${index}`);
    if (!required.includes(kind) || seen.has(kind)) fail("retained artifact kind is unknown or duplicated");
    seen.add(kind);
    const bytesBase64url = stringField(
      entry,
      "bytes_base64url",
      `retained artifact ${index}`,
      MAX_ENCODED_RETAINED_BYTES,
    );
    const digestMultihash = stringField(entry, "digest_multihash", `retained artifact ${index}`, 68);
    verifyDigest(digestMultihash, `retained artifact ${index} digest`);
    return { kind, bytesBase64url, digestMultihash };
  });
}

function verifyArtifacts(required: readonly string[], artifacts: readonly RetainedArtifact[]): ArtifactVerification {
  const verifiedBytes = new Map<string, Buffer>();
  for (const artifact of artifacts) {
    const bytes = decodeExactBase64url(artifact.bytesBase64url, `${artifact.kind} artifact`, false);
    if (multihash(bytes) === artifact.digestMultihash) verifiedBytes.set(artifact.kind, bytes);
  }
  return {
    verifiedBytes,
    missing: required.filter((kind) => !verifiedBytes.has(kind)),
  };
}

function rejectDuplicateJsonKeys(source: string): void {
  let offset = 0;

  function whitespace(): void {
    while (offset < source.length && /[\u0009\u000a\u000d\u0020]/u.test(source[offset] ?? "")) offset += 1;
  }

  function parseString(): string {
    if (source[offset] !== '"') fail("invalid JSON string");
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        const decoded = JSON.parse(source.slice(start, offset)) as unknown;
        if (typeof decoded !== "string") fail("invalid JSON string");
        return decoded;
      }
      if (character === "\\") {
        offset += 1;
        const escape = source[offset];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(source.slice(offset + 1, offset + 5))) fail("invalid JSON escape");
          offset += 5;
          continue;
        }
        if (escape === undefined || !'"\\/bfnrt'.includes(escape)) fail("invalid JSON escape");
        offset += 1;
        continue;
      }
      if (character === undefined || character.charCodeAt(0) < 0x20) fail("invalid JSON string character");
      offset += 1;
    }
    fail("unterminated JSON string");
  }

  function parseValue(depth: number): void {
    if (depth > MAX_JSON_DEPTH) fail("JSON nesting exceeds its bound");
    whitespace();
    const character = source[offset];
    if (character === "{") {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (source[offset] === "}") {
        offset += 1;
        return;
      }
      while (true) {
        whitespace();
        const key = parseString();
        if (keys.has(key)) fail("duplicate JSON object key");
        keys.add(key);
        whitespace();
        if (source[offset] !== ":") fail("JSON object key lacks a value");
        offset += 1;
        parseValue(depth + 1);
        whitespace();
        if (source[offset] === "}") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") fail("invalid JSON object separator");
        offset += 1;
      }
    }
    if (character === "[") {
      offset += 1;
      whitespace();
      if (source[offset] === "]") {
        offset += 1;
        return;
      }
      while (true) {
        parseValue(depth + 1);
        whitespace();
        if (source[offset] === "]") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") fail("invalid JSON array separator");
        offset += 1;
      }
    }
    if (character === '"') {
      parseString();
      return;
    }
    for (const literal of ["true", "false", "null"] as const) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(offset));
    if (number === null) fail("invalid JSON value");
    offset += number[0].length;
  }

  parseValue(0);
  whitespace();
  if (offset !== source.length) fail("fixture contains trailing JSON");
}

function main(): void {
  const path = process.argv[2] ?? "schemas/vectors/replay-v1.json";
  const source = readFileSync(path);
  if (source.length === 0 || source.length > MAX_FIXTURE_BYTES) fail("fixture size is invalid");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    fail("fixture is not valid UTF-8");
  }
  rejectDuplicateJsonKeys(text);
  const root = strictObject(JSON.parse(text) as unknown, [
    "schema_version",
    "digest_algorithm",
    "observation_framing",
    "retained",
    "required_dependencies",
    "retained_artifacts",
    "missing_artifact_probe",
    "tampered_artifact_probe",
    "empty_recorded_response_probe",
    "expected",
  ], "fixture");
  if (stringField(root, "schema_version", "fixture") !== "cigar.replay-vector.v1"
    || stringField(root, "digest_algorithm", "fixture") !== "sha256-multihash-raw-v1"
    || stringField(root, "observation_framing", "fixture") !== "u32be-length-prefixed-v1") {
    fail("fixture declares an unsupported profile");
  }

  const retained = strictObject(root.retained, [
    "bundle_bytes_base64url",
    "invocation_bytes_base64url",
    "recorded_observation_bytes_base64url",
  ], "retained");
  const bundle = decodeExactBase64url(
    stringField(retained, "bundle_bytes_base64url", "retained", MAX_ENCODED_RETAINED_BYTES),
    "bundle",
    false,
  );
  const invocation = decodeExactBase64url(
    stringField(retained, "invocation_bytes_base64url", "retained", MAX_ENCODED_RETAINED_BYTES),
    "invocation",
    false,
  );
  const encodedObservations = stringArray(
    retained.recorded_observation_bytes_base64url,
    "recorded observations",
    MAX_OBSERVATIONS,
  );
  if (encodedObservations.length === 0) fail("recorded observations must not be empty");
  const observations = encodedObservations.map((value, index) =>
    decodeExactBase64url(value, `recorded observation ${index}`, true));

  const required = stringArray(root.required_dependencies, "required dependencies");
  sameStrings(required, DEPENDENCY_ORDER, "required dependency order");
  const artifacts = parseArtifacts(required, root.retained_artifacts);

  const expected = strictObject(root.expected, [
    "bundle_digest_multihash",
    "invocation_digest_multihash",
    "observation_digest_multihash",
    "complete",
    "missing_dependencies",
  ], "expected");
  const expectedBundle = stringField(expected, "bundle_digest_multihash", "expected", 68);
  const expectedInvocation = stringField(expected, "invocation_digest_multihash", "expected", 68);
  const expectedObservations = stringField(expected, "observation_digest_multihash", "expected", 68);
  for (const [context, value] of [
    ["bundle digest", expectedBundle],
    ["invocation digest", expectedInvocation],
    ["observation digest", expectedObservations],
  ] as const) verifyDigest(value, context);
  const bundleDigest = multihash(bundle);
  const invocationDigest = multihash(invocation);
  const observationDigest = observationMultihash(observations);
  if (bundleDigest !== expectedBundle || invocationDigest !== expectedInvocation
    || observationDigest !== expectedObservations) fail("retained replay digest mismatch");

  const verification = verifyArtifacts(required, artifacts);
  const complete = verification.missing.length === 0;
  if (complete !== booleanField(expected, "complete", "expected")) fail("completeness mismatch");
  sameStrings(
    verification.missing,
    stringArray(expected.missing_dependencies, "expected missing dependencies"),
    "missing dependencies",
  );
  const artifactBundle = verification.verifiedBytes.get("bundle");
  if (artifactBundle === undefined || !artifactBundle.equals(bundle)) {
    fail("retained bundle and bundle dependency artifact differ");
  }

  const missingProbe = strictObject(root.missing_artifact_probe, [
    "kind",
    "expected_complete",
    "expected_missing_dependencies",
  ], "missing artifact probe");
  const missingKind = stringField(missingProbe, "kind", "missing artifact probe");
  if (!required.includes(missingKind)) fail("missing artifact probe names an unknown dependency");
  const missingVerification = verifyArtifacts(
    required,
    artifacts.filter((artifact) => artifact.kind !== missingKind),
  );
  const missingComplete = missingVerification.missing.length === 0;
  if (missingComplete !== booleanField(missingProbe, "expected_complete", "missing artifact probe")) {
    fail("missing artifact probe completeness differs");
  }
  sameStrings(
    missingVerification.missing,
    stringArray(missingProbe.expected_missing_dependencies, "missing artifact probe dependencies"),
    "missing artifact probe dependencies",
  );

  const tamperProbe = strictObject(root.tampered_artifact_probe, [
    "kind",
    "replacement_bytes_base64url",
    "expected_accepted",
    "expected_missing_dependencies",
  ], "tampered artifact probe");
  const tamperKind = stringField(tamperProbe, "kind", "tampered artifact probe");
  if (!required.includes(tamperKind)) fail("tampered artifact probe names an unknown dependency");
  const replacement = stringField(
    tamperProbe,
    "replacement_bytes_base64url",
    "tampered artifact probe",
    MAX_ENCODED_RETAINED_BYTES,
  );
  let replacements = 0;
  const tampered = artifacts.map((artifact) => {
    if (artifact.kind !== tamperKind) return artifact;
    replacements += 1;
    return { ...artifact, bytesBase64url: replacement };
  });
  if (replacements !== 1) fail("tampered artifact probe must identify exactly one artifact");
  const tamperedVerification = verifyArtifacts(required, tampered);
  const tamperAccepted = tamperedVerification.missing.length === 0;
  if (tamperAccepted !== booleanField(tamperProbe, "expected_accepted", "tampered artifact probe")) {
    fail("tampered artifact probe acceptance differs");
  }
  sameStrings(
    tamperedVerification.missing,
    stringArray(tamperProbe.expected_missing_dependencies, "tampered artifact probe dependencies"),
    "tampered artifact probe dependencies",
  );

  const emptyProbe = strictObject(root.empty_recorded_response_probe, [
    "bytes_base64url",
    "digest_multihash",
    "expected_accepted",
  ], "empty recorded response probe");
  const emptyResponse = decodeExactBase64url(
    stringField(
      emptyProbe,
      "bytes_base64url",
      "empty recorded response probe",
      MAX_ENCODED_RETAINED_BYTES,
      true,
    ),
    "empty recorded response",
    true,
  );
  const expectedEmptyDigest = stringField(emptyProbe, "digest_multihash", "empty recorded response probe", 68);
  verifyDigest(expectedEmptyDigest, "empty recorded response digest");
  const emptyDigest = multihash(emptyResponse);
  const emptyAccepted = emptyResponse.length === 0 && emptyDigest === expectedEmptyDigest;
  if (emptyAccepted !== booleanField(emptyProbe, "expected_accepted", "empty recorded response probe")) {
    fail("empty recorded response probe acceptance differs");
  }

  process.stdout.write(`${JSON.stringify({
    schema_version: "cigar.replay-reproduction-result.v1",
    bundle_digest_multihash: bundleDigest,
    invocation_digest_multihash: invocationDigest,
    observation_digest_multihash: observationDigest,
    complete,
    missing_dependencies: verification.missing,
    missing_artifact_probe: {
      complete: missingComplete,
      missing_dependencies: missingVerification.missing,
    },
    tampered_artifact_probe: {
      accepted: tamperAccepted,
      missing_dependencies: tamperedVerification.missing,
    },
    empty_recorded_response_probe: {
      accepted: emptyAccepted,
      digest_multihash: emptyDigest,
    },
  })}\n`);
}

main();
