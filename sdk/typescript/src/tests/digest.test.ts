import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  ContextBundle as GeneratedContextBundle,
  ContextDeltaResponse,
  ValidationError,
  applyContextDelta,
  bundleId,
  deltaDigest,
  deterministicCbor,
  verifyBundle,
  type SemanticBundleBlock,
  type SemanticContextBundle,
  type SemanticContextDelta,
} from "../index.js";

const digest = (character: string): string => `1220${character.repeat(64)}`;
const block = (character: string, tokens: number): SemanticBundleBlock => ({
  block_id: digest(character),
  lane: "evidence",
  representation: "exact",
  content_digest: digest(character === "a" ? "c" : "d"),
  token_count: tokens,
  provenance: [digest(character === "a" ? "e" : "f")],
});

function makeBundle(blocks: readonly SemanticBundleBlock[]): SemanticContextBundle {
  const candidate: SemanticContextBundle = {
    schema_version: "cigar.context-bundle.v1",
    bundle_id: digest("0"),
    contract_digest: digest("1"),
    manifest_digest: digest("2"),
    blocks,
    total_tokens: blocks.reduce((total, item) => total + item.token_count, 0),
    extensions: {},
  };
  return { ...candidate, bundle_id: bundleId(candidate) };
}

function uncheckedBundleId(bundle: Omit<SemanticContextBundle, "bundle_id">): string {
  const canonicalBlocks = bundle.blocks.map((item) => ({
    block_id: item.block_id,
    lane: item.lane,
    representation: item.representation,
    content_digest: item.content_digest,
    token_count: item.token_count,
    provenance: item.provenance,
    ...(item.transform_receipt === undefined ? {} : { transform_receipt: item.transform_receipt }),
  }));
  const encoded = deterministicCbor([2, {
    schema_version: bundle.schema_version,
    contract_digest: bundle.contract_digest,
    manifest_digest: bundle.manifest_digest,
    blocks: canonicalBlocks,
    total_tokens: bundle.total_tokens,
    extensions: bundle.extensions as Record<string, never>,
  }] as never);
  return `1220${createHash("sha256")
    .update("CIGAR-BUNDLE")
    .update(Uint8Array.of(0))
    .update("v1")
    .update(Uint8Array.of(0))
    .update(encoded)
    .digest("hex")}`;
}

function makeUncheckedBundle(blocks: readonly SemanticBundleBlock[]): SemanticContextBundle {
  const semantic = {
    schema_version: "cigar.context-bundle.v1" as const,
    contract_digest: digest("1"),
    manifest_digest: digest("2"),
    blocks,
    total_tokens: blocks.reduce((total, item) => total + item.token_count, 0),
    extensions: {},
  };
  return { ...semantic, bundle_id: uncheckedBundleId(semantic) };
}

test("bundle identity and sealed delta are verified locally", () => {
  const base = makeBundle([block("a", 2)]);
  const target = makeBundle([block("b", 3)]);
  verifyBundle(base);
  verifyBundle(target);
  const delta: SemanticContextDelta = {
    schema_version: "cigar.context-delta.v1",
    base_bundle_id: base.bundle_id,
    target_bundle_id: target.bundle_id,
    added_blocks: target.blocks,
    removed_block_ids: [base.blocks[0]?.block_id ?? ""],
    resulting_tokens: target.total_tokens,
  };
  const applied = applyContextDelta(base, target, delta, deltaDigest(delta));
  assert.deepEqual(applied, target);
  assert.notEqual(applied, target);
  assert.throws(() => applyContextDelta(base, target, delta, digest("f")), ValidationError);
});

test("tampered bundle identity fails closed", () => {
  const valid = makeBundle([block("a", 2)]);
  assert.throws(() => verifyBundle({ ...valid, total_tokens: 3 }), ValidationError);
});

test("transform receipts exactly match representations at every TypeScript boundary", () => {
  const forms = [
    { representation: "exact", receipt: false, valid: true },
    { representation: "redacted", receipt: false, valid: true },
    { representation: "extracted", receipt: true, valid: true },
    { representation: "summarized", receipt: true, valid: true },
    { representation: "exact", receipt: true, valid: false },
    { representation: "redacted", receipt: true, valid: false },
    { representation: "extracted", receipt: false, valid: false },
    { representation: "summarized", receipt: false, valid: false },
  ] as const;
  for (const [index, form] of forms.entries()) {
    const candidate = {
      ...block(index % 2 === 0 ? "a" : "b", 1),
      representation: form.representation,
      ...(form.receipt ? { transform_receipt: digest("f") } : {}),
    } as unknown as SemanticBundleBlock;
    const bundle = makeUncheckedBundle([candidate]);
    const generated = bundle as unknown as Parameters<typeof GeneratedContextBundle.create>[0];
    const delta: SemanticContextDelta = {
      schema_version: "cigar.context-delta.v1",
      base_bundle_id: digest("8"),
      target_bundle_id: digest("9"),
      added_blocks: [candidate],
      removed_block_ids: [],
      resulting_tokens: 1,
    };
    const generatedDelta = {
      delta: delta as unknown as Record<string, never>,
      delta_digest: digest("d"),
    } as unknown as Parameters<typeof ContextDeltaResponse.create>[0];

    if (form.valid) {
      assert.doesNotThrow(() => verifyBundle(bundle));
      assert.doesNotThrow(() => bundleId(bundle));
      assert.doesNotThrow(() => deltaDigest(delta));
      assert.doesNotThrow(() => GeneratedContextBundle.create(generated));
      assert.doesNotThrow(() => ContextDeltaResponse.create(generatedDelta));
      continue;
    }

    assert.throws(() => verifyBundle(bundle), ValidationError);
    assert.throws(() => bundleId(bundle), ValidationError);
    assert.throws(() => deltaDigest(delta), ValidationError);
    const base = makeBundle([]);
    const target = makeBundle([block("b", 1)]);
    const boundDelta = { ...delta, base_bundle_id: base.bundle_id, target_bundle_id: target.bundle_id };
    assert.throws(() => applyContextDelta(base, target, boundDelta, digest("d")), ValidationError);
    assert.throws(() => GeneratedContextBundle.create(generated), ValidationError);
    assert.throws(() => ContextDeltaResponse.create(generatedDelta), ValidationError);
  }
});
