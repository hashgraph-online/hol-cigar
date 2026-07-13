package cigar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const sdkTestDigest = "12201111111111111111111111111111111111111111111111111111111111111111"

func TestSharedSemanticBundleAndDelta(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../fixtures/semantic-bundle-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bundle           json.RawMessage `json:"bundle"`
		ExpectedBundleID string          `json:"expected_bundle_id"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	id, err := VerifyBundleJSON(fixture.Bundle)
	if err != nil || id != fixture.ExpectedBundleID {
		t.Fatalf("shared bundle differs: id=%s err=%v", id, err)
	}
	var target map[string]any
	if err := json.Unmarshal(fixture.Bundle, &target); err != nil {
		t.Fatal(err)
	}
	target["contract_digest"] = "1220" + string(bytes.Repeat([]byte{'3'}, 64))
	delete(target, "bundle_id")
	// Compute target identity by inserting the shared ID as a temporary well-formed field,
	// then using the same canonical envelope directly.
	target["bundle_id"] = fixture.ExpectedBundleID
	parsedTarget, err := parseStrictJSON(mustJSON(target))
	if err != nil {
		t.Fatal(err)
	}
	targetMap := parsedTarget.(map[string]any)
	semantic := make(map[string]any)
	for key, value := range targetMap {
		if key != "bundle_id" {
			semantic[key] = value
		}
	}
	encoded, _ := deterministicCBOR([]any{uint64(2), semantic})
	target["bundle_id"] = multihash("CIGAR-BUNDLE", encoded)
	targetJSON := mustJSON(target)
	if _, err := VerifyBundleJSON(targetJSON); err != nil {
		t.Fatal(err)
	}
	delta := map[string]any{
		"schema_version":    "cigar.context-delta.v1",
		"base_bundle_id":    fixture.ExpectedBundleID,
		"target_bundle_id":  target["bundle_id"],
		"added_blocks":      []any{},
		"removed_block_ids": []any{},
		"resulting_tokens":  0,
	}
	deltaJSON := mustJSON(delta)
	digest, err := DeltaDigestJSON(deltaJSON)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := ApplyContextDeltaJSON(fixture.Bundle, targetJSON, deltaJSON, digest)
	if err != nil || !bytes.Equal(applied, targetJSON) {
		t.Fatalf("delta application failed: %v", err)
	}
	applied[0] ^= 1
	if bytes.Equal(applied, targetJSON) {
		t.Fatal("delta result aliases caller bytes")
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func semanticBundleDocument(t *testing.T, blocks []any, extensions map[string]any, contractDigit byte) []byte {
	t.Helper()
	bundle := map[string]any{
		"schema_version":  "cigar.context-bundle.v1",
		"bundle_id":       sdkTestDigest,
		"contract_digest": "1220" + strings.Repeat(string(contractDigit), 64),
		"manifest_digest": "1220" + strings.Repeat("2", 64),
		"blocks":          blocks,
		"total_tokens":    uint64(len(blocks)),
		"extensions":      extensions,
	}
	parsed, err := parseStrictJSON(mustJSON(bundle))
	if err != nil {
		t.Fatal(err)
	}
	semantic := make(map[string]any)
	for key, value := range parsed.(map[string]any) {
		if key != "bundle_id" {
			semantic[key] = value
		}
	}
	encoded, err := deterministicCBOR([]any{uint64(2), semantic})
	if err != nil {
		t.Fatal(err)
	}
	bundle["bundle_id"] = multihash("CIGAR-BUNDLE", encoded)
	return mustJSON(bundle)
}

func semanticBlock(representation string, receipt bool, digit byte) map[string]any {
	block := map[string]any{
		"block_id":       "1220" + strings.Repeat(string(digit), 64),
		"lane":           "evidence",
		"representation": representation,
		"content_digest": "1220" + strings.Repeat("c", 64),
		"token_count":    uint64(1),
		"provenance":     []any{"1220" + strings.Repeat("e", 64)},
	}
	if receipt {
		block["transform_receipt"] = "1220" + strings.Repeat("f", 64)
	}
	return block
}

func TestTransformReceiptMatchesRepresentationAcrossBundleAndDeltaBoundaries(t *testing.T) {
	for _, test := range []struct {
		name           string
		representation string
		receipt        bool
		valid          bool
	}{
		{name: "exact without receipt", representation: "exact", valid: true},
		{name: "redacted without receipt", representation: "redacted", valid: true},
		{name: "extracted with receipt", representation: "extracted", receipt: true, valid: true},
		{name: "summarized with receipt", representation: "summarized", receipt: true, valid: true},
		{name: "exact with spurious receipt", representation: "exact", receipt: true},
		{name: "redacted with spurious receipt", representation: "redacted", receipt: true},
		{name: "extracted without receipt", representation: "extracted"},
		{name: "summarized without receipt", representation: "summarized"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := semanticBundleDocument(t, []any{semanticBlock(test.representation, test.receipt, 'a')}, map[string]any{}, '1')
			_, verifyErr := VerifyBundleJSON(document)
			_, identityErr := BundleIDJSON(document)
			delta := map[string]any{
				"schema_version":    "cigar.context-delta.v1",
				"base_bundle_id":    sdkTestDigest,
				"target_bundle_id":  "1220" + strings.Repeat("2", 64),
				"added_blocks":      []any{semanticBlock(test.representation, test.receipt, 'a')},
				"removed_block_ids": []any{},
				"resulting_tokens":  uint64(1),
			}
			if test.valid {
				if verifyErr != nil || identityErr != nil {
					t.Fatalf("legitimate receipt form failed: verify=%v identity=%v", verifyErr, identityErr)
				}
				if _, err := DeltaDigestJSON(mustJSON(delta)); err != nil {
					t.Fatalf("legitimate receipt form failed delta validation: %v", err)
				}
				return
			}
			if verifyErr == nil || identityErr == nil {
				t.Fatalf("representation/receipt mismatch passed: verify=%v identity=%v", verifyErr, identityErr)
			}

			if _, err := DeltaDigestJSON(mustJSON(delta)); err == nil {
				t.Fatal("delta digest accepted a representation/receipt mismatch")
			}
			base := semanticBundleDocument(t, []any{}, map[string]any{}, '1')
			target := semanticBundleDocument(t, []any{}, map[string]any{}, '3')
			if _, err := ApplyContextDeltaJSON(base, target, mustJSON(delta), sdkTestDigest); err == nil {
				t.Fatal("delta application accepted a representation/receipt mismatch")
			}
		})
	}
}

func TestBundleExtensionsEnforceCanonicalProtocolBounds(t *testing.T) {
	valid := map[string]any{
		"vendor.example/value": map[string]any{
			"type": "object",
			"value": map[string]any{
				"array": map[string]any{
					"type": "array",
					"value": []any{
						map[string]any{"type": "boolean", "value": true},
						map[string]any{"type": "integer", "value": int64(-7)},
						map[string]any{"type": "text", "value": "text"},
						map[string]any{"type": "bytes", "value": base64.RawURLEncoding.EncodeToString([]byte{0, 1, 2})},
					},
				},
			},
		},
	}
	if _, err := VerifyBundleJSON(semanticBundleDocument(t, []any{}, valid, '1')); err != nil {
		t.Fatalf("valid optional canonical extension failed: %v", err)
	}

	tooManyEntries := make(map[string]any)
	for index := 0; index < 65; index++ {
		tooManyEntries[fmt.Sprintf("vendor/%02d", index)] = map[string]any{"type": "boolean", "value": true}
	}
	tooManyItems := make([]any, 257)
	for index := range tooManyItems {
		tooManyItems[index] = map[string]any{"type": "boolean", "value": true}
	}
	tooManyObjectItems := make(map[string]any)
	for index := 0; index < 257; index++ {
		tooManyObjectItems[fmt.Sprintf("item-%03d", index)] = map[string]any{"type": "boolean", "value": true}
	}
	deep := any(map[string]any{"type": "boolean", "value": true})
	for range 16 {
		deep = map[string]any{"type": "array", "value": []any{deep}}
	}
	invalid := []struct {
		name       string
		extensions map[string]any
	}{
		{name: "entry count", extensions: tooManyEntries},
		{name: "key grammar", extensions: map[string]any{"Uppercase": map[string]any{"type": "boolean", "value": true}}},
		{name: "key byte length", extensions: map[string]any{"v" + strings.Repeat("a", 128): map[string]any{"type": "boolean", "value": true}}},
		{name: "unknown mandatory", extensions: map[string]any{"required/vendor-feature": map[string]any{"type": "boolean", "value": true}}},
		{name: "unknown tag", extensions: map[string]any{"vendor/value": map[string]any{"type": "float", "value": 1}}},
		{name: "tag extra field", extensions: map[string]any{"vendor/value": map[string]any{"type": "boolean", "value": true, "extra": false}}},
		{name: "integer above i64", extensions: map[string]any{"vendor/value": map[string]any{"type": "integer", "value": uint64(1) << 63}}},
		{name: "text byte length", extensions: map[string]any{"vendor/value": map[string]any{"type": "text", "value": strings.Repeat("x", 65_537)}}},
		{name: "byte length", extensions: map[string]any{"vendor/value": map[string]any{"type": "bytes", "value": base64.RawURLEncoding.EncodeToString(make([]byte, 65_537))}}},
		{name: "padded bytes", extensions: map[string]any{"vendor/value": map[string]any{"type": "bytes", "value": "AA=="}}},
		{name: "non-zero base64 trailing bits", extensions: map[string]any{"vendor/value": map[string]any{"type": "bytes", "value": "AB"}}},
		{name: "collection items", extensions: map[string]any{"vendor/value": map[string]any{"type": "array", "value": tooManyItems}}},
		{name: "object items", extensions: map[string]any{"vendor/value": map[string]any{"type": "object", "value": tooManyObjectItems}}},
		{name: "nesting depth", extensions: map[string]any{"vendor/value": deep}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			document := semanticBundleDocument(t, []any{}, test.extensions, '1')
			if _, err := VerifyBundleJSON(document); err == nil {
				t.Fatal("invalid extension passed bundle verification")
			}
			if _, err := BundleIDJSON(document); err == nil {
				t.Fatal("invalid extension passed bundle identity boundary")
			}
		})
	}

	maximumEntries := make(map[string]any)
	for index := 0; index < 63; index++ {
		maximumEntries[fmt.Sprintf("vendor/%02d", index)] = map[string]any{"type": "boolean", "value": true}
	}
	maximumArray := make([]any, 256)
	maximumObject := make(map[string]any)
	for index := range maximumArray {
		item := map[string]any{"type": "boolean", "value": true}
		maximumArray[index] = item
		maximumObject[fmt.Sprintf("item-%03d", index)] = item
	}
	maximumDepth := any(map[string]any{"type": "boolean", "value": true})
	for range 14 {
		maximumDepth = map[string]any{"type": "array", "value": []any{maximumDepth}}
	}
	maximumEntries["v"+strings.Repeat("a", 127)] = map[string]any{
		"type": "object",
		"value": map[string]any{
			"integer": map[string]any{"type": "integer", "value": maximumExtensionInteger},
			"text":    map[string]any{"type": "text", "value": strings.Repeat("x", maximumExtensionValueBytes)},
			"bytes":   map[string]any{"type": "bytes", "value": base64.RawURLEncoding.EncodeToString(make([]byte, maximumExtensionValueBytes))},
			"array":   map[string]any{"type": "array", "value": maximumArray},
			"object":  map[string]any{"type": "object", "value": maximumObject},
			"depth":   maximumDepth,
		},
	}
	if _, err := VerifyBundleJSON(semanticBundleDocument(t, []any{}, maximumEntries, '1')); err != nil {
		t.Fatalf("exact extension maxima failed: %v", err)
	}
}

func TestRequestAndResponseCopies(t *testing.T) {
	payload := []byte{1, 2, 3}
	request, err := NewRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 9
	if request.PayloadCBOR()[0] != 1 {
		t.Fatal("request retained caller slice")
	}
	copyOfPayload := request.PayloadCBOR()
	copyOfPayload[0] = 8
	if request.PayloadCBOR()[0] != 1 {
		t.Fatal("request exposed mutable payload")
	}
}
