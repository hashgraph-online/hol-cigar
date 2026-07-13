package cigar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var laneOrder = map[string]int{"rules": 0, "task": 1, "evidence": 2, "history": 3, "tools": 4}

const (
	maximumExtensionEntries         = 64
	maximumExtensionKeyBytes        = 128
	maximumExtensionDepth           = 16
	maximumExtensionCollectionItems = 256
	maximumExtensionValueBytes      = 65_536
	maximumExtensionEncodedBytes    = 87_382
	maximumExtensionInteger         = uint64(1<<63 - 1)
)

func parseStrictJSON(source []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	nodes := 0
	value, err := parseJSONValue(decoder, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, &ValidationError{Message: "JSON contains trailing data"}
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes = *nodes + 1
	if depth > 64 || *nodes > 100_000 {
		return nil, &ValidationError{Message: "JSON exceeds nesting or node bounds"}
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, &ValidationError{Message: "JSON is invalid"}
	}
	switch value := token.(type) {
	case nil:
		return nil, &ValidationError{Message: "null is not canonical"}
	case bool:
		return value, nil
	case string:
		return norm.NFC.String(value), nil
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, &ValidationError{Message: "floating point is not canonical"}
		}
		if strings.HasPrefix(text, "-") {
			parsed, parseErr := strconv.ParseInt(text, 10, 64)
			if parseErr != nil {
				return nil, &ValidationError{Message: "integer exceeds i64"}
			}
			return parsed, nil
		}
		parsed, parseErr := strconv.ParseUint(text, 10, 64)
		if parseErr != nil {
			return nil, &ValidationError{Message: "integer exceeds u64"}
		}
		return parsed, nil
	case json.Delim:
		switch value {
		case '[':
			items := make([]any, 0)
			for decoder.More() {
				child, childErr := parseJSONValue(decoder, depth+1, nodes)
				if childErr != nil {
					return nil, childErr
				}
				items = append(items, child)
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
				return nil, &ValidationError{Message: "JSON array is invalid"}
			}
			return items, nil
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return nil, &ValidationError{Message: "JSON object key is invalid"}
				}
				key = norm.NFC.String(key)
				if _, duplicate := object[key]; duplicate {
					return nil, &ValidationError{Message: "JSON object contains a duplicate key"}
				}
				child, childErr := parseJSONValue(decoder, depth+1, nodes)
				if childErr != nil {
					return nil, childErr
				}
				object[key] = child
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
				return nil, &ValidationError{Message: "JSON object is invalid"}
			}
			return object, nil
		}
	}
	return nil, &ValidationError{Message: "JSON value is not canonical"}
}

func cborHead(major byte, argument uint64) []byte {
	prefix := major << 5
	switch {
	case argument < 24:
		return []byte{prefix | byte(argument)}
	case argument <= 0xff:
		return []byte{prefix | 24, byte(argument)}
	case argument <= 0xffff:
		return []byte{prefix | 25, byte(argument >> 8), byte(argument)}
	case argument <= 0xffff_ffff:
		return []byte{prefix | 26, byte(argument >> 24), byte(argument >> 16), byte(argument >> 8), byte(argument)}
	default:
		result := make([]byte, 9)
		result[0] = prefix | 27
		binary.BigEndian.PutUint64(result[1:], argument)
		return result
	}
}

func deterministicCBOR(value any) ([]byte, error) {
	nodes := 0
	return deterministicCBORAt(value, 0, &nodes)
}

func deterministicCBORAt(value any, depth int, nodes *int) ([]byte, error) {
	*nodes = *nodes + 1
	if depth > 64 || *nodes > 100_000 {
		return nil, &ValidationError{Message: "canonical value exceeds nesting or node bounds"}
	}
	switch current := value.(type) {
	case bool:
		if current {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case uint64:
		return cborHead(0, current), nil
	case int64:
		if current >= 0 {
			return cborHead(0, uint64(current)), nil
		}
		return cborHead(1, uint64(-1-current)), nil
	case string:
		encoded := []byte(norm.NFC.String(current))
		return append(cborHead(3, uint64(len(encoded))), encoded...), nil
	case []byte:
		return append(cborHead(2, uint64(len(current))), current...), nil
	case []any:
		result := cborHead(4, uint64(len(current)))
		for _, child := range current {
			encoded, err := deterministicCBORAt(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, encoded...)
		}
		return result, nil
	case map[string]any:
		type entry struct {
			key   []byte
			value any
		}
		entries := make([]entry, 0, len(current))
		for key, child := range current {
			encoded, err := deterministicCBORAt(norm.NFC.String(key), depth+1, nodes)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{key: encoded, value: child})
		}
		sort.Slice(entries, func(left, right int) bool { return bytes.Compare(entries[left].key, entries[right].key) < 0 })
		result := cborHead(5, uint64(len(entries)))
		for _, item := range entries {
			encoded, err := deterministicCBORAt(item.value, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, item.key...)
			result = append(result, encoded...)
		}
		return result, nil
	default:
		return nil, &ValidationError{Message: "value is outside the canonical CBOR subset"}
	}
}

func multihash(domain string, canonical []byte) string {
	hasher := sha256.New()
	hasher.Write([]byte(domain))
	hasher.Write([]byte{0})
	hasher.Write([]byte("v1"))
	hasher.Write([]byte{0})
	hasher.Write(canonical)
	return "1220" + hex.EncodeToString(hasher.Sum(nil))
}

func rawMultihash(value []byte) string {
	digest := sha256.Sum256(value)
	return "1220" + hex.EncodeToString(digest[:])
}

func exactMap(value any, fields []string, context string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(fields) {
		return nil, &ValidationError{Message: context + " has unknown or missing fields"}
	}
	for _, field := range fields {
		if _, present := object[field]; !present {
			return nil, &ValidationError{Message: context + " has unknown or missing fields"}
		}
	}
	return object, nil
}

func digestString(value any, context string) (string, error) {
	text, ok := value.(string)
	if !ok || len(text) != 68 || !strings.HasPrefix(text, "1220") {
		return "", &ValidationError{Message: context + " must be a lowercase SHA-256 multihash"}
	}
	if _, err := hex.DecodeString(text); err != nil || strings.ToLower(text) != text {
		return "", &ValidationError{Message: context + " must be a lowercase SHA-256 multihash"}
	}
	return text, nil
}

func validateBlock(value any, index int) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, &ValidationError{Message: fmt.Sprintf("block %d must be an object", index)}
	}
	fields := []string{"block_id", "lane", "representation", "content_digest", "token_count", "provenance"}
	if _, present := object["transform_receipt"]; present {
		fields = append(fields, "transform_receipt")
	}
	if _, err := exactMap(object, fields, fmt.Sprintf("block %d", index)); err != nil {
		return nil, err
	}
	if _, err := digestString(object["block_id"], "block id"); err != nil {
		return nil, err
	}
	if _, err := digestString(object["content_digest"], "block content digest"); err != nil {
		return nil, err
	}
	lane, laneOK := object["lane"].(string)
	representation, representationOK := object["representation"].(string)
	if _, known := laneOrder[lane]; !laneOK || !known || !representationOK ||
		(representation != "exact" && representation != "extracted" && representation != "summarized" && representation != "redacted") {
		return nil, &ValidationError{Message: "block enum is unknown"}
	}
	tokens, ok := object["token_count"].(uint64)
	if !ok || tokens == 0 || tokens > 0xffff_ffff {
		return nil, &ValidationError{Message: "block token count is invalid"}
	}
	provenance, ok := object["provenance"].([]any)
	if !ok || len(provenance) == 0 || len(provenance) > 10_000 {
		return nil, &ValidationError{Message: "block provenance is invalid"}
	}
	previous := ""
	for _, item := range provenance {
		current, err := digestString(item, "block provenance")
		if err != nil || current <= previous {
			return nil, &ValidationError{Message: "block provenance must be sorted and unique"}
		}
		previous = current
	}
	receipt, receiptPresent := object["transform_receipt"]
	receiptRequired := representation == "extracted" || representation == "summarized"
	if receiptRequired != receiptPresent {
		return nil, &ValidationError{Message: "extracted and summarized blocks require exactly one transform receipt"}
	}
	if receiptPresent {
		if _, err := digestString(receipt, "transform receipt"); err != nil {
			return nil, err
		}
	}
	return object, nil
}

func validateExtensionMap(value any) error {
	extensions, ok := value.(map[string]any)
	if !ok {
		return &ValidationError{Message: "bundle extensions must be an object"}
	}
	if len(extensions) > maximumExtensionEntries {
		return &ValidationError{Message: "extension map exceeds the configured entry maximum"}
	}
	for key, child := range extensions {
		if !validExtensionKey(key) {
			return &ValidationError{Message: "extension key does not match the stable bounded grammar"}
		}
		if strings.HasPrefix(key, "required/") {
			return &ValidationError{Message: "unknown mandatory extension is not supported"}
		}
		if err := validateCanonicalExtensionValue(child, 1); err != nil {
			return err
		}
	}
	return nil
}

func validExtensionKey(value string) bool {
	if len(value) == 0 || len(value) > maximumExtensionKeyBytes {
		return false
	}
	for index, current := range []byte(value) {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' {
			continue
		}
		if index > 0 && (current == '.' || current == '_' || current == '/' || current == '-') {
			continue
		}
		return false
	}
	return true
}

func validateCanonicalExtensionValue(value any, depth int) error {
	if depth > maximumExtensionDepth {
		return &ValidationError{Message: "extension nesting exceeds the configured maximum"}
	}
	tagged, err := exactMap(value, []string{"type", "value"}, "extension value")
	if err != nil {
		return err
	}
	tag, ok := tagged["type"].(string)
	if !ok {
		return &ValidationError{Message: "extension value type is invalid"}
	}
	child := tagged["value"]
	switch tag {
	case "boolean":
		if _, ok := child.(bool); !ok {
			return &ValidationError{Message: "extension boolean value is invalid"}
		}
	case "integer":
		switch integer := child.(type) {
		case int64:
		case uint64:
			if integer > maximumExtensionInteger {
				return &ValidationError{Message: "extension integer exceeds i64"}
			}
		default:
			return &ValidationError{Message: "extension integer value is invalid"}
		}
	case "text":
		text, ok := child.(string)
		if !ok || len(text) > maximumExtensionValueBytes {
			return &ValidationError{Message: "extension text exceeds the configured byte maximum"}
		}
	case "bytes":
		encoded, ok := child.(string)
		if !ok || len(encoded) > maximumExtensionEncodedBytes {
			return &ValidationError{Message: "extension bytes exceed the configured maximum"}
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil || len(decoded) > maximumExtensionValueBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return &ValidationError{Message: "extension bytes must use bounded canonical base64url"}
		}
	case "array":
		values, ok := child.([]any)
		if !ok || len(values) > maximumExtensionCollectionItems {
			return &ValidationError{Message: "extension array exceeds the configured item maximum"}
		}
		for _, item := range values {
			if err := validateCanonicalExtensionValue(item, depth+1); err != nil {
				return err
			}
		}
	case "object":
		values, ok := child.(map[string]any)
		if !ok || len(values) > maximumExtensionCollectionItems {
			return &ValidationError{Message: "extension object exceeds the configured item maximum"}
		}
		for _, item := range values {
			if err := validateCanonicalExtensionValue(item, depth+1); err != nil {
				return err
			}
		}
	default:
		return &ValidationError{Message: "extension value type is unknown"}
	}
	return nil
}

func validateBundle(value any) (map[string]any, string, error) {
	bundle, err := exactMap(value, []string{
		"schema_version", "bundle_id", "contract_digest", "manifest_digest", "blocks", "total_tokens", "extensions",
	}, "bundle")
	if err != nil {
		return nil, "", err
	}
	if bundle["schema_version"] != "cigar.context-bundle.v1" {
		return nil, "", &ValidationError{Message: "bundle schema is unsupported"}
	}
	id, err := digestString(bundle["bundle_id"], "bundle id")
	if err != nil {
		return nil, "", err
	}
	if _, err := digestString(bundle["contract_digest"], "contract digest"); err != nil {
		return nil, "", err
	}
	if _, err := digestString(bundle["manifest_digest"], "manifest digest"); err != nil {
		return nil, "", err
	}
	blocks, ok := bundle["blocks"].([]any)
	if !ok || len(blocks) > 10_000 {
		return nil, "", &ValidationError{Message: "bundle block count is invalid"}
	}
	var total uint64
	previousLane := -1
	previousID := ""
	for index, value := range blocks {
		block, blockErr := validateBlock(value, index)
		if blockErr != nil {
			return nil, "", blockErr
		}
		lane := laneOrder[block["lane"].(string)]
		blockID := block["block_id"].(string)
		if lane < previousLane || (lane == previousLane && blockID <= previousID) {
			return nil, "", &ValidationError{Message: "bundle blocks must be lane/id sorted and unique"}
		}
		total += block["token_count"].(uint64)
		if total > 0xffff_ffff {
			return nil, "", &ValidationError{Message: "bundle token total exceeds u32"}
		}
		previousLane, previousID = lane, blockID
	}
	declared, ok := bundle["total_tokens"].(uint64)
	if !ok || declared != total {
		return nil, "", &ValidationError{Message: "bundle token total is not exact"}
	}
	if err := validateExtensionMap(bundle["extensions"]); err != nil {
		return nil, "", err
	}
	semantic := make(map[string]any, len(bundle)-1)
	for key, child := range bundle {
		if key != "bundle_id" {
			semantic[key] = child
		}
	}
	canonical, err := deterministicCBOR([]any{uint64(2), semantic})
	if err != nil {
		return nil, "", err
	}
	computed := multihash("CIGAR-BUNDLE", canonical)
	if id != computed {
		return nil, "", &ValidationError{Message: "bundle identity verification failed"}
	}
	return bundle, computed, nil
}

// VerifyBundleJSON strict-parses and verifies one semantic context bundle.
func VerifyBundleJSON(document []byte) (string, error) {
	value, err := parseStrictJSON(document)
	if err != nil {
		return "", err
	}
	_, id, err := validateBundle(value)
	return id, err
}

// BundleIDJSON computes an identity after strict parsing; it still requires every bundle invariant.
func BundleIDJSON(document []byte) (string, error) { return VerifyBundleJSON(document) }

type deltaBlockJSON struct {
	BlockID          string   `json:"block_id"`
	Lane             string   `json:"lane"`
	Representation   string   `json:"representation"`
	ContentDigest    string   `json:"content_digest"`
	TokenCount       uint64   `json:"token_count"`
	Provenance       []string `json:"provenance"`
	TransformReceipt string   `json:"transform_receipt,omitempty"`
}

type deltaJSON struct {
	SchemaVersion   string           `json:"schema_version"`
	BaseBundleID    string           `json:"base_bundle_id"`
	TargetBundleID  string           `json:"target_bundle_id"`
	AddedBlocks     []deltaBlockJSON `json:"added_blocks"`
	RemovedBlockIDs []string         `json:"removed_block_ids"`
	ResultingTokens uint64           `json:"resulting_tokens"`
}

func validatedDelta(value any) (map[string]any, []byte, error) {
	delta, err := exactMap(value, []string{
		"schema_version", "base_bundle_id", "target_bundle_id", "added_blocks", "removed_block_ids", "resulting_tokens",
	}, "delta")
	if err != nil {
		return nil, nil, err
	}
	if delta["schema_version"] != "cigar.context-delta.v1" {
		return nil, nil, &ValidationError{Message: "delta schema is unsupported"}
	}
	baseID, err := digestString(delta["base_bundle_id"], "delta base id")
	if err != nil {
		return nil, nil, err
	}
	targetID, err := digestString(delta["target_bundle_id"], "delta target id")
	if err != nil || targetID == baseID {
		return nil, nil, &ValidationError{Message: "delta target id is invalid"}
	}
	added, ok := delta["added_blocks"].([]any)
	if !ok || len(added) > 10_000 {
		return nil, nil, &ValidationError{Message: "delta additions are invalid"}
	}
	wireAdded := make([]deltaBlockJSON, len(added))
	previous := ""
	for index, value := range added {
		block, blockErr := validateBlock(value, index)
		if blockErr != nil {
			return nil, nil, blockErr
		}
		id := block["block_id"].(string)
		if id <= previous {
			return nil, nil, &ValidationError{Message: "delta additions must be block-id sorted and unique"}
		}
		provenanceValues := block["provenance"].([]any)
		provenance := make([]string, len(provenanceValues))
		for ordinal, item := range provenanceValues {
			provenance[ordinal] = item.(string)
		}
		wireAdded[index] = deltaBlockJSON{
			BlockID:        id,
			Lane:           block["lane"].(string),
			Representation: block["representation"].(string),
			ContentDigest:  block["content_digest"].(string),
			TokenCount:     block["token_count"].(uint64),
			Provenance:     provenance,
		}
		if receipt, present := block["transform_receipt"].(string); present {
			wireAdded[index].TransformReceipt = receipt
		}
		previous = id
	}
	removed, ok := delta["removed_block_ids"].([]any)
	if !ok || len(removed) > 10_000 {
		return nil, nil, &ValidationError{Message: "delta removals are invalid"}
	}
	wireRemoved := make([]string, len(removed))
	previous = ""
	for index, value := range removed {
		id, digestErr := digestString(value, "removed block id")
		if digestErr != nil || id <= previous {
			return nil, nil, &ValidationError{Message: "delta removals must be sorted and unique"}
		}
		wireRemoved[index] = id
		previous = id
	}
	resultingTokens, ok := delta["resulting_tokens"].(uint64)
	if !ok || resultingTokens > 0xffff_ffff {
		return nil, nil, &ValidationError{Message: "delta resulting tokens are invalid"}
	}
	stable, err := json.Marshal(deltaJSON{
		SchemaVersion:   "cigar.context-delta.v1",
		BaseBundleID:    baseID,
		TargetBundleID:  targetID,
		AddedBlocks:     wireAdded,
		RemovedBlockIDs: wireRemoved,
		ResultingTokens: resultingTokens,
	})
	if err != nil {
		return nil, nil, &TransportError{Message: "delta serialization failed", Cause: err}
	}
	return delta, stable, nil
}

// DeltaDigestJSON computes the raw SHA-256 multihash of the stable Rust delta JSON record.
func DeltaDigestJSON(document []byte) (string, error) {
	value, err := parseStrictJSON(document)
	if err != nil {
		return "", err
	}
	_, stable, err := validatedDelta(value)
	if err != nil {
		return "", err
	}
	return rawMultihash(stable), nil
}

// ApplyContextDeltaJSON verifies a sealed transition and returns an owned target JSON copy.
func ApplyContextDeltaJSON(baseJSON, targetJSON, deltaDocument []byte, sealedDigest string) ([]byte, error) {
	baseValue, err := parseStrictJSON(baseJSON)
	if err != nil {
		return nil, err
	}
	base, baseID, err := validateBundle(baseValue)
	if err != nil {
		return nil, err
	}
	targetValue, err := parseStrictJSON(targetJSON)
	if err != nil {
		return nil, err
	}
	target, targetID, err := validateBundle(targetValue)
	if err != nil {
		return nil, err
	}
	deltaValue, err := parseStrictJSON(deltaDocument)
	if err != nil {
		return nil, err
	}
	delta, stable, err := validatedDelta(deltaValue)
	if err != nil {
		return nil, err
	}
	if delta["base_bundle_id"] != baseID || delta["target_bundle_id"] != targetID || rawMultihash(stable) != sealedDigest {
		return nil, &ValidationError{Message: "sealed delta identity or binding does not match"}
	}
	blocks := make(map[string]map[string]any)
	for _, value := range base["blocks"].([]any) {
		block := value.(map[string]any)
		blocks[block["block_id"].(string)] = block
	}
	removed := delta["removed_block_ids"].([]any)
	for _, value := range removed {
		id := value.(string)
		if _, present := blocks[id]; !present {
			return nil, &ValidationError{Message: "delta removes a block absent from the base"}
		}
		delete(blocks, id)
	}
	for _, value := range delta["added_blocks"].([]any) {
		block := value.(map[string]any)
		id := block["block_id"].(string)
		if _, present := blocks[id]; present {
			return nil, &ValidationError{Message: "delta addition already exists in the base"}
		}
		for _, removedID := range removed {
			if removedID == id {
				return nil, &ValidationError{Message: "delta both adds and removes a block"}
			}
		}
		blocks[id] = block
	}
	targetBlocks := target["blocks"].([]any)
	if len(blocks) != len(targetBlocks) || delta["resulting_tokens"] != target["total_tokens"] {
		return nil, &ValidationError{Message: "delta result does not reproduce the target"}
	}
	for _, value := range targetBlocks {
		block := value.(map[string]any)
		actual, present := blocks[block["block_id"].(string)]
		if !present || !deepEqualCanonical(actual, block) {
			return nil, &ValidationError{Message: "delta result does not reproduce the target"}
		}
	}
	return append([]byte(nil), targetJSON...), nil
}

func deepEqualCanonical(left, right any) bool {
	leftCBOR, leftErr := deterministicCBOR(left)
	rightCBOR, rightErr := deterministicCBOR(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCBOR, rightCBOR)
}
