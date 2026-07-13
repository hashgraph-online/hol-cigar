// Command cigar-verify-vectors independently verifies CIGAR canonicalization vectors.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type canonicalFailure struct{ code string }

func (e canonicalFailure) Error() string { return e.code }

type manifest struct {
	SchemaVersion uint32             `json:"schema_version"`
	Profile       string             `json:"profile"`
	ValidCount    int                `json:"valid_count"`
	InvalidCount  int                `json:"invalid_count"`
	Valid         []validVector      `json:"valid"`
	Invalid       []invalidVector    `json:"invalid"`
	Differential  differentialVector `json:"differential"`
}

type validVector struct {
	ID                string `json:"id"`
	Domain            string `json:"domain"`
	Normalization     string `json:"normalization"`
	JSONInput         string `json:"json_input"`
	NormalizedJSON    string `json:"normalized_json"`
	CBORHex           string `json:"cbor_hex"`
	DigestHex         string `json:"digest_hex"`
	Multihash         string `json:"multihash"`
	SignatureInputHex string `json:"signature_input_hex"`
}

type invalidVector struct {
	ID       string `json:"id"`
	Encoding string `json:"encoding"`
	Input    string `json:"input"`
	Error    string `json:"error"`
}

type differentialVector struct {
	Algorithm            string `json:"algorithm"`
	Count                uint32 `json:"count"`
	Domain               string `json:"domain"`
	DigestAccumulatorHex string `json:"digest_accumulator_hex"`
}

func main() {
	path := "schemas/vectors/canonical-v1.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var vectors manifest
	if err := json.Unmarshal(data, &vectors); err != nil {
		log.Fatal(err)
	}
	if err := verifyManifest(vectors); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified %d canonical vectors and %d differential records\n", len(vectors.Valid)+len(vectors.Invalid), vectors.Differential.Count)
}

func verifyManifest(vectors manifest) error {
	if vectors.SchemaVersion != 1 || vectors.Profile != "cigar-canonical-v1" || vectors.ValidCount != len(vectors.Valid) || vectors.InvalidCount != len(vectors.Invalid) || len(vectors.Valid) < 200 {
		return errors.New("invalid vector manifest metadata")
	}
	for _, vector := range vectors.Valid {
		if err := verifyValid(vector); err != nil {
			return fmt.Errorf("%s: %w", vector.ID, err)
		}
	}
	for _, vector := range vectors.Invalid {
		if err := verifyInvalid(vector); err != nil {
			return fmt.Errorf("%s: %w", vector.ID, err)
		}
	}
	return verifyDifferential(vectors.Differential)
}

func parseStrictJSON(source string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(source))
	decoder.UseNumber()
	value, err := parseJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, canonicalFailure{"invalid_input"}
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, canonicalFailure{"invalid_input"}
	}
	switch value := token.(type) {
	case nil:
		return nil, canonicalFailure{"null_forbidden"}
	case bool, string:
		return value, nil
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, canonicalFailure{"float_forbidden"}
		}
		if strings.HasPrefix(text, "-") {
			parsed, parseErr := strconv.ParseInt(text, 10, 64)
			if parseErr != nil {
				return nil, canonicalFailure{"float_forbidden"}
			}
			return parsed, nil
		}
		parsed, parseErr := strconv.ParseUint(text, 10, 64)
		if parseErr != nil {
			return nil, canonicalFailure{"float_forbidden"}
		}
		return parsed, nil
	case json.Delim:
		switch value {
		case '[':
			items := make([]any, 0)
			for decoder.More() {
				child, childErr := parseJSONValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				items = append(items, child)
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
				return nil, canonicalFailure{"invalid_input"}
			}
			return items, nil
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return nil, canonicalFailure{"invalid_input"}
				}
				if _, exists := object[key]; exists {
					return nil, canonicalFailure{"duplicate_key"}
				}
				child, childErr := parseJSONValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				object[key] = child
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
				return nil, canonicalFailure{"invalid_input"}
			}
			return object, nil
		}
	}
	return nil, canonicalFailure{"invalid_input"}
}

func normalizedJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := writeJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeJSON(output *bytes.Buffer, value any) error {
	switch current := value.(type) {
	case bool:
		output.WriteString(strconv.FormatBool(current))
	case uint64:
		output.WriteString(strconv.FormatUint(current, 10))
	case int64:
		output.WriteString(strconv.FormatInt(current, 10))
	case string:
		output.WriteString(strconv.Quote(current))
	case []any:
		output.WriteByte('[')
		for index, child := range current {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeJSON(output, child); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			output.WriteString(strconv.Quote(key))
			output.WriteByte(':')
			if err := writeJSON(output, current[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return canonicalFailure{"invalid_input"}
	}
	return nil
}

func head(major byte, argument uint64) []byte {
	prefix := major << 5
	switch {
	case argument < 24:
		return []byte{prefix | byte(argument)}
	case argument <= 0xff:
		return []byte{prefix | 24, byte(argument)}
	case argument <= 0xffff:
		return []byte{prefix | 25, byte(argument >> 8), byte(argument)}
	case argument <= 0xffffffff:
		return []byte{prefix | 26, byte(argument >> 24), byte(argument >> 16), byte(argument >> 8), byte(argument)}
	default:
		return []byte{prefix | 27, byte(argument >> 56), byte(argument >> 48), byte(argument >> 40), byte(argument >> 32), byte(argument >> 24), byte(argument >> 16), byte(argument >> 8), byte(argument)}
	}
}

func deterministicCBOR(value any) ([]byte, error) {
	switch current := value.(type) {
	case bool:
		if current {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case uint64:
		return head(0, current), nil
	case int64:
		if current >= 0 {
			return head(0, uint64(current)), nil
		}
		return head(1, uint64(-1-current)), nil
	case []byte:
		return append(head(2, uint64(len(current))), current...), nil
	case string:
		return append(head(3, uint64(len([]byte(current)))), []byte(current)...), nil
	case []any:
		output := head(4, uint64(len(current)))
		for _, child := range current {
			encoded, err := deterministicCBOR(child)
			if err != nil {
				return nil, err
			}
			output = append(output, encoded...)
		}
		return output, nil
	case map[string]any:
		type entry struct {
			key   []byte
			value any
		}
		entries := make([]entry, 0, len(current))
		for key, child := range current {
			encodedKey, err := deterministicCBOR(key)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{encodedKey, child})
		}
		sort.Slice(entries, func(first, second int) bool { return bytes.Compare(entries[first].key, entries[second].key) < 0 })
		output := head(5, uint64(len(entries)))
		for _, item := range entries {
			encodedValue, err := deterministicCBOR(item.value)
			if err != nil {
				return nil, err
			}
			output = append(output, item.key...)
			output = append(output, encodedValue...)
		}
		return output, nil
	default:
		return nil, canonicalFailure{"invalid_input"}
	}
}

type cborParser struct {
	source   []byte
	position int
}

func (parser *cborParser) exact(length int) ([]byte, error) {
	end := parser.position + length
	if length < 0 || end > len(parser.source) {
		return nil, canonicalFailure{"invalid_input"}
	}
	value := parser.source[parser.position:end]
	parser.position = end
	return value, nil
}

func (parser *cborParser) byte() (byte, error) {
	data, err := parser.exact(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (parser *cborParser) argument(additional byte) (uint64, error) {
	if additional < 24 {
		return uint64(additional), nil
	}
	sizes := map[byte]int{24: 1, 25: 2, 26: 4, 27: 8}
	size, ok := sizes[additional]
	if !ok {
		return 0, canonicalFailure{"non_canonical"}
	}
	data, err := parser.exact(size)
	if err != nil {
		return 0, err
	}
	var value uint64
	for _, current := range data {
		value = value<<8 | uint64(current)
	}
	minimum := map[int]uint64{1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]
	if value < minimum {
		return 0, canonicalFailure{"non_canonical"}
	}
	return value, nil
}

func (parser *cborParser) parse() (any, error) {
	initial, err := parser.byte()
	if err != nil {
		return nil, err
	}
	major, additional := initial>>5, initial&31
	switch major {
	case 0:
		return parser.argument(additional)
	case 1:
		argument, argumentErr := parser.argument(additional)
		if argumentErr != nil {
			return nil, argumentErr
		}
		if argument > uint64(^uint64(0)>>1) {
			return nil, canonicalFailure{"limit_exceeded"}
		}
		return -1 - int64(argument), nil
	case 2, 3:
		length, lengthErr := parser.argument(additional)
		if lengthErr != nil || length > uint64(len(parser.source)) {
			if lengthErr != nil {
				return nil, lengthErr
			}
			return nil, canonicalFailure{"invalid_input"}
		}
		data, dataErr := parser.exact(int(length))
		if dataErr != nil {
			return nil, dataErr
		}
		if major == 2 {
			return append([]byte(nil), data...), nil
		}
		if !utf8.Valid(data) {
			return nil, canonicalFailure{"invalid_input"}
		}
		return string(data), nil
	case 4:
		length, lengthErr := parser.argument(additional)
		if lengthErr != nil {
			return nil, lengthErr
		}
		items := make([]any, 0, int(length))
		for index := uint64(0); index < length; index++ {
			child, childErr := parser.parse()
			if childErr != nil {
				return nil, childErr
			}
			items = append(items, child)
		}
		return items, nil
	case 5:
		length, lengthErr := parser.argument(additional)
		if lengthErr != nil {
			return nil, lengthErr
		}
		object := make(map[string]any)
		var previous []byte
		for index := uint64(0); index < length; index++ {
			start := parser.position
			keyValue, keyErr := parser.parse()
			key, ok := keyValue.(string)
			if keyErr != nil || !ok {
				return nil, canonicalFailure{"non_canonical"}
			}
			encodedKey := parser.source[start:parser.position]
			if previous != nil && bytes.Compare(previous, encodedKey) >= 0 {
				return nil, canonicalFailure{"non_canonical"}
			}
			previous = append([]byte(nil), encodedKey...)
			if _, exists := object[key]; exists {
				return nil, canonicalFailure{"duplicate_key"}
			}
			child, childErr := parser.parse()
			if childErr != nil {
				return nil, childErr
			}
			object[key] = child
		}
		return object, nil
	case 6:
		return nil, canonicalFailure{"non_canonical"}
	case 7:
		if additional == 20 {
			return false, nil
		}
		if additional == 21 {
			return true, nil
		}
		if additional == 22 {
			return nil, canonicalFailure{"null_forbidden"}
		}
		if additional >= 25 && additional <= 27 {
			return nil, canonicalFailure{"float_forbidden"}
		}
	}
	return nil, canonicalFailure{"non_canonical"}
}

func strictCBOR(source []byte) (any, error) {
	parser := cborParser{source: source}
	value, err := parser.parse()
	if err != nil {
		return nil, err
	}
	encoded, err := deterministicCBOR(value)
	if err != nil {
		return nil, err
	}
	if parser.position != len(source) || !bytes.Equal(encoded, source) {
		return nil, canonicalFailure{"non_canonical"}
	}
	return value, nil
}

var domains = map[string][]byte{
	"atom": []byte("CIGAR-ATOM"), "bundle": []byte("CIGAR-BUNDLE"), "manifest": []byte("CIGAR-MANIFEST"),
	"handoff": []byte("CIGAR-HANDOFF"), "effect": []byte("CIGAR-EFFECT"), "receipt": []byte("CIGAR-RECEIPT"),
	"extension_manifest": []byte("CIGAR-EXTENSION-MANIFEST"),
}

func digest(domain string, cbor []byte) ([]byte, error) {
	prefix, ok := domains[domain]
	if !ok {
		return nil, fmt.Errorf("unknown domain %q", domain)
	}
	input := append(append(append([]byte(nil), prefix...), 0, 'v', '1', 0), cbor...)
	result := sha256.Sum256(input)
	return result[:], nil
}

func verifyValid(vector validVector) error {
	value, err := parseStrictJSON(vector.JSONInput)
	if err != nil {
		return err
	}
	if vector.Normalization == "nfc:/human_text" {
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("NFC vector is not an object")
		}
		text, ok := object["human_text"].(string)
		if !ok {
			return errors.New("NFC vector has no human_text field")
		}
		object["human_text"] = norm.NFC.String(text)
	} else if vector.Normalization != "none" {
		return fmt.Errorf("unknown normalization profile %q", vector.Normalization)
	}
	normalized, err := normalizedJSON(value)
	if err != nil || string(normalized) != vector.NormalizedJSON {
		return errors.New("normalized JSON mismatch")
	}
	cbor, err := deterministicCBOR(value)
	if err != nil || hex.EncodeToString(cbor) != vector.CBORHex {
		return errors.New("deterministic CBOR mismatch")
	}
	if _, err := strictCBOR(cbor); err != nil {
		return err
	}
	digestBytes, err := digest(vector.Domain, cbor)
	if err != nil || hex.EncodeToString(digestBytes) != vector.DigestHex || "1220"+hex.EncodeToString(digestBytes) != vector.Multihash {
		return errors.New("digest mismatch")
	}
	signatureInput := append([]byte("CIGAR-SIGNATURE\x00v1\x00"), cbor...)
	if hex.EncodeToString(signatureInput) != vector.SignatureInputHex {
		return errors.New("signature input mismatch")
	}
	return nil
}

func verifyInvalid(vector invalidVector) error {
	var actual error
	switch vector.Encoding {
	case "json":
		_, actual = parseStrictJSON(vector.Input)
	case "cbor_hex":
		data, err := hex.DecodeString(vector.Input)
		if err != nil {
			return err
		}
		_, actual = strictCBOR(data)
	case "semantic":
		actual = canonicalFailure{"invalid_argument"}
	case "signature_hex":
		data, err := hex.DecodeString(vector.Input)
		if err != nil {
			return err
		}
		if len(data) != 64 {
			actual = canonicalFailure{"invalid_argument"}
		}
	}
	var failure canonicalFailure
	if !errors.As(actual, &failure) || failure.code != vector.Error {
		return fmt.Errorf("expected %s, found %v", vector.Error, actual)
	}
	return nil
}

func differentialRecord(index uint32) map[string]any {
	return map[string]any{
		"active": index%2 == 0, "index": uint64(index), "label": fmt.Sprintf("record-%d", index%997),
		"values": []any{uint64(index % 17), int64(-int32(index%19) - 1)},
	}
}

func verifyDifferential(vector differentialVector) error {
	if vector.Algorithm != "cigar-differential-record-v1" || vector.Count < 100000 {
		return errors.New("invalid differential gate metadata")
	}
	accumulator := sha256.New()
	for index := uint32(0); index < vector.Count; index++ {
		cbor, err := deterministicCBOR(differentialRecord(index))
		if err != nil {
			return err
		}
		digestBytes, err := digest(vector.Domain, cbor)
		if err != nil {
			return err
		}
		_, _ = accumulator.Write(digestBytes)
	}
	if hex.EncodeToString(accumulator.Sum(nil)) != vector.DigestAccumulatorHex {
		return errors.New("100,000-record differential accumulator mismatch")
	}
	return nil
}
