package cigar

import (
	"bytes"
	"encoding/json"
)

// JSONValue is an immutable, canonical, non-null JSON protocol value.
// Its zero value is unset; construct values with NewJSONValue or ParseJSONValue.
type JSONValue struct {
	document string
}

// NewJSONValue takes an owned canonical snapshot of a nested protocol value.
func NewJSONValue(value any) (JSONValue, error) {
	if existing, ok := value.(JSONValue); ok {
		if existing.document == "" {
			return JSONValue{}, &ValidationError{Message: "JSON value is unset"}
		}
		return existing, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return JSONValue{}, &ValidationError{Message: "JSON value cannot be serialized"}
	}
	return ParseJSONValue(encoded)
}

// MustJSONValue constructs a value and panics only for programmer-invalid constants.
func MustJSONValue(value any) JSONValue {
	result, err := NewJSONValue(value)
	if err != nil {
		panic(err)
	}
	return result
}

// ParseJSONValue strictly parses and owns one non-null, integer-only JSON value.
func ParseJSONValue(source []byte) (JSONValue, error) {
	value, err := parseStrictJSON(source)
	if err != nil {
		return JSONValue{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return JSONValue{}, &ValidationError{Message: "JSON value cannot be canonicalized"}
	}
	return JSONValue{document: string(canonical)}, nil
}

// IsSet reports whether this value was explicitly constructed.
func (value JSONValue) IsSet() bool { return value.document != "" }

// JSON returns an owned canonical JSON encoding.
func (value JSONValue) JSON() []byte { return append([]byte(nil), []byte(value.document)...) }

// Value returns a deep, caller-owned representation.
func (value JSONValue) Value() (any, error) {
	if value.document == "" {
		return nil, &ValidationError{Message: "JSON value is unset"}
	}
	return parseStrictJSON([]byte(value.document))
}

// MarshalJSON implements json.Marshaler without exposing internal storage.
func (value JSONValue) MarshalJSON() ([]byte, error) {
	if value.document == "" {
		return nil, &ValidationError{Message: "JSON value is unset"}
	}
	return value.JSON(), nil
}

// UnmarshalJSON implements json.Unmarshaler using the same strict canonical subset.
func (value *JSONValue) UnmarshalJSON(source []byte) error {
	parsed, err := ParseJSONValue(bytes.Clone(source))
	if err != nil {
		return err
	}
	*value = parsed
	return nil
}
