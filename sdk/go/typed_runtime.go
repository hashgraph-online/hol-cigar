package cigar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const maximumPayloadNodes = 100_000

type validationBudget struct{ nodes int }

var payloadSchemaCache sync.Map

func payloadSchema(name string) (map[string]any, error) {
	if cached, ok := payloadSchemaCache.Load(name); ok {
		return cached.(map[string]any), nil
	}
	document, ok := payloadSchemaJSON[name]
	if !ok {
		return nil, &ValidationError{Message: "unknown nominal payload model " + name}
	}
	parsed, err := parseStrictJSON([]byte(document))
	if err != nil {
		return nil, &ValidationError{Message: "generated payload schema is invalid"}
	}
	schema, ok := parsed.(map[string]any)
	if !ok {
		return nil, &ValidationError{Message: "generated payload schema is not an object"}
	}
	payloadSchemaCache.Store(name, schema)
	return schema, nil
}

func schemaString(schema map[string]any, name string) (string, bool) {
	value, ok := schema[name].(string)
	return value, ok
}

func schemaInteger(value any) (*big.Int, bool) {
	result := new(big.Int)
	switch current := value.(type) {
	case uint64:
		result.SetUint64(current)
		return result, true
	case int64:
		result.SetInt64(current)
		return result, true
	default:
		return nil, false
	}
}

func validateSchema(schema map[string]any, value any, root map[string]any, path string, depth int, budget *validationBudget) error {
	budget.nodes++
	if depth > 64 || budget.nodes > maximumPayloadNodes {
		return &ValidationError{Message: path + ": payload exceeds nesting or node bounds"}
	}
	if reference, ok := schemaString(schema, "$ref"); ok {
		definitions, ok := root["$defs"].(map[string]any)
		const prefix = "#/$defs/"
		if !ok || len(reference) < len(prefix) || reference[:len(prefix)] != prefix {
			return &ValidationError{Message: path + ": schema reference is unresolved"}
		}
		target, ok := definitions[reference[len(prefix):]].(map[string]any)
		if !ok {
			return &ValidationError{Message: path + ": schema reference is unresolved"}
		}
		return validateSchema(target, value, root, path, depth+1, budget)
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		if alternatives, ok := schema[keyword].([]any); ok {
			matches := 0
			for _, alternative := range alternatives {
				candidate, ok := alternative.(map[string]any)
				if ok && validateSchema(candidate, value, root, path, depth+1, budget) == nil {
					matches++
				}
			}
			if (keyword == "oneOf" && matches != 1) || (keyword == "anyOf" && matches < 1) {
				return &ValidationError{Message: path + ": payload does not match its schema variants"}
			}
			return nil
		}
	}
	if constant, present := schema["const"]; present && !deepEqualCanonical(constant, value) {
		return &ValidationError{Message: path + ": value differs from its const"}
	}
	if declaredTypes, ok := schema["type"].([]any); ok {
		matches := 0
		for _, declaredType := range declaredTypes {
			candidate := make(map[string]any, len(schema))
			for key, child := range schema {
				candidate[key] = child
			}
			candidate["type"] = declaredType
			if validateSchema(candidate, value, root, path, depth+1, budget) == nil {
				matches++
			}
		}
		if matches != 1 {
			return &ValidationError{Message: path + ": value does not match its type union"}
		}
		return nil
	}
	declared, _ := schemaString(schema, "type")
	switch declared {
	case "string":
		text, ok := value.(string)
		if !ok {
			return &ValidationError{Message: path + ": expected string"}
		}
		length := uint64(len([]byte(text)))
		if minimum, ok := schema["minLength"].(uint64); ok && length < minimum {
			return &ValidationError{Message: path + ": string is too short"}
		}
		if maximum, ok := schema["maxLength"].(uint64); ok && length > maximum {
			return &ValidationError{Message: path + ": string is too long"}
		}
		if pattern, ok := schemaString(schema, "pattern"); ok {
			matched, err := regexp.MatchString(pattern, text)
			if err != nil || !matched {
				return &ValidationError{Message: path + ": string does not match pattern"}
			}
		}
		return nil
	case "integer", "number":
		integer, ok := schemaInteger(value)
		if !ok {
			return &ValidationError{Message: path + ": expected exact integer"}
		}
		if minimum, ok := schemaInteger(schema["minimum"]); ok && integer.Cmp(minimum) < 0 {
			return &ValidationError{Message: path + ": integer is below minimum"}
		}
		if maximum, ok := schemaInteger(schema["maximum"]); ok && integer.Cmp(maximum) > 0 {
			return &ValidationError{Message: path + ": integer exceeds maximum"}
		}
		return nil
	case "boolean":
		if _, ok := value.(bool); !ok {
			return &ValidationError{Message: path + ": expected boolean"}
		}
		return nil
	case "array":
		items, ok := value.([]any)
		if !ok {
			return &ValidationError{Message: path + ": expected array"}
		}
		if minimum, ok := schema["minItems"].(uint64); ok && uint64(len(items)) < minimum {
			return &ValidationError{Message: path + ": array is too short"}
		}
		if maximum, ok := schema["maxItems"].(uint64); ok && uint64(len(items)) > maximum {
			return &ValidationError{Message: path + ": array is too long"}
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for index, child := range items {
				if err := validateSchema(itemSchema, child, root, fmt.Sprintf("%s/%d", path, index), depth+1, budget); err != nil {
					return err
				}
			}
		}
		return nil
	case "object", "":
		return validateObjectSchema(schema, value, root, path, depth, budget)
	default:
		return &ValidationError{Message: path + ": unsupported generated schema type"}
	}
}

func validateObjectSchema(
	schema map[string]any,
	value any,
	root map[string]any,
	path string,
	depth int,
	budget *validationBudget,
) error {
	declared, _ := schemaString(schema, "type")
	if declared == "" {
		if _, hasProperties := schema["properties"]; !hasProperties {
			if _, hasAdditional := schema["additionalProperties"]; !hasAdditional {
				return nil
			}
		}
	}
	object, ok := value.(map[string]any)
	if !ok {
		return &ValidationError{Message: path + ": expected object"}
	}
	properties, _ := schema["properties"].(map[string]any)
	patterns, _ := schema["patternProperties"].(map[string]any)
	if required, ok := schema["required"].([]any); ok {
		for _, rawName := range required {
			name, ok := rawName.(string)
			if !ok {
				return &ValidationError{Message: path + ": generated required field is invalid"}
			}
			if _, present := object[name]; !present {
				return &ValidationError{Message: path + "/" + name + ": required field is missing"}
			}
		}
	}
	if minimum, ok := schema["minProperties"].(uint64); ok && uint64(len(object)) < minimum {
		return &ValidationError{Message: path + ": object has too few fields"}
	}
	if maximum, ok := schema["maxProperties"].(uint64); ok && uint64(len(object)) > maximum {
		return &ValidationError{Message: path + ": object has too many fields"}
	}
	for name, child := range object {
		if rawChildSchema, present := properties[name]; present {
			childSchema, ok := rawChildSchema.(map[string]any)
			if !ok {
				return &ValidationError{Message: path + "/" + name + ": property schema is invalid"}
			}
			if err := validateSchema(childSchema, child, root, path+"/"+name, depth+1, budget); err != nil {
				return err
			}
			continue
		}
		matched := false
		for pattern, rawPatternSchema := range patterns {
			ok, regexErr := regexp.MatchString(pattern, name)
			if regexErr != nil || !ok {
				continue
			}
			matched = true
			patternSchema, ok := rawPatternSchema.(map[string]any)
			if !ok {
				return &ValidationError{Message: path + "/" + name + ": pattern schema is invalid"}
			}
			if err := validateSchema(patternSchema, child, root, path+"/"+name, depth+1, budget); err != nil {
				return err
			}
		}
		if matched {
			continue
		}
		switch additional := schema["additionalProperties"].(type) {
		case bool:
			if !additional {
				return &ValidationError{Message: path + "/" + name + ": unknown field"}
			}
		case map[string]any:
			if err := validateSchema(additional, child, root, path+"/"+name, depth+1, budget); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePayload(name string, value any) error {
	schema, err := payloadSchema(name)
	if err != nil {
		return err
	}
	return validateSchema(schema, value, schema, name, 0, &validationBudget{})
}

type payloadCBORParser struct {
	source []byte
	pos    int
	nodes  int
}

func (parser *payloadCBORParser) exact(length uint64) ([]byte, error) {
	if length > uint64(len(parser.source)-parser.pos) {
		return nil, &ValidationError{Message: "payload CBOR is truncated"}
	}
	end := parser.pos + int(length)
	result := append([]byte(nil), parser.source[parser.pos:end]...)
	parser.pos = end
	return result, nil
}

func (parser *payloadCBORParser) argument(additional byte) (uint64, error) {
	if additional < 24 {
		return uint64(additional), nil
	}
	widths := map[byte]uint64{24: 1, 25: 2, 26: 4, 27: 8}
	width, ok := widths[additional]
	if !ok {
		return 0, &ValidationError{Message: "payload CBOR uses an indefinite or reserved form"}
	}
	raw, err := parser.exact(width)
	if err != nil {
		return 0, err
	}
	var value uint64
	switch width {
	case 1:
		value = uint64(raw[0])
	case 2:
		value = uint64(binary.BigEndian.Uint16(raw))
	case 4:
		value = uint64(binary.BigEndian.Uint32(raw))
	case 8:
		value = binary.BigEndian.Uint64(raw)
	}
	minimum := map[uint64]uint64{1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[width]
	if value < minimum {
		return 0, &ValidationError{Message: "payload CBOR integer is non-canonical"}
	}
	return value, nil
}

func (parser *payloadCBORParser) parse(depth int) (any, error) {
	parser.nodes++
	if depth > 64 || parser.nodes > maximumPayloadNodes {
		return nil, &ValidationError{Message: "payload CBOR exceeds nesting or node bounds"}
	}
	initial, err := parser.exact(1)
	if err != nil {
		return nil, err
	}
	major, additional := initial[0]>>5, initial[0]&31
	switch major {
	case 0:
		return parser.argument(additional)
	case 1:
		argument, err := parser.argument(additional)
		if err != nil {
			return nil, err
		}
		if argument > uint64(^uint64(0)>>1) {
			return nil, &ValidationError{Message: "payload CBOR integer exceeds i64"}
		}
		return -1 - int64(argument), nil
	case 2, 3:
		length, err := parser.argument(additional)
		if err != nil {
			return nil, err
		}
		raw, err := parser.exact(length)
		if err != nil {
			return nil, err
		}
		if major == 2 {
			return raw, nil
		}
		if !utf8.Valid(raw) {
			return nil, &ValidationError{Message: "payload CBOR text is invalid UTF-8"}
		}
		return norm.NFC.String(string(raw)), nil
	case 4:
		length, err := parser.argument(additional)
		if err != nil {
			return nil, err
		}
		if length > maximumPayloadNodes {
			return nil, &ValidationError{Message: "payload CBOR collection exceeds its node bound"}
		}
		result := make([]any, int(length))
		for index := range result {
			result[index], err = parser.parse(depth + 1)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case 5:
		length, err := parser.argument(additional)
		if err != nil {
			return nil, err
		}
		if length > maximumPayloadNodes {
			return nil, &ValidationError{Message: "payload CBOR collection exceeds its node bound"}
		}
		result := make(map[string]any, int(length))
		var previous []byte
		for index := uint64(0); index < length; index++ {
			start := parser.pos
			keyValue, keyErr := parser.parse(depth + 1)
			if keyErr != nil {
				return nil, keyErr
			}
			key, ok := keyValue.(string)
			encoded := parser.source[start:parser.pos]
			if !ok || (previous != nil && bytes.Compare(previous, encoded) >= 0) {
				return nil, &ValidationError{Message: "payload CBOR map keys are not canonical and unique"}
			}
			if _, duplicate := result[key]; duplicate {
				return nil, &ValidationError{Message: "payload CBOR map keys are not canonical and unique"}
			}
			previous = append(previous[:0], encoded...)
			result[key], err = parser.parse(depth + 1)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case 7:
		if additional == 20 {
			return false, nil
		}
		if additional == 21 {
			return true, nil
		}
	}
	return nil, &ValidationError{Message: "payload CBOR contains a forbidden tag, null, float, or simple value"}
}

func decodeOperationPayload(source []byte) (any, error) {
	parser := payloadCBORParser{source: append([]byte(nil), source...)}
	value, err := parser.parse(0)
	if err != nil {
		return nil, err
	}
	canonical, err := deterministicCBOR(value)
	if err != nil || parser.pos != len(source) || !bytes.Equal(canonical, source) {
		return nil, &ValidationError{Message: "payload CBOR is not deterministic"}
	}
	return value, nil
}

// InvocationOption configures one high-level nominal invocation.
type InvocationOption func(*invocationConfig) error

type invocationConfig struct {
	idempotencyKey   string
	expectedRevision string
	dryRun           bool
	pageCursor       string
	pageSize         uint32
	callOptions      []CallOption
}

func withRawCallOption(option CallOption) InvocationOption {
	return func(config *invocationConfig) error {
		if option == nil {
			return &ValidationError{Message: "call option must not be nil"}
		}
		config.callOptions = append(config.callOptions, option)
		return nil
	}
}

// WithInvocationIdempotencyKey binds the exact key reused by safe retries.
func WithInvocationIdempotencyKey(key string) InvocationOption {
	return func(config *invocationConfig) error { config.idempotencyKey = key; return nil }
}

// WithInvocationExpectedRevision binds optimistic concurrency metadata.
func WithInvocationExpectedRevision(revision string) InvocationOption {
	return func(config *invocationConfig) error { config.expectedRevision = revision; return nil }
}

// WithInvocationDryRun requests a governed preview.
func WithInvocationDryRun() InvocationOption {
	return func(config *invocationConfig) error { config.dryRun = true; return nil }
}

// WithInvocationPage sets an opaque pagination cursor and bounded page size.
func WithInvocationPage(cursor string, size uint32) InvocationOption {
	return func(config *invocationConfig) error { config.pageCursor, config.pageSize = cursor, size; return nil }
}

// WithInvocationTimeout sets one end-to-end call deadline.
func WithInvocationTimeout(timeout time.Duration) InvocationOption {
	return withRawCallOption(WithCallTimeout(timeout))
}

// WithInvocationMaxAttempts sets total attempts including the first.
func WithInvocationMaxAttempts(attempts int) InvocationOption {
	return withRawCallOption(WithCallMaxAttempts(attempts))
}

// WithInvocationResume sets the exact Last-Event-ID, distinct from page cursors.
func WithInvocationResume(eventID string) InvocationOption {
	return withRawCallOption(WithStreamResume(eventID))
}

func applyInvocationOptions(options []InvocationOption) (invocationConfig, error) {
	var config invocationConfig
	for _, option := range options {
		if option == nil {
			return invocationConfig{}, &ValidationError{Message: "invocation option must not be nil"}
		}
		if err := option(&config); err != nil {
			return invocationConfig{}, err
		}
	}
	return config, nil
}

func nominalRequest(operationID string, payload any, config invocationConfig) (Request, error) {
	definition, ok := operations[operationID]
	if !ok {
		return Request{}, &ValidationError{Message: "operation is unknown"}
	}
	document, err := json.Marshal(payload)
	if err != nil {
		return Request{}, &ValidationError{Message: definition.RequestType + " cannot be serialized"}
	}
	value, err := parseStrictJSON(document)
	if err != nil {
		return Request{}, err
	}
	if err := validatePayload(definition.RequestType, value); err != nil {
		return Request{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Request{}, &ValidationError{Message: definition.RequestType + " must be an object"}
	}
	parameters := make([]PathParameter, 0, len(definition.PathFields))
	for _, name := range definition.PathFields {
		pathValue, ok := object[name].(string)
		if !ok {
			return Request{}, &ValidationError{Message: definition.RequestType + "." + name + " must be a path string"}
		}
		parameter, err := NewPathParameter(name, pathValue)
		if err != nil {
			return Request{}, err
		}
		parameters = append(parameters, parameter)
	}
	var payloadCBOR []byte
	if definition.HTTPMethod != "GET" {
		payloadCBOR, err = deterministicCBOR(value)
		if err != nil {
			return Request{}, err
		}
	}
	requestOptions := []RequestOption{WithPathParameters(parameters...)}
	if config.idempotencyKey != "" {
		requestOptions = append(requestOptions, WithIdempotencyKey(config.idempotencyKey))
	}
	if config.expectedRevision != "" {
		requestOptions = append(requestOptions, WithExpectedRevision(config.expectedRevision))
	}
	if config.dryRun {
		requestOptions = append(requestOptions, WithDryRun())
	}
	if config.pageCursor != "" || config.pageSize != 0 {
		requestOptions = append(requestOptions, WithPage(config.pageCursor, config.pageSize))
	}
	return NewRequest(payloadCBOR, requestOptions...)
}

// TypedResponse is a copy-safe nominal unary result.
type TypedResponse[T any] struct {
	raw         Response
	payloadJSON []byte
}

// OperationID returns the exact response operation identity.
func (response TypedResponse[T]) OperationID() string { return response.raw.OperationID() }

// Payload returns a fresh deep copy of the validated nominal payload.
func (response TypedResponse[T]) Payload() T {
	var result T
	if err := json.Unmarshal(response.payloadJSON, &result); err != nil {
		panic("cigar: validated payload failed internal nominal decode: " + err.Error())
	}
	return result
}

// PayloadCBOR returns an owned copy of the canonical payload bytes.
func (response TypedResponse[T]) PayloadCBOR() []byte { return response.raw.PayloadCBOR() }

// SemanticETag returns the semantic ETag, or an empty string when absent.
func (response TypedResponse[T]) SemanticETag() string { return response.raw.SemanticETag() }

// NextPageCursor returns the next opaque cursor, or empty at completion.
func (response TypedResponse[T]) NextPageCursor() string { return response.raw.NextPageCursor() }

func typedResponse[T any](raw Response, model string) (TypedResponse[T], error) {
	value, err := decodeOperationPayload(raw.payloadCBOR)
	if err != nil {
		return TypedResponse[T]{}, &TransportError{Message: model + " response payload is invalid", Cause: err}
	}
	if err := validatePayload(model, value); err != nil {
		return TypedResponse[T]{}, &TransportError{Message: model + " response violates its schema", Cause: err}
	}
	document, err := json.Marshal(value)
	if err != nil {
		return TypedResponse[T]{}, &TransportError{Message: model + " response cannot be materialized", Cause: err}
	}
	var probe T
	if err := json.Unmarshal(document, &probe); err != nil {
		return TypedResponse[T]{}, &TransportError{Message: model + " response cannot be decoded", Cause: err}
	}
	return TypedResponse[T]{raw: raw, payloadJSON: append([]byte(nil), document...)}, nil
}

func callTyped[RequestPayload, ResponsePayload any](
	client *Client,
	ctx context.Context,
	operationID string,
	payload RequestPayload,
	options ...InvocationOption,
) (TypedResponse[ResponsePayload], error) {
	config, err := applyInvocationOptions(options)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	request, err := nominalRequest(operationID, payload, config)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	raw, err := client.call(ctx, operationID, request, config.callOptions...)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	return typedResponse[ResponsePayload](raw, operations[operationID].ResponseType)
}

// TypedEvent is a copy-safe nominal stream event.
type TypedEvent[T any] struct {
	raw         Event
	payloadJSON []byte
}

// OperationID returns the event operation identity.
func (event TypedEvent[T]) OperationID() string { return event.raw.OperationID() }

// EventID returns the exact resumable event identity.
func (event TypedEvent[T]) EventID() string { return event.raw.EventID() }

// PayloadCBOR returns an owned canonical event payload copy.
func (event TypedEvent[T]) PayloadCBOR() []byte { return event.raw.PayloadCBOR() }

// Payload returns a fresh deep copy of the validated event payload.
func (event TypedEvent[T]) Payload() T {
	var result T
	if err := json.Unmarshal(event.payloadJSON, &result); err != nil {
		panic("cigar: validated event failed internal nominal decode: " + err.Error())
	}
	return result
}

type rawEventStream interface {
	Next() bool
	Event() Event
	LastEventID() string
	Err() error
	Close() error
}

// TypedEventStream wraps a resumable raw HTTP or gRPC stream with schema validation.
type TypedEventStream[T any] struct {
	raw   rawEventStream
	model string
	event TypedEvent[T]
	err   error
}

// Next advances to one exact validated event.
func (stream *TypedEventStream[T]) Next() bool {
	if stream.err != nil || !stream.raw.Next() {
		return false
	}
	raw := stream.raw.Event()
	value, err := decodeOperationPayload(raw.payloadCBOR)
	if err == nil {
		err = validatePayload(stream.model, value)
	}
	if err != nil {
		stream.err = &TransportError{Message: stream.model + " event payload is invalid", Cause: err}
		_ = stream.raw.Close()
		return false
	}
	document, err := json.Marshal(value)
	if err != nil {
		stream.err = &TransportError{Message: stream.model + " event cannot be materialized", Cause: err}
		_ = stream.raw.Close()
		return false
	}
	var probe T
	if err := json.Unmarshal(document, &probe); err != nil {
		stream.err = &TransportError{Message: stream.model + " event cannot be decoded", Cause: err}
		_ = stream.raw.Close()
		return false
	}
	stream.event = TypedEvent[T]{raw: raw, payloadJSON: append([]byte(nil), document...)}
	return true
}

// Event returns the current copy-safe nominal event.
func (stream *TypedEventStream[T]) Event() TypedEvent[T] { return stream.event }

// LastEventID returns the last verified resume identity.
func (stream *TypedEventStream[T]) LastEventID() string { return stream.raw.LastEventID() }

// Err returns the terminal typed or transport failure.
func (stream *TypedEventStream[T]) Err() error {
	if stream.err != nil {
		return stream.err
	}
	return stream.raw.Err()
}

// Close cancels the stream and releases its response.
func (stream *TypedEventStream[T]) Close() error { return stream.raw.Close() }

func streamTyped[RequestPayload, EventPayload any](
	client *Client,
	ctx context.Context,
	operationID string,
	payload RequestPayload,
	options ...InvocationOption,
) (*TypedEventStream[EventPayload], error) {
	config, err := applyInvocationOptions(options)
	if err != nil {
		return nil, err
	}
	if config.pageCursor != "" || config.pageSize != 0 {
		return nil, &ValidationError{Message: "SSE resume uses WithInvocationResume, not a page cursor"}
	}
	request, err := nominalRequest(operationID, payload, config)
	if err != nil {
		return nil, err
	}
	raw, err := client.stream(ctx, operationID, request, config.callOptions...)
	if err != nil {
		return nil, err
	}
	return &TypedEventStream[EventPayload]{raw: raw, model: operations[operationID].EventType}, nil
}

func callGRPCTyped[RequestPayload, ResponsePayload any](
	client *GRPCClient,
	ctx context.Context,
	operationID string,
	payload RequestPayload,
	options ...InvocationOption,
) (TypedResponse[ResponsePayload], error) {
	config, err := applyInvocationOptions(options)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	request, err := nominalRequest(operationID, payload, config)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	raw, err := client.call(ctx, operationID, request, config.callOptions...)
	if err != nil {
		return TypedResponse[ResponsePayload]{}, err
	}
	return typedResponse[ResponsePayload](raw, operations[operationID].ResponseType)
}

func streamGRPCTyped[RequestPayload, EventPayload any](
	client *GRPCClient,
	ctx context.Context,
	operationID string,
	payload RequestPayload,
	options ...InvocationOption,
) (*TypedEventStream[EventPayload], error) {
	config, err := applyInvocationOptions(options)
	if err != nil {
		return nil, err
	}
	if config.pageCursor != "" || config.pageSize != 0 {
		return nil, &ValidationError{Message: "gRPC stream resume uses WithInvocationResume, not a page cursor"}
	}
	request, err := nominalRequest(operationID, payload, config)
	if err != nil {
		return nil, err
	}
	raw, err := client.stream(ctx, operationID, request, config.callOptions...)
	if err != nil {
		return nil, err
	}
	return &TypedEventStream[EventPayload]{raw: raw, model: operations[operationID].EventType}, nil
}
