// Package cigar is the copy-safe CIGAR v1 HTTP SDK.
package cigar

import (
	"context"
	"time"
)

// ContextABI is the exact Protobuf package name of the stable Context ABI implemented by this SDK.
const ContextABI = "cigar.context.v1"

// PathParameter is an immutable path binding.
type PathParameter struct {
	name  string
	value string
}

// NewPathParameter validates and constructs a path binding.
func NewPathParameter(name, value string) (PathParameter, error) {
	if !pathName.MatchString(name) || !pathValue.MatchString(value) {
		return PathParameter{}, &ValidationError{Message: "path parameter violates the frozen alphabet"}
	}
	return PathParameter{name: name, value: value}, nil
}

// Name returns the immutable parameter name.
func (parameter PathParameter) Name() string { return parameter.name }

// Value returns the immutable parameter value.
func (parameter PathParameter) Value() string { return parameter.value }

// Request is an immutable copy-safe operation envelope.
type Request struct {
	payloadCBOR      []byte
	pathParameters   []PathParameter
	idempotencyKey   string
	expectedRevision string
	dryRun           bool
	pageCursor       string
	pageSize         uint32
}

// RequestOption configures a request while preserving owned copies.
type RequestOption func(*Request) error

// NewRequest copies payload and applies validated options.
func NewRequest(payloadCBOR []byte, options ...RequestOption) (Request, error) {
	request := Request{payloadCBOR: append([]byte(nil), payloadCBOR...)}
	for _, option := range options {
		if option == nil {
			return Request{}, &ValidationError{Message: "request option must not be nil"}
		}
		if err := option(&request); err != nil {
			return Request{}, err
		}
	}
	return request, nil
}

// NewEmptyRequest returns a zero-payload low-level request.
func NewEmptyRequest(options ...RequestOption) (Request, error) { return NewRequest(nil, options...) }

// WithPathParameters binds a copy of path parameters.
func WithPathParameters(parameters ...PathParameter) RequestOption {
	copyOfParameters := append([]PathParameter(nil), parameters...)
	return func(request *Request) error {
		request.pathParameters = append([]PathParameter(nil), copyOfParameters...)
		return nil
	}
}

// WithIdempotencyKey binds the exact key preserved across retry attempts.
func WithIdempotencyKey(key string) RequestOption {
	return func(request *Request) error {
		request.idempotencyKey = key
		return nil
	}
}

// WithExpectedRevision binds optimistic concurrency metadata.
func WithExpectedRevision(revision string) RequestOption {
	return func(request *Request) error {
		request.expectedRevision = revision
		return nil
	}
}

// WithDryRun requests a governed preview.
func WithDryRun() RequestOption {
	return func(request *Request) error {
		request.dryRun = true
		return nil
	}
}

// WithPage sets a bounded cursor and page size.
func WithPage(cursor string, size uint32) RequestOption {
	return func(request *Request) error {
		request.pageCursor = cursor
		request.pageSize = size
		return nil
	}
}

// PayloadCBOR returns an owned payload copy.
func (request Request) PayloadCBOR() []byte { return append([]byte(nil), request.payloadCBOR...) }

// PathParameters returns an owned path-binding copy.
func (request Request) PathParameters() []PathParameter {
	return append([]PathParameter(nil), request.pathParameters...)
}

// Response is an immutable copy-safe unary result.
type Response struct {
	operationID    string
	payloadCBOR    []byte
	semanticETag   string
	nextPageCursor string
}

// OperationID returns the exact response operation identity.
func (response Response) OperationID() string { return response.operationID }

// PayloadCBOR returns an owned payload copy.
func (response Response) PayloadCBOR() []byte { return append([]byte(nil), response.payloadCBOR...) }

// SemanticETag returns the semantic ETag, or an empty string when absent.
func (response Response) SemanticETag() string { return response.semanticETag }

// NextPageCursor returns the next cursor, or an empty string at completion.
func (response Response) NextPageCursor() string { return response.nextPageCursor }

// Event is an immutable copy-safe server-stream event.
type Event struct {
	operationID string
	eventID     string
	payloadCBOR []byte
}

// OperationID returns the exact event operation identity.
func (event Event) OperationID() string { return event.operationID }

// EventID returns the resumable event identity.
func (event Event) EventID() string { return event.eventID }

// PayloadCBOR returns an owned event payload copy.
func (event Event) PayloadCBOR() []byte { return append([]byte(nil), event.payloadCBOR...) }

// OperationDefinition describes one frozen v1 operation.
type OperationDefinition struct {
	OperationID         string
	RPC                 string
	Service             string
	HTTPMethod          string
	HTTPPath            string
	Mutation            bool
	IdempotencyRequired bool
	RevisionRequired    bool
	Stream              bool
	AuthClass           string
	RequestType         string
	ResponseType        string
	EventType           string
	RequestMaxBytes     int
	ResponseMaxBytes    int
	EventMaxBytes       int
	PathFields          []string
}

// Operation returns a descriptor copy.
func Operation(operationID string) (OperationDefinition, bool) {
	definition, ok := operations[operationID]
	definition.PathFields = append([]string(nil), definition.PathFields...)
	return definition, ok
}

// CallOption configures one invocation.
type CallOption func(*callConfig) error

type callConfig struct {
	timeout     time.Duration
	maxAttempts int
	resumeFrom  string
}

// WithCallTimeout sets a bounded per-call timeout.
func WithCallTimeout(timeout time.Duration) CallOption {
	return func(config *callConfig) error {
		config.timeout = timeout
		return nil
	}
}

// WithCallMaxAttempts sets total attempts including the first. Dispatch remains one attempt.
func WithCallMaxAttempts(attempts int) CallOption {
	return func(config *callConfig) error {
		config.maxAttempts = attempts
		return nil
	}
}

// WithStreamResume sets the exact Last-Event-ID.
func WithStreamResume(eventID string) CallOption {
	return func(config *callConfig) error {
		config.resumeFrom = eventID
		return nil
	}
}

// TokenProvider resolves short-lived bearer material for one request.
type TokenProvider func(context.Context) (string, error)

// Compatibility contains the version and capabilities negotiation responses.
type Compatibility struct {
	APIVersion   string
	Version      TypedResponse[VersionResponse]
	Capabilities TypedResponse[CapabilitiesResponse]
}
