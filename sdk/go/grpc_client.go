package cigar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	cigarv1 "github.com/CIGAR/cigar/sdk/go/gen/cigarv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const grpcEnvelopeOverheadBytes = 64 * 1024

// GRPCClientOptions configure a high-level client over a caller-owned gRPC connection.
type GRPCClientOptions struct {
	Connection                     grpc.ClientConnInterface
	TrustCustomConnectionNoRetries bool
	BearerToken                    string
	TokenProvider                  TokenProvider
	DefaultTimeout                 time.Duration
	MaxAttempts                    int
}

// GRPCDialOptions configure the SDK-owned, transport-retry-disabled gRPC connection.
type GRPCDialOptions struct {
	Target               string
	TransportCredentials credentials.TransportCredentials
	ContextDialer        func(context.Context, string) (net.Conn, error)
	BearerToken          string
	TokenProvider        TokenProvider
	DefaultTimeout       time.Duration
	MaxAttempts          int
}

// GRPCClient is a goroutine-safe high-level CIGAR v1 gRPC client.
//
// DialGRPCClient owns its connection. NewGRPCClient accepts a caller-owned connection only
// after an explicit acknowledgement that transport-level retries are disabled.
type GRPCClient struct {
	connection      grpc.ClientConnInterface
	bearerToken     string
	tokenProvider   TokenProvider
	defaultTimeout  time.Duration
	maxAttempts     int
	ownedConnection *grpc.ClientConn
}

// DialGRPCClient creates the safe default high-level transport. gRPC service-config retries are
// disabled so the SDK remains the only authority that can repeat an operation.
func DialGRPCClient(options GRPCDialOptions) (*GRPCClient, error) {
	if options.Target == "" || options.TransportCredentials == nil {
		return nil, &ValidationError{Message: "gRPC target and transport credentials are required"}
	}
	if err := validateGRPCAuthorization(options.BearerToken, options.TokenProvider); err != nil {
		return nil, err
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(options.TransportCredentials),
		grpc.WithDisableRetry(),
		grpc.WithNoProxy(),
	}
	if options.ContextDialer != nil {
		dialOptions = append(dialOptions, grpc.WithContextDialer(options.ContextDialer))
	}
	connection, err := grpc.NewClient(options.Target, dialOptions...)
	if err != nil {
		return nil, &TransportError{Message: "gRPC client construction failed", Cause: err}
	}
	client, err := newGRPCClient(GRPCClientOptions{
		Connection: connection, TrustCustomConnectionNoRetries: true,
		BearerToken: options.BearerToken, TokenProvider: options.TokenProvider,
		DefaultTimeout: options.DefaultTimeout, MaxAttempts: options.MaxAttempts,
	})
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	client.ownedConnection = connection
	return client, nil
}

// NewGRPCClient validates bounded behavior around a caller-owned generated gRPC transport.
// Prefer DialGRPCClient, which disables hidden transport retries by construction.
func NewGRPCClient(options GRPCClientOptions) (*GRPCClient, error) {
	return newGRPCClient(options)
}

func newGRPCClient(options GRPCClientOptions) (*GRPCClient, error) {
	if options.Connection == nil {
		return nil, &ValidationError{Message: "gRPC connection must not be nil"}
	}
	if !options.TrustCustomConnectionNoRetries {
		return nil, &ValidationError{Message: "custom gRPC connection requires an explicit no-transport-retry acknowledgement"}
	}
	if err := validateGRPCAuthorization(options.BearerToken, options.TokenProvider); err != nil {
		return nil, err
	}
	timeout := options.DefaultTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout <= 0 || timeout > maximumTimeout {
		return nil, &ValidationError{Message: "default timeout must be in (0, 5m]"}
	}
	attempts := options.MaxAttempts
	if attempts == 0 {
		attempts = 3
	}
	if attempts < 1 || attempts > 8 {
		return nil, &ValidationError{Message: "max attempts must be in 1..8"}
	}
	return &GRPCClient{
		connection: options.Connection, bearerToken: options.BearerToken,
		tokenProvider: options.TokenProvider, defaultTimeout: timeout, maxAttempts: attempts,
	}, nil
}

func validateGRPCAuthorization(token string, provider TokenProvider) error {
	if token == "" && provider == nil {
		return &ValidationError{Message: "remote gRPC requires an explicit bearer source"}
	}
	if token != "" && provider != nil {
		return &ValidationError{Message: "configure one bearer source"}
	}
	if token != "" && !boundedVisibleASCII(token, 8192) {
		return &ValidationError{Message: "bearer token must be 1..8192 visible ASCII bytes"}
	}
	return nil
}

// Close closes an SDK-owned connection. It is a no-op for caller-owned connections.
func (client *GRPCClient) Close() error {
	if client.ownedConnection == nil {
		return nil
	}
	return client.ownedConnection.Close()
}

func (client *GRPCClient) config(options []CallOption) (callConfig, error) {
	config := callConfig{timeout: client.defaultTimeout, maxAttempts: client.maxAttempts}
	for _, option := range options {
		if option == nil {
			return callConfig{}, &ValidationError{Message: "call option must not be nil"}
		}
		if err := option(&config); err != nil {
			return callConfig{}, err
		}
	}
	if config.timeout <= 0 || config.timeout > maximumTimeout {
		return callConfig{}, &ValidationError{Message: "call timeout must be in (0, 5m]"}
	}
	if config.maxAttempts < 1 || config.maxAttempts > 8 {
		return callConfig{}, &ValidationError{Message: "call max attempts must be in 1..8"}
	}
	return config, nil
}

func (client *GRPCClient) call(
	ctx context.Context,
	operationID string,
	request Request,
	options ...CallOption,
) (Response, error) {
	definition, ok := operations[operationID]
	if !ok || definition.Stream {
		return Response{}, &ValidationError{Message: "operation is unknown or streaming"}
	}
	config, err := client.config(options)
	if err != nil {
		return Response{}, err
	}
	if config.resumeFrom != "" {
		return Response{}, &ValidationError{Message: "stream resume cannot be applied to a unary operation"}
	}
	wire, err := grpcOperationRequest(definition, request, "")
	if err != nil {
		return Response{}, err
	}
	attempts := config.maxAttempts
	if operationID == "dispatchEffect" || (definition.Mutation && request.idempotencyKey == "") {
		attempts = 1
	}
	callContext, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		response, callErr := client.callOnce(callContext, definition, request, wire)
		if callErr == nil {
			return response, nil
		}
		lastErr = callErr
		if attempt == attempts || !retryableError(callErr) {
			return Response{}, callErr
		}
		if err := waitGRPCBackoff(callContext, attempt); err != nil {
			return Response{}, err
		}
	}
	return Response{}, lastErr
}

func (client *GRPCClient) callOnce(
	ctx context.Context,
	definition OperationDefinition,
	request Request,
	wire *cigarv1.OperationRequest,
) (Response, error) {
	requestContext, err := client.metadataContext(ctx, definition, request, "")
	if err != nil {
		return Response{}, err
	}
	var header, trailer metadata.MD
	output := new(cigarv1.OperationResponse)
	err = client.connection.Invoke(
		requestContext,
		grpcMethod(definition),
		wire,
		output,
		grpc.StaticMethod(),
		grpc.Header(&header),
		grpc.Trailer(&trailer),
		grpc.MaxCallSendMsgSize(definition.RequestMaxBytes+grpcEnvelopeOverheadBytes),
		grpc.MaxCallRecvMsgSize(definition.ResponseMaxBytes+grpcEnvelopeOverheadBytes),
	)
	if err != nil {
		return Response{}, decodeGRPCError(requestContext, err, trailer)
	}
	return grpcOperationResponse(definition, output, header)
}

func grpcOperationRequest(
	definition OperationDefinition,
	request Request,
	resume string,
) (*cigarv1.OperationRequest, error) {
	_, parameters, err := bindPath(definition.HTTPPath, request.pathParameters)
	if err != nil {
		return nil, err
	}
	if len(request.payloadCBOR) > definition.RequestMaxBytes {
		return nil, &ValidationError{Message: "request payload exceeds operation bound"}
	}
	if request.pageCursor != "" && len(request.pageCursor) > 4096 {
		return nil, &ValidationError{Message: "page cursor exceeds its bound"}
	}
	if request.pageSize > 1000 {
		return nil, &ValidationError{Message: "page size must be in 1..1000"}
	}
	if definition.HTTPMethod == http.MethodGet {
		if len(request.payloadCBOR) != 0 || request.idempotencyKey != "" || request.expectedRevision != "" || request.dryRun {
			return nil, &ValidationError{Message: "GET operations do not carry payload or mutation metadata"}
		}
	} else {
		if definition.IdempotencyRequired {
			if !boundedVisibleASCII(request.idempotencyKey, 256) {
				return nil, &ValidationError{Message: definition.OperationID + " requires a bounded idempotency key"}
			}
		} else if request.idempotencyKey != "" {
			return nil, &ValidationError{Message: definition.OperationID + " does not accept an idempotency key"}
		}
		if definition.RevisionRequired {
			if len(request.expectedRevision) < 1 || len(request.expectedRevision) > 256 {
				return nil, &ValidationError{Message: definition.OperationID + " requires an expected revision"}
			}
		} else if request.expectedRevision != "" {
			return nil, &ValidationError{Message: definition.OperationID + " does not accept an expected revision"}
		}
	}
	if definition.Stream {
		if request.pageCursor != "" || request.pageSize != 0 {
			return nil, &ValidationError{Message: "gRPC stream resume is distinct from pagination"}
		}
		if resume != "" && !boundedVisibleASCII(resume, 256) {
			return nil, &ValidationError{Message: "stream resume identity must be 1..256 visible ASCII bytes"}
		}
	}
	wireParameters := make([]*cigarv1.PathParameter, len(parameters))
	for index, parameter := range parameters {
		wireParameters[index] = &cigarv1.PathParameter{Name: parameter.name, Value: parameter.value}
	}
	pageCursor := request.pageCursor
	if definition.Stream {
		pageCursor = resume
	}
	return &cigarv1.OperationRequest{
		OperationId: definition.OperationID, IdempotencyKey: request.idempotencyKey,
		ExpectedRevision: request.expectedRevision, PayloadCbor: append([]byte(nil), request.payloadCBOR...),
		PageCursor: pageCursor, PageSize: request.pageSize, PathParameters: wireParameters, DryRun: request.dryRun,
	}, nil
}

func grpcOperationResponse(
	definition OperationDefinition,
	wire *cigarv1.OperationResponse,
	header metadata.MD,
) (Response, error) {
	if wire == nil || wire.OperationId != definition.OperationID || len(wire.PayloadCbor) > definition.ResponseMaxBytes ||
		len(wire.SemanticEtag) > 256 || len(wire.NextPageCursor) > 4096 {
		return Response{}, &TransportError{Message: "gRPC response metadata or payload is invalid"}
	}
	etag, err := uniqueGRPCMetadata(header, "etag")
	if err != nil || (etag != "" && etag != wire.SemanticEtag) {
		return Response{}, &TransportError{Message: "gRPC response ETag metadata is inconsistent", Cause: err}
	}
	cursor, err := uniqueGRPCMetadata(header, "x-cigar-next-page-cursor")
	if err != nil || (cursor != "" && cursor != wire.NextPageCursor) {
		return Response{}, &TransportError{Message: "gRPC response cursor metadata is inconsistent", Cause: err}
	}
	return Response{
		operationID: wire.OperationId, payloadCBOR: append([]byte(nil), wire.PayloadCbor...),
		semanticETag: wire.SemanticEtag, nextPageCursor: wire.NextPageCursor,
	}, nil
}

func (client *GRPCClient) metadataContext(
	ctx context.Context,
	definition OperationDefinition,
	request Request,
	resume string,
) (context.Context, error) {
	existing, _ := metadata.FromOutgoingContext(ctx)
	owned := existing.Copy()
	for _, key := range []string{"authorization", "idempotency-key", "if-match", "last-event-id", "x-cigar-operation-id"} {
		if len(owned.Get(key)) != 0 {
			return nil, &ValidationError{Message: "caller metadata conflicts with SDK-owned " + key}
		}
	}
	owned.Set("x-cigar-operation-id", definition.OperationID)
	if request.idempotencyKey != "" {
		owned.Set("idempotency-key", request.idempotencyKey)
	}
	if request.expectedRevision != "" {
		owned.Set("if-match", request.expectedRevision)
	}
	if resume != "" {
		owned.Set("last-event-id", resume)
	}
	token := client.bearerToken
	if client.tokenProvider != nil {
		resolved, err := client.tokenProvider(ctx)
		if err != nil {
			return nil, &TransportError{Message: "bearer token provider failed", Cause: err}
		}
		token = resolved
	}
	if !boundedVisibleASCII(token, 8192) {
		return nil, &ValidationError{Message: "bearer token must be 1..8192 visible ASCII bytes"}
	}
	owned.Set("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(ctx, owned), nil
}

func grpcMethod(definition OperationDefinition) string {
	return "/cigar.v1." + definition.Service + "/" + definition.RPC
}

func uniqueGRPCMetadata(source metadata.MD, key string) (string, error) {
	values := source.Get(key)
	if len(values) > 1 {
		return "", &TransportError{Message: "gRPC metadata field is duplicated"}
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}

func decodeGRPCError(ctx context.Context, source error, trailer metadata.MD) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &TimeoutError{Cause: source}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	grpcStatus, ok := status.FromError(source)
	if !ok {
		return &TransportError{Message: "gRPC exchange failed", Cause: source}
	}
	details := trailer.Get("grpc-status-details-bin")
	if len(details) == 1 && len(details[0]) > 0 && len(details[0]) <= maximumProblemBytes {
		var envelope struct {
			HTTPStatus int `json:"http_status"`
		}
		if json.Unmarshal([]byte(details[0]), &envelope) == nil && envelope.HTTPStatus != 0 {
			problem := decodeProblem(envelope.HTTPStatus, []byte(details[0]))
			var apiError *APIError
			if errors.As(problem, &apiError) {
				definition := errorCatalog[apiError.Code]
				if definition.GRPCStatus != grpcCodeName(grpcStatus.Code()) {
					return &TransportError{Message: "gRPC status disagrees with the frozen error catalog"}
				}
			}
			return problem
		}
	}
	if grpcStatus.Code() == codes.DeadlineExceeded {
		return &TimeoutError{Cause: source}
	}
	return &TransportError{Message: "gRPC exchange returned an unverified status", Cause: source}
}

func grpcCodeName(code codes.Code) string {
	return map[codes.Code]string{
		codes.InvalidArgument: "INVALID_ARGUMENT", codes.ResourceExhausted: "RESOURCE_EXHAUSTED",
		codes.Unauthenticated: "UNAUTHENTICATED", codes.PermissionDenied: "PERMISSION_DENIED",
		codes.Unavailable: "UNAVAILABLE", codes.FailedPrecondition: "FAILED_PRECONDITION",
		codes.Aborted: "ABORTED", codes.DeadlineExceeded: "DEADLINE_EXCEEDED", codes.Internal: "INTERNAL",
	}[code]
}

func waitGRPCBackoff(ctx context.Context, attempt int) error {
	delay := min(100*time.Millisecond*time.Duration(1<<(attempt-1)), time.Second)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &TimeoutError{Cause: ctx.Err()}
		}
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type grpcEventStream struct {
	client     *GRPCClient
	ctx        context.Context
	cancel     context.CancelFunc
	definition OperationDefinition
	request    Request
	config     callConfig
	lastID     string
	seen       map[string]struct{}
	attempt    int
	stream     grpc.ClientStream
	event      Event
	err        error
	closed     atomic.Bool
	stateMu    sync.RWMutex
}

func (client *GRPCClient) stream(
	ctx context.Context,
	operationID string,
	request Request,
	options ...CallOption,
) (*grpcEventStream, error) {
	definition, ok := operations[operationID]
	if !ok || !definition.Stream {
		return nil, &ValidationError{Message: "operation is unknown or not streaming"}
	}
	config, err := client.config(options)
	if err != nil {
		return nil, err
	}
	if _, err := grpcOperationRequest(definition, request, config.resumeFrom); err != nil {
		return nil, err
	}
	streamContext, cancel := context.WithTimeout(ctx, config.timeout)
	seen := make(map[string]struct{})
	if config.resumeFrom != "" {
		seen[config.resumeFrom] = struct{}{}
	}
	return &grpcEventStream{
		client: client, ctx: streamContext, cancel: cancel, definition: definition,
		request: request, config: config, lastID: config.resumeFrom, seen: seen,
	}, nil
}

func (stream *grpcEventStream) Next() bool {
	if stream.closed.Load() || stream.Err() != nil {
		return false
	}
	for stream.attempt < stream.config.maxAttempts {
		if stream.stream == nil {
			if err := stream.open(); err != nil {
				stream.attempt++
				if stream.attempt >= stream.config.maxAttempts || !retryableError(err) {
					stream.setErr(err)
					return false
				}
				if err := waitGRPCBackoff(stream.ctx, stream.attempt); err != nil {
					stream.setErr(err)
					return false
				}
				continue
			}
			stream.attempt++
		}
		wire := new(cigarv1.OperationEvent)
		err := stream.stream.RecvMsg(wire)
		if err != nil {
			trailer := stream.stream.Trailer()
			stream.stream = nil
			if errors.Is(err, io.EOF) {
				if stream.attempt >= stream.config.maxAttempts {
					return false
				}
			} else {
				decoded := decodeGRPCError(stream.ctx, err, trailer)
				if stream.attempt >= stream.config.maxAttempts || !retryableError(decoded) {
					stream.setErr(decoded)
					return false
				}
			}
			if err := waitGRPCBackoff(stream.ctx, stream.attempt); err != nil {
				stream.setErr(err)
				return false
			}
			continue
		}
		if wire.OperationId != stream.definition.OperationID || !boundedVisibleASCII(wire.EventId, 256) ||
			len(wire.PayloadCbor) > stream.definition.EventMaxBytes {
			stream.setErr(&TransportError{Message: "gRPC event identity or payload is invalid"})
			return false
		}
		if _, duplicate := stream.seen[wire.EventId]; duplicate {
			continue
		}
		if len(stream.seen) >= maximumPayloadNodes {
			stream.setErr(&TransportError{Message: "event identity set exceeds its bound"})
			return false
		}
		stream.seen[wire.EventId] = struct{}{}
		stream.stateMu.Lock()
		stream.event = Event{operationID: wire.OperationId, eventID: wire.EventId, payloadCBOR: append([]byte(nil), wire.PayloadCbor...)}
		stream.lastID = wire.EventId
		stream.stateMu.Unlock()
		return true
	}
	return false
}

func (stream *grpcEventStream) open() error {
	if deadline, ok := stream.ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
		return &TimeoutError{Cause: context.DeadlineExceeded}
	}
	resume := stream.LastEventID()
	wire, err := grpcOperationRequest(stream.definition, stream.request, resume)
	if err != nil {
		return err
	}
	requestContext, err := stream.client.metadataContext(stream.ctx, stream.definition, stream.request, resume)
	if err != nil {
		return err
	}
	clientStream, err := stream.client.connection.NewStream(
		requestContext,
		&grpc.StreamDesc{ServerStreams: true},
		grpcMethod(stream.definition),
		grpc.StaticMethod(),
		grpc.MaxCallSendMsgSize(stream.definition.RequestMaxBytes+grpcEnvelopeOverheadBytes),
		grpc.MaxCallRecvMsgSize(stream.definition.EventMaxBytes+grpcEnvelopeOverheadBytes),
	)
	if err != nil {
		return decodeGRPCError(requestContext, err, nil)
	}
	if err := clientStream.SendMsg(wire); err != nil {
		return decodeGRPCError(requestContext, err, clientStream.Trailer())
	}
	if err := clientStream.CloseSend(); err != nil {
		return decodeGRPCError(requestContext, err, clientStream.Trailer())
	}
	stream.stream = clientStream
	return nil
}

func (stream *grpcEventStream) Event() Event {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return Event{operationID: stream.event.operationID, eventID: stream.event.eventID, payloadCBOR: append([]byte(nil), stream.event.payloadCBOR...)}
}

func (stream *grpcEventStream) LastEventID() string {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.lastID
}

func (stream *grpcEventStream) Err() error {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.err
}

func (stream *grpcEventStream) Close() error {
	if stream.closed.Swap(true) {
		return nil
	}
	stream.cancel()
	return nil
}

func (stream *grpcEventStream) setErr(err error) {
	stream.stateMu.Lock()
	stream.err = err
	stream.stateMu.Unlock()
}

// Negotiate fetches version and capabilities through generated gRPC methods.
func (client *GRPCClient) Negotiate(ctx context.Context, options ...CallOption) (Compatibility, error) {
	invocationOptions := make([]InvocationOption, 0, len(options))
	for _, option := range options {
		invocationOptions = append(invocationOptions, withRawCallOption(option))
	}
	version, err := client.GetVersion(ctx, EmptyRequest{}, invocationOptions...)
	if err != nil {
		return Compatibility{}, err
	}
	capabilities, err := client.GetCapabilities(ctx, EmptyRequest{}, invocationOptions...)
	if err != nil {
		return Compatibility{}, err
	}
	return Compatibility{APIVersion: "1", Version: version, Capabilities: capabilities}, nil
}
