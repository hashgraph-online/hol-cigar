package cigar

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cigarv1 "github.com/CIGAR/cigar/sdk/go/gen/cigarv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type operationsGRPCServer struct {
	cigarv1.UnimplementedOperationsServiceServer
}

func (operationsGRPCServer) GetVersion(
	_ context.Context,
	request *cigarv1.OperationRequest,
) (*cigarv1.OperationResponse, error) {
	return &cigarv1.OperationResponse{
		OperationId: request.OperationId,
		PayloadCbor: append([]byte(nil), request.PayloadCbor...),
	}, nil
}

type spaceGRPCServer struct {
	cigarv1.UnimplementedSpaceServiceServer
	closed chan struct{}
}

func (server spaceGRPCServer) SubscribeSpaceEvents(
	request *cigarv1.OperationRequest,
	stream grpc.ServerStreamingServer[cigarv1.OperationEvent],
) error {
	if err := stream.Send(&cigarv1.OperationEvent{
		OperationId: request.OperationId,
		EventId:     "event-1",
		PayloadCbor: append([]byte(nil), request.PayloadCbor...),
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	close(server.closed)
	return stream.Context().Err()
}

func TestGeneratedGRPCUnaryAndClosableStream(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	closed := make(chan struct{})
	cigarv1.RegisterOperationsServiceServer(grpcServer, operationsGRPCServer{})
	cigarv1.RegisterSpaceServiceServer(grpcServer, spaceGRPCServer{closed: closed})
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///cigar-buffer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	operations := cigarv1.NewOperationsServiceClient(connection)
	unary, err := operations.GetVersion(context.Background(), &cigarv1.OperationRequest{
		OperationId: "getVersion",
		PayloadCbor: []byte{1, 2, 3},
	})
	if err != nil || unary.OperationId != "getVersion" || string(unary.PayloadCbor) != "\x01\x02\x03" {
		t.Fatalf("generated unary client contract failed: response=%v err=%v", unary, err)
	}

	streamContext, cancel := context.WithCancel(context.Background())
	spaces := cigarv1.NewSpaceServiceClient(connection)
	stream, err := spaces.SubscribeSpaceEvents(streamContext, &cigarv1.OperationRequest{
		OperationId: "subscribeSpaceEvents",
		PayloadCbor: []byte{4},
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv()
	if err != nil || event.EventId != "event-1" || string(event.PayloadCbor) != "\x04" {
		t.Fatalf("generated server-stream client contract failed: event=%v err=%v", event, err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := stream.Recv(); err == nil || !errors.Is(streamContext.Err(), context.Canceled) {
		t.Fatalf("cancelled generated stream did not terminate: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("server did not observe generated stream cancellation")
	}
}

type highLevelOperationsGRPCServer struct {
	cigarv1.UnimplementedOperationsServiceServer
	attempts atomic.Int32
}

func (server *highLevelOperationsGRPCServer) GetVersion(
	ctx context.Context,
	request *cigarv1.OperationRequest,
) (*cigarv1.OperationResponse, error) {
	if server.attempts.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "transient")
	}
	if request.OperationId != "getVersion" || len(request.PayloadCbor) != 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	values := metadata.ValueFromIncomingContext(ctx, "x-cigar-operation-id")
	authorization := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 || values[0] != "getVersion" || len(authorization) != 1 || authorization[0] != "Bearer test-token" {
		return nil, status.Error(codes.InvalidArgument, "invalid metadata")
	}
	payload, err := deterministicCBOR(map[string]any{
		"version": "0.1.0", "source_revision": "test", "protocol_min": "1.0",
		"protocol_max": "1.x", "build_profile": "test", "enabled_features": []any{},
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "fixture")
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs("etag", "version-etag")); err != nil {
		return nil, err
	}
	return &cigarv1.OperationResponse{
		OperationId: request.OperationId, PayloadCbor: payload, SemanticEtag: "version-etag",
	}, nil
}

type highLevelSpaceGRPCServer struct {
	cigarv1.UnimplementedSpaceServiceServer
	attempts atomic.Int32
	closed   chan struct{}
	once     sync.Once
}

func (server *highLevelSpaceGRPCServer) SubscribeSpaceEvents(
	request *cigarv1.OperationRequest,
	stream grpc.ServerStreamingServer[cigarv1.OperationEvent],
) error {
	attempt := server.attempts.Add(1)
	expectedResume := "event-0"
	if attempt > 1 {
		expectedResume = "event-1"
	}
	resume := metadata.ValueFromIncomingContext(stream.Context(), "last-event-id")
	if request.OperationId != "subscribeSpaceEvents" || request.PageCursor != expectedResume ||
		len(resume) != 1 || resume[0] != expectedResume {
		return status.Error(codes.InvalidArgument, "resume identity was not preserved")
	}
	payload, err := deterministicCBOR(map[string]any{
		"space_id":   "01900000-0000-7000-8000-000000000001",
		"project_id": "01900000-0000-7000-8000-000000000002",
		"event": map[string]any{
			"event_id":       "01900000-0000-7000-8000-000000000003",
			"kind":           "context_committed",
			"payload_digest": "12200000000000000000000000000000000000000000000000000000000000000000",
		},
	})
	if err != nil {
		return status.Error(codes.Internal, "fixture")
	}
	eventID := "event-1"
	if attempt > 1 {
		eventID = "event-2"
	}
	if err := stream.Send(&cigarv1.OperationEvent{
		OperationId: request.OperationId, EventId: eventID, PayloadCbor: payload,
	}); err != nil {
		return err
	}
	if attempt == 1 {
		return status.Error(codes.Unavailable, "reconnect")
	}
	<-stream.Context().Done()
	server.once.Do(func() { close(server.closed) })
	return stream.Context().Err()
}

type highLevelEffectGRPCServer struct {
	cigarv1.UnimplementedEffectServiceServer
	attempts atomic.Int32
}

func (server *highLevelEffectGRPCServer) DispatchEffect(
	_ context.Context,
	_ *cigarv1.OperationRequest,
) (*cigarv1.OperationResponse, error) {
	server.attempts.Add(1)
	return nil, status.Error(codes.Unavailable, "remote outcome unknown")
}

func TestHighLevelGRPCUnaryResumeCancellationAndUnsafeRetry(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	operations := &highLevelOperationsGRPCServer{}
	spaces := &highLevelSpaceGRPCServer{closed: make(chan struct{})}
	effects := &highLevelEffectGRPCServer{}
	cigarv1.RegisterOperationsServiceServer(grpcServer, operations)
	cigarv1.RegisterSpaceServiceServer(grpcServer, spaces)
	cigarv1.RegisterEffectServiceServer(grpcServer, effects)
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///cigar-high-level-buffer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := NewGRPCClient(GRPCClientOptions{Connection: connection}); err == nil {
		t.Fatal("custom gRPC connection was accepted without no-retry acknowledgement")
	}
	client, err := NewGRPCClient(GRPCClientOptions{
		Connection: connection, TrustCustomConnectionNoRetries: true,
		BearerToken: "test-token", DefaultTimeout: 2 * time.Second, MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	version, err := client.GetVersion(context.Background(), EmptyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if version.OperationID() != "getVersion" || version.SemanticETag() != "version-etag" ||
		version.Payload().ProtocolMax != "1.x" || operations.attempts.Load() != 2 {
		t.Fatalf("high-level gRPC unary response or retry differs: response=%+v attempts=%d", version.Payload(), operations.attempts.Load())
	}
	if _, err := client.GetVersion(context.Background(), EmptyRequest{}, WithInvocationResume("event-1")); err == nil {
		t.Fatal("unary gRPC call accepted stream resume metadata")
	}

	stream, err := client.SubscribeSpaceEvents(
		context.Background(),
		SpaceIdRequest{SpaceID: "01900000-0000-7000-8000-000000000001"},
		WithInvocationResume("event-0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Next() || stream.Event().EventID() != "event-1" {
		t.Fatalf("first generated gRPC event failed: event=%+v err=%v", stream.Event(), stream.Err())
	}
	if !stream.Next() || stream.Event().EventID() != "event-2" || stream.LastEventID() != "event-2" {
		t.Fatalf("resumed generated gRPC event failed: event=%+v err=%v", stream.Event(), stream.Err())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-spaces.closed:
	case <-time.After(time.Second):
		t.Fatal("server did not observe high-level stream cancellation")
	}

	_, err = client.DispatchEffect(
		context.Background(),
		EffectIdRequest{EffectID: "01900000-0000-7000-8000-000000000004"},
		WithInvocationIdempotencyKey("dispatch-once"),
		WithInvocationExpectedRevision("revision-1"),
		WithInvocationMaxAttempts(8),
	)
	if err == nil || effects.attempts.Load() != 1 {
		t.Fatalf("unsafe dispatch was retried: error=%v attempts=%d", err, effects.attempts.Load())
	}
}

func TestGRPCProblemDetailsMapToStableTypedError(t *testing.T) {
	fixture, err := os.ReadFile("../fixtures/problem-index-unavailable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeGRPCError(
		context.Background(),
		status.Error(codes.Unavailable, "safe public message"),
		metadata.MD{"grpc-status-details-bin": []string{string(fixture)}},
	)
	var apiError *APIError
	if !errors.As(decoded, &apiError) || apiError.Code != "INDEX_UNAVAILABLE" || apiError.Retry != RetryAfterBackoff {
		t.Fatalf("gRPC problem did not map to stable typed error: %v", decoded)
	}
}
