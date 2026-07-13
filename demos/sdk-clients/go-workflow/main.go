// Command go-workflow exercises the public Go SDK over an in-memory gRPC transport.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	cigar "github.com/CIGAR/cigar/sdk/go"
	cigarv1 "github.com/CIGAR/cigar/sdk/go/gen/cigarv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type pathParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type operation struct {
	OperationID    string          `json:"operation_id"`
	IdempotencyKey *string         `json:"idempotency_key"`
	PathParameters []pathParameter `json:"path_parameters"`
	Request        json.RawMessage `json:"request"`
	RequestCBOR    string          `json:"request_cbor_base64url"`
	Response       json.RawMessage `json:"response"`
	ResponseCBOR   string          `json:"response_cbor_base64url"`
}

type fixture struct {
	SchemaVersion          string      `json:"schema_version"`
	ExpectedOperations     []string    `json:"expected_operations"`
	ExpectedBundleID       string      `json:"expected_bundle_id"`
	ExpectedManifestID     string      `json:"expected_manifest_id"`
	ExpectedContractDigest string      `json:"expected_contract_digest"`
	Operations             []operation `json:"operations"`
}

type recorder struct {
	mu       sync.Mutex
	fixture  *fixture
	position int
	err      error
}

func (r *recorder) call(ctx context.Context, operationID string, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.position >= len(r.fixture.Operations) {
		r.err = errors.New("SDK issued an unexpected extra operation")
		return nil, r.err
	}
	expected := r.fixture.Operations[r.position]
	r.position++
	if operationID != expected.OperationID || request.GetOperationId() != expected.OperationID {
		r.err = errors.New("SDK operation identity differs from the recorded operation")
		return nil, r.err
	}
	incoming, _ := metadata.FromIncomingContext(ctx)
	if values := incoming.Get("x-cigar-operation-id"); len(values) != 1 || values[0] != expected.OperationID {
		r.err = errors.New("SDK operation metadata differs from the recorded operation")
		return nil, r.err
	}
	expectedKey := ""
	if expected.IdempotencyKey != nil {
		expectedKey = *expected.IdempotencyKey
	}
	if request.GetIdempotencyKey() != expectedKey {
		r.err = errors.New("SDK idempotency field differs from the recorded request")
		return nil, r.err
	}
	keyMetadata := incoming.Get("idempotency-key")
	if (expectedKey == "" && len(keyMetadata) != 0) || (expectedKey != "" && (len(keyMetadata) != 1 || keyMetadata[0] != expectedKey)) {
		r.err = errors.New("SDK idempotency metadata differs from the recorded request")
		return nil, r.err
	}
	if len(request.GetPathParameters()) != len(expected.PathParameters) {
		r.err = errors.New("SDK path parameter count differs from the recorded request")
		return nil, r.err
	}
	for index, parameter := range request.GetPathParameters() {
		if parameter.GetName() != expected.PathParameters[index].Name || parameter.GetValue() != expected.PathParameters[index].Value {
			r.err = errors.New("SDK path parameters differ from the recorded request")
			return nil, r.err
		}
	}
	if expected.OperationID == "getContextBundleManifest" {
		if len(request.GetPayloadCbor()) != 0 {
			r.err = errors.New("SDK emitted a payload for a GET operation")
			return nil, r.err
		}
	} else {
		expectedPayload, decodeErr := base64.RawURLEncoding.DecodeString(expected.RequestCBOR)
		if decodeErr != nil || !bytes.Equal(request.GetPayloadCbor(), expectedPayload) {
			r.err = errors.New("SDK typed request CBOR differs from the fixture")
			return nil, r.err
		}
	}
	response, decodeErr := base64.RawURLEncoding.DecodeString(expected.ResponseCBOR)
	if decodeErr != nil {
		r.err = errors.New("fixture response CBOR is invalid")
		return nil, r.err
	}
	return &cigarv1.OperationResponse{OperationId: expected.OperationID, PayloadCbor: response}, nil
}

func (r *recorder) complete() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.position != len(r.fixture.Operations) {
		return errors.New("SDK did not execute every workflow operation")
	}
	return nil
}

type catalogServer struct {
	cigarv1.UnimplementedCatalogServiceServer
	recorder *recorder
}

func (s *catalogServer) DiscoverSources(ctx context.Context, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	return s.recorder.call(ctx, "discoverSources", request)
}

func (s *catalogServer) IngestCatalog(ctx context.Context, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	return s.recorder.call(ctx, "ingestCatalog", request)
}

type contextServer struct {
	cigarv1.UnimplementedContextServiceServer
	recorder *recorder
}

func (s *contextServer) CreateContextPlan(ctx context.Context, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	return s.recorder.call(ctx, "createContextPlan", request)
}

func (s *contextServer) CompileContextBundle(ctx context.Context, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	return s.recorder.call(ctx, "compileContextBundle", request)
}

func (s *contextServer) GetContextBundleManifest(ctx context.Context, request *cigarv1.OperationRequest) (*cigarv1.OperationResponse, error) {
	return s.recorder.call(ctx, "getContextBundleManifest", request)
}

func decodePayload[T any](source json.RawMessage) (T, error) {
	var result T
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if decoder.Decode(new(any)) == nil {
		return result, errors.New("fixture payload has trailing JSON")
	}
	return result, nil
}

func operationByID(source *fixture, operationID string) (operation, error) {
	for _, candidate := range source.Operations {
		if candidate.OperationID == operationID {
			return candidate, nil
		}
	}
	return operation{}, errors.New("fixture operation is missing")
}

func appendHead(target *bytes.Buffer, major byte, value uint64) {
	switch {
	case value < 24:
		target.WriteByte(major<<5 | byte(value))
	case value <= 0xff:
		target.Write([]byte{major<<5 | 24, byte(value)})
	case value <= 0xffff:
		target.WriteByte(major<<5 | 25)
		_ = binary.Write(target, binary.BigEndian, uint16(value))
	case value <= 0xffff_ffff:
		target.WriteByte(major<<5 | 26)
		_ = binary.Write(target, binary.BigEndian, uint32(value))
	default:
		target.WriteByte(major<<5 | 27)
		_ = binary.Write(target, binary.BigEndian, value)
	}
}

func deterministicCBOR(value any) ([]byte, error) {
	var result bytes.Buffer
	var encode func(any) error
	encode = func(current any) error {
		switch typed := current.(type) {
		case bool:
			if typed {
				result.WriteByte(0xf5)
			} else {
				result.WriteByte(0xf4)
			}
		case string:
			appendHead(&result, 3, uint64(len([]byte(typed))))
			result.WriteString(typed)
		case json.Number:
			integer, err := typed.Int64()
			if err != nil || integer < 0 {
				return errors.New("manifest contains a non-unsigned integer")
			}
			appendHead(&result, 0, uint64(integer))
		case uint64:
			appendHead(&result, 0, typed)
		case []any:
			appendHead(&result, 4, uint64(len(typed)))
			for _, child := range typed {
				if err := encode(child); err != nil {
					return err
				}
			}
		case map[string]any:
			type entry struct {
				key []byte
				val any
			}
			entries := make([]entry, 0, len(typed))
			for key, child := range typed {
				var keyBuffer bytes.Buffer
				appendHead(&keyBuffer, 3, uint64(len([]byte(key))))
				keyBuffer.WriteString(key)
				entries = append(entries, entry{key: keyBuffer.Bytes(), val: child})
			}
			sort.Slice(entries, func(left, right int) bool { return bytes.Compare(entries[left].key, entries[right].key) < 0 })
			appendHead(&result, 5, uint64(len(entries)))
			for _, item := range entries {
				result.Write(item.key)
				if err := encode(item.val); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("manifest contains unsupported canonical value %T", current)
		}
		return nil
	}
	if err := encode(value); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func canonicalRawCBOR(source json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return deterministicCBOR(value)
}

func manifestID(manifest cigar.SelectionManifest) (string, error) {
	document, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	delete(value, "manifest_id")
	canonical, err := deterministicCBOR([]any{json.Number("3"), value})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("CIGAR-MANIFEST\x00v1\x00"), canonical...))
	return "1220" + hex.EncodeToString(digest[:]), nil
}

func run() error {
	source, err := os.ReadFile("../workflow-fixture-v1.json")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var fixture fixture
	if err := decoder.Decode(&fixture); err != nil {
		return err
	}
	if fixture.SchemaVersion != "cigar.sdk-recorded-workflow.v1" || len(fixture.Operations) != 5 {
		return errors.New("workflow fixture schema or operation inventory is unsupported")
	}
	for _, operation := range fixture.Operations {
		requestCBOR, requestErr := canonicalRawCBOR(operation.Request)
		responseCBOR, responseErr := canonicalRawCBOR(operation.Response)
		if requestErr != nil || responseErr != nil ||
			base64.RawURLEncoding.EncodeToString(requestCBOR) != operation.RequestCBOR ||
			base64.RawURLEncoding.EncodeToString(responseCBOR) != operation.ResponseCBOR {
			return errors.New("workflow fixture contains non-canonical operation CBOR")
		}
	}
	planOperation, operationErr := operationByID(&fixture, "createContextPlan")
	if operationErr != nil {
		return operationErr
	}
	var planRequestValue map[string]json.RawMessage
	if err := json.Unmarshal(planOperation.Request, &planRequestValue); err != nil {
		return err
	}
	contractCBOR, err := canonicalRawCBOR(planRequestValue["contract"])
	if err != nil {
		return err
	}
	contractHash := sha256.Sum256(append([]byte("CIGAR-CONTEXT-CONTRACT\x00v1\x00"), contractCBOR...))
	if "1220"+hex.EncodeToString(contractHash[:]) != fixture.ExpectedContractDigest {
		return errors.New("workflow contract digest differs from its canonical request")
	}
	recorder := &recorder{fixture: &fixture}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	cigarv1.RegisterCatalogServiceServer(server, &catalogServer{recorder: recorder})
	cigarv1.RegisterContextServiceServer(server, &contextServer{recorder: recorder})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		server.Stop()
		_ = listener.Close()
		<-serveDone
	}()
	connection, err := grpc.NewClient(
		"passthrough:///cigar-recorded-workflow",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDisableRetry(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	client, err := cigar.NewGRPCClient(cigar.GRPCClientOptions{
		Connection: connection, TrustCustomConnectionNoRetries: true,
		DefaultTimeout: 5 * time.Second, MaxAttempts: 1,
	})
	if err != nil {
		return err
	}
	ctx := context.Background()
	discoverOperation, _ := operationByID(&fixture, "discoverSources")
	discoverRequest, err := decodePayload[cigar.DiscoverSourcesRequest](discoverOperation.Request)
	if err != nil {
		return err
	}
	discovered, err := client.DiscoverSources(ctx, discoverRequest)
	if err != nil {
		return err
	}
	ingestOperation, _ := operationByID(&fixture, "ingestCatalog")
	ingestRequest, err := decodePayload[cigar.IngestCatalogRequest](ingestOperation.Request)
	if err != nil {
		return err
	}
	ingested, err := client.IngestCatalog(ctx, ingestRequest, cigar.WithInvocationIdempotencyKey(*ingestOperation.IdempotencyKey))
	if err != nil {
		return err
	}
	planRequest, err := decodePayload[cigar.CreateContextPlanRequest](planOperation.Request)
	if err != nil {
		return err
	}
	planned, err := client.CreateContextPlan(ctx, planRequest, cigar.WithInvocationIdempotencyKey(*planOperation.IdempotencyKey))
	if err != nil {
		return err
	}
	compileOperation, _ := operationByID(&fixture, "compileContextBundle")
	compileRequest, err := decodePayload[cigar.CompileContextBundleRequest](compileOperation.Request)
	if err != nil {
		return err
	}
	compiled, err := client.CompileContextBundle(ctx, compileRequest, cigar.WithInvocationIdempotencyKey(*compileOperation.IdempotencyKey))
	if err != nil {
		return err
	}
	manifestOperation, _ := operationByID(&fixture, "getContextBundleManifest")
	manifestRequest, err := decodePayload[cigar.BundleIdRequest](manifestOperation.Request)
	if err != nil {
		return err
	}
	manifest, err := client.GetContextBundleManifest(ctx, manifestRequest)
	if err != nil {
		return err
	}
	if err := recorder.complete(); err != nil {
		return err
	}
	if discovered.Payload().SourceID != discoverRequest.SourceID || ingested.Payload().SnapshotID == "" || planned.Payload().BundleID != fixture.ExpectedBundleID {
		return errors.New("workflow response chain differs from the fixture")
	}
	bundleDocument, err := json.Marshal(compiled.Payload())
	if err != nil {
		return err
	}
	verifiedBundleID, err := cigar.VerifyBundleJSON(bundleDocument)
	if err != nil || verifiedBundleID != fixture.ExpectedBundleID {
		return errors.New("compiled bundle identity verification failed")
	}
	verifiedManifestID, err := manifestID(manifest.Payload())
	if err != nil || verifiedManifestID != fixture.ExpectedManifestID {
		return errors.New("selection manifest identity verification failed")
	}
	if compiled.Payload().ManifestDigest != manifest.Payload().ManifestID ||
		compiled.Payload().ContractDigest != manifest.Payload().ContractDigest ||
		compiled.Payload().ContractDigest != fixture.ExpectedContractDigest {
		return errors.New("compiled bundle and manifest are not bound to the same contract")
	}
	if strings.Join(fixture.ExpectedOperations, ",") != "discoverSources,ingestCatalog,createContextPlan,compileContextBundle,getContextBundleManifest" {
		return errors.New("workflow fixture operation order differs from the frozen sequence")
	}
	fmt.Println(fixture.ExpectedBundleID)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "go-workflow:", err)
		os.Exit(1)
	}
}
