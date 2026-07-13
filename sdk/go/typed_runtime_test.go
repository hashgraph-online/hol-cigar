package cigar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	contextv1 "github.com/CIGAR/cigar/sdk/go/gen/contextv1"
)

const testUUID = "01900000-0000-7000-8000-000000000001"

var testDigest = "1220" + strings.Repeat("1", 64)

func nominalWireResponse(t *testing.T, operationID string, payload any) string {
	t.Helper()
	document, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	value, err := parseStrictJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := deterministicCBOR(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(map[string]string{
		"operation_id": operationID,
		"payload_cbor": base64.RawURLEncoding.EncodeToString(encoded),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func TestNominalGeneratedClientValidatesAndCopies(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, body)
		writer.Header().Set("content-type", "application/json")
		writer.Header().Set("x-cigar-api-version", "1")
		_, _ = io.WriteString(writer, nominalWireResponse(t, "ingestCatalog", map[string]any{
			"revision":           uint64(1),
			"snapshot_id":        testUUID,
			"published_atoms":    uint64(2),
			"tombstoned_atoms":   uint64(0),
			"publication_digest": testDigest,
		}))
	}))
	defer server.Close()
	client := localClient(t, server, 1)
	response, err := client.IngestCatalog(
		context.Background(),
		IngestCatalogRequest{SourceID: testUUID, PlanDigest: testDigest},
		WithInvocationIdempotencyKey("fixed-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.Payload().Revision != 1 || len(bodies) != 1 {
		t.Fatal("nominal response did not decode")
	}
	first := response.PayloadCBOR()
	first[0] ^= 0xff
	if reflect.DeepEqual(first, response.PayloadCBOR()) {
		t.Fatal("typed response leaked payload bytes")
	}
}

func TestMalformedNominalResponseAndOptionalNullFailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(writer, nominalWireResponse(t, "getVersion", map[string]any{"version": "missing"}))
	}))
	defer server.Close()
	client := localClient(t, server, 1)
	if _, err := client.GetVersion(context.Background(), EmptyRequest{}); err == nil {
		t.Fatal("malformed nominal server payload passed")
	}
	if _, err := ParseJSONValue([]byte("null")); err == nil {
		t.Fatal("canonical JSON wrapper accepted null")
	}
	if len(PayloadTypeNames()) != 70 {
		t.Fatal("payload model parity failed")
	}
}

func TestTypedEventStreamValidatesNominalPayload(t *testing.T) {
	eventValue := map[string]any{
		"space_id":   testUUID,
		"project_id": testUUID,
		"event": map[string]any{
			"event_id":       testUUID,
			"kind":           "context_committed",
			"payload_digest": testDigest,
		},
	}
	document, _ := json.Marshal(eventValue)
	parsed, _ := parseStrictJSON(document)
	payload, _ := deterministicCBOR(parsed)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(writer, "id: event-1\ndata: {\"operation_id\":\"subscribeSpaceEvents\",\"event_id\":\"event-1\",\"payload_cbor\":\""+encoded+"\"}\n\n")
	}))
	defer server.Close()
	client := localClient(t, server, 1)
	stream, err := client.SubscribeSpaceEvents(
		context.Background(),
		SpaceIdRequest{SpaceID: testUUID},
		WithInvocationMaxAttempts(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stream.Next() || stream.Event().Payload().SpaceID != testUUID || stream.LastEventID() != "event-1" {
		t.Fatalf("typed event failed: %v", stream.Err())
	}
}

func TestSchemaAnyOfPatternPropertiesAndDescriptorCopies(t *testing.T) {
	anyOf := map[string]any{
		"anyOf": []any{map[string]any{}, map[string]any{}},
	}
	if err := validateSchema(anyOf, "value", anyOf, "test", 0, &validationBudget{}); err != nil {
		t.Fatalf("anyOf incorrectly required exactly one match: %v", err)
	}
	schema, err := payloadSchema("ContextBundle")
	if err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	extensions := definitions["ExtensionMap"].(map[string]any)
	value := map[string]any{"valid.key": map[string]any{"type": "integer", "value": int64(-1)}}
	if err := validateSchema(extensions, value, schema, "extensions", 0, &validationBudget{}); err != nil {
		t.Fatalf("patternProperties rejected valid extension: %v", err)
	}
	descriptor, ok := Operation("getSpaceLog")
	if !ok || len(descriptor.PathFields) != 1 {
		t.Fatal("operation descriptor is incomplete")
	}
	descriptor.PathFields[0] = "tampered"
	again, _ := Operation("getSpaceLog")
	if again.PathFields[0] != "space_id" {
		t.Fatal("operation descriptor leaked mutable path fields")
	}
}

func TestJSONValueAndProblemDetailsAreDeepCopySafe(t *testing.T) {
	source := map[string]any{"nested": []any{map[string]any{"value": "before"}}}
	value, err := NewJSONValue(source)
	if err != nil {
		t.Fatal(err)
	}
	source["nested"].([]any)[0].(map[string]any)["value"] = "after"
	decoded, err := value.Value()
	if err != nil || decoded.(map[string]any)["nested"].([]any)[0].(map[string]any)["value"] != "before" {
		t.Fatal("JSONValue did not own a deep snapshot")
	}
	apiError := &APIError{details: map[string]any{"nested": []any{map[string]any{"value": "before"}}}}
	details := apiError.Details()
	details["nested"].([]any)[0].(map[string]any)["value"] = "after"
	if apiError.Details()["nested"].([]any)[0].(map[string]any)["value"] != "before" {
		t.Fatal("APIError details leaked nested state")
	}
}

func TestProtoSnapshotOwnsMapsAndIsDeterministic(t *testing.T) {
	left := &contextv1.ContextContract{CanonicalExtensions: map[string][]byte{"b": {2}, "a": {1}}}
	right := &contextv1.ContextContract{CanonicalExtensions: map[string][]byte{"a": {1}, "b": {2}}}
	leftSnapshot, err := SnapshotProto(left)
	if err != nil {
		t.Fatal(err)
	}
	rightSnapshot, err := SnapshotProto(right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftSnapshot.Bytes(), rightSnapshot.Bytes()) {
		t.Fatal("deterministic protobuf snapshot depends on map insertion order")
	}
	before := leftSnapshot.Bytes()
	left.CanonicalExtensions["a"][0] = 9
	left.CanonicalExtensions["c"] = []byte{3}
	if !reflect.DeepEqual(before, leftSnapshot.Bytes()) {
		t.Fatal("protobuf snapshot retained caller-owned map or bytes")
	}
	var restored contextv1.ContextContract
	if err := leftSnapshot.UnmarshalInto(&restored); err != nil || restored.CanonicalExtensions["a"][0] != 1 {
		t.Fatal("protobuf snapshot did not materialize an owned message")
	}
}
