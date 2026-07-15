package cigar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sdkCapabilityAuthority struct {
	OperationCount int `json:"operation_count"`
	Operations     []struct {
		OperationID  string  `json:"operation_id"`
		RequestType  string  `json:"request_type"`
		ResponseType string  `json:"response_type"`
		EventType    *string `json:"event_type"`
		Stream       string  `json:"stream"`
	} `json:"operations"`
	SDKs struct {
		Go struct {
			OperationCount int      `json:"operation_count"`
			Operations     []string `json:"operations"`
			Transport      []string `json:"transport"`
		} `json:"go"`
	} `json:"sdks"`
}

func responseJSON(operationID, cursor string) string {
	response := map[string]string{"operation_id": operationID, "payload_cbor": "AQ"}
	if cursor != "" {
		response["next_page_cursor"] = cursor
	}
	encoded, _ := json.Marshal(response)
	return string(encoded)
}

func writeResponse(writer http.ResponseWriter, operationID, cursor string) {
	writer.Header().Set("content-type", "application/json")
	writer.Header().Set("x-cigar-api-version", "1")
	_, _ = io.WriteString(writer, responseJSON(operationID, cursor))
}

func writeTypedResponse(writer http.ResponseWriter, operationID string, payload any) {
	encoded, err := deterministicCBOR(payload)
	if err != nil {
		panic(err)
	}
	wrapper, err := json.Marshal(map[string]string{
		"operation_id": operationID,
		"payload_cbor": base64.RawURLEncoding.EncodeToString(encoded),
	})
	if err != nil {
		panic(err)
	}
	writer.Header().Set("content-type", "application/json")
	writer.Header().Set("x-cigar-api-version", "1")
	_, _ = writer.Write(wrapper)
}

func localClient(t *testing.T, server *httptest.Server, attempts int) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		BaseURL:               server.URL,
		AllowInsecureLoopback: true,
		MaxAttempts:           attempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestGeneratedSurfaceAndIdempotentRetry(t *testing.T) {
	if OperationCount != 45 || len(operations) != OperationCount || len(PayloadTypeNames()) != 70 {
		t.Fatalf("unexpected generated parity: %d operations, %d types", len(operations), len(PayloadTypeNames()))
	}
	var mu sync.Mutex
	var bodies [][]byte
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		bodies = append(bodies, body)
		keys = append(keys, request.Header.Get("idempotency-key"))
		attempt := len(bodies)
		mu.Unlock()
		if attempt == 1 {
			fixture, _ := os.ReadFile("fixtures/problem-index-unavailable-v1.json")
			writer.Header().Set("content-type", "application/problem+json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(fixture)
			return
		}
		writeResponse(writer, "ingestCatalog", "")
	}))
	defer server.Close()
	client := localClient(t, server, 2)
	request, err := NewRequest([]byte{1}, WithIdempotencyKey("fixed-key"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.call(context.Background(), "ingestCatalog", request)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.PayloadCBOR()) != "\x01" || len(bodies) != 2 || !strings.EqualFold(keys[0], "fixed-key") || keys[0] != keys[1] || string(bodies[0]) != string(bodies[1]) {
		t.Fatal("retry did not preserve exact body and idempotency key")
	}
}

func TestSafeReadRetryPreservesRequestIdentityAndDeadline(t *testing.T) {
	var methods []string
	var requestURIs []string
	var operationIDs []string
	var bodies [][]byte
	var remainingTimeouts []int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		remaining, _ := strconv.Atoi(request.Header.Get("x-cigar-timeout-ms"))
		methods = append(methods, request.Method)
		requestURIs = append(requestURIs, request.URL.RequestURI())
		operationIDs = append(operationIDs, request.Header.Get("x-cigar-operation-id"))
		bodies = append(bodies, body)
		remainingTimeouts = append(remainingTimeouts, remaining)
		if len(methods) == 1 {
			fixture, _ := os.ReadFile("fixtures/problem-index-unavailable-v1.json")
			writer.Header().Set("content-type", "application/problem+json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(fixture)
			return
		}
		writeResponse(writer, "getVersion", "")
	}))
	defer server.Close()
	client := localClient(t, server, 2)
	request, err := NewEmptyRequest()
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.call(context.Background(), "getVersion", request, WithCallTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if response.OperationID() != "getVersion" || len(methods) != 2 {
		t.Fatalf("safe read did not retry exactly once: response=%+v calls=%d", response, len(methods))
	}
	if methods[0] != http.MethodGet || methods[0] != methods[1] ||
		requestURIs[0] != "/v1/version" || requestURIs[0] != requestURIs[1] ||
		operationIDs[0] != "getVersion" || operationIDs[0] != operationIDs[1] ||
		len(bodies[0]) != 0 || len(bodies[1]) != 0 {
		t.Fatalf("safe read request identity changed: methods=%v uris=%v operations=%v bodies=%q", methods, requestURIs, operationIDs, bodies)
	}
	if remainingTimeouts[0] <= remainingTimeouts[1] || remainingTimeouts[1] <= 0 {
		t.Fatalf("safe read deadline was reset: remaining=%v", remainingTimeouts)
	}
}

func TestAllGeneratedOperationsMatchCapabilityAuthority(t *testing.T) {
	raw, err := os.ReadFile("capabilities-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var authority sdkCapabilityAuthority
	if err := json.Unmarshal(raw, &authority); err != nil {
		t.Fatal(err)
	}
	if authority.OperationCount != OperationCount || len(authority.Operations) != OperationCount {
		t.Fatalf("capability authority count differs: count=%d rows=%d", authority.OperationCount, len(authority.Operations))
	}
	if authority.SDKs.Go.OperationCount != OperationCount || len(authority.SDKs.Go.Operations) != OperationCount {
		t.Fatalf("Go capability count differs: count=%d rows=%d", authority.SDKs.Go.OperationCount, len(authority.SDKs.Go.Operations))
	}
	if len(authority.SDKs.Go.Transport) != 2 || authority.SDKs.Go.Transport[0] != "http" || authority.SDKs.Go.Transport[1] != "grpc" {
		t.Fatalf("Go transport capability differs: %v", authority.SDKs.Go.Transport)
	}
	seen := make(map[string]struct{}, OperationCount)
	for index, expected := range authority.Operations {
		if authority.SDKs.Go.Operations[index] != expected.OperationID {
			t.Fatalf("Go capability operation order differs at %d", index)
		}
		definition, ok := operations[expected.OperationID]
		if !ok {
			t.Fatalf("generated operation missing: %s", expected.OperationID)
		}
		if _, duplicate := seen[expected.OperationID]; duplicate {
			t.Fatalf("duplicate authority operation: %s", expected.OperationID)
		}
		seen[expected.OperationID] = struct{}{}
		eventType := ""
		if expected.EventType != nil {
			eventType = *expected.EventType
		}
		if definition.OperationID != expected.OperationID ||
			definition.RequestType != expected.RequestType ||
			definition.ResponseType != expected.ResponseType ||
			definition.EventType != eventType ||
			definition.Stream != (expected.Stream == "server_stream") {
			t.Fatalf("generated descriptor differs for %s", expected.OperationID)
		}
	}
	if len(seen) != len(operations) {
		t.Fatalf("generated operation inventory has unbound rows: authority=%d generated=%d", len(seen), len(operations))
	}
}

func TestDispatchNeverRetries(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		fixture, _ := os.ReadFile("fixtures/problem-index-unavailable-v1.json")
		writer.Header().Set("content-type", "application/problem+json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write(fixture)
	}))
	defer server.Close()
	client := localClient(t, server, 8)
	parameter, _ := NewPathParameter("effect_id", "effect-1")
	request, _ := NewRequest(
		[]byte{1},
		WithPathParameters(parameter),
		WithIdempotencyKey("dispatch-key"),
		WithExpectedRevision("revision-1"),
	)
	_, err := client.call(context.Background(), "dispatchEffect", request)
	var apiError *APIError
	if !errors.As(err, &apiError) || calls != 1 || apiError.Code != "INDEX_UNAVAILABLE" {
		t.Fatalf("dispatch retry invariant failed: calls=%d err=%v", calls, err)
	}
}

func TestPaginationAndResumableStream(t *testing.T) {
	var pages int
	var streams int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/log"):
			pages++
			if pages == 1 {
				writeResponse(writer, "getSpaceLog", "cursor-2")
			} else {
				if request.URL.Query().Get("page_cursor") != "cursor-2" {
					t.Error("pagination cursor was not preserved")
				}
				writeResponse(writer, "getSpaceLog", "")
			}
		case strings.HasSuffix(request.URL.Path, "/events"):
			streams++
			writer.Header().Set("content-type", "text/event-stream")
			if streams == 1 {
				_, _ = io.WriteString(writer, "id: event-1\ndata: {\"operation_id\":\"subscribeSpaceEvents\",\"event_id\":\"event-1\",\"payload_cbor\":\"AQ\"}\n\n")
				return
			}
			if request.Header.Get("last-event-id") != "event-1" {
				t.Error("stream did not send last verified event identity")
			}
			_, _ = io.WriteString(writer, "id: event-2\ndata: {\"operation_id\":\"subscribeSpaceEvents\",\"event_id\":\"event-2\",\"payload_cbor\":\"Ag\"}\n\n")
		}
	}))
	defer server.Close()
	client := localClient(t, server, 2)
	parameter, _ := NewPathParameter("space_id", "space-1")
	request, _ := NewEmptyRequest(WithPathParameters(parameter), WithPage("", 10))
	iterator, err := client.Paginate(context.Background(), "getSpaceLog", request)
	if err != nil {
		t.Fatal(err)
	}
	var pageCount int
	for iterator.Next() {
		pageCount++
	}
	if iterator.Err() != nil || pageCount != 2 {
		t.Fatalf("pagination failed: count=%d err=%v", pageCount, iterator.Err())
	}
	streamRequest, _ := NewEmptyRequest(WithPathParameters(parameter))
	stream, err := client.stream(context.Background(), "subscribeSpaceEvents", streamRequest, WithCallMaxAttempts(2))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stream.Next() || stream.Event().EventID() != "event-1" {
		t.Fatalf("first stream event failed: %v", stream.Err())
	}
	if !stream.Next() || stream.Event().EventID() != "event-2" || stream.LastEventID() != "event-2" {
		t.Fatalf("resumed stream event failed: %v", stream.Err())
	}
}

func TestSecurityProblemCompatibilityAndCancellation(t *testing.T) {
	for _, options := range []ClientOptions{
		{BaseURL: "http://example.com"},
		{BaseURL: "https://example.com"},
		{BaseURL: "https://example.com/prefix"},
		{BaseURL: "http://127.0.0.1", AllowInsecureLoopback: false},
		{BaseURL: "https://example.com", BearerToken: strings.Repeat("x", 8193)},
	} {
		if _, err := NewClient(options); err == nil {
			t.Fatalf("unsafe client options passed: %+v", options)
		}
	}

	t.Run("content type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, responseJSON("getVersion", ""))
		}))
		defer server.Close()
		client := localClient(t, server, 1)
		request, _ := NewEmptyRequest()
		if _, err := client.call(context.Background(), "getVersion", request); err == nil {
			t.Fatal("missing response content type passed")
		}
	})

	t.Run("duplicate JSON key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("content-type", "application/json")
			_, _ = io.WriteString(writer, `{"operation_id":"getVersion","operation_id":"getVersion","payload_cbor":"oA"}`)
		}))
		defer server.Close()
		client := localClient(t, server, 1)
		request, _ := NewEmptyRequest()
		if _, err := client.call(context.Background(), "getVersion", request); err == nil {
			t.Fatal("duplicate response key passed")
		}
	})

	t.Run("problem catalog", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			fixture, _ := os.ReadFile("fixtures/problem-index-unavailable-v1.json")
			fixture = []byte(strings.Replace(string(fixture), `"retry": "after_backoff"`, `"retry": "never"`, 1))
			writer.Header().Set("content-type", "application/problem+json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(fixture)
		}))
		defer server.Close()
		client := localClient(t, server, 1)
		request, _ := NewEmptyRequest()
		var transportError *TransportError
		_, err := client.call(context.Background(), "getVersion", request)
		if !errors.As(err, &transportError) {
			t.Fatalf("catalog mismatch did not fail as transport integrity: %v", err)
		}
	})

	t.Run("compatibility", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("content-type", "application/json")
			writer.Header().Set("x-cigar-api-version", "2")
			_, _ = io.WriteString(writer, responseJSON("getVersion", ""))
		}))
		defer server.Close()
		client := localClient(t, server, 1)
		request, _ := NewEmptyRequest()
		var compatibilityError *CompatibilityError
		_, err := client.call(context.Background(), "getVersion", request)
		if !errors.As(err, &compatibilityError) {
			t.Fatalf("version mismatch passed: %v", err)
		}
	})

	t.Run("stream cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("content-type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		}))
		defer server.Close()
		client := localClient(t, server, 1)
		parameter, _ := NewPathParameter("space_id", "space-1")
		request, _ := NewEmptyRequest(WithPathParameters(parameter))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream, err := client.stream(ctx, "subscribeSpaceEvents", request)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan bool, 1)
		go func() { done <- stream.Next() }()
		time.Sleep(20 * time.Millisecond)
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case present := <-done:
			if present {
				t.Fatal("cancelled stream yielded an event")
			}
		case <-time.After(time.Second):
			t.Fatal("stream cancellation did not unblock Next")
		}
	})
}

func TestEndToEndDeadlineAndCustomClientTrust(t *testing.T) {
	t.Run("deadline spans retry and backoff", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			calls++
			time.Sleep(35 * time.Millisecond)
			fixture, _ := os.ReadFile("fixtures/problem-index-unavailable-v1.json")
			writer.Header().Set("content-type", "application/problem+json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(fixture)
		}))
		defer server.Close()
		client := localClient(t, server, 8)
		request, _ := NewEmptyRequest()
		started := time.Now()
		_, err := client.call(context.Background(), "getVersion", request, WithCallTimeout(70*time.Millisecond))
		var timeoutError *TimeoutError
		if !errors.As(err, &timeoutError) || time.Since(started) > 150*time.Millisecond || calls != 1 {
			t.Fatalf("deadline was reset across attempts: elapsed=%s calls=%d err=%v", time.Since(started), calls, err)
		}
	})

	t.Run("custom client requires trust and cannot redirect credentials", func(t *testing.T) {
		var targetCalls int
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
		defer target.Close()
		origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("location", target.URL)
			writer.WriteHeader(http.StatusFound)
		}))
		defer origin.Close()
		custom := &http.Client{}
		if _, err := NewClient(ClientOptions{
			BaseURL: origin.URL, AllowInsecureLoopback: true, HTTPClient: custom,
		}); err == nil {
			t.Fatal("custom HTTP client passed without explicit trust")
		}
		client, err := NewClient(ClientOptions{
			BaseURL:               origin.URL,
			AllowInsecureLoopback: true,
			HTTPClient:            custom,
			TrustCustomHTTPClient: true,
			BearerToken:           "secret",
			MaxAttempts:           1,
		})
		if err != nil {
			t.Fatal(err)
		}
		request, _ := NewEmptyRequest()
		_, _ = client.call(context.Background(), "getVersion", request)
		if targetCalls != 0 {
			t.Fatal("custom HTTP client followed a redirect and leaked request authority")
		}
	})
}

func TestHandoffEffectReconciliationAndReplayMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		operationID := request.Header.Get("x-cigar-operation-id")
		writeResponse(writer, operationID, "")
	}))
	defer server.Close()
	client := localClient(t, server, 1)
	tests := []struct {
		name      string
		parameter string
		value     string
		operation string
		revision  bool
	}{
		{"accept handoff", "handoff_id", "handoff-1", "acceptHandoff", true},
		{"reconcile effect", "effect_id", "effect-1", "reconcileEffect", true},
		{"run replay", "replay_id", "replay-1", "runObservationalReplay", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameter, _ := NewPathParameter(test.parameter, test.value)
			options := []RequestOption{WithPathParameters(parameter), WithIdempotencyKey("fixed-key")}
			if test.revision {
				options = append(options, WithExpectedRevision("revision-1"))
			}
			request, _ := NewRequest([]byte{1}, options...)
			response, err := client.call(context.Background(), test.operation, request)
			if err != nil || response.OperationID() == "" {
				t.Fatalf("method failed: %v", err)
			}
		})
	}
}

func TestTypedHandoffReconciliationAndReplayWorkflows(t *testing.T) {
	const id = "01900000-0000-7000-8000-000000000001"
	const digest = "12201111111111111111111111111111111111111111111111111111111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch operation := request.Header.Get("x-cigar-operation-id"); operation {
		case "acceptHandoff":
			writeTypedResponse(writer, operation, map[string]any{
				"schema_version": "cigar.handoff-acceptance.v1", "acceptance_id": id,
				"handoff_id": id, "recipient_id": id, "accepted_capabilities": []any{"read_context"},
				"rejected_capabilities": []any{}, "unavailable_references": []any{}, "policy_digest": digest,
				"bundle_id": digest, "accepted_at": "2026-01-01T00:00:00Z", "acknowledgement_digest": digest,
			})
		case "reconcileEffect":
			writeTypedResponse(writer, operation, map[string]any{
				"effect_id": id, "state": "succeeded", "effect_version": uint64(2), "intent_digest": digest,
				"attempt_count": uint64(1), "reconciliation_count": uint64(1),
			})
		case "runObservationalReplay":
			writeTypedResponse(writer, operation, map[string]any{
				"schema_version": "cigar.replay-execution.v1", "execution_id": id, "request_id": id,
				"mode": "observational", "status": "complete",
				"completeness":     map[string]any{"available": []any{"bundle"}, "missing": []any{}},
				"egress_permitted": false, "effect_dispatch_permitted": false, "started_at": "2026-01-01T00:00:00Z",
			})
		default:
			http.Error(writer, "unexpected operation", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := localClient(t, server, 1)
	handoff, err := client.AcceptHandoff(
		context.Background(),
		AcceptHandoffRequest{HandoffID: id, TargetPlanID: id},
		WithInvocationIdempotencyKey("accept-1"),
		WithInvocationExpectedRevision("revision-1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := client.ReconcileEffect(
		context.Background(),
		EffectIdRequest{EffectID: id},
		WithInvocationIdempotencyKey("reconcile-1"),
		WithInvocationExpectedRevision("revision-2"),
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := client.RunObservationalReplay(
		context.Background(),
		ReplayIdRequest{ReplayID: id},
		WithInvocationIdempotencyKey("replay-1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if effect.Payload().State != EffectStateSucceeded || replay.Payload().Mode != ReplayModeObservational {
		t.Fatal("typed effect or replay response differs")
	}
	capabilities, err := handoff.Payload().AcceptedCapabilities.Value()
	if err != nil || fmt.Sprint(capabilities) != "[read_context]" {
		t.Fatalf("typed handoff response differs: %v %v", capabilities, err)
	}
}

func ExampleClient_GetVersion() {
	fmt.Println("see examples/quickstart")
	// Output: see examples/quickstart
}
