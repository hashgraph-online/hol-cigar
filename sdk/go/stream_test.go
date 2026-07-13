package cigar

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const testMaximumEventFrameBytes = maximumEventBytes * 2

func testEventStream(wire string) *EventStream {
	scanner := bufio.NewScanner(strings.NewReader(wire))
	scanner.Buffer(make([]byte, 4096), testMaximumEventFrameBytes)
	return &EventStream{
		definition: OperationDefinition{OperationID: "subscribeSpaceEvents"},
		scanner:    scanner,
	}
}

func validEventFrame(eventID string) string {
	return "id: " + eventID + "\n" +
		"data: {\"operation_id\":\"subscribeSpaceEvents\",\n" +
		"data: \"event_id\":\"" + eventID + "\",\"payload_cbor\":\"AQ\"}\n\n"
}

func TestScanEventAcceptsNormalAndProblemFrames(t *testing.T) {
	stream := testEventStream(validEventFrame("event-1"))
	event, present, err := stream.scanEvent()
	if err != nil || !present || event.EventID() != "event-1" || string(event.PayloadCBOR()) != "\x01" {
		t.Fatalf("normal multi-line event failed: event=%+v present=%t err=%v", event, present, err)
	}

	fixture, err := os.ReadFile("../fixtures/problem-index-unavailable-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, fixture); err != nil {
		t.Fatal(err)
	}
	stream = testEventStream("event: problem\ndata: " + compact.String() + "\n\n")
	_, present, err = stream.scanEvent()
	var apiError *APIError
	if present || !errors.As(err, &apiError) || apiError.Code != "INDEX_UNAVAILABLE" {
		t.Fatalf("problem event failed: present=%t err=%v", present, err)
	}
}

func TestScanEventRejectsAggregateFrameBeforeRetention(t *testing.T) {
	line := "data: " + strings.Repeat("x", 1024) + "\n"
	stream := testEventStream(strings.Repeat(line, testMaximumEventFrameBytes/len(line)+2) + "\n")
	_, present, err := stream.scanEvent()
	if present || err == nil || !strings.Contains(err.Error(), "frame exceeds") {
		t.Fatalf("oversized terminated frame was not rejected at the aggregate boundary: present=%t err=%v", present, err)
	}

	stream = testEventStream(strings.Repeat(line, testMaximumEventFrameBytes/len(line)+2))
	_, present, err = stream.scanEvent()
	if present || err == nil || !strings.Contains(err.Error(), "frame exceeds") {
		t.Fatalf("oversized unterminated frame was not rejected at the aggregate boundary: present=%t err=%v", present, err)
	}
}

func TestScanEventFrameBoundIsExactAndEmptyFramesResetState(t *testing.T) {
	valid := validEventFrame("event-2")
	commentLength := testMaximumEventFrameBytes - len(valid) - 2
	if commentLength < 0 {
		t.Fatal("test event unexpectedly exceeds frame maximum")
	}
	exact := ":" + strings.Repeat("x", commentLength) + "\n" + valid
	if len(exact) != testMaximumEventFrameBytes {
		t.Fatalf("test fixture is not exact: got=%d want=%d", len(exact), testMaximumEventFrameBytes)
	}
	stream := testEventStream(exact)
	if event, present, err := stream.scanEvent(); err != nil || !present || event.EventID() != "event-2" {
		t.Fatalf("exact-size event failed: event=%+v present=%t err=%v", event, present, err)
	}

	stream = testEventStream(":" + strings.Repeat("x", commentLength+1) + "\n" + valid)
	if _, present, err := stream.scanEvent(); present || err == nil || !strings.Contains(err.Error(), "frame exceeds") {
		t.Fatalf("maximum-plus-one frame passed: present=%t err=%v", present, err)
	}

	stream = testEventStream("event: problem\nid: stale-without-data\n\n" + validEventFrame("event-3"))
	if event, present, err := stream.scanEvent(); err != nil || !present || event.EventID() != "event-3" {
		t.Fatalf("empty SSE frame did not reset event state: event=%+v present=%t err=%v", event, present, err)
	}
}
