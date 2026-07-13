package cigar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maximumEventBytes      = 1024 * 1024
	maximumEventFrameBytes = maximumEventBytes * 2
)

// EventStream is a resumable, explicitly closable SSE iterator.
type EventStream struct {
	client           *Client
	ctx              context.Context
	cancel           context.CancelFunc
	definition       OperationDefinition
	request          Request
	config           callConfig
	path             string
	lastEventID      string
	seenEventIDs     map[string]struct{}
	attempt          int
	response         *http.Response
	connectionCancel context.CancelFunc
	scanner          *bufio.Scanner
	event            Event
	err              error
	closed           atomic.Bool
	stateMu          sync.RWMutex
}

func (client *Client) stream(
	ctx context.Context,
	operationID string,
	request Request,
	options ...CallOption,
) (*EventStream, error) {
	definition, ok := operations[operationID]
	if !ok || !definition.Stream {
		return nil, &ValidationError{Message: "operation is unknown or not streaming"}
	}
	config, err := client.config(options)
	if err != nil {
		return nil, err
	}
	if len(request.payloadCBOR) != 0 || request.idempotencyKey != "" || request.expectedRevision != "" || request.dryRun {
		return nil, &ValidationError{Message: "stream GET does not carry payload or mutation metadata"}
	}
	path, _, err := bindPath(definition.HTTPPath, request.pathParameters)
	if err != nil {
		return nil, err
	}
	if request.pageCursor != "" || request.pageSize != 0 {
		return nil, &ValidationError{Message: "SSE resume uses WithStreamResume, not a pagination cursor"}
	}
	resume := config.resumeFrom
	if resume != "" && !boundedVisibleASCII(resume, 256) {
		return nil, &ValidationError{Message: "stream resume identity must be 1..256 visible ASCII bytes"}
	}
	streamContext, cancel := context.WithTimeout(ctx, config.timeout)
	seen := make(map[string]struct{})
	if resume != "" {
		seen[resume] = struct{}{}
	}
	return &EventStream{
		client:       client,
		ctx:          streamContext,
		cancel:       cancel,
		definition:   definition,
		request:      request,
		config:       config,
		path:         path,
		lastEventID:  resume,
		seenEventIDs: seen,
	}, nil
}

// Next blocks until one validated event, terminal error, context cancellation, or close.
func (stream *EventStream) Next() bool {
	if stream.closed.Load() || stream.Err() != nil {
		return false
	}
	for stream.attempt < stream.config.maxAttempts {
		if stream.scanner == nil {
			if err := stream.open(); err != nil {
				stream.attempt++
				if stream.attempt >= stream.config.maxAttempts || !retryableError(err) {
					stream.setErr(err)
					return false
				}
				if !stream.backoff() {
					return false
				}
				continue
			}
			stream.attempt++
		}
		event, present, err := stream.scanEvent()
		if err != nil {
			stream.closeResponse()
			if stream.attempt >= stream.config.maxAttempts || !retryableError(err) {
				stream.setErr(err)
				return false
			}
			if !stream.backoff() {
				return false
			}
			continue
		}
		if present {
			if _, duplicate := stream.seenEventIDs[event.EventID()]; duplicate {
				continue
			}
			if len(stream.seenEventIDs) >= maximumPayloadNodes {
				stream.setErr(&TransportError{Message: "event identity set exceeds its bound"})
				return false
			}
			stream.seenEventIDs[event.EventID()] = struct{}{}
			stream.stateMu.Lock()
			stream.event = event
			stream.lastEventID = event.EventID()
			stream.stateMu.Unlock()
			return true
		}
		stream.closeResponse()
		if stream.attempt < stream.config.maxAttempts && !stream.backoff() {
			return false
		}
	}
	return false
}

// Event returns the current immutable event.
func (stream *EventStream) Event() Event {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return Event{
		operationID: stream.event.operationID,
		eventID:     stream.event.eventID,
		payloadCBOR: append([]byte(nil), stream.event.payloadCBOR...),
	}
}

// LastEventID returns the last verified resume identity.
func (stream *EventStream) LastEventID() string {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.lastEventID
}

// Err returns the terminal stream failure.
func (stream *EventStream) Err() error {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.err
}

// Close cancels the request and releases the response body. It is idempotent.
func (stream *EventStream) Close() error {
	if stream.closed.Swap(true) {
		return nil
	}
	stream.cancel()
	return nil
}

func (stream *EventStream) setErr(err error) {
	stream.stateMu.Lock()
	stream.err = err
	stream.stateMu.Unlock()
}

func (stream *EventStream) open() error {
	deadline, present := stream.ctx.Deadline()
	if !present || time.Until(deadline) <= 0 {
		return &TimeoutError{Cause: context.DeadlineExceeded}
	}
	remaining := time.Until(deadline)
	requestContext, connectionCancel := context.WithCancel(stream.ctx)
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		stream.client.baseURL.String()+stream.path,
		nil,
	)
	if err != nil {
		connectionCancel()
		return &ValidationError{Message: "stream URL is invalid"}
	}
	if err := stream.client.applyHeaders(requestContext, request, stream.definition.OperationID, remaining); err != nil {
		connectionCancel()
		return err
	}
	request.Header.Set("accept", "text/event-stream, application/problem+json")
	resume := stream.LastEventID()
	if resume != "" {
		request.Header.Set("last-event-id", resume)
	}
	response, err := stream.client.httpClient.Do(request)
	if err != nil {
		connectionCancel()
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return &TimeoutError{Cause: err}
		}
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return &TransportError{Message: "stream HTTP exchange failed", Cause: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		connectionCancel()
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumProblemBytes+1))
		if readErr != nil {
			return &TransportError{Message: "stream problem read failed", Cause: readErr}
		}
		return decodeProblemResponse(response.StatusCode, response.Header, body)
	}
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("content-type"))
	if parseErr != nil || mediaType != "text/event-stream" {
		connectionCancel()
		response.Body.Close()
		return &TransportError{Message: "stream response must use text/event-stream", Cause: parseErr}
	}
	stream.response = response
	stream.connectionCancel = connectionCancel
	stream.scanner = bufio.NewScanner(response.Body)
	stream.scanner.Buffer(make([]byte, 4096), maximumEventFrameBytes)
	return nil
}

func (stream *EventStream) scanEvent() (Event, bool, error) {
	eventType := "message"
	eventID := ""
	var data strings.Builder
	dataLines := 0
	frameBytes := 0
	for stream.scanner.Scan() {
		wireLine := stream.scanner.Bytes()
		wireBytes := len(wireLine) + 1
		if wireBytes > maximumEventFrameBytes-frameBytes {
			return Event{}, false, &TransportError{Message: "event frame exceeds its aggregate byte bound"}
		}
		frameBytes += wireBytes
		line := strings.TrimSuffix(string(wireLine), "\r")
		if line == "" {
			if dataLines == 0 {
				eventType = "message"
				eventID = ""
				data.Reset()
				frameBytes = 0
				continue
			}
			return stream.decodeEvent(eventType, eventID, data.String())
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			value = ""
		} else {
			value = strings.TrimPrefix(value, " ")
		}
		switch field {
		case "event":
			eventType = value
		case "id":
			eventID = value
		case "data":
			if dataLines > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
			dataLines++
		}
	}
	if err := stream.scanner.Err(); err != nil {
		return Event{}, false, &TransportError{Message: "event stream read failed", Cause: err}
	}
	return Event{}, false, nil
}

func (stream *EventStream) decodeEvent(eventType, eventID, data string) (Event, bool, error) {
	if eventType == "problem" {
		var status struct {
			HTTPStatus int `json:"http_status"`
		}
		if err := json.Unmarshal([]byte(data), &status); err != nil || status.HTTPStatus == 0 {
			return Event{}, false, &TransportError{Message: "problem event lacks its HTTP status", Cause: err}
		}
		return Event{}, false, decodeProblem(status.HTTPStatus, []byte(data))
	}
	var wire struct {
		OperationID string `json:"operation_id"`
		EventID     string `json:"event_id"`
		PayloadCBOR string `json:"payload_cbor"`
	}
	if err := validateUniqueJSON([]byte(data)); err != nil {
		return Event{}, false, &TransportError{Message: "event JSON contains duplicate keys or excessive structure", Cause: err}
	}
	decoder := json.NewDecoder(bytes.NewBufferString(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Event{}, false, &TransportError{Message: "event JSON is invalid", Cause: err}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Event{}, false, &TransportError{Message: "event JSON contains trailing data", Cause: err}
	}
	if wire.OperationID != stream.definition.OperationID || wire.EventID != eventID || !boundedVisibleASCII(wire.EventID, 256) {
		return Event{}, false, &TransportError{Message: "event identity is invalid"}
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(wire.PayloadCBOR)
	if err != nil || len(payload) > maximumEventBytes || base64.RawURLEncoding.EncodeToString(payload) != wire.PayloadCBOR {
		return Event{}, false, &TransportError{Message: "event payload is invalid", Cause: err}
	}
	return Event{operationID: wire.OperationID, eventID: wire.EventID, payloadCBOR: append([]byte(nil), payload...)}, true, nil
}

func (stream *EventStream) closeResponse() {
	if stream.response != nil {
		stream.response.Body.Close()
	}
	if stream.connectionCancel != nil {
		stream.connectionCancel()
	}
	stream.response = nil
	stream.connectionCancel = nil
	stream.scanner = nil
}

func (stream *EventStream) backoff() bool {
	delay := min(100*time.Millisecond*time.Duration(1<<max(stream.attempt-1, 0)), time.Second)
	timer := time.NewTimer(delay)
	select {
	case <-stream.ctx.Done():
		timer.Stop()
		stream.setErr(stream.ctx.Err())
		return false
	case <-timer.C:
		return true
	}
}
