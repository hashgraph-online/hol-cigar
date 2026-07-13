package cigar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maximumProblemBytes = 64 * 1024
	maximumTimeout      = 5 * time.Minute
)

var (
	pathName      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	pathValue     = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)
	visibleASCII  = regexp.MustCompile(`^[\x21-\x7e]+$`)
	correlationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// ClientOptions configure one remote client.
type ClientOptions struct {
	BaseURL               string
	BearerToken           string
	TokenProvider         TokenProvider
	DefaultTimeout        time.Duration
	MaxAttempts           int
	HTTPClient            *http.Client
	TrustCustomHTTPClient bool
	AllowInsecureLoopback bool
}

// Client is a goroutine-safe CIGAR v1 HTTP client.
type Client struct {
	baseURL        *url.URL
	bearerToken    string
	tokenProvider  TokenProvider
	defaultTimeout time.Duration
	maxAttempts    int
	httpClient     *http.Client
}

// NewClient validates transport security and returns a client.
func NewClient(options ClientOptions) (*Client, error) {
	baseURL, err := url.Parse(options.BaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "https" && baseURL.Scheme != "http") {
		return nil, &ValidationError{Message: "base URL must be an HTTP(S) origin"}
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" || (baseURL.Path != "" && baseURL.Path != "/") {
		return nil, &ValidationError{Message: "base URL must be an origin without credentials, path, query, or fragment"}
	}
	host := baseURL.Hostname()
	loopback := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if baseURL.Scheme == "http" && (!loopback || !options.AllowInsecureLoopback) {
		return nil, &ValidationError{Message: "cleartext HTTP requires explicit loopback opt-in"}
	}
	if options.BearerToken != "" && options.TokenProvider != nil {
		return nil, &ValidationError{Message: "configure one bearer source"}
	}
	if options.BearerToken != "" && !boundedVisibleASCII(options.BearerToken, 8192) {
		return nil, &ValidationError{Message: "bearer token must be 1..8192 visible ASCII bytes"}
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
	httpClient := options.HTTPClient
	if httpClient != nil && !options.TrustCustomHTTPClient {
		return nil, &ValidationError{Message: "custom HTTP client requires explicit TrustCustomHTTPClient acknowledgement"}
	}
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		httpClient = &http.Client{
			Transport:     transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		}
	} else {
		ownedClient := *httpClient
		ownedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &ownedClient
	}
	baseURL.Path = ""
	return &Client{
		baseURL:        baseURL,
		bearerToken:    options.BearerToken,
		tokenProvider:  options.TokenProvider,
		defaultTimeout: timeout,
		maxAttempts:    attempts,
		httpClient:     httpClient,
	}, nil
}

func (client *Client) config(options []CallOption) (callConfig, error) {
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

func (client *Client) call(
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
	attempts := config.maxAttempts
	if operationID == "dispatchEffect" || (definition.Mutation && request.idempotencyKey == "") {
		attempts = 1
	}
	callContext, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		response, callErr := client.callOnce(callContext, definition, request)
		if callErr == nil {
			return response, nil
		}
		lastErr = callErr
		if attempt == attempts || !retryableError(callErr) {
			return Response{}, callErr
		}
		delay := min(100*time.Millisecond*time.Duration(1<<(attempt-1)), time.Second)
		timer := time.NewTimer(delay)
		select {
		case <-callContext.Done():
			timer.Stop()
			if errors.Is(callContext.Err(), context.DeadlineExceeded) {
				return Response{}, &TimeoutError{Cause: callContext.Err()}
			}
			return Response{}, callContext.Err()
		case <-timer.C:
		}
	}
	return Response{}, lastErr
}

type wirePathParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type wireRequest struct {
	OperationID      string              `json:"operation_id"`
	PayloadCBOR      string              `json:"payload_cbor"`
	DryRun           bool                `json:"dry_run"`
	IdempotencyKey   string              `json:"idempotency_key,omitempty"`
	ExpectedRevision string              `json:"expected_revision,omitempty"`
	PageCursor       string              `json:"page_cursor,omitempty"`
	PageSize         uint32              `json:"page_size,omitempty"`
	PathParameters   []wirePathParameter `json:"path_parameters"`
}

type wireResponse struct {
	OperationID    string `json:"operation_id"`
	PayloadCBOR    string `json:"payload_cbor"`
	SemanticETag   string `json:"semantic_etag,omitempty"`
	NextPageCursor string `json:"next_page_cursor,omitempty"`
}

func (client *Client) callOnce(
	ctx context.Context,
	definition OperationDefinition,
	request Request,
) (Response, error) {
	deadline, present := ctx.Deadline()
	if !present {
		return Response{}, &ValidationError{Message: "call context lacks its bounded deadline"}
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return Response{}, &TimeoutError{Cause: context.DeadlineExceeded}
	}
	path, parameters, err := bindPath(definition.HTTPPath, request.pathParameters)
	if err != nil {
		return Response{}, err
	}
	if len(request.payloadCBOR) > definition.RequestMaxBytes {
		return Response{}, &ValidationError{Message: "request payload exceeds operation bound"}
	}
	var body []byte
	if definition.HTTPMethod == http.MethodGet {
		if len(request.payloadCBOR) != 0 || request.idempotencyKey != "" || request.expectedRevision != "" || request.dryRun {
			return Response{}, &ValidationError{Message: "GET operations do not carry payload or mutation metadata"}
		}
		query := make(url.Values)
		if request.pageCursor != "" {
			if len(request.pageCursor) > 4096 {
				return Response{}, &ValidationError{Message: "page cursor exceeds its bound"}
			}
			query.Set("page_cursor", request.pageCursor)
		}
		if request.pageSize != 0 {
			if request.pageSize > 1000 {
				return Response{}, &ValidationError{Message: "page size must be in 1..1000"}
			}
			query.Set("page_size", strconv.FormatUint(uint64(request.pageSize), 10))
		}
		if encoded := query.Encode(); encoded != "" {
			path += "?" + encoded
		}
	} else {
		if definition.IdempotencyRequired {
			if !boundedVisibleASCII(request.idempotencyKey, 256) {
				return Response{}, &ValidationError{Message: definition.OperationID + " requires a bounded idempotency key"}
			}
		} else if request.idempotencyKey != "" {
			return Response{}, &ValidationError{Message: definition.OperationID + " does not accept an idempotency key"}
		}
		if definition.RevisionRequired {
			if len(request.expectedRevision) < 1 || len(request.expectedRevision) > 256 {
				return Response{}, &ValidationError{Message: definition.OperationID + " requires an expected revision"}
			}
		} else if request.expectedRevision != "" {
			return Response{}, &ValidationError{Message: definition.OperationID + " does not accept an expected revision"}
		}
		wireParameters := make([]wirePathParameter, len(parameters))
		for index, parameter := range parameters {
			wireParameters[index] = wirePathParameter{Name: parameter.name, Value: parameter.value}
		}
		body, err = json.Marshal(wireRequest{
			OperationID:      definition.OperationID,
			PayloadCBOR:      base64.RawURLEncoding.EncodeToString(request.payloadCBOR),
			DryRun:           request.dryRun,
			IdempotencyKey:   request.idempotencyKey,
			ExpectedRevision: request.expectedRevision,
			PageCursor:       request.pageCursor,
			PageSize:         request.pageSize,
			PathParameters:   wireParameters,
		})
		if err != nil {
			return Response{}, &TransportError{Message: "request serialization failed", Cause: err}
		}
	}
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		definition.HTTPMethod,
		client.baseURL.String()+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return Response{}, &ValidationError{Message: "request URL is invalid"}
	}
	if err := client.applyHeaders(ctx, httpRequest, definition.OperationID, timeout); err != nil {
		return Response{}, err
	}
	if definition.HTTPMethod == http.MethodPost {
		httpRequest.Header.Set("content-type", "application/json")
		if request.idempotencyKey != "" {
			httpRequest.Header.Set("idempotency-key", request.idempotencyKey)
		}
		if request.expectedRevision != "" {
			httpRequest.Header.Set("if-match", request.expectedRevision)
		}
	}
	httpResponse, err := client.httpClient.Do(httpRequest)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Response{}, &TimeoutError{Cause: err}
		}
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, &TransportError{Message: "HTTP exchange failed", Cause: err}
	}
	defer httpResponse.Body.Close()
	maximum := int64(maximumProblemBytes)
	mediaType := ""
	var parseErr error
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode < 300 {
		mediaType, _, parseErr = mime.ParseMediaType(httpResponse.Header.Get("content-type"))
		if parseErr != nil {
			return Response{}, &TransportError{Message: "response content type is missing or invalid", Cause: parseErr}
		}
		switch mediaType {
		case "application/openmetrics-text":
			maximum = int64(definition.ResponseMaxBytes)
		case "application/json":
			maximum = int64(definition.ResponseMaxBytes)*4/3 + 16*1024
		default:
			return Response{}, &TransportError{Message: "response has an unsupported content type"}
		}
	}
	if httpResponse.ContentLength > maximum {
		return Response{}, &TransportError{Message: "response Content-Length exceeds its bound"}
	}
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, maximum+1))
	if err != nil {
		return Response{}, &TransportError{Message: "response body read failed", Cause: err}
	}
	if int64(len(responseBody)) > maximum {
		return Response{}, &TransportError{Message: "response exceeds its bound"}
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return Response{}, decodeProblemResponse(httpResponse.StatusCode, httpResponse.Header, responseBody)
	}
	serverVersion := httpResponse.Header.Get("x-cigar-api-version")
	if serverVersion != "" && serverVersion != "1" {
		return Response{}, &CompatibilityError{ServerVersion: serverVersion}
	}
	if mediaType == "application/openmetrics-text" {
		return Response{operationID: definition.OperationID, payloadCBOR: append([]byte(nil), responseBody...)}, nil
	}
	if mediaType != "application/json" {
		return Response{}, &TransportError{Message: "response must use application/json"}
	}
	if err := validateUniqueJSON(responseBody); err != nil {
		return Response{}, &TransportError{Message: "response JSON contains duplicate keys or excessive structure", Cause: err}
	}
	var wire wireResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Response{}, &TransportError{Message: "response JSON is invalid", Cause: err}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Response{}, &TransportError{Message: "response JSON contains trailing data", Cause: err}
	}
	if wire.OperationID != definition.OperationID || len(wire.SemanticETag) > 256 || len(wire.NextPageCursor) > 4096 {
		return Response{}, &TransportError{Message: "response metadata is invalid"}
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(wire.PayloadCBOR)
	if err != nil || len(payload) > definition.ResponseMaxBytes || base64.RawURLEncoding.EncodeToString(payload) != wire.PayloadCBOR {
		return Response{}, &TransportError{Message: "response payload is invalid"}
	}
	return Response{
		operationID:    wire.OperationID,
		payloadCBOR:    append([]byte(nil), payload...),
		semanticETag:   wire.SemanticETag,
		nextPageCursor: wire.NextPageCursor,
	}, nil
}

func (client *Client) applyHeaders(
	ctx context.Context,
	request *http.Request,
	operationID string,
	timeout time.Duration,
) error {
	request.Header.Set("accept", "application/json, application/problem+json")
	request.Header.Set("x-cigar-api-version", "1")
	request.Header.Set("x-cigar-operation-id", operationID)
	request.Header.Set("x-cigar-timeout-ms", strconv.FormatInt(timeout.Milliseconds(), 10))
	token := client.bearerToken
	if client.tokenProvider != nil {
		resolved, err := client.tokenProvider(ctx)
		if err != nil {
			return &TransportError{Message: "bearer token provider failed", Cause: err}
		}
		token = resolved
	}
	if token != "" {
		if !boundedVisibleASCII(token, 8192) {
			return &ValidationError{Message: "bearer token must be 1..8192 visible ASCII bytes"}
		}
		request.Header.Set("authorization", "Bearer "+token)
	}
	return nil
}

func bindPath(template string, source []PathParameter) (string, []PathParameter, error) {
	parameters := append([]PathParameter(nil), source...)
	if len(parameters) > 8 {
		return "", nil, &ValidationError{Message: "at most eight path parameters are allowed"}
	}
	sort.Slice(parameters, func(left, right int) bool { return parameters[left].name < parameters[right].name })
	for index, parameter := range parameters {
		if !pathName.MatchString(parameter.name) || !pathValue.MatchString(parameter.value) {
			return "", nil, &ValidationError{Message: "path parameter violates the frozen alphabet"}
		}
		if index > 0 && parameters[index-1].name == parameter.name {
			return "", nil, &ValidationError{Message: "path parameter names must be unique"}
		}
	}
	expected := regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`).FindAllStringSubmatch(template, -1)
	if len(expected) != len(parameters) {
		return "", nil, &ValidationError{Message: "path parameters do not exactly match the operation path"}
	}
	path := template
	for _, match := range expected {
		found := false
		for _, parameter := range parameters {
			if parameter.name == match[1] {
				path = strings.Replace(path, match[0], parameter.value, 1)
				found = true
				break
			}
		}
		if !found {
			return "", nil, &ValidationError{Message: "path parameters do not exactly match the operation path"}
		}
	}
	return path, parameters, nil
}

type wireProblem struct {
	SchemaVersion string         `json:"schema_version"`
	Code          string         `json:"code"`
	HTTPStatus    int            `json:"http_status"`
	Retry         string         `json:"retry"`
	Message       string         `json:"message"`
	Remediation   string         `json:"remediation"`
	CorrelationID string         `json:"correlation_id"`
	Details       map[string]any `json:"details"`
}

func decodeProblemResponse(status int, headers http.Header, body []byte) error {
	mediaType, _, err := mime.ParseMediaType(headers.Get("content-type"))
	if err != nil || mediaType != "application/problem+json" {
		return &TransportError{Message: fmt.Sprintf("HTTP %d did not use application/problem+json", status), Cause: err}
	}
	return decodeProblem(status, body)
}

func decodeProblem(status int, body []byte) error {
	if len(body) == 0 || len(body) > maximumProblemBytes {
		return &TransportError{Message: "problem body exceeds its bound"}
	}
	if err := validateUniqueJSON(body); err != nil {
		return &TransportError{Message: "problem JSON contains duplicate keys or excessive structure", Cause: err}
	}
	var wire wireProblem
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return &TransportError{Message: "problem JSON is invalid", Cause: err}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return &TransportError{Message: "problem JSON contains trailing data", Cause: err}
	}
	definition, ok := errorCatalog[wire.Code]
	if !ok || wire.SchemaVersion != "cigar.problem.v1" {
		return &TransportError{Message: "problem code or schema is unsupported"}
	}
	if wire.HTTPStatus != status || definition.HTTPStatus != status || wire.Retry != definition.Retry {
		return &TransportError{Message: "problem disagrees with the frozen error catalog"}
	}
	if len(wire.Message) < 1 || len(wire.Message) > 4096 || len(wire.Remediation) < 1 || len(wire.Remediation) > 4096 ||
		!correlationID.MatchString(wire.CorrelationID) || wire.Details == nil || len(wire.Details) > 256 {
		return &TransportError{Message: "problem fields violate their bounds"}
	}
	details, cloneErr := cloneJSONMap(wire.Details)
	if cloneErr != nil {
		return &TransportError{Message: "problem details violate nesting or node bounds", Cause: cloneErr}
	}
	return &APIError{
		Status:        status,
		Code:          wire.Code,
		NumericCode:   definition.NumericCode,
		Retry:         RetryClass(wire.Retry),
		Message:       wire.Message,
		Remediation:   wire.Remediation,
		CorrelationID: wire.CorrelationID,
		details:       details,
	}
}

func validateUniqueJSON(source []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	nodes := 0
	if err := scanUniqueJSONValue(decoder, 0, &nodes); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return &ValidationError{Message: "JSON contains trailing data"}
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder, depth int, nodes *int) error {
	(*nodes)++
	if depth > 64 || *nodes > maximumPayloadNodes {
		return &ValidationError{Message: "JSON exceeds nesting or node bounds"}
	}
	token, err := decoder.Token()
	if err != nil {
		return &ValidationError{Message: "JSON is invalid"}
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return &ValidationError{Message: "JSON array is invalid"}
		}
		return nil
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return &ValidationError{Message: "JSON object key is invalid"}
			}
			if _, exists := keys[key]; exists {
				return &ValidationError{Message: "JSON object contains a duplicate key"}
			}
			keys[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return &ValidationError{Message: "JSON object is invalid"}
		}
		return nil
	default:
		return &ValidationError{Message: "JSON delimiter is invalid"}
	}
}

func cloneJSONMap(source map[string]any) (map[string]any, error) {
	nodes := 0
	value, err := cloneJSONValue(source, 0, &nodes)
	if err != nil {
		return nil, err
	}
	return value.(map[string]any), nil
}

func cloneJSONValue(source any, depth int, nodes *int) (any, error) {
	*nodes = *nodes + 1
	if depth > 64 || *nodes > maximumPayloadNodes {
		return nil, &ValidationError{Message: "JSON value exceeds nesting or node bounds"}
	}
	switch current := source.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			copyOfChild, err := cloneJSONValue(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[key] = copyOfChild
		}
		return result, nil
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			copyOfChild, err := cloneJSONValue(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[index] = copyOfChild
		}
		return result, nil
	case nil, bool, float64, string:
		return current, nil
	default:
		return nil, &ValidationError{Message: "JSON value contains an unsupported node"}
	}
}

func retryableError(err error) bool {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return apiError.Retry == RetrySafe || apiError.Retry == RetryAfterBackoff
	}
	var transportError *TransportError
	var timeoutError *TimeoutError
	return errors.As(err, &transportError) || errors.As(err, &timeoutError)
}

func boundedVisibleASCII(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && visibleASCII.MatchString(value)
}

// Negotiate fetches version and capabilities under the same API-major contract.
func (client *Client) Negotiate(ctx context.Context, options ...CallOption) (Compatibility, error) {
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
