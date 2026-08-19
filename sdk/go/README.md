# CIGAR Go SDK

The Go 1.26.6-or-newer module exposes all 45 frozen CIGAR v1 HTTP operations, generated
Protobuf records and gRPC client/server stubs, context cancellation, typed problems, bounded deadlines,
idempotency-preserving safe retry, cursor iteration, closable/resumable SSE,
and local semantic bundle/delta verification.
The exported `cigar.ContextABI` constant is the exact string `cigar.context.v1`.

```go
client, err := cigar.NewClient(cigar.ClientOptions{
    BaseURL: "https://cigar.example",
    TokenProvider: tokenProvider,
})
if err != nil { return err }

result, err := client.CompileContextBundle(ctx,
    cigar.CompileContextBundleRequest{PlanID: planID},
    cigar.WithInvocationIdempotencyKey("compile-..."),
    cigar.WithInvocationTimeout(5*time.Second),
)
```

All high-level calls use schema-validated nominal payload records. Nested values use
the immutable `JSONValue` wrapper; protobuf maps cross the copy-safe boundary through
`ProtoSnapshot`. A custom `http.Client` requires `TrustCustomHTTPClient: true`, and
redirects are still disabled.

Remote HTTP and high-level gRPC construction require an explicit bearer token or provider. The
SDK never discovers credentials from a URL, environment, project configuration, ambient proxy, or
redirect target. Explicit cleartext loopback mode remains available only for local development.
SDK-owned HTTP and gRPC transports disable ambient proxy discovery. Caller-owned HTTP clients,
gRPC connections, and dialers require explicit trust acknowledgements and remain the caller's
channel-identity boundary.

Streams honor the context passed to `SubscribeSpaceEvents` and require `Close`.
Mutations preserve exact idempotency bytes across retries; `DispatchEffect` always
performs exactly one attempt.

The high-level gRPC surface has the same 45 nominal methods. The safe dialer disables
gRPC service-config retries so no transport layer can silently redispatch an effect:

```go
grpcClient, err := cigar.DialGRPCClient(cigar.GRPCDialOptions{
    Target: "dns:///cigar.example:9465",
    TransportCredentials: credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13}),
    TokenProvider: tokenProvider,
})
if err != nil { return err }
defer grpcClient.Close()

stream, err := grpcClient.SubscribeSpaceEvents(ctx,
    cigar.SpaceIdRequest{SpaceID: spaceID},
    cigar.WithInvocationResume(lastEventID),
)
```

`NewGRPCClient` is available for a caller-owned connection only with
`TrustCustomConnectionNoRetries: true`. The caller is then responsible for disabling
gRPC transport retry policies. The generated raw clients and server stubs live under
`gen/cigarv1`.

The checked-in gRPC bindings are reproducible with protoc 6.33.2,
`protoc-gen-go` 1.36.11, and `protoc-gen-go-grpc` 1.6.2:

```sh
protoc -I ../../schemas/proto \
  --plugin=protoc-gen-go=/tmp/cigar-sdk-tools/protoc-gen-go \
  --plugin=protoc-gen-go-grpc=/tmp/cigar-sdk-tools/protoc-gen-go-grpc \
  --go_out=. --go_opt=module=github.com/CIGAR/cigar/sdk/go \
  --go-grpc_out=. --go-grpc_opt=module=github.com/CIGAR/cigar/sdk/go \
  ../../schemas/proto/cigar_service.proto
```

From the module root, `go run ./examples/quickstart` verifies the packaged cross-SDK
fixture and prints its semantic bundle ID. Set `CIGAR_GRPC_TARGET` to make the same
example negotiate through the high-level gRPC client first.
