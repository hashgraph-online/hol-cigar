module cigar-sdk-recorded-workflow

go 1.26.6

require (
	github.com/CIGAR/cigar/sdk/go v0.0.0
	google.golang.org/grpc v1.83.1
)

require (
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/CIGAR/cigar/sdk/go => ../../../sdk/go
