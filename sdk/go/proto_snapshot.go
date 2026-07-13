package cigar

import (
	"bytes"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtoSnapshot is an immutable deterministic-wire snapshot of a generated message.
// It is the copy-safe boundary for generated protobuf records that expose map fields.
type ProtoSnapshot struct {
	messageName protoreflect.FullName
	wire        []byte
}

// SnapshotProto deep-copies a generated message into deterministic protobuf bytes.
func SnapshotProto(message proto.Message) (ProtoSnapshot, error) {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ProtoSnapshot{}, &ValidationError{Message: "protobuf message must be non-nil and valid"}
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return ProtoSnapshot{}, &ValidationError{Message: "protobuf message cannot be serialized"}
	}
	return ProtoSnapshot{
		messageName: message.ProtoReflect().Descriptor().FullName(),
		wire:        bytes.Clone(wire),
	}, nil
}

// MessageName returns the exact frozen protobuf message name.
func (snapshot ProtoSnapshot) MessageName() protoreflect.FullName { return snapshot.messageName }

// Bytes returns an owned deterministic wire copy.
func (snapshot ProtoSnapshot) Bytes() []byte { return bytes.Clone(snapshot.wire) }

// UnmarshalInto materializes a fresh generated message of the exact snapshotted type.
func (snapshot ProtoSnapshot) UnmarshalInto(destination proto.Message) error {
	if destination == nil || !destination.ProtoReflect().IsValid() {
		return &ValidationError{Message: "protobuf destination must be non-nil and valid"}
	}
	if destination.ProtoReflect().Descriptor().FullName() != snapshot.messageName {
		return &ValidationError{Message: "protobuf destination type does not match snapshot"}
	}
	proto.Reset(destination)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(snapshot.wire, destination); err != nil {
		return &TransportError{Message: "protobuf snapshot cannot be decoded", Cause: err}
	}
	return nil
}
