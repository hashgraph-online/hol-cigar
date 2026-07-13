# SDK guides

All SDKs implement the same protocol and error registry; version and Context ABI constants must agree
with binary release metadata and schemas.

## Rust

The Rust SDK provides a typed remote daemon client and an optional embedded runtime. Use a bounded
async runtime, configure explicit TLS roots and authorization, and preserve structured problems.

## TypeScript

The ESM TypeScript package contains generated protobuf types, HTTP/gRPC operations, semantic digest
helpers, pagination, and streams. Ship only the exact npm tarball validated in an empty project.

## Python

The CPython 3.14 package contains generated protobuf types and a bundle qualification entry point.
Install the exact wheel or sdist in a new virtual environment with hashes and egress disabled.

## Go

The Go module provides generated models plus HTTP/gRPC clients, pagination, and streams. Resolve the
signed module tag, verify `go.sum`, and run the module from a clean cache before claiming support.

Clients must use HTTPS for remote targets, explicit authorization files, bounded deadlines, stable
idempotency keys for retried mutations, and structured problem codes. Never retry an unknown effect
based only on transport failure.
