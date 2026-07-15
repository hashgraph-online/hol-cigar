import test from "node:test";
import assert from "node:assert/strict";

import {
  filterProtocolOperations,
  normalizeProtocolCatalog,
} from "../public/protocol-catalog.20260713.js";

function catalog() {
  const services = Array.from({ length: 7 }, (_, serviceIndex) => ({
    name: `Service${serviceIndex}Service`,
    operations: Array.from({ length: serviceIndex === 6 ? 9 : 6 }, (_, operationIndex) => ({
      service: `Service${serviceIndex}Service`,
      rpc: `Operation${serviceIndex}x${operationIndex}`,
      operation_id: `operation${serviceIndex}x${operationIndex}`,
      http_method: operationIndex % 2 ? "POST" : "GET",
      http_path: `/v1/service-${serviceIndex}/operation-${operationIndex}`,
      mutation: operationIndex % 2 === 1,
      idempotency: operationIndex % 2 ? "required" : "not_applicable",
      revision: "none",
      stream: "unary",
      auth: "tenant",
      payload: {
        request_schema: "ExampleRequest",
        response_schema: "ExampleResponse",
        event_schema: null,
        request_max_bytes: 1024,
        response_max_bytes: 1024,
        event_max_bytes: 0,
        request_fields: [{ name: "value", source: "caller", bound: "max_bytes=256" }],
        response_fields: [{ name: "payload", source: "server", bound: "operation_schema,max_bytes=1024" }],
        event_fields: [],
      },
    })),
  }));
  return {
    schema_version: "cigar.dashboard-protocol.v1",
    source: "cargo-xtask-interface-projection",
    service_count: 7,
    operation_count: 45,
    error_count: 34,
    envelope_fields: [
      { name: "dry_run", source: "envelope", bound: "boolean" },
      { name: "expected_revision", source: "envelope", bound: "max_bytes=256" },
      { name: "idempotency_key", source: "envelope", bound: "max_bytes=256" },
      { name: "page_cursor", source: "envelope", bound: "max_bytes=4096" },
      { name: "page_size", source: "envelope", bound: "1..=1000" },
      { name: "path_parameters", source: "transport", bound: "max_items=8,sorted_unique" },
    ],
    services,
    errors: Array.from({ length: 34 }, (_, index) => ({
      numeric_code: 1000 + index,
      symbol: `ERROR_${index}`,
      http_status: 400,
      grpc_status: "INVALID_ARGUMENT",
      retry: "never",
      disclose_identity: false,
    })),
  };
}

test("generated protocol catalog requires exactly 7 services and 45 unique operations", () => {
  const value = catalog();
  assert.equal(normalizeProtocolCatalog(value), value);
  value.services[6].operations[0].operation_id = value.services[0].operations[0].operation_id;
  assert.throws(() => normalizeProtocolCatalog(value), /invalid operation/);
});

test("protocol filtering covers IDs, paths, auth, methods, and services", () => {
  const value = normalizeProtocolCatalog(catalog());
  assert.equal(filterProtocolOperations(value, "operation6x8").length, 1);
  assert.equal(filterProtocolOperations(value, "service-2").length, 6);
  assert.equal(filterProtocolOperations(value, "POST").length, 22);
  assert.equal(filterProtocolOperations(value, "operator").length, 0);
  assert.equal(filterProtocolOperations(value, "").length, 45);
});

test("protocol filtering tokenizes camelCase and requires every search term", () => {
  const value = catalog();
  value.services[0].operations[0].operation_id = "subscribeSpaceEvents";
  value.services[0].operations[0].rpc = "SubscribeSpaceEvents";
  const normalized = normalizeProtocolCatalog(value);
  assert.deepEqual(
    filterProtocolOperations(normalized, "subscribe space events").map((operation) => operation.operation_id),
    ["subscribeSpaceEvents"],
  );
  assert.deepEqual(filterProtocolOperations(normalized, "subscribe missing"), []);
});

test("protocol catalog rejects unsafe enums and inconsistent counts", () => {
  const unsafe = catalog();
  unsafe.services[0].operations[0].auth = "root";
  assert.throws(() => normalizeProtocolCatalog(unsafe), /invalid operation/);
  const incomplete = catalog();
  incomplete.operation_count = 44;
  assert.throws(() => normalizeProtocolCatalog(incomplete), /incompatible response/);
  const duplicateError = catalog();
  duplicateError.errors[1].numeric_code = duplicateError.errors[0].numeric_code;
  assert.throws(() => normalizeProtocolCatalog(duplicateError), /invalid error registry/);
  const unexpectedContent = catalog();
  unexpectedContent.errors[0].message = "untrusted dynamic content";
  assert.throws(() => normalizeProtocolCatalog(unexpectedContent), /invalid error registry/);
});
