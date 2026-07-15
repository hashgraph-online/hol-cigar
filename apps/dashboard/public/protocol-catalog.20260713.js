const METHODS = Object.freeze(["GET", "POST"]);
const IDEMPOTENCY = Object.freeze(["required", "not_applicable"]);
const REVISIONS = Object.freeze(["none", "required"]);
const STREAMS = Object.freeze(["unary", "server_stream"]);
const AUTH_CLASSES = Object.freeze(["tenant", "operator", "health", "anonymous"]);
const FIELD_SOURCES = Object.freeze(["caller", "envelope", "path", "server", "transport"]);
const ERROR_RETRIES = Object.freeze([
  "never",
  "safe",
  "after_backoff",
  "after_reauthorization",
  "after_reconciliation",
]);

function boundedText(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function exactKeys(value, expected) {
  return value && typeof value === "object"
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validField(field) {
  return exactKeys(field, ["name", "source", "bound"])
    && /^[a-z][a-z0-9_]{0,63}$/.test(field.name)
    && FIELD_SOURCES.includes(field.source)
    && boundedText(field.bound, 256)
    && /^[a-z0-9_,.=]+$/.test(field.bound);
}

function validPayload(payload, stream) {
  if (!exactKeys(payload, [
    "event_fields",
    "event_max_bytes",
    "event_schema",
    "request_fields",
    "request_max_bytes",
    "request_schema",
    "response_fields",
    "response_max_bytes",
    "response_schema",
  ])) return false;
  const schema = (value) => typeof value === "string" && /^[A-Z][A-Za-z0-9]{0,127}$/.test(value);
  const fields = (value) => Array.isArray(value) && value.length <= 64 && value.every(validField);
  return schema(payload.request_schema)
    && schema(payload.response_schema)
    && (payload.event_schema === null || schema(payload.event_schema))
    && Number.isSafeInteger(payload.request_max_bytes)
    && payload.request_max_bytes >= 1
    && payload.request_max_bytes <= 16 * 1024 * 1024
    && Number.isSafeInteger(payload.response_max_bytes)
    && payload.response_max_bytes >= 1
    && payload.response_max_bytes <= 16 * 1024 * 1024
    && Number.isSafeInteger(payload.event_max_bytes)
    && payload.event_max_bytes >= 0
    && payload.event_max_bytes <= 1024 * 1024
    && fields(payload.request_fields)
    && fields(payload.response_fields)
    && fields(payload.event_fields)
    && (stream === "server_stream") === (payload.event_schema !== null)
    && (stream === "server_stream" ? payload.event_max_bytes === 1024 * 1024 : payload.event_max_bytes === 0);
}

function validError(error) {
  return exactKeys(error, [
    "disclose_identity",
    "grpc_status",
    "http_status",
    "numeric_code",
    "retry",
    "symbol",
  ])
    && Number.isSafeInteger(error.numeric_code)
    && error.numeric_code > 0
    && /^[A-Z][A-Z0-9_]{0,127}$/.test(error.symbol)
    && Number.isSafeInteger(error.http_status)
    && error.http_status >= 400
    && error.http_status <= 599
    && /^[A-Z][A-Z_]{0,63}$/.test(error.grpc_status)
    && ERROR_RETRIES.includes(error.retry)
    && typeof error.disclose_identity === "boolean";
}

export function normalizeProtocolCatalog(value) {
  if (
    !exactKeys(value, [
      "envelope_fields",
      "error_count",
      "errors",
      "operation_count",
      "schema_version",
      "service_count",
      "services",
      "source",
    ])
    || value.schema_version !== "cigar.dashboard-protocol.v1"
    || value.source !== "cargo-xtask-interface-projection"
    || value.service_count !== 7
    || value.operation_count !== 45
    || value.error_count !== 34
    || !Array.isArray(value.envelope_fields)
    || value.envelope_fields.length !== 6
    || !value.envelope_fields.every(validField)
    || !Array.isArray(value.services)
    || value.services.length !== value.service_count
    || !Array.isArray(value.errors)
    || value.errors.length !== value.error_count
  ) {
    throw new Error("Protocol catalog returned an incompatible response.");
  }
  const operationIds = new Set();
  let operationCount = 0;
  for (const service of value.services) {
    if (
      !exactKeys(service, ["name", "operations"])
      || !boundedText(service?.name, 64)
      || !service.name.endsWith("Service")
      || !Array.isArray(service.operations)
      || service.operations.length === 0
      || service.operations.length > 45
    ) {
      throw new Error("Protocol catalog contained an invalid service.");
    }
    for (const operation of service.operations) {
      operationCount += 1;
      if (
        !exactKeys(operation, [
          "auth",
          "http_method",
          "http_path",
          "idempotency",
          "mutation",
          "operation_id",
          "payload",
          "revision",
          "rpc",
          "service",
          "stream",
        ])
        || !boundedText(operation?.operation_id, 128)
        || operationIds.has(operation.operation_id)
        || !boundedText(operation.rpc, 128)
        || operation.service !== service.name
        || !METHODS.includes(operation.http_method)
        || !boundedText(operation.http_path, 512)
        || !operation.http_path.startsWith("/")
        || typeof operation.mutation !== "boolean"
        || !IDEMPOTENCY.includes(operation.idempotency)
        || !REVISIONS.includes(operation.revision)
        || !STREAMS.includes(operation.stream)
        || !AUTH_CLASSES.includes(operation.auth)
        || !validPayload(operation.payload, operation.stream)
      ) {
        throw new Error("Protocol catalog contained an invalid operation.");
      }
      operationIds.add(operation.operation_id);
    }
  }
  if (operationCount !== value.operation_count || operationIds.size !== value.operation_count) {
    throw new Error("Protocol catalog operation count disagreed with its contents.");
  }
  const errorCodes = new Set();
  const errorSymbols = new Set();
  for (const error of value.errors) {
    if (
      !validError(error)
      || errorCodes.has(error.numeric_code)
      || errorSymbols.has(error.symbol)
    ) {
      throw new Error("Protocol catalog contained an invalid error registry.");
    }
    errorCodes.add(error.numeric_code);
    errorSymbols.add(error.symbol);
  }
  return value;
}

export function filterProtocolOperations(catalog, query) {
  const searchable = (field) => field
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll(/[_./:-]+/g, " ")
    .toLowerCase();
  const normalized = typeof query === "string" ? query.trim().slice(0, 128).toLowerCase() : "";
  const operations = catalog.services.flatMap((service) => service.operations);
  if (!normalized) return operations;
  const terms = normalized.includes(" ") ? normalized.split(/\s+/).filter(Boolean) : null;
  return operations.filter((operation) => {
    const fields = [
      operation.service,
      operation.rpc,
      operation.operation_id,
      operation.http_method,
      operation.http_path,
      operation.auth,
      operation.stream,
    ];
    if (!terms) return fields.some((field) => field.toLowerCase().includes(normalized));
    const haystack = fields.map(searchable).join(" ");
    return terms.every((term) => haystack.includes(term));
  });
}
