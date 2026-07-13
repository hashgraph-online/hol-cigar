# ContextContract v1

`ContextContract` is the normalized semantic input to compilation. Transport request IDs and trace IDs are intentionally absent. The record requires a non-empty bounded goal, operation class, authenticated principal, purpose, context-space or project scope, target tokenizer/materializer fingerprints, exact integer budgets, context requirements, and a closed consistency mode.

Lane allocations must be non-zero and sum exactly to `total_input_tokens`. Input plus output reserve must fit the target context window. Project IDs are sorted and unique. Bounded-staleness mode requires a maximum duration; snapshot and strong modes forbid one.

Human goal, purpose, query text, provider, model-family, and project identities are omitted from `Debug` output. The generated contract is `schemas/json/context-contract-v1.schema.json` and its transport counterpart is in `schemas/proto/context_abi.proto`.

