# Proposal adapters and controller

All proposal transports emit `cigar.refinement-model-action.v1`. Only
`ProposalController` interprets an action. It restricts paths to the task packet,
supports three read-only Git queries, applies checked unified diffs without a
shell, and resolves gates exclusively through the named command registry.

The hosted profile follows the OpenAI Responses API function-calling loop:
`POST /v1/responses`, one strict function tool, `parallel_tool_calls=false`,
`store=false`, and subsequent `function_call_output` items associated by
`call_id`. Because storage is disabled, the client replays the original input and
all prior response output items (including encrypted reasoning items) instead of
using server-side `previous_response_id`. The implementation source was checked
against the official function-calling and GPT-5.6 Sol documentation on
2026-07-27:

- https://developers.openai.com/api/docs/guides/function-calling
- https://developers.openai.com/api/docs/models/gpt-5.6-sol

Hosted credentials are environment *handles* in profiles. The value is resolved
only while constructing an Authorization header and is absent from descriptions,
task packets, transcripts, usage records, and evidence. Compatible plain HTTP is
accepted only on an explicit IP loopback address and port. Ambient proxies and
redirects are disabled.

Provider qualification uses deterministic protocol doubles; it does not consume a
credential or claim a live-model quality result. A live hosted run is a separately
authorized, metered operation.

Focused gate failures allow at most two distinct repair cycles. Repeated failures,
forbidden paths, patch budget failures, arbitrary commands, and non-allowlisted
context are denied rather than repaired.
