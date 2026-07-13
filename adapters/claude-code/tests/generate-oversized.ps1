$ErrorActionPreference = "Stop"

$event = [ordered]@{
    session_id = "fixture-oversized"
    transcript_path = "/opaque/provider-transcript.jsonl"
    cwd = "/workspace/cigar-fixture"
    hook_event_name = "UserPromptSubmit"
    prompt = "x" * 70000
}
$event | ConvertTo-Json -Compress
