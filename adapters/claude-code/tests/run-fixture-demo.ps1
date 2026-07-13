$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Hook = if ($env:CIGAR_CLAUDE_HOOK_BINARY) { $env:CIGAR_CLAUDE_HOOK_BINARY } else { "cigar-claude-hook" }
$Data = Join-Path ([System.IO.Path]::GetTempPath()) ("cigar-claude-fixture-" + [guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $Data

try {
    $env:CIGAR_CLI_BINARY = Join-Path $Root "tests/fake-cigar.cmd"
    $env:CIGAR_CLAUDE_PLAN_ID = "plan-fixture"
    $env:CIGAR_CLAUDE_SPACE_ID = "space-fixture"
    $env:CIGAR_CLAUDE_FOCUS_ID = "focus-fixture"
    $env:CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE = "fixture-recipient"
    $env:CIGAR_CLAUDE_HANDOFF_PROJECT_ID = "project-fixture"
    $env:CIGAR_CLAUDE_HANDOFF_AUDIENCE = "fixture-runtime"

    $order = @(
        "session-start", "user-prompt-submit", "instructions-loaded", "pre-tool-use",
        "post-tool-use", "post-tool-use-failure", "post-tool-batch", "subagent-start",
        "subagent-stop", "task-created", "task-completed", "pre-compact", "post-compact",
        "cwd-changed", "worktree-create", "worktree-remove", "setup", "user-prompt-expansion",
        "permission-request", "permission-denied", "notification", "message-display",
        "teammate-idle", "config-change", "file-changed", "elicitation", "elicitation-result",
        "stop", "stop-failure", "session-end"
    )
    foreach ($name in $order) {
        $event = Get-Content -Raw (Join-Path $Root "tests/fixtures/events/$name.json")
        $output = $event | & $Hook run --plugin-root $Root --plugin-data $Data
        if ($LASTEXITCODE -ne 0) { throw "hook failed for $name" }
        $null = $output | ConvertFrom-Json -Depth 64
    }

    $prompt = Get-Content -Raw (Join-Path $Root "tests/fixtures/events/user-prompt-submit.json")
    $first = $prompt | & $Hook run --plugin-root $Root --plugin-data $Data
    $second = $prompt | & $Hook run --plugin-root $Root --plugin-data $Data
    if ($first -ne $second) { throw "duplicate event response changed" }

    $effectEvent = Get-Content -Raw (Join-Path $Root "tests/fixtures/scenarios/governed-effect.json")
    $effect = $effectEvent | & $Hook run --plugin-root $Root --plugin-data $Data | ConvertFrom-Json -Depth 64
    if ($null -ne $effect.hookSpecificOutput.permissionDecision) { throw "authorized effect was denied" }

    $env:CIGAR_CLI_BINARY = "C:\definitely-not-present\cigar.exe"
    $degradedEvent = $prompt.Replace("fixture-session", "fixture-degraded-session")
    $degraded = $degradedEvent | & $Hook run --plugin-root $Root --plugin-data $Data | ConvertFrom-Json -Depth 64
    if (-not $degraded.systemMessage.Contains("CIGAR degraded")) { throw "degraded marker missing" }
    $deniedEvent = $effectEvent.Replace("fixture-effect-session", "fixture-denied-session")
    $denied = $deniedEvent | & $Hook run --plugin-root $Root --plugin-data $Data | ConvertFrom-Json -Depth 64
    if ($denied.hookSpecificOutput.permissionDecision -ne "deny") { throw "effect did not fail closed" }
    $env:CIGAR_CLI_BINARY = Join-Path $Root "tests/fake-cigar.cmd"

    $malformed = Get-Content -Raw (Join-Path $Root "tests/fixtures/invalid/malformed.json")
    $null = $malformed | & $Hook run --plugin-root $Root --plugin-data $Data 2>$null
    if ($LASTEXITCODE -eq 0) { throw "malformed event was accepted" }

    $oversized = & (Join-Path $Root "tests/generate-oversized.ps1")
    $null = $oversized | & $Hook run --plugin-root $Root --plugin-data $Data 2>$null
    if ($LASTEXITCODE -eq 0) { throw "oversized event was accepted" }

    $notDirectory = Join-Path $Data "not-a-directory"
    $null = New-Item -ItemType File -Path $notDirectory
    $stopEvent = Get-Content -Raw (Join-Path $Root "tests/fixtures/events/stop.json")
    $null = $stopEvent | & $Hook run --plugin-root $Root --plugin-data $notDirectory 2>$null
    if ($LASTEXITCODE -eq 0) { throw "invalid state boundary was accepted" }

    $latencies = @()
    for ($index = 0; $index -lt 55; $index++) {
        $event = [ordered]@{
            session_id = "latency-$index"
            transcript_path = "/opaque/provider-transcript.jsonl"
            cwd = "/workspace/cigar-fixture"
            hook_event_name = "UserPromptSubmit"
            prompt = "fixture prompt $index"
        } | ConvertTo-Json -Compress
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $output = $event | & $Hook run --plugin-root $Root --plugin-data $Data
        $timer.Stop()
        if ($LASTEXITCODE -ne 0) { throw "latency hook failed" }
        $null = $output | ConvertFrom-Json -Depth 64
        if ($index -ge 5) { $latencies += $timer.Elapsed.TotalMilliseconds }
    }
    $latencies = $latencies | Sort-Object
    $p95 = $latencies[[Math]::Ceiling($latencies.Count * 0.95) - 1]
    $p99 = $latencies[[Math]::Ceiling($latencies.Count * 0.99) - 1]
    if ($p95 -gt 150 -or $p99 -gt 1000) { throw "prompt hook latency exceeds budget" }

    Write-Output (@{ samples = $latencies.Count; p95_ms = $p95; p99_ms = $p99 } | ConvertTo-Json -Compress)
    Write-Output "CIGAR Claude PowerShell fixture demo passed without a model or network call"
} finally {
    Remove-Item -Recurse -Force $Data -ErrorAction SilentlyContinue
}
