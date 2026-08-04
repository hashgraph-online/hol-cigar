$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$metadata = @(Get-ChildItem -Force (Join-Path $Root ".claude-plugin"))
Require ($metadata.Count -eq 1 -and $metadata[0].Name -eq "plugin.json") ".claude-plugin must contain only plugin.json"

$malformed = Join-Path $Root "tests/fixtures/invalid/malformed.json"
Get-ChildItem $Root -Recurse -File -Filter "*.json" |
    Where-Object { $_.FullName -ne $malformed } |
    ForEach-Object {
        $null = Get-Content -Raw $_.FullName | ConvertFrom-Json -Depth 64
    }
$rejected = $false
try {
    $null = Get-Content -Raw $malformed | ConvertFrom-Json -Depth 64
} catch {
    $rejected = $true
}
Require $rejected "malformed fixture unexpectedly parsed"

$plugin = Get-Content -Raw (Join-Path $Root ".claude-plugin/plugin.json") | ConvertFrom-Json
Require ($plugin.name -eq "cigar" -and $plugin.version -eq "0.9.2") "plugin identity mismatch"
foreach ($name in @("skills", "agents", "hooks", "mcpServers", "commands")) {
    Require ($null -eq $plugin.PSObject.Properties[$name]) "redundant default component path: $name"
}

$readme = Get-Content -Raw (Join-Path $Root "README.md")
foreach ($heading in @(
    "## Development compatibility target",
    "## What is registered",
    "## Limitations",
    "## Development qualification procedure"
)) {
    Require ($readme.Contains($heading)) "README section missing: $heading"
}
foreach ($statement in @(
    "unpublished, unsupported development package",
    "define a future qualification scope only",
    "not evidence of installed compatibility, signing, release qualification, publication, or support",
    "These commands are qualification inputs, not release installation instructions."
)) {
    Require ($readme.Contains($statement)) "README development disclaimer missing: $statement"
}
foreach ($forbidden in @(
    "This package is qualified",
    "runs signed CIGAR executables",
    'The signed `cigar` installer embeds'
)) {
    Require (-not $readme.Contains($forbidden)) "README contains a premature claim: $forbidden"
}

$compatibility = Get-Content -Raw (Join-Path $Root "compatibility.json") | ConvertFrom-Json
Require ($compatibility.context_abi -eq "cigar.context.v1") "context ABI mismatch"
Require ($compatibility.claude_code.minimum_inclusive -eq "2.1.207") "minimum Claude version mismatch"
Require ($compatibility.claude_code.maximum_exclusive -eq "2.1.208") "maximum Claude version mismatch"
Require ($compatibility.public_surfaces_only -eq $true) "private compatibility surface declared"

$expectedRegistered = @(
    "CwdChanged", "InstructionsLoaded", "PostCompact", "PostToolBatch", "PostToolUse",
    "PostToolUseFailure", "PreCompact", "PreToolUse", "SessionEnd", "SessionStart",
    "Stop", "StopFailure", "SubagentStart", "SubagentStop", "TaskCompleted", "TaskCreated",
    "UserPromptSubmit", "WorktreeRemove"
) | Sort-Object
$hookDocument = Get-Content -Raw (Join-Path $Root "hooks/hooks.json") | ConvertFrom-Json -Depth 64
$registered = @($hookDocument.hooks.PSObject.Properties.Name) | Sort-Object
Require (($registered -join "`n") -eq ($expectedRegistered -join "`n")) "hook registration differs from the safe qualified set"
foreach ($property in $hookDocument.hooks.PSObject.Properties) {
    $groups = @($property.Value)
    Require ($groups.Count -eq 1) "hook group count invalid: $($property.Name)"
    $handlers = @($groups[0].hooks)
    Require ($handlers.Count -eq 1) "hook handler count invalid: $($property.Name)"
    $handler = $handlers[0]
    Require ($handler.type -eq "command" -and $handler.command -eq '${CLAUDE_PLUGIN_ROOT}/bin/cigar-claude-hook') "non-command hook: $($property.Name)"
    Require ($handler.timeout -eq 1) "unbounded hook: $($property.Name)"
    $args = @($handler.args)
    Require ($args.Count -eq 5) "hook argument count invalid: $($property.Name)"
    Require ($args[0] -eq "run" -and $args[1] -eq "--plugin-root" -and $args[3] -eq "--plugin-data") "hook exec arguments invalid: $($property.Name)"
    Require ($args[2] -eq '${CLAUDE_PLUGIN_ROOT}' -and $args[4] -eq '${CLAUDE_PLUGIN_DATA}') "hook public paths invalid: $($property.Name)"
}

$expectedEvents = @(
    "ConfigChange", "CwdChanged", "Elicitation", "ElicitationResult", "FileChanged",
    "InstructionsLoaded", "MessageDisplay", "Notification", "PermissionDenied",
    "PermissionRequest", "PostCompact", "PostToolBatch", "PostToolUse",
    "PostToolUseFailure", "PreCompact", "PreToolUse", "SessionEnd", "SessionStart",
    "Setup", "Stop", "StopFailure", "SubagentStart", "SubagentStop", "TaskCompleted",
    "TaskCreated", "TeammateIdle", "UserPromptExpansion", "UserPromptSubmit",
    "WorktreeCreate", "WorktreeRemove"
) | Sort-Object
$seen = @()
Get-ChildItem (Join-Path $Root "tests/fixtures/events") -File -Filter "*.json" |
    ForEach-Object {
        $event = Get-Content -Raw $_.FullName | ConvertFrom-Json -Depth 64
        Require ($event.transcript_path -eq "/opaque/provider-transcript.jsonl") "opaque transcript field missing: $($_.Name)"
        $seen += $event.hook_event_name
    }
$seen = $seen | Sort-Object
Require (($seen -join "`n") -eq ($expectedEvents -join "`n")) "event fixture coverage mismatch"

Get-ChildItem $Root -Recurse -File | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    Require (-not ($bytes -contains 0)) "NUL byte in $($_.FullName)"
    Require (-not ($bytes -contains 13)) "non-LF line ending in $($_.FullName)"
    Require ($bytes.Length -gt 0 -and $bytes[-1] -eq 10) "missing final newline in $($_.FullName)"
}

$manifestPath = Join-Path $Root "package-manifest.json"
$manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json -Depth 64
Require ($manifest.schema_version -eq "cigar.claude-code-package.v1") "package manifest schema mismatch"
$actual = @(Get-ChildItem $Root -Recurse -File |
    Where-Object { $_.FullName -ne $manifestPath } |
    ForEach-Object { $_.FullName.Substring($Root.Length + 1).Replace("\", "/") } |
    Sort-Object)
$declared = @($manifest.files | ForEach-Object { $_.path })
Require (($actual -join "`n") -eq ($declared -join "`n")) "package manifest coverage mismatch"
foreach ($entry in $manifest.files) {
    $path = Join-Path $Root $entry.path
    $item = Get-Item $path
    $hash = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    Require ($item.Length -eq $entry.bytes) "manifest byte count mismatch: $($entry.path)"
    Require ($hash -eq $entry.sha256) "manifest digest mismatch: $($entry.path)"
}

Write-Output "CIGAR Claude plugin PowerShell validation passed"
