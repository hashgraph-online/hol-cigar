$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Claude = if ($env:CIGAR_CLAUDE_BINARY) { $env:CIGAR_CLAUDE_BINARY } else { "claude" }
$Hook = if ($env:CIGAR_CLAUDE_HOOK_BINARY) { $env:CIGAR_CLAUDE_HOOK_BINARY } else { "cigar-claude-hook" }
$Mcp = if ($env:CIGAR_MCP_BINARY) { $env:CIGAR_MCP_BINARY } else { "cigar-mcp" }

$version = & $Claude --version
if ($LASTEXITCODE -ne 0 -or -not ($version -match "2\.1\.207")) {
    throw "Claude Code 2.1.207 is required; received: $version"
}
& $Claude plugin validate $Root --strict
if ($LASTEXITCODE -ne 0) { throw "strict plugin validation failed" }
& $Hook doctor --plugin-root $Root
if ($LASTEXITCODE -ne 0) { throw "hook doctor failed" }
& $Mcp schema-noop
if ($LASTEXITCODE -ne 0) { throw "MCP schema handshake failed" }

if ($env:CIGAR_CLAUDE_LIVE_SMOKE -eq "1") {
    $response = & $Claude --plugin-dir $Root -p "/cigar:why current" --output-format json --max-turns 1 --permission-mode dontAsk
    if ($LASTEXITCODE -ne 0) { throw "authenticated Claude smoke failed" }
    $null = $response | ConvertFrom-Json -Depth 64
} else {
    Write-Output "Recorded public-surface smoke passed; authenticated model smoke was not requested."
}
