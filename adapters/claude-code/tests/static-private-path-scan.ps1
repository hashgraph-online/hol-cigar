$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Fail([string]$Message) {
    throw $Message
}

$runtime = @(
    ".claude-plugin/plugin.json", ".mcp.json", "compatibility.json", "hooks/hooks.json", "README.md"
)
$runtime += Get-ChildItem (Join-Path $Root "skills") -Recurse -File | ForEach-Object { $_.FullName.Substring($Root.Length + 1) }
$runtime += Get-ChildItem (Join-Path $Root "agents") -File | ForEach-Object { $_.FullName.Substring($Root.Length + 1) }
$forbidden = @(
    (".claude" + "/projects"),
    (".claude" + ".json"),
    ("open(transcript" + "_path"),
    ("cat " + '${transcript_path}')
)
foreach ($relative in $runtime) {
    $text = Get-Content -Raw (Join-Path $Root $relative)
    foreach ($pattern in $forbidden) {
        if ($text.Contains($pattern)) {
            Fail "private provider dependency in $relative"
        }
    }
}

$hooks = Get-Content -Raw (Join-Path $Root "hooks/hooks.json") | ConvertFrom-Json -Depth 64
if ($null -ne $hooks.hooks.PSObject.Properties["WorktreeCreate"]) {
    Fail "WorktreeCreate registration would replace Claude default Git behavior"
}
foreach ($property in $hooks.hooks.PSObject.Properties) {
    foreach ($group in @($property.Value)) {
        foreach ($handler in @($group.hooks)) {
            if ($handler.type -ne "command" -or $handler.command -ne "cigar-claude-hook") {
                Fail "non-command or shell-indirect hook: $($property.Name)"
            }
            if (-not (@($handler.args) -contains '${CLAUDE_PLUGIN_ROOT}') -or -not (@($handler.args) -contains '${CLAUDE_PLUGIN_DATA}')) {
                Fail "hook does not use documented public paths: $($property.Name)"
            }
        }
    }
}

$mcp = Get-Content -Raw (Join-Path $Root ".mcp.json") | ConvertFrom-Json
if ($mcp.mcpServers.cigar.command -ne "cigar-mcp") {
    Fail "MCP must invoke only the signed installed cigar-mcp binary"
}
Write-Output "CIGAR Claude plugin PowerShell private-path scan passed"
