$ErrorActionPreference = 'Stop'
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
$programs = Get-Content -Raw "$env:RUNNER_TEMP/installed/programs.json" | ConvertFrom-Json
$index = 0
foreach ($program in $programs) {
  New-NetFirewallRule -DisplayName "CIGAR qualification $index" -Group 'CIGAR context distribution qualification' `
    -Direction Outbound -Action Block -Profile Any -Protocol Any -Program $program | Out-Null
  $index++
}
python scripts/release/qualify_context_distribution.py offline --output "$env:RUNNER_TEMP/installed"
if ($LASTEXITCODE -ne 0) { throw 'Offline Windows consumer qualification failed' }
