#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python3 "$ROOT/tests/validate_package.py"

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoLogo -NoProfile -File "$ROOT/tests/validate-package.ps1"
fi
