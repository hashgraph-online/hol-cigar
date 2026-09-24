#!/bin/sh
set -eu
context_python="$(uv python find --managed-python "${CIGAR_PYTHON_VERSION}")"
exec "${context_python}" "$@"
