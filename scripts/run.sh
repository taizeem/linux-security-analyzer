#!/usr/bin/env bash

set -euo pipefail

# Resolve absolute paths regardless of caller's working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify python3 is installed and available in PATH
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but was not found in PATH." >&2
    exit 127
fi

# Ensure runtime directories exist with safe permissions
mkdir -p "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/reports"

# Export PYTHONPATH so Python resolves src/security_analyzer cleanly
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

# Move to PROJECT_ROOT so relative paths in config resolve consistently
cd "${PROJECT_ROOT}"

# Replace the shell process with the Python CLI and forward all arguments
exec python3 -m security_analyzer.cli "$@"
