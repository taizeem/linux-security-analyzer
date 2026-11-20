#!/usr/bin/env bash
# scripts/run.sh — Production Bash entry point for Linux Security Log Analyzer

set -euo pipefail

# Restrict newly created databases and reports to owner rw / group r / other none (0640/0750)
umask 027

# Resolve symlink-safe absolute paths regardless of caller working directory
if command -v readlink >/dev/null 2>&1; then
    SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
else
    SCRIPT_PATH="${BASH_SOURCE[0]}"
fi
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify python3 is installed and meets the minimum 3.10 requirement
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but was not found in PATH." >&2
    exit 127
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Error: Python 3.10 or newer is required." >&2
    exit 1
fi

# Ensure runtime directories exist with restrictive permissions
mkdir -p "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/reports"

# Export PYTHONPATH cleanly without introducing empty path entries
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

# Auto-load local config.json when present and no explicit config/meta flag was supplied
EXTRA_ARGS=()
HAS_CONFIG_FLAG=false
IS_META_FLAG=false
for arg in "$@"; do
    case "${arg}" in
        -c|--config|--config=*)
            HAS_CONFIG_FLAG=true
            ;;
        -h|--help|-v|--version)
            IS_META_FLAG=true
            ;;
    esac
done

if [[ "${HAS_CONFIG_FLAG}" == "false" && "${IS_META_FLAG}" == "false" && $# -gt 0 && -f "${PROJECT_ROOT}/config.json" ]]; then
    EXTRA_ARGS=(--config "${PROJECT_ROOT}/config.json")
fi

# Change into PROJECT_ROOT so relative paths in config resolve consistently
cd "${PROJECT_ROOT}"

# Replace the shell process with the Python CLI and forward all arguments
exec python3 -m security_analyzer.cli "${EXTRA_ARGS[@]}" "$@"