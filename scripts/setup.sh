#!/usr/bin/env bash
# scripts/setup.sh — Idempotent environment setup for Linux Security Log Analyzer

set -euo pipefail
umask 027

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Setting up Linux Security Log Analyzer in ${PROJECT_ROOT}..."

# 1. Verify required tools
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required but not installed." >&2
    exit 127
fi

if ! python3 -c 'import sys, sqlite3; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Error: Python 3.10+ with sqlite3 support is required." >&2
    exit 1
fi

if ! command -v flock >/dev/null 2>&1; then
    echo "Warning: 'flock' not found; install util-linux before enabling cron overlap locks." >&2
fi

# 2. Ensure runtime directories exist with restrictive permissions (0750)
mkdir -p "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/reports"
chmod 750 "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/reports"

# 3. Copy config.example.json -> config.json only if not already present
CONFIG_TARGET="${LSA_CONFIG_PATH:-${PROJECT_ROOT}/config.json}"
if [[ ! -f "${CONFIG_TARGET}" ]]; then
    cp "${PROJECT_ROOT}/config.example.json" "${CONFIG_TARGET}"
    chmod 640 "${CONFIG_TARGET}"
    echo "Created configuration file: ${CONFIG_TARGET}"
else
    echo "Configuration file already exists (preserved): ${CONFIG_TARGET}"
fi

# 4. Ensure Bash scripts are executable
for script in "${PROJECT_ROOT}"/scripts/*.sh; do
    if [[ -f "${script}" ]]; then
        chmod 755 "${script}"
    fi
done

# 5. Initialize SQLite database schema and indexes idempotently
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
DB_OVERRIDE="${LSA_DB_PATH:-}"

python3 - "${CONFIG_TARGET}" "${DB_OVERRIDE}" "${PROJECT_ROOT}" << 'PYEOF'
from pathlib import Path
import sys
from security_analyzer.config import load_config
from security_analyzer.database import DatabaseManager

config_path = Path(sys.argv[1])
db_override = sys.argv[2]
project_root = Path(sys.argv[3])

cfg = load_config(config_path)
if db_override:
    db_path = Path(db_override)
else:
    raw_db = Path(cfg.db_path)
    db_path = raw_db if raw_db.is_absolute() else (project_root / raw_db)

db = DatabaseManager(db_path)
db.initialize()
print(f"Initialized SQLite database: {db.db_path}")
PYEOF

# 6. Check readability of standard host authentication logs (informational only)
if [[ -r /var/log/auth.log ]]; then
    echo "Log access check: OK (/var/log/auth.log is readable by $(whoami))"
elif [[ -r /var/log/secure ]]; then
    echo "Log access check: OK (/var/log/secure is readable by $(whoami))"
else
    echo "Notice: Neither /var/log/auth.log nor /var/log/secure is readable by $(whoami)."
    echo "        Add your user to the 'adm' group (Ubuntu/Debian) or pass --file sample_logs/auth_sample.log."
fi

echo "Setup completed successfully."