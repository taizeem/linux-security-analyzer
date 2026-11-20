#!/usr/bin/env bash
# scripts/scheduled_scan.sh — Automated authentication log scan and report generator

set -euo pipefail
umask 027

# Ensure standard system binary directories are in PATH under minimal cron environments
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_SCRIPT="${PROJECT_ROOT}/scripts/run.sh"

LOG_FILE="${LSA_LOG_FILE:-/var/log/auth.log}"
DB_PATH="${LSA_DB_PATH:-${PROJECT_ROOT}/data/security_events.db}"
REPORT_DIR="${LSA_REPORT_DIR:-${PROJECT_ROOT}/reports}"
RUN_LOG="${LSA_RUN_LOG:-${PROJECT_ROOT}/data/scheduled_scan.log}"
CONFIG_PATH="${LSA_CONFIG_PATH:-}"

mkdir -p "$(dirname "${DB_PATH}")" "${REPORT_DIR}" "$(dirname "${RUN_LOG}")"

log_msg() {
    local level="$1"
    shift
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf "%s | %-7s | scheduled_scan | %s\n" "${ts}" "${level}" "$*" >> "${RUN_LOG}"
}

TIMESTAMP_TAG="$(date -u +"%Y%m%d_%H%M%SZ")"
JSON_REPORT="${REPORT_DIR}/security_report_${TIMESTAMP_TAG}.json"
TXT_REPORT="${REPORT_DIR}/security_report_${TIMESTAMP_TAG}.txt"

COMMON_FLAGS=(--db "${DB_PATH}")
if [[ -n "${CONFIG_PATH}" ]]; then
    COMMON_FLAGS+=(--config "${CONFIG_PATH}")
fi

log_msg "INFO" "Starting scheduled scan for log=${LOG_FILE}"

# 1. Analyze log file and store deduplicated events/alerts in SQLite
"${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" analyze --file "${LOG_FILE}" >> "${RUN_LOG}" 2>&1

# 2. Generate timestamped JSON and terminal reports
"${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" report --format json --output "${JSON_REPORT}" >> "${RUN_LOG}" 2>&1
"${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" report --format terminal --output "${TXT_REPORT}" >> "${RUN_LOG}" 2>&1

log_msg "INFO" "Scheduled scan completed successfully. Reports: ${JSON_REPORT}, ${TXT_REPORT}"