#!/usr/bin/env bash
# scripts/scheduled_scan.sh — Automated authentication log scan and report generator
#
# Exit codes:
#   0  - Success
#   10 - Target authentication log file missing or unreadable
#   11 - Analyze command failed
#   12 - Report generation failed
#   20 - Skipped because another scan instance already holds the lock

set -euo pipefail
umask 027

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

readonly E_LOG_UNREADABLE=10
readonly E_ANALYZE_FAILED=11
readonly E_REPORT_FAILED=12
readonly E_LOCK_CONTENTION=20

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_SCRIPT="${PROJECT_ROOT}/scripts/run.sh"

LOG_FILE="${LSA_LOG_FILE:-/var/log/auth.log}"
DB_PATH="${LSA_DB_PATH:-${PROJECT_ROOT}/data/security_events.db}"
REPORT_DIR="${LSA_REPORT_DIR:-${PROJECT_ROOT}/reports}"
RUN_LOG="${LSA_RUN_LOG:-${PROJECT_ROOT}/data/scheduled_scan.log}"
LOCK_FILE="${LSA_LOCK_FILE:-${PROJECT_ROOT}/data/scheduled_scan.lock}"
CONFIG_PATH="${LSA_CONFIG_PATH:-}"

mkdir -p "$(dirname "${DB_PATH}")" "${REPORT_DIR}" "$(dirname "${RUN_LOG}")" "$(dirname "${LOCK_FILE}")"

log_msg() {
    local level="$1"
    shift
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf "%s | %-7s | scheduled_scan | %s\n" "${ts}" "${level}" "$*" >> "${RUN_LOG}"
}

on_error() {
    local exit_code="$1"
    local line_no="$2"
    log_msg "ERROR" "Unexpected failure at line ${line_no} (exit code ${exit_code})"
    echo "Error: scheduled_scan.sh failed at line ${line_no} (exit code ${exit_code})" >&2
}
trap 'on_error $? $LINENO' ERR

# Acquire a non-blocking exclusive kernel lock to prevent overlapping scans
if command -v flock >/dev/null 2>&1; then
    exec 9>"${LOCK_FILE}"
    if ! flock -n 9; then
        log_msg "WARNING" "Another scheduled scan is already running (lock: ${LOCK_FILE}); skipping."
        echo "Warning: another scheduled scan is already running; skipping." >&2
        exit "${E_LOCK_CONTENTION}"
    fi
else
    log_msg "WARNING" "'flock' not available; proceeding without overlap lock."
fi

# Pre-flight checks
if [[ ! -x "${RUN_SCRIPT}" ]]; then
    log_msg "ERROR" "Launcher script is missing or not executable: ${RUN_SCRIPT}"
    echo "Error: launcher script not executable: ${RUN_SCRIPT}" >&2
    exit "${E_ANALYZE_FAILED}"
fi

if [[ ! -f "${LOG_FILE}" || ! -r "${LOG_FILE}" ]]; then
    log_msg "ERROR" "Log file is missing or unreadable: ${LOG_FILE}"
    echo "Error: cannot read log file: ${LOG_FILE}" >&2
    exit "${E_LOG_UNREADABLE}"
fi

TIMESTAMP_TAG="$(date -u +"%Y%m%d_%H%M%SZ")"
JSON_REPORT="${REPORT_DIR}/security_report_${TIMESTAMP_TAG}.json"
TXT_REPORT="${REPORT_DIR}/security_report_${TIMESTAMP_TAG}.txt"

COMMON_FLAGS=(--db "${DB_PATH}")
if [[ -n "${CONFIG_PATH}" ]]; then
    COMMON_FLAGS+=(--config "${CONFIG_PATH}")
fi

log_msg "INFO" "Starting scheduled scan for log=${LOG_FILE}"

# 1. Analyze log file and store deduplicated events/alerts in SQLite
if ! "${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" analyze --file "${LOG_FILE}" >> "${RUN_LOG}" 2>&1; then
    log_msg "ERROR" "Analyze stage failed for log=${LOG_FILE}"
    echo "Error: analyze stage failed (see ${RUN_LOG})" >&2
    exit "${E_ANALYZE_FAILED}"
fi

# 2. Generate timestamped JSON and terminal reports
if ! "${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" report --format json --output "${JSON_REPORT}" >> "${RUN_LOG}" 2>&1; then
    log_msg "ERROR" "JSON report export failed: ${JSON_REPORT}"
    echo "Error: JSON report export failed (see ${RUN_LOG})" >&2
    exit "${E_REPORT_FAILED}"
fi

if ! "${RUN_SCRIPT}" "${COMMON_FLAGS[@]}" report --format terminal --output "${TXT_REPORT}" >> "${RUN_LOG}" 2>&1; then
    log_msg "ERROR" "Terminal report export failed: ${TXT_REPORT}"
    echo "Error: terminal report export failed (see ${RUN_LOG})" >&2
    exit "${E_REPORT_FAILED}"
fi

log_msg "INFO" "Scheduled scan completed successfully. Reports: ${JSON_REPORT}, ${TXT_REPORT}"
exit 0