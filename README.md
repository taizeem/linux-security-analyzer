# Linux Security Log Analyzer

A defensive, production-minded Linux authentication log analyzer built with **Bash**, **Python 3 (standard library only)**, **SQLite**, and **Cron**.

It ingests Linux authentication logs (`/var/log/auth.log`, `/var/log/secure`, or synthetic datasets), parses SSH (`sshd`) and `sudo` events across both modern RFC 3339 / ISO-8601 and legacy BSD syslog formats, evaluates configurable sliding-window detection rules, persists deduplicated events and alerts in SQLite, and generates human-readable terminal reports and versioned JSON reports.

---

## Defensive Scope & Philosophy

This project is strictly a **read-only defensive security monitoring and investigation tool** intended only for systems and logs you own or are authorized to inspect.

- **No active host modification**: Does not alter firewall rules (`iptables`/`ufw`/`nftables`), automatically block IP addresses, or terminate processes.
- **Evidence-based alerting**: Alerts describe what the log evidence establishes (e.g., repeated authentication failures within a sliding window) and attach underlying log lines rather than blindly labeling every anomaly as confirmed malicious activity.
- **Least-privilege execution**: Designed to run under an unprivileged Linux user in the `adm` group reading `0640 syslog:adm` logs directly—never requiring `root` or `sudo` during routine operation.

---

## Architecture Overview

```text
/var/log/auth.log (or sample_logs/*.log)
        │
        ▼  [Bash Layer: scripts/run.sh & scripts/scheduled_scan.sh]
        │  umask 027 · flock non-blocking lock · PATH & Python 3.10+ guard
        ▼
  collector.py      O(1)-memory line streaming · permission checks · UTF-8 replacement
        │
        ▼
  parser.py         Control-char sanitization · two-stage regex (Syslog -> SSH/sudo)
        │           Timestamp normalization · RFC-compliant IPv4/IPv6 & port validation
        ▼
  models.py         Frozen AuthEvent & SecurityAlert dataclasses · SHA-256 fingerprints
        │
        ▼
  detector.py       O(N) sliding-window detectors · configurable DetectionEngine
        │           Contextual 4-tier severity scoring · bounded evidence attachment
        ▼
  database.py       SQLite (WAL mode · foreign keys · 8 B-tree indexes · INSERT OR IGNORE)
        │
        ├──▶ cli.py       Interactive investigation (analyze, events, alerts, stats, report)
        └──▶ reporter.py  Terminal posture reports & schema-versioned (1.0) JSON reports
```

---

## Detection Rules & Severity Scoring

All rules use linear $O(N)$ two-pointer sliding time windows and can be tuned or toggled independently in `config.json`.

| Rule ID | Pattern Detected | Default Threshold / Window | Severity Escalation |
| :--- | :--- | :--- | :--- |
| `SSH_REPEATED_FAILURES` | Repeated failed SSH password logins from a single IP | `5` failures in `300s` | `medium` (baseline), `high` (`>= 2x` threshold, min `10`) |
| `SSH_MULTI_USER_PROBE` | Single IP attempting logins across multiple distinct usernames | `3` distinct users in `600s` | `medium` (baseline), `high` (`>= 2x` threshold, min `6`) |
| `SSH_SUCCESS_AFTER_FAILURES` | Successful SSH login preceded by repeated failures from the same IP | `3` preceding failures in `300s` | `high` (baseline), `critical` (`root` login or `>= 5` failures + `password` auth) |
| `SUDO_REPEATED_FAILURES` | Repeated failed `sudo` authentication events for a local user | `3` failures in `300s` | `medium` (baseline), `high` (sensitive commands like `visudo`, `bash`, `su`, `passwd` or `>= 2x` threshold) |

Every generated `SecurityAlert` attaches bounded, JSON-serializable evidence records (`line_number`, `timestamp`, `event_type`, `username`, `source_ip`, `port`, `command`, `event_hash`, `message`), preserving both the start and end of large bursts.

---

## Project Structure

```text
linux-security-analyzer/
├── scripts/
│   ├── run.sh                 # Symlink-safe Bash CLI entry point (umask 027, Python 3.10+ guard)
│   ├── setup.sh               # Idempotent environment, config.json, and SQLite bootstrapper
│   └── scheduled_scan.sh      # Cron-safe unattended runner (flock, ERR traps, report retention)
├── src/
│   └── security_analyzer/
│       ├── __init__.py        # Package metadata (__app_name__, __version__)
│       ├── cli.py             # argparse subcommand CLI & strict input validation
│       ├── collector.py       # Streaming log reader & filesystem/permission validation
│       ├── config.py          # JSON config loader, merging, and fail-fast validation
│       ├── database.py        # SQLite WAL persistence, atomic deduplication, queries & indexes
│       ├── detector.py        # Sliding-window detectors & rule-based DetectionEngine
│       ├── logger.py          # Structured stderr logging
│       ├── models.py          # Frozen AuthEvent, SecurityAlert, ParseResult & Severity enum
│       ├── parser.py          # Two-stage syslog + SSH/sudo parser & input sanitization
│       └── reporter.py        # Terminal (posture banner, bars, textwrap) & JSON (v1.0) reports
├── tests/                     # 126 unittest cases across 13 test modules
├── sample_logs/
│   ├── auth_sample.log        # Synthetic RFC 5737/3849 attack & mixed-format log dataset
│   └── benign_activity.log    # Synthetic normal-operations log for false-positive testing
├── docs/
│   ├── architecture.md        # System data flow, module map & security threat model
│   ├── database_schema.md     # SQLite tables, constraints & deduplication keys
│   ├── log_formats.md         # Supported ISO-8601/BSD syslog & SSH/sudo patterns
│   └── cron_setup.md          # Unprivileged crontab installation & troubleshooting
├── reports/                   # Generated local reports (gitignored)
├── data/                      # Local SQLite database & runtime logs (gitignored)
├── .gitignore                 # Excludes real logs, local configs, DBs, reports & locks
├── config.example.json        # Documented configuration template
└── README.md
```

---

## Requirements & Linux Permissions

- **Operating System**: Linux (tested on Ubuntu/Debian; compatible with RHEL-family `/var/log/secure`)
- **Shell**: Bash 4.0+ and `flock` (`util-linux`, pre-installed on standard Linux distributions)
- **Python**: Python 3.10+ (standard library only—no `pip` packages or virtual environments required)
- **SQLite**: Built-in `sqlite3` module

### Unprivileged Log Access
On Ubuntu/Debian, `/var/log/auth.log` is owned by `syslog:adm` with mode `0640` (`-rw-r-----`). Verify your user can read it without `sudo`:

```bash
id
test -r /var/log/auth.log && echo "READ_OK"
```

Never make `/var/log/auth.log` world-readable (`chmod 644`). If needed, add your monitoring user to the `adm` group (`sudo usermod -aG adm $USER`) or analyze authorized log snapshots and `sample_logs/`.

---

## Quickstart

```bash
# 1. Bootstrap runtime directories (0750), config.json (0640), and SQLite schema
./scripts/setup.sh

# 2. Run an analysis against the included synthetic attack dataset
./scripts/run.sh analyze --file sample_logs/auth_sample.log --year 2026

# 3. Inspect prioritized alerts with underlying evidence lines
./scripts/run.sh alerts --show-evidence

# 4. View aggregated authentication and alert statistics
./scripts/run.sh stats

# 5. Generate a formatted terminal report
./scripts/run.sh report
```

To analyze your live host log:

```bash
./scripts/run.sh analyze --file /var/log/auth.log
```

---

## CLI Reference

Global options (`--config <path>`, `--db <path>`, `--log-level <DEBUG|INFO|WARNING|ERROR>`) are accepted both before and after any subcommand.

### 1. `analyze` — Ingest & Detect
```bash
./scripts/run.sh analyze --file sample_logs/auth_sample.log --year 2026
./scripts/run.sh analyze --file /var/log/auth.log --json
```
- Streams the log file, parses events, evaluates all enabled detection rules, and stores only net-new events and alerts via SHA-256 deduplication (`INSERT OR IGNORE`).

### 2. `events` — Investigate Stored Events
```bash
./scripts/run.sh events --ip 203.0.113.50 --limit 20
./scripts/run.sh events --service sudo --user intern
./scripts/run.sh events --event-type ssh_failed_login --since 2026-11-18T08:00:00+05:30 --json
```
- Supports `--ip` (IPv4/IPv6 validated), `--user`, `--event-type`, `--service`, `--since`, `--until`, `--limit`, and `--json`.

### 3. `alerts` — Triage Security Alerts
```bash
./scripts/run.sh alerts
./scripts/run.sh alerts --severity critical --show-evidence
./scripts/run.sh alerts --rule-id SSH_REPEATED_FAILURES --ip 203.0.113.50 --json
```
- Orders alerts by severity priority (`critical` -> `high` -> `medium` -> `low`) and recency.

### 4. `stats` — Aggregate Security Metrics
```bash
./scripts/run.sh stats --top 10
./scripts/run.sh stats --json
```
- Displays total events, successful/failed SSH logins, SSH failure rate, auth-method breakdown (`publickey` vs. `password`), unique source IPs, alerts by severity, top IPs/users, and recent scan runs.

### 5. `report` — Terminal, JSON & Historical Reports
```bash
./scripts/run.sh report --max-evidence 3
./scripts/run.sh report --format json --days 7 --output reports/weekly.json
./scripts/run.sh report --since 2026-11-18T08:00:00+05:30 --until 2026-11-18T09:00:00+05:30 --output reports/incident.txt
```
- Supports `--format terminal|json`, `-o/--output <path>`, `--top N`, `--max-evidence N`, `--since`, `--until`, and `--days N`.

---

## Configuration

`./scripts/setup.sh` copies `config.example.json` to `config.json` (gitignored) if one does not already exist. Partial overrides merge safely over built-in defaults, and invalid thresholds or JSON syntax fail fast at startup.

```json
{
  "log_source": {
    "default_path": "/var/log/auth.log",
    "fallback_sample_path": "sample_logs/auth_sample.log",
    "encoding": "utf-8"
  },
  "database": {
    "db_path": "data/security_events.db"
  },
  "reporting": {
    "output_dir": "reports",
    "retention_days": 30
  },
  "logging": {
    "app_log_path": "data/analyzer.log",
    "level": "INFO"
  },
  "detection_rules": {
    "brute_force_threshold": 5,
    "brute_force_window_seconds": 300,
    "multi_user_threshold": 3,
    "multi_user_window_seconds": 600,
    "success_after_failure_threshold": 3,
    "success_after_failure_window_seconds": 300,
    "sudo_failure_threshold": 3,
    "sudo_failure_window_seconds": 300,
    "enabled_rules": {
      "SSH_REPEATED_FAILURES": true,
      "SSH_MULTI_USER_PROBE": true,
      "SSH_SUCCESS_AFTER_FAILURES": true,
      "SUDO_REPEATED_FAILURES": true
    }
  }
}
```

---

## SQLite Storage & Indexing

Events, alerts, and scan audit metadata are persisted in SQLite (`data/security_events.db`) with:
- **`PRAGMA journal_mode = WAL`** and `timeout=30.0` so concurrent CLI reads never block scheduled cron writes.
- **`PRAGMA foreign_keys = ON`** linking `auth_events` and `security_alerts` to `scan_runs`.
- **Idempotent Deduplication**: `UNIQUE (event_hash)` and `UNIQUE (alert_hash)` ensure re-scanning a rolling log file inserts zero duplicate rows.
- **8 Targeted B-Tree Indexes**: Covering timestamps, `source_ip`, `username`, `(event_type, timestamp DESC)`, `service`, `(severity, last_seen DESC)`, and `rule_id` (verified via `EXPLAIN QUERY PLAN` tests).

---

## Bash Automation & Cron Integration

`scripts/scheduled_scan.sh` automates ingestion, timestamped JSON + terminal report generation, and safe retention pruning (`find -maxdepth 1 -type f` scoped strictly to `security_report_*.{json,txt}` older than `LSA_RETENTION_DAYS`).

### Documented Exit Codes (`scripts/scheduled_scan.sh`)

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Scan, report export, and retention completed cleanly |
| `10` | Target authentication log file is missing or unreadable |
| `11` | `analyze` command failed (e.g., invalid config or database error) |
| `12` | Report export failed |
| `20` | Skipped cleanly because another scan instance holds the `flock` lockfile |

### Installing in User Crontab (`crontab -e`)

```cron
*/30 * * * * /ABS/PATH/TO/linux-security-analyzer/scripts/scheduled_scan.sh >> /ABS/PATH/TO/linux-security-analyzer/data/cron.log 2>&1
```

See [docs/cron_setup.md](docs/cron_setup.md) for verification, log inspection, and removal commands.

---

## Testing & Quality Assurance

The project includes **126 automated `unittest` tests** across 13 test modules covering:
- **Collector & Permissions**: Missing files, directories, `0000` permission errors, empty files, and corrupted UTF-8 bytes.
- **Parser & Models**: ISO-8601 and BSD timestamps, leap-year dates, IPv4/IPv6 canonicalization, port bounds (`1–65535`), control-character sanitization, and frozen dataclass hashing.
- **Detection Engine & Accuracy**: Exact sliding-window boundaries, severity escalation, evidence capping, and zero false positives on `sample_logs/benign_activity.log`.
- **SQLite Layer**: WAL mode, FK constraints, incremental append deduplication, historical queries, corruption handling, and `EXPLAIN QUERY PLAN` index checks.
- **CLI, Reporting & Bash Automation**: All 5 subcommands, strict input validation, symlinked launcher execution, idempotent `setup.sh`, `flock` lock contention, exit codes, and scoped report retention.
- **Adversarial Resilience**: Empty logs, binary garbage, 20KB lines (ReDoS check), and SQL injection payloads inside SSH usernames.

Run the full test suite and Bash syntax checks:

```bash
for s in scripts/*.sh; do bash -n "$s" && echo "SYNTAX_OK: $s"; done
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## Additional Documentation

- [Architecture & Security Review](docs/architecture.md)
- [SQLite Database Schema](docs/database_schema.md)
- [Supported Authentication Log Formats](docs/log_formats.md)
- [Cron Scheduling Guide](docs/cron_setup.md)