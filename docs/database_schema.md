# SQLite Database Schema

The analyzer persists scan metadata, normalized authentication events, and generated security alerts in SQLite (`data/security_events.db` by default) with `PRAGMA foreign_keys = ON` and `PRAGMA journal_mode = WAL`.

## Tables

### 1. `scan_runs`
Tracks every execution of the log analyzer for operational auditing and reporting.

| Column | Type | Constraints | Purpose |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique scan identifier |
| `started_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp of scan execution |
| `source_path` | `TEXT` | `NOT NULL` | Resolved path of the analyzed log file |
| `total_lines` | `INTEGER` | `NOT NULL DEFAULT 0` | Total non-empty lines read |
| `valid_events` | `INTEGER` | `NOT NULL DEFAULT 0` | Successfully parsed events |
| `malformed_lines` | `INTEGER` | `NOT NULL DEFAULT 0` | Skipped malformed lines |
| `new_events_stored` | `INTEGER` | `NOT NULL DEFAULT 0` | Net new events inserted after deduplication |
| `alerts_generated` | `INTEGER` | `NOT NULL DEFAULT 0` | Net new alerts stored |

### 2. `auth_events`
Stores normalized `AuthEvent` records. Deduplication is enforced via `UNIQUE (event_hash)`.

| Column | Type | Constraints | Purpose |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Row ID |
| `scan_run_id` | `INTEGER` | `REFERENCES scan_runs(id) ON DELETE SET NULL` | Originating scan run |
| `line_number` | `INTEGER` | `NOT NULL` | 1-based line number in source file |
| `timestamp` | `TEXT` | `NOT NULL` | Normalized ISO-8601 event timestamp |
| `hostname` | `TEXT` | `NOT NULL` | Hostname from syslog header |
| `service` | `TEXT` | `NOT NULL` | Daemon (`sshd`, `sudo`, `CRON`, etc.) |
| `pid` | `INTEGER` | Nullable | Optional process ID |
| `event_type` | `TEXT` | `NOT NULL` | Classified event type |
| `username` | `TEXT` | Nullable | Associated username |
| `source_ip` | `TEXT` | Nullable | Validated IPv4 or IPv6 address |
| `port` | `INTEGER` | Nullable | Validated TCP/UDP port (1–65535) |
| `auth_method` | `TEXT` | Nullable | SSH auth method (`password`, `publickey`, etc.) |
| `target_user` | `TEXT` | Nullable | Target user for `sudo` or PAM session events |
| `command` | `TEXT` | Nullable | Executed or attempted `sudo` command |
| `is_invalid_user` | `INTEGER` | `NOT NULL DEFAULT 0` | Boolean flag (`0` or `1`) |
| `message` | `TEXT` | `NOT NULL` | Syslog message payload |
| `raw_line` | `TEXT` | `NOT NULL` | Sanitized raw log line |
| `event_hash` | `TEXT` | `NOT NULL UNIQUE` | Deterministic SHA-256 fingerprint |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC insertion timestamp |

### 3. `security_alerts`
Stores generated `SecurityAlert` records. Deduplication is enforced via `UNIQUE (alert_hash)`.

| Column | Type | Constraints | Purpose |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Row ID |
| `scan_run_id` | `INTEGER` | `REFERENCES scan_runs(id) ON DELETE SET NULL` | Originating scan run |
| `rule_id` | `TEXT` | `NOT NULL` | Detection rule identifier |
| `rule_name` | `TEXT` | `NOT NULL` | Human-readable rule name |
| `severity` | `TEXT` | `NOT NULL CHECK (severity IN ('low','medium','high','critical'))` | Validated severity tier |
| `title` | `TEXT` | `NOT NULL` | Short alert summary |
| `description` | `TEXT` | `NOT NULL` | Detailed evidence-grounded description |
| `source_ip` | `TEXT` | Nullable | Associated source IP address |
| `username` | `TEXT` | Nullable | Associated username |
| `first_seen` | `TEXT` | `NOT NULL` | First evidence event timestamp |
| `last_seen` | `TEXT` | `NOT NULL` | Last evidence event timestamp |
| `event_count` | `INTEGER` | `NOT NULL` | Number of events in the triggering window |
| `evidence_json` | `TEXT` | `NOT NULL` | JSON array of bounded evidence records |
| `alert_hash` | `TEXT` | `NOT NULL UNIQUE` | Deterministic SHA-256 fingerprint |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC insertion timestamp |