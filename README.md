# Linux Security Log Analyzer

A defensive Linux authentication log analyzer built with Bash, Python 3 (standard library), and SQLite.

## Defensive Scope
This tool performs read-only ingestion and analysis of Linux authentication logs (`/var/log/auth.log`, `/var/log/secure`, or synthetic sample logs) that you own or are authorized to inspect. It does not modify firewall rules, block IP addresses, or terminate system processes.

## Project Structure
```text
linux-security-analyzer/
├── scripts/                # Bash entry point, setup, and cron wrapper scripts
├── src/
│   └── security_analyzer/  # Core Python package (collector, parser, detector, database, CLI)
├── tests/                  # Python unittest suite
├── sample_logs/            # Synthetic authentication logs for testing
├── reports/                # Generated terminal and JSON security reports
├── data/                   # Local SQLite database and application runtime logs
├── docs/                   # Architecture and operational documentation
├── .gitignore
├── config.example.json
└── README.md
