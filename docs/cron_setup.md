# Cron Scheduling Guide

This guide explains how to schedule `scripts/scheduled_scan.sh` with Linux `cron` under an unprivileged user account (member of the `adm` group on Ubuntu/Debian).

## Prerequisites
1. Run `./scripts/setup.sh` at least once to initialize `config.json` and `data/security_events.db`.
2. Verify `cron` is active on your host:
   ```bash
   systemctl is-active cron