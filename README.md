# waf_blocker

A secure, production-ready Python script to automate blocking of malicious IPs detected in ModSecurity/WAF logs, with full configuration and safe operation for cron/systemd.

## Features
- Reads all paths and settings from `config.yml` (no hardcoded values)
- Efficient, stateful log parsing (supports log rotation)
- Attack detection with anomaly score, VM scan logic, and whitelisting
- Idempotent, TTL-based IP blocking (iptables/ipset)
- Dry-run by default; requires `--apply` and `WAF_BLOCKER_CONFIRM=1` to block
- Resource limits (CPU, memory) for safe automation
- Audit logging and persistent blocklist state
- Self-test mode with sample log

## Setup
1. Install dependencies (offline):
   - On a machine with internet, download all required .whl or .tar.gz files for dependencies in requirements.txt.
   - Place them in the `offline_packages/` directory in this project.
   - On the production server, run:
     ```bash
     pip install --no-index --find-links=offline_packages -r requirements.txt
     ```
2. Edit `config.yml` to match your environment (log paths, output, limits, etc.).
   - Set `output_csv` to a directory (e.g., `/opt/waf_blocker/output/`).
   - The script will create a new file each day: `modsec_output_YYYY-MM-DD.csv` for daily reporting.
3. Place `attack_indicators.txt` and `url_whitelist.txt` as referenced in config.

## Usage
- Dry-run (default):
  ```bash
  python3 waf_blocker.py --config /etc/waf_blocker/config.yml
  ```
- Apply blocking (requires root):
  ```bash
  WAF_BLOCKER_CONFIRM=1 python3 waf_blocker.py --config /etc/waf_blocker/config.yml --apply
  ```
- Self-test mode:
  ```bash
  python3 waf_blocker.py --test-sample sample_modsec.log
  ```

## Automation
- Add to cron (every 15 min):
  ```cron
  */15 * * * * /usr/bin/python3 /opt/waf_blocker/waf_blocker.py --config /etc/waf_blocker/config.yml --apply
  ```
- Or use a systemd timer for more control.

## Security & Safety
- Never uses `shell=True` with user input
- Checks for root before applying iptables/ipset
- Skips private/reserved/whitelisted IPs
- Resource limits prevent server overload
- All actions logged to audit log

## Sample Test Cases
- VM scan (Qualys header) with anomaly score 28 → no block
- Non-VM scan, anomaly score 28, non-whitelisted URL → block in dry-run
- Same IP appears again → marked as already blocked, no duplicate rule

---

For questions or issues, see the script comments and logs for troubleshooting.
