#!/usr/bin/env python3
"""
waf_blocker.py

A secure, production-ready, idempotent script for automated WAF/ModSecurity log analysis and IP blocking.

Author: (Your Name)
"""
import sys
import os
import platform
from pathlib import Path
import yaml
import argparse
import csv
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil
import subprocess

# --- Utility Functions ---
def load_yaml(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def load_list_file(path: str) -> Set[str]:
    items = set()
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                items.add(line)
    return items

def load_crs_attack_patterns(crs_path: str) -> Set[str]:
    """
    Recursively scan CRS ruleset directory or file for SecRule patterns.
    Extracts keywords/regexes from SecRule lines.
    """
    patterns = set()
    crs_path = Path(crs_path)
    if not crs_path.exists():
        return patterns
    files = []
    if crs_path.is_dir():
        for file in crs_path.rglob('*'):
            if file.suffix in ['.conf', '.rules']:
                files.append(file)
    else:
        files = [crs_path]
    sec_rule_re = re.compile(r'SecRule\s+[^\"]+\"([^\"]+)\"')
    for file in files:
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = sec_rule_re.search(line)
                    if m:
                        rule_pattern = m.group(1)
                        for part in rule_pattern.split('|'):
                            part = part.strip()
                            if part:
                                patterns.add(part)
        except Exception:
            continue
    return patterns

def is_valid_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast)
    except ValueError:
        return False

def is_whitelisted(ip: str, whitelist: Set[str]) -> bool:
    return ip in whitelist

def is_url_whitelisted(url: str, whitelist: Set[str]) -> bool:
    for pattern in whitelist:
        if pattern.endswith('/') and url.startswith(pattern):
            return True
        if url == pattern:
            return True
    return False

def check_resource_limits(cpu_limit: int, mem_limit: int):
    p = psutil.Process(os.getpid())
    if p.cpu_percent(interval=0.1) > cpu_limit:
        logging.warning(f"CPU usage exceeded {cpu_limit}% - exiting early.")
        sys.exit(1)
    if p.memory_info().rss / 1024 / 1024 > mem_limit:
        logging.warning(f"Memory usage exceeded {mem_limit}MB - exiting early.")
        sys.exit(1)

def is_root() -> bool:
    return os.name != 'nt' and os.geteuid() == 0

def load_state(state_file: str) -> dict:
    state_file = Path(state_file)
    if state_file.exists():
        with open(state_file, 'r') as f:
            return json.load(f)
    return {}

def save_state(state_file: str, state: dict):
    state_file = Path(state_file)
    with open(state_file, 'w') as f:
        json.dump(state, f)

# Helper to detect ModSecurity section markers (supports "--" and "---")
def is_section(line: str, letter: str) -> bool:
    s = line.strip()
    return re.match(rf'^-+[A-Za-z0-9\-]+-+{letter}--', s) is not None

# --- Log Parsing ---
def parse_modsec_log(log_path: str, last_offset: int) -> Tuple[List[dict], int]:
    txs = []
    tx = {}
    tx_lines = []
    offset = last_offset
    log_path = Path(log_path)
    if not log_path.exists():
        logging.warning(f"WAF log not found: {log_path}. Skipping.")
        return txs, last_offset
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        try:
            size = log_path.stat().st_size
        except Exception:
            size = 0
        if last_offset > size:
            last_offset = 0
        f.seek(last_offset)
        for line in f:
            offset += len(line.encode('utf-8'))
            if is_section(line, 'A'):
                if tx_lines:
                    tx = parse_transaction(tx_lines)
                    if tx:
                        txs.append(tx)
                    tx_lines = []
            tx_lines.append(line)
        if tx_lines:
            tx = parse_transaction(tx_lines)
            if tx:
                txs.append(tx)
    return txs, offset

def parse_transaction(lines: List[str]) -> Optional[dict]:
    tx = {
        'tx_id': '',
        'timestamp': '',
        'client_ip': '',
        'x_forwarded_for': '',
        'host': '',
        'method': '',
        'url': '',
        'url_type': '',
        'response_code': '',
        'anomaly_score': 0,
        'severity': '',
        'rule_ids': '',
        'messages': '',
        'user_agent': '',
        'is_vm_scan': False,
        'confirmed_attack': False,
        'blocked': False,
        'block_mode': '',
        'block_time': ''
    }
    # Robust extraction for all required fields
    for line in lines:
        # Timestamp (try multiple patterns)
        if not tx['timestamp']:
            m = re.search(r'\[(\d{2,4}-\d{2}-\d{2}[^\]]*)\]', line)  # [2025-08-11 17:01:51,...]
            if m:
                tx['timestamp'] = m.group(1)
        if not tx['timestamp']:
            m = re.search(r'\[(.*?)\]', line)
            if m:
                tx['timestamp'] = m.group(1)
        # Client IP (try multiple patterns)
        if not tx['client_ip']:
            m = re.search(r'client\s*(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)', line, re.IGNORECASE)
            if m:
                tx['client_ip'] = m.group(1)
        if not tx['client_ip']:
            m = re.search(r'Client\sIP:\s*(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)', line)
            if m:
                tx['client_ip'] = m.group(1)
        if not tx['client_ip']:
            m = re.search(r'X-Real-IP:\s*(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)', line)
            if m:
                tx['client_ip'] = m.group(1)
        if not tx['client_ip']:
            m = re.search(r'X-Forwarded-For:\s*(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)', line)
            if m:
                tx['client_ip'] = m.group(1)
        # Host (try bracketed hostname or Host: header)
        if not tx['host']:
            m = re.search(r'\[hostname\s*"([^"]+)"\]', line)
            if m:
                tx['host'] = m.group(1)
        if not tx['host']:
            m = re.search(r'Host:\s*([^\s]+)', line)
            if m:
                tx['host'] = m.group(1)
        # x_forwarded_for (try header and bracketed)
        if not tx['x_forwarded_for']:
            m = re.search(r'X-Forwarded-For:\s*([^\s;\]]+)', line)
            if m:
                tx['x_forwarded_for'] = m.group(1)
        if not tx['x_forwarded_for']:
            m = re.search(r'\[x_forwarded_for\s*"([^"]+)"\]', line, re.IGNORECASE)
            if m:
                tx['x_forwarded_for'] = m.group(1)
        # Legacy: original pattern for all three fields
        if (not tx['timestamp'] or not tx['client_ip'] or not tx['host']):
            m = re.search(r'\[(.*?)\]\s+(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+(\S+)', line)
            if m:
                if not tx['timestamp']:
                    tx['timestamp'] = m.group(1)
                if not tx['client_ip']:
                    tx['client_ip'] = m.group(2)
                if not tx['host']:
                    tx['host'] = m.group(3)
        # Method and URL
        if not tx['method'] or not tx['url']:
            m = re.search(r'\b([A-Z]{3,10})\s+(\S+)\s+HTTP/\d\.\d', line)
            if not m:
                m = re.search(r'\b([A-Z]{3,10})\s+(\S+)', line)
            if m:
                tx['method'] = m.group(1)
                tx['url'] = m.group(2)
                tx['url_type'] = detect_url_type(tx['url'])
        # Headers
        if 'User-Agent:' in line and not tx['user_agent']:
            tx['user_agent'] = line.split('User-Agent:', 1)[1].strip()
        if 'X-Forwarded-For:' in line and not tx['x_forwarded_for']:
            tx['x_forwarded_for'] = line.split('X-Forwarded-For:', 1)[1].strip()
        if 'Qualys-Scan:' in line:
            tx['is_vm_scan'] = 'VM' in line
        # Response code
        if not tx['response_code']:
            m = re.search(r'HTTP/\d\.\d\s+(\d{3})', line)
            if m:
                tx['response_code'] = m.group(1)
        # Rule IDs and messages (try to extract from any line)
        rule_ids_found = re.findall(r'id "(\d+)"', line)
        if rule_ids_found:
            tx['rule_ids'] += (',' if tx['rule_ids'] else '') + ','.join(rule_ids_found)
        messages_found = re.findall(r'msg "([^"]+)"', line)
        if messages_found:
            tx['messages'] += (';' if tx['messages'] else '') + ';'.join(messages_found)
        # Robust anomaly score extraction (case-insensitive; multiple formats)
        anomaly = (
            re.search(r'(?i)anomaly[_ ]score[:=]\s*(\d+)', line) or
            re.search(r'(?i)total\s+(?:inbound|outbound)?\s*anomaly\s*score[:=]\s*(\d+)', line) or
            re.search(r"(?i)TX:ANOMALY_SCORE.*?Value\s*:\s*['\"]?(\d+)", line) or
            re.search(r'(?i)Total Score:\s*(\d+)', line) or
            re.search(r'(?i)Total Inbound Score:\s*(\d+)', line)
        )
        if anomaly:
            try:
                tx['anomaly_score'] = int(anomaly.group(1))
            except Exception:
                pass
        # Severity extraction (look for severity or map anomaly score)
        sev_match = re.search(r'Severity:\s*(\w+)', line, re.IGNORECASE)
        if sev_match:
            tx['severity'] = sev_match.group(1).lower()
    # Map anomaly_score to severity if not set
    if not tx['severity']:
        score = tx['anomaly_score']
        if score >= 15:
            tx['severity'] = 'critical'
        elif score >= 10:
            tx['severity'] = 'high'
        elif score >= 5:
            tx['severity'] = 'medium'
        elif score > 0:
            tx['severity'] = 'low'
        else:
            tx['severity'] = 'info'
    tx['tx_id'] = extract_tx_id(lines)
    # Final fallback: ensure all fields are strings (except anomaly_score, is_vm_scan, confirmed_attack, blocked)
    for key in ['timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type', 'response_code', 'rule_ids', 'messages', 'user_agent', 'block_mode', 'block_time', 'severity']:
        if tx[key] is None:
            tx[key] = ''
    return tx if tx['tx_id'] else None

def extract_tx_id(lines: List[str]) -> str:
    for line in lines:
        s = line.strip()
        m = re.match(r'^-+([A-Za-z0-9\-]+)-+A--', s)
        if m:
            return m.group(1)
    return ''

def detect_url_type(url: str) -> str:
    if url.endswith('.cgi'):
        return 'CGI'
    if url.endswith('.asp'):
        return 'ASP'
    if url.endswith('.php'):
        return 'PHP'
    return 'OTHER'

# --- Blocking Logic ---
def block_ip(ip: str, mode: str, ttl: int, dry_run: bool, audit_log: str, persistent_blocklist: str, block_time: str) -> bool:
    blocklist = load_state(persistent_blocklist)
    now = datetime.now(timezone.utc).isoformat()
    applied = False
    if ip in blocklist:
        expiry = blocklist[ip]['expiry']
        if expiry and datetime.fromisoformat(expiry) > datetime.now(timezone.utc):
            log_block_action(ip, 'already_blocked', mode, audit_log, block_time)
            return False
        else:
            unblock_ip(ip, mode, dry_run)
            del blocklist[ip]
    if dry_run:
        log_block_action(ip, 'dry_run', mode, audit_log, block_time)
        return False
    else:
        # Real blocking logic
        # Remove is_valid_ip check: block all except whitelisted
        if not is_root():
            log_block_action(ip, 'not_root', mode, audit_log, block_time)
            return False
        if mode == 'iptables':
            try:
                check = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode == 0:
                    log_block_action(ip, 'already_present', mode, audit_log, block_time)
                    applied = True
                else:
                    add = subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                                          check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if add.returncode == 0:
                        log_block_action(ip, 'blocked', mode, audit_log, block_time)
                        applied = True
                    else:
                        log_block_action(ip, 'block_failed', mode, audit_log, block_time)
            except Exception as e:
                log_block_action(ip, f'block_exception:{e}', mode, audit_log, block_time)
        elif mode == 'ipset':
            try:
                add = subprocess.run(['ipset', 'add', 'waf_blocklist', ip],
                                     check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if add.returncode != 0:
                    subprocess.run(['ipset', 'create', 'waf_blocklist', 'hash:ip'],
                                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    add = subprocess.run(['ipset', 'add', 'waf_blocklist', ip],
                                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if add.returncode == 0:
                    log_block_action(ip, 'blocked', mode, audit_log, block_time)
                    applied = True
                else:
                    log_block_action(ip, 'block_failed', mode, audit_log, block_time)
            except Exception as e:
                log_block_action(ip, f'block_exception:{e}', mode, audit_log, block_time)
        else:
            log_block_action(ip, 'unsupported_mode', mode, audit_log, block_time)
            return False
    if applied:
        blocklist[ip] = {'blocked_at': now, 'expiry': (datetime.now(timezone.utc) + timedelta(minutes=ttl)).isoformat()}
        save_state(persistent_blocklist, blocklist)
    return applied

def unblock_ip(ip: str, mode: str, dry_run: bool):
    if dry_run:
        logging.info(f"Unblock IP {ip} (mode={mode}) [dry-run]")
        return
    if not is_valid_ip(ip):
        logging.info(f"Unblock IP {ip} (mode={mode}) [invalid_ip]")
        return
    if not is_root():
        logging.info(f"Unblock IP {ip} (mode={mode}) [not_root]")
        return
    if mode == 'iptables':
        try:
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"Unblocked IP {ip} (mode={mode})")
        except Exception as e:
            logging.info(f"Unblock failed for {ip} (mode={mode}): {e}")
    elif mode == 'ipset':
        try:
            subprocess.run([
                'ipset', 'del', 'waf_blocklist', ip
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"Unblocked IP {ip} (mode={mode})")
        except Exception as e:
            logging.info(f"Unblock failed for {ip} (mode={mode}): {e}")
    else:
        logging.info(f"Unblock IP {ip} (mode={mode}) [unsupported_mode]")

def log_block_action(ip: str, action: str, mode: str, audit_log: str, block_time: str):
    audit_log = Path(audit_log)
    with open(audit_log, 'a') as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} {ip} {action} {mode} {block_time}\n")

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="WAF Blocker - Secure ModSecurity log parser and IP blocker.")
    parser.add_argument('--config', type=str, help='Path to config.yml', required=False)
    parser.add_argument('--apply', action='store_true', help='Apply blocking (default: dry-run)')
    parser.add_argument('--test-sample', type=str, help='Test mode: parse sample log file (dry-run)')
    args = parser.parse_args()

    config_path = args.config or 'config.yml'
    config = load_yaml(config_path)

    log_dir_val = config.get('log_dir') or (config.get('logging', {}) or {}).get('log_dir', 'logs/')
    log_level_name = config.get('log_level') or (config.get('logging', {}) or {}).get('log_level', 'INFO')
    log_dir = Path(log_dir_val)
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=str(log_dir / 'waf_blocker.log'), level=getattr(logging, log_level_name.upper()), format='%(asctime)s %(levelname)s %(message)s')

    cpu_limit = config.get('max_cpu_percent') or (config.get('resource_limits', {}) or {}).get('max_cpu_percent', 50)
    mem_limit = config.get('max_memory_mb') or (config.get('resource_limits', {}) or {}).get('max_memory_mb', 512)
    check_resource_limits(cpu_limit, mem_limit)

    url_whitelist = load_list_file(config['url_whitelist'])
    attack_indicators = load_list_file(config['attack_indicators'])
    all_attack_patterns = attack_indicators
    # Anomaly threshold (default 8)
    anomaly_threshold = int(config.get('anomaly_threshold', 8))
    ip_whitelist = set()
    wl_path = config.get('ip_whitelist')
    if wl_path:
        try:
            ip_whitelist = load_list_file(wl_path)
        except Exception:
            ip_whitelist = set()

    state_file = config['state_file']
    state = load_state(state_file)

    block_cfg = config.get('block', {}) or {}
    persistent_blocklist = config.get('block_state') or block_cfg.get('persistent_blocklist', 'state/blocked_state.json')
    blocklist = load_state(persistent_blocklist)

    output_dir_val = config.get('output_dir') or config.get('output_csv', 'output/')
    output_dir = Path(output_dir_val)
    output_dir.mkdir(parents=True, exist_ok=True)
    utc_now = datetime.now(timezone.utc)
    ist_now = utc_now.astimezone(timezone(timedelta(hours=5, minutes=30)))
    today_str = ist_now.strftime('%Y-%m-%d')
    output_csv = output_dir / f"modsec_output_{today_str}.csv"
    output_csv_single = output_dir / 'modsec_output.csv'
    csv_exists = output_csv.exists()
    csv_single_exists = output_csv_single.exists()
    csv_file = open(output_csv, 'a', newline='')
    csv_writer = csv.DictWriter(csv_file, fieldnames=[
        'tx_id', 'timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type',
        'response_code', 'anomaly_score', 'severity', 'rule_ids', 'messages', 'user_agent', 'is_vm_scan', 'confirmed_attack',
        'blocked', 'block_mode', 'block_time'
    ])
    if not csv_exists:
        csv_writer.writeheader()
    # Also write to single aggregate file
    csv_file_single = open(output_csv_single, 'a', newline='')
    csv_writer_single = csv.DictWriter(csv_file_single, fieldnames=[
        'tx_id', 'timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type',
        'response_code', 'anomaly_score', 'severity', 'rule_ids', 'messages', 'user_agent', 'is_vm_scan', 'confirmed_attack',
        'blocked', 'block_mode', 'block_time'
    ])
    if not csv_single_exists:
        csv_writer_single.writeheader()

    waf_logs_cfg = config.get('waf_logs') or config.get('waf_log')
    if isinstance(waf_logs_cfg, str):
        waf_logs = [waf_logs_cfg]
    elif isinstance(waf_logs_cfg, list):
        waf_logs = waf_logs_cfg
    else:
        waf_logs = ['sample_modsec.log']

    max_ips = config.get('block_max_ips_per_run') or block_cfg.get('max_ips_per_run', 20)
    mode = config.get('block_mode') or block_cfg.get('mode', 'iptables')
    ttl = config.get('block_ttl_minutes') or block_cfg.get('ttl_minutes', 60)
    # Enforce WAF_BLOCKER_CONFIRM=1 for real blocking
    env_confirm = os.environ.get('WAF_BLOCKER_CONFIRM', '0')
    cfg_dry_run = config.get('block_dry_run') if 'block_dry_run' in config else block_cfg.get('dry_run', True)
    dry_run = cfg_dry_run if not args.apply or env_confirm != '1' else False
    if args.apply and env_confirm != '1':
        logging.warning("--apply was used but WAF_BLOCKER_CONFIRM=1 is not set. Running in dry-run mode for safety.")
    audit_log = config.get('block_audit_log') or block_cfg.get('audit_log', 'logs/blocked.log')
    block_time = datetime.now(timezone.utc).isoformat()

    if args.test_sample:
        waf_logs = [args.test_sample]
        dry_run = True

    blocked_this_run = 0
    for log_path in waf_logs:
        last_offset = state.get(log_path, 0)
        txs, new_offset = parse_modsec_log(log_path, last_offset)
        state[log_path] = new_offset
        for tx in txs:
            # Ensure all required fields are present
            for field in [
                'tx_id', 'timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type',
                'response_code', 'anomaly_score', 'severity', 'rule_ids', 'messages', 'user_agent', 'is_vm_scan', 'confirmed_attack',
                'blocked', 'block_mode', 'block_time']:
                if field not in tx:
                    tx[field] = ''
            if tx.get('is_vm_scan'):
                tx['confirmed_attack'] = False
                tx['blocked'] = False
                tx['block_mode'] = mode
                tx['block_time'] = block_time
                csv_writer.writerow(tx)
                csv_writer_single.writerow(tx)
                continue
            confirmed_attack = tx.get('anomaly_score', 0) > anomaly_threshold
            tx['confirmed_attack'] = confirmed_attack
            ips = set()
            client = tx.get('client_ip', '')
            if client and not is_whitelisted(client, ip_whitelist):
                ips.add(client)
            xff_raw = tx.get('x_forwarded_for', '')
            if xff_raw:
                for part in xff_raw.split(','):
                    cand = part.strip()
                    if cand and not is_whitelisted(cand, ip_whitelist):
                        ips.add(cand)
            tx['blocked'] = False
            blocked_any = False
            if confirmed_attack and blocked_this_run < max_ips:
                for ip in ips:
                    if block_ip(ip, mode, ttl, dry_run, audit_log, persistent_blocklist, block_time):
                        blocked_any = True
                        blocked_this_run += 1
            tx['blocked'] = blocked_any
            tx['block_mode'] = mode
            tx['block_time'] = block_time
            csv_writer.writerow(tx)
            csv_writer_single.writerow(tx)
            check_resource_limits(cpu_limit, mem_limit)
    save_state(state_file, state)
    csv_file.close()
    csv_file_single.close()

if __name__ == '__main__':
    main()
