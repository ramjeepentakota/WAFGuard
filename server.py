#!/usr/bin/env python3
"""
server.py

HTTP service and daemon manager for WAF Blocker.
- CLI: python3 server.py start|stop|status|serve|run-once
- Background management uses a child process (Popen) for portability (no double-fork)
- Threaded HTTP server with dashboard UI and JSON APIs
- Optional scheduler (service.auto_run_minutes, service.auto_apply)

Compatible with Python 3.8+.
"""
import os
import sys
import json
import time
import yaml
import signal
import threading
import subprocess
import re
import csv
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, List
import psutil

# --- Paths & Config ---
PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = str(PROJECT_DIR / 'config.yml')
CONFIG_PATH = os.environ.get('WAF_CONFIG', DEFAULT_CONFIG_PATH)
PID_FILE = PROJECT_DIR / 'state' / 'server.pid'
STATIC_DIR = PROJECT_DIR / 'static'

# Service log
CFG_TMP = {}
try:
    with open(CONFIG_PATH, 'r') as _f:
        CFG_TMP = yaml.safe_load(_f) or {}
except Exception:
    CFG_TMP = {}
LOG_DIR = Path((CFG_TMP.get('logging', {}) or {}).get('log_dir') or 'logs')
if not LOG_DIR.is_absolute():
    LOG_DIR = PROJECT_DIR / LOG_DIR
LOG_DIR.mkdir(parents=True, exist_ok=True)
SERVICE_LOG = LOG_DIR / 'service.log'


def log(msg: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        SERVICE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(SERVICE_LOG, 'a') as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass


def load_config(path: str) -> dict:
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def get_service_bind(cfg: dict) -> Tuple[str, int]:
    service_cfg = (cfg or {}).get('service', {}) or {}
    host = service_cfg.get('host') or os.environ.get('WAF_SERVICE_HOST') or '127.0.0.1'
    port_raw = service_cfg.get('port') or os.environ.get('WAF_SERVICE_PORT') or 8085
    try:
        port = int(port_raw)
    except Exception:
        port = 8085
    return host, port


# --- State ---
class ServiceState:
    def __init__(self):
        self._lock = threading.Lock()
        self.in_progress = False
        self.last_run: Optional[dict] = None

    def start(self) -> bool:
        with self._lock:
            if self.in_progress:
                return False
            self.in_progress = True
            return True

    def finish(self, result: dict):
        with self._lock:
            self.in_progress = False
            self.last_run = result

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'in_progress': self.in_progress,
                'last_run': self.last_run,
            }


STATE = ServiceState()


# --- Utilities ---

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def tail_file(path: Path, lines: int = 200) -> str:
    try:
        if not path.exists():
            return ''
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            size = 0
            chunk = 2048
            data = b''
            while end > 0 and size < (lines * 200):
                read_size = min(chunk, end)
                end -= read_size
                f.seek(end)
                data = f.read(read_size) + data
                size += read_size
            text = data.decode('utf-8', errors='ignore')
            return '\n'.join(text.splitlines()[-lines:])
    except Exception:
        return ''


def run_waf_blocker(apply: bool = False, sample: Optional[str] = None) -> dict:
    start_ts = now_iso()
    t0 = time.time()

    cmd = [sys.executable, str(PROJECT_DIR / 'waf_blocker.py'), '--config', CONFIG_PATH]
    env = os.environ.copy()

    if apply:
        env['WAF_BLOCKER_CONFIRM'] = '1'
        cmd.append('--apply')
    if sample:
        cmd += ['--test-sample', sample]

    try:
        proc = subprocess.run(cmd, cwd=str(PROJECT_DIR), env=env,
                              capture_output=True, text=True, check=False)
        rc = proc.returncode
        out = (proc.stdout or '').strip()
        err = (proc.stderr or '').strip()
    except Exception as e:
        rc = -1
        out = ''
        err = f'Exception: {e!r}'

    dt = time.time() - t0
    end_ts = now_iso()

    result = {
        'command': cmd,
        'returncode': rc,
        'duration_sec': round(dt, 3),
        'started_at': start_ts,
        'finished_at': end_ts,
        'apply': apply,
        'sample': sample,
        'stdout': out[-8000:],
        'stderr': err[-8000:],
    }
    return result


# --- CSV & Summary helpers ---
CSV_DATE_RE = re.compile(r'^modsec_output_(\d{4}-\d{2}-\d{2})\.csv$')


def get_output_dir(cfg: dict) -> Path:
    out = (cfg or {}).get('output_dir') or (cfg or {}).get('output_csv') or 'output/'
    p = Path(out)
    if not p.is_absolute():
        p = PROJECT_DIR / p
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_csv_files(cfg: dict) -> List[dict]:
    out_dir = get_output_dir(cfg)
    rows: List[dict] = []
    for p in sorted(out_dir.glob('modsec_output_*.csv')):
        m = CSV_DATE_RE.match(p.name)
        if not m:
            continue
        rows.append({'date': m.group(1), 'path': str(p)})
    return rows


def read_csv_for_date(cfg: dict, date_str: str) -> List[dict]:
    out_dir = get_output_dir(cfg)
    path = out_dir / f'modsec_output_{date_str}.csv'
    if not path.exists():
        return []
    with open(path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        return [row for row in reader]

# Helpers for reports and logs
def get_waf_logs(cfg: dict) -> List[Path]:
    logs = []
    waf_logs = cfg.get('waf_logs') or []
    if isinstance(waf_logs, str):
        waf_logs = [waf_logs]
    waf_log = cfg.get('waf_log')
    if waf_log:
        logs.append(Path(waf_log))
    for l in waf_logs or []:
        logs.append(Path(l))
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for p in logs:
        sp = str(p)
        if sp not in seen:
            seen.add(sp)
            uniq.append(p)
    return uniq or [Path('sample_modsec.log')]


def collect_csv_between(cfg: dict, start: datetime, end: datetime) -> List[dict]:
    rows: List[dict] = []
    for date_str, day_rows in iter_csv_range(cfg, start, end):
        rows.extend(day_rows)
    return rows


def default_csv_headers() -> List[str]:
    return [
        'tx_id', 'timestamp', 'client_ip', 'x_forwarded_for', 'host', 'method', 'url', 'url_type',
        'response_code', 'anomaly_score', 'rule_ids', 'messages', 'is_vm_scan', 'confirmed_attack',
        'blocked', 'block_mode', 'block_time'
    ]


def iter_csv_range(cfg: dict, start: datetime, end: datetime):
    cur = start
    while cur.date() <= end.date():
        yield cur.strftime('%Y-%m-%d'), read_csv_for_date(cfg, cur.strftime('%Y-%m-%d'))
        cur += timedelta(days=1)


def anomaly_to_severity(score: int) -> str:
    if score >= 20:
        return 'critical'
    if score >= 15:
        return 'high'
    if score >= 10:
        return 'medium'
    if score >= 5:
        return 'low'
    return 'info'


def parse_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).lower() in ('1', 'true', 'yes', 'y')


def summarize_period(cfg: dict, period: str, center_date: str) -> dict:
    try:
        base = datetime.strptime(center_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except Exception:
        base = datetime.now(timezone.utc)
    if period == 'day':
        start = base
        end = base
    elif period == 'week':
        start = base - timedelta(days=base.weekday())
        end = start + timedelta(days=6)
    elif period == 'month':
        start = base.replace(day=1)
        next_month = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
        end = next_month - timedelta(days=1)
    else:
        start = base
        end = base

    totals = {'total': 0, 'blocked': 0, 'confirmed': 0, 'severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}}
    timeline = []
    bucket_fmt = '%Y-%m-%d %H:00' if period == 'day' else '%Y-%m-%d'
    buckets: Dict[str, Dict[str, int]] = {}

    for date_str, rows in iter_csv_range(cfg, start, end):
        for r in rows:
            totals['total'] += 1
            try:
                score = int(r.get('anomaly_score') or 0)
            except Exception:
                score = 0
            sev = anomaly_to_severity(score)
            totals['severity'][sev] += 1
            if parse_bool(r.get('confirmed_attack')):
                totals['confirmed'] += 1
            if parse_bool(r.get('blocked')):
                totals['blocked'] += 1
            ts = r.get('timestamp') or f'{date_str}T00:00:00Z'
            try:
                dt = datetime.strptime(ts.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
                dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except Exception:
                    dt = start
            key = dt.strftime(bucket_fmt)
            b = buckets.setdefault(key, {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0})
            b['count'] += 1
            b[sev] += 1

    for k in sorted(buckets.keys()):
        timeline.append({'bucket': k, **buckets[k]})

    return {'period': period, 'start': start.date().isoformat(), 'end': end.date().isoformat(), 'totals': totals, 'timeline': timeline}


# --- Scheduler (optional) ---
class AutoRunner(threading.Thread):
    def __init__(self, minutes: int, apply: bool):
        super().__init__(daemon=True)
        self.minutes = minutes
        self.apply = apply
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            if STATE.start():
                try:
                    result = run_waf_blocker(apply=self.apply)
                    STATE.finish(result)
                except Exception as e:
                    STATE.finish({'returncode': -1, 'error': repr(e), 'finished_at': now_iso()})
            self._stop.wait(self.minutes * 60)

    def stop(self):
        self._stop.set()


AUTORUNNER: Optional[AutoRunner] = None


# --- HTTP Handler ---
class APIHandler(BaseHTTPRequestHandler):
    server_version = 'WAFBlockerService/2.1'

    def _send_json(self, obj: dict, status: int = 200):
        body = json.dumps(obj, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str = 'text/plain', status: int = 200):
        if not path.exists():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text: str, content_type: str = 'text/plain', status: int = 200):
        data = text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        # Log to file instead of stderr when running as a service
        try:
            log(format % args)
        except Exception:
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query or '')
        cfg = load_config(CONFIG_PATH)

        # Dashboard & static
        if path in ('/', '/dashboard'):
            index = STATIC_DIR / 'index.html'
            if index.exists():
                return self._send_file(index, 'text/html; charset=utf-8')
            html = '<html><head><title>WAF Blocker</title></head><body><h1>WAF Blocker</h1><p>Static dashboard not found. Create static/index.html.</p></body></html>'
            return self._send_text(html, 'text/html; charset=utf-8')
        if path.startswith('/static/'):
            rel = unquote(path[len('/static/'):])
            f = (STATIC_DIR / rel).resolve()
            if STATIC_DIR in f.parents or f == STATIC_DIR:
                ctype = 'text/plain'
                if f.suffix == '.js':
                    ctype = 'application/javascript'
                elif f.suffix == '.css':
                    ctype = 'text/css'
                elif f.suffix in ('.html', '.htm'):
                    ctype = 'text/html; charset=utf-8'
                elif f.suffix == '.png':
                    ctype = 'image/png'
                elif f.suffix == '.svg':
                    ctype = 'image/svg+xml'
                return self._send_file(f, ctype)
            return self._send_json({'error': 'forbidden'}, 403)
        if path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        # Health & status
        if path == '/health':
            return self._send_json({'status': 'ok', 'time': now_iso()})
        if path == '/status':
            return self._send_json(STATE.snapshot())
        if path == '/logs':
            try:
                # Prefer flattened log_dir, fallback to nested logging.log_dir
                log_dir_str = cfg.get('log_dir') or (cfg.get('logging', {}) or {}).get('log_dir', 'logs/')
                log_dir = Path(log_dir_str)
                log_path = (PROJECT_DIR / log_dir) if not log_dir.is_absolute() else log_dir
                log_path = log_path / 'waf_blocker.log'
            except Exception:
                log_path = PROJECT_DIR / 'logs' / 'waf_blocker.log'
            tail = int((qs.get('tail', ['200'])[0]))
            log_text = tail_file(log_path, lines=max(1, min(tail, 2000)))
            return self._send_json({'path': str(log_path), 'tail': tail, 'log': log_text})

        # Trigger run (allow GET for convenience)
        if path == '/run':
            apply_flag = qs.get('apply', ['0'])[0] in ('1', 'true', 'yes')
            sample = qs.get('sample', [None])[0]
            if not STATE.start():
                return self._send_json({'error': 'another_run_in_progress'}, status=409)
            try:
                result = run_waf_blocker(apply=apply_flag, sample=sample)
                STATE.finish(result)
                return self._send_json({'status': 'completed', **STATE.snapshot()})
            except Exception as e:
                STATE.finish({'returncode': -1, 'error': repr(e), 'finished_at': now_iso()})
                return self._send_json({'status': 'failed', **STATE.snapshot()}, status=500)

        # CSV listing & download
        if path == '/api/csv/list':
            files = list_csv_files(cfg)
            return self._send_json({'files': files})
        if path == '/api/csv/download':
            date_str = qs.get('date', [''])[0]
            out_dir = get_output_dir(cfg)
            f = out_dir / f'modsec_output_{date_str}.csv'
            if not f.exists():
                return self._send_json({'error': 'not_found'}, 404)
            try:
                data = f.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.send_header('Content-Disposition', f'attachment; filename="{f.name}"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                return self._send_json({'error': 'read_failed'}, 500)
            return

        # Recent events for a date
        if path == '/api/events':
            date_str = qs.get('date', [datetime.now().date().isoformat()])[0]
            try:
                limit = int(qs.get('limit', ['100'])[0])
            except Exception:
                limit = 100
            rows = read_csv_for_date(cfg, date_str)
            if not rows:
                return self._send_json({'date': date_str, 'events': []})
            slice_rows = rows[-limit:][::-1]
            return self._send_json({'date': date_str, 'events': slice_rows})

        # Active WAF log tail
        if path == '/api/active-log':
            tailsz = int((qs.get('tail', ['200'])[0]))
            waf_logs = get_waf_logs(cfg)
            # Prefer the first configured log that exists
            chosen = None
            for p in waf_logs:
                if p.is_absolute():
                    chosen = p
                else:
                    chosen = (PROJECT_DIR / p)
                if chosen.exists():
                    break
            if chosen is None:
                chosen = PROJECT_DIR / (waf_logs[0] if waf_logs else Path('sample_modsec.log'))
            text = tail_file(chosen, lines=max(1, min(tailsz, 4000)))
            return self._send_json({'path': str(chosen), 'tail': tailsz, 'log': text})

        # Recently blocked IPs with reasons
        if path == '/api/blocked_recent':
            try:
                limit = int(qs.get('limit', ['50'])[0])
            except Exception:
                limit = 50
            try:
                days = int(qs.get('days', ['7'])[0])
            except Exception:
                days = 7
            # Load block state
            bs_path = cfg.get('block_state') or (cfg.get('block', {}) or {}).get('persistent_blocklist', 'state/blocked_state.json')
            bs = {}
            try:
                p = Path(bs_path)
                if not p.is_absolute():
                    p = PROJECT_DIR / p
                if p.exists():
                    bs = json.loads(p.read_text() or '{}')
            except Exception:
                bs = {}
            # Build recent list
            entries = []
            for ip, meta in bs.items():
                blocked_at = meta.get('blocked_at') or meta.get('blocked_time') or meta.get('blockedAt')
                expiry = meta.get('expiry')
                entries.append({'ip': ip, 'blocked_at': blocked_at, 'expiry': expiry})
            # Sort desc by blocked_at
            def parse_ts(ts: Optional[str]):
                try:
                    return datetime.fromisoformat(ts.replace('Z', '+00:00')) if ts else datetime.min.replace(tzinfo=timezone.utc)
                except Exception:
                    return datetime.min.replace(tzinfo=timezone.utc)
            entries.sort(key=lambda x: parse_ts(x['blocked_at']), reverse=True)
            entries = entries[:limit]
            # Attach reasons by scanning last N days of CSVs
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=days)
            all_rows = collect_csv_between(cfg, start_dt, end_dt)
            # Map IP -> last reason
            reasons: Dict[str, dict] = {}
            for r in reversed(all_rows):  # earliest to latest so later wins afterward
                if str(r.get('blocked', '')).lower() in ('true', '1', 'yes'):
                    ip_fields = [r.get('client_ip', ''), r.get('x_forwarded_for', '')]
                    for ip in ip_fields:
                        if ip and ip not in reasons:
                            reasons[ip] = {
                                'anomaly_score': r.get('anomaly_score'),
                                'rule_ids': r.get('rule_ids'),
                                'messages': r.get('messages'),
                                'url': r.get('url'),
                                'timestamp': r.get('timestamp'),
                            }
            for e in entries:
                ip = e['ip']
                e['reason'] = reasons.get(ip, {})
            return self._send_json({'items': entries})

        # Reports download: day, month, year
        if path == '/api/reports/download':
            period = qs.get('period', ['day'])[0]
            filename = 'report.csv'
            rows: List[dict] = []
            if period == 'day':
                date_str = qs.get('date', [datetime.now().date().isoformat()])[0]
                rows = read_csv_for_date(cfg, date_str)
                filename = f'modsec_{date_str}.csv'
            elif period == 'month':
                y = int(qs.get('year', ['0'])[0])
                m = int(qs.get('month', ['0'])[0])
                if y <= 0 or m <= 0 or m > 12:
                    return self._send_json({'error': 'invalid_parameters'}, 400)
                start = datetime(y, m, 1, tzinfo=timezone.utc)
                next_month = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
                end = next_month - timedelta(days=1)
                rows = collect_csv_between(cfg, start, end)
                filename = f'modsec_{y}-{m:02d}.csv'
            elif period == 'year':
                y = int(qs.get('year', ['0'])[0])
                if y <= 0:
                    return self._send_json({'error': 'invalid_parameters'}, 400)
                start = datetime(y, 1, 1, tzinfo=timezone.utc)
                end = datetime(y, 12, 31, tzinfo=timezone.utc)
                rows = collect_csv_between(cfg, start, end)
                filename = f'modsec_{y}.csv'
            else:
                return self._send_json({'error': 'invalid_period'}, 400)
            # Build CSV content
            headers = default_csv_headers()
            if rows:
                # Ensure all default headers are present; include any extras at end
                extras = [k for k in rows[0].keys() if k not in headers]
                headers = headers + extras
            import io
            sio = io.StringIO()
            w = csv.DictWriter(sio, fieldnames=headers)
            w.writeheader()
            for r in rows:
                w.writerow(r)
            data = sio.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Summaries & activity
        if path == '/api/summary':
            period = qs.get('period', ['day'])[0]
            date_str = qs.get('date', [datetime.now().date().isoformat()])[0]
            summary = summarize_period(cfg, period, date_str)
            return self._send_json(summary)

        return self._send_json({'error': 'not_found'}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query or '')

        if path == '/run':
            if not STATE.start():
                return self._send_json({'error': 'another_run_in_progress'}, status=409)
            apply_flag = qs.get('apply', ['0'])[0] in ('1', 'true', 'yes')
            sample = qs.get('sample', [None])[0]
            try:
                result = run_waf_blocker(apply=apply_flag, sample=sample)
                STATE.finish(result)
                return self._send_json({'status': 'completed', **STATE.snapshot()})
            except Exception as e:
                STATE.finish({'returncode': -1, 'error': repr(e), 'finished_at': now_iso()})
                return self._send_json({'status': 'failed', **STATE.snapshot()}, status=500)

        return self._send_json({'error': 'not_found'}, status=404)


# --- Server runner & background process management ---
class ServerWrapper:
    def __init__(self, host: str, port: int):
        self.server = ThreadingHTTPServer((host, port), APIHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        try:
            self.server.shutdown()
        except Exception:
            pass


def ensure_state_dir():
    (PROJECT_DIR / 'state').mkdir(parents=True, exist_ok=True)


def write_pid():
    ensure_state_dir()
    PID_FILE.write_text(str(os.getpid()))


def read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

# --- Port helpers ---

def _listening_pids_on_port(port: int) -> List[int]:
    pids: set[int] = set()
    try:
        for kind in ('inet', 'inet6'):
            for c in psutil.net_connections(kind=kind):
                if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port and c.pid:
                    pids.add(c.pid)
    except Exception as e:
        log(f"Error enumerating port listeners: {e!r}")
    return list(pids)


def _kill_pids(pids: List[int], timeout: float = 5.0) -> bool:
    any_killed = False
    for pid in pids:
        try:
            if pid == os.getpid():
                continue
            os.kill(pid, signal.SIGTERM)
            any_killed = True
            log(f"Sent SIGTERM to PID {pid}")
        except Exception as e:
            log(f"Failed to SIGTERM PID {pid}: {e!r}")
    # Wait
    end = time.time() + timeout
    alive = [p for p in pids if pid_alive(p)]
    while alive and time.time() < end:
        time.sleep(0.1)
        alive = [p for p in alive if pid_alive(p)]
    # Force kill remaining
    for pid in alive:
        try:
            os.kill(pid, signal.SIGKILL)
            log(f"Sent SIGKILL to PID {pid}")
        except Exception as e:
            log(f"Failed to SIGKILL PID {pid}: {e!r}")
    return any_killed


def remove_pid():
    try:
        PID_FILE.unlink()
    except Exception:
        pass


def run_server_foreground():
    cfg = load_config(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else {}
    host, port = get_service_bind(cfg)
    # Check port availability first
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        sock.close()
    except OSError:
        log(f"Port {host}:{port} is already in use.")
        print(f"Port {host}:{port} is already in use.")
        sys.exit(1)
    server = ServerWrapper(host, port)

    def on_term(signum, frame):
        log(f"Received signal {signum}, shutting down")
        server.stop()
        remove_pid()
        os._exit(0)

    signal.signal(signal.SIGINT, on_term)
    signal.signal(signal.SIGTERM, on_term)

    # Optional auto runner
    svc_cfg = (cfg or {}).get('service', {}) or {}
    minutes = int(svc_cfg.get('auto_run_minutes') or 0)
    apply = bool(svc_cfg.get('auto_apply') or False)
    global AUTORUNNER
    if minutes > 0:
        AUTORUNNER = AutoRunner(minutes, apply)
        AUTORUNNER.start()

    write_pid()
    log(f"Service listening on http://{host}:{port} (config={CONFIG_PATH})")
    server.start()
    while True:
        time.sleep(60)


def cmd_start() -> int:
    ensure_state_dir()
    pid = read_pid()
    if pid and pid_alive(pid):
        print(f"Service already running (PID {pid})")
        return 0
    # Launch child process in serve mode
    python = sys.executable or 'python3'
    out = open(SERVICE_LOG, 'a')
    try:
        proc = subprocess.Popen(
            [python, str(PROJECT_DIR / 'server.py'), 'serve'],
            cwd=str(PROJECT_DIR),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=out,
            start_new_session=True,
            close_fds=True,
            env={**os.environ, 'WAF_CONFIG': CONFIG_PATH},
        )
    except Exception as e:
        print(f"Failed to start service: {e}")
        log(f"Start failed: {e!r}")
        out.close()
        return 1
    # Wait for PID file
    for _ in range(50):
        time.sleep(0.1)
        pid2 = read_pid()
        if pid2 and pid_alive(pid2):
            print(f"Service running (PID {pid2})")
            out.close()
            return 0
    print("Service failed to start. Check logs/service.log")
    log("Service failed to start within timeout")
    out.close()
    return 1


def cmd_serve() -> int:
    ensure_state_dir()
    run_server_foreground()
    return 0


def cmd_stop() -> int:
    # Attempt graceful stop using PID file
    pid = read_pid()
    if pid and pid_alive(pid):
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            time.sleep(0.1)
            if not pid_alive(pid):
                remove_pid()
                print("Service stopped")
                break
        else:
            print("Service did not stop in time (PID-file method)")
    else:
        if pid and not pid_alive(pid):
            remove_pid()
        print("Service not running via PID file; proceeding to free port if occupied")

    # Ensure the configured port is freed by killing any listeners
    cfg = load_config(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else {}
    host, port = get_service_bind(cfg)
    pids = _listening_pids_on_port(port)
    if pids:
        log(f"Stopping listeners on port {port}: {pids}")
        _kill_pids(pids)
        # Verify
        remain = _listening_pids_on_port(port)
        if remain:
            print(f"Warning: some processes still listen on port {port}: {remain}")
            log(f"Port {port} still has listeners: {remain}")
            return 1
        print(f"Port {host}:{port} freed")
    else:
        print(f"No listeners found on port {host}:{port}")
    return 0


def cmd_status() -> int:
    pid = read_pid()
    if pid and pid_alive(pid):
        print(f"Service running (PID {pid})")
        return 0
    print("Service not running")
    return 3


def cmd_run_once() -> int:
    result = run_waf_blocker(apply=False)
    print(json.dumps(result, indent=2))
    return 0


def main():
    if sys.version_info < (3, 8):
        print("Python 3.8+ is required.")
        sys.exit(1)
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'serve'
    if cmd == 'start':
        rc = cmd_start()
    elif cmd == 'stop':
        rc = cmd_stop()
    elif cmd == 'status':
        rc = cmd_status()
    elif cmd == 'serve':
        rc = cmd_serve()
    elif cmd == 'run-once':
        rc = cmd_run_once()
    else:
        print("Usage: python3 server.py [start|stop|status|serve|run-once]")
        rc = 2
    sys.exit(rc)


if __name__ == '__main__':
    main()
