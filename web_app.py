#!/usr/bin/env python3
"""
보안 스캐너 웹 제어판 — Flask + SSE 실시간 모니터링
포트: 5001  /  접속: http://127.0.0.1:5001
"""
import importlib
import io
import json
import os
import sys
import threading
import time
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, send_file

# 모듈 경로 설정 (security_scanner/ 디렉토리 기준)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules.utils import kill_current_proc

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── 이벤트 브로드캐스트 (Condition 기반 pub/sub) ──────────────────
event_log: list[dict] = []          # 전체 이벤트 누적 (200건 링 버퍼, file_progress 제외)
event_log_offset = 0                # pop(0) 횟수 — 절대 인덱스 = offset + 상대위치
event_condition = threading.Condition()


def _emit(**kwargs):
    """모든 SSE 구독자에게 이벤트를 브로드캐스트합니다.
    file_progress는 링버퍼에 저장하지 않아 중요 이벤트(scan_complete 등) 유실을 방지합니다."""
    global event_log_offset
    event = {'ts': time.time(), **kwargs}
    with event_condition:
        if kwargs.get('type') == 'file_progress':
            manager.last_file   = kwargs.get('file', '')
            manager.last_file_n = kwargs.get('scanned', 0)
        else:
            event_log.append(event)
            if len(event_log) > 200:
                event_log.pop(0)
                event_log_offset += 1
        event_condition.notify_all()


# ── 모듈 정의 ─────────────────────────────────────────────────────
_SVG = {
    'server':    '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    'wifi':      '<path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    'cpu':       '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
    'file-text': '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
    'shield':    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'search':    '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    'lock':      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
}

MODULES: dict[str, dict] = {
    'server':  {'name': '서버 상태 검사',       'desc': 'CPU/메모리/방화벽/UAC/Defender',  'svg': _SVG['server'],    'default': True},
    'network': {'name': '네트워크 트래픽 분석',  'desc': '연결 분석 · 위험 포트 탐지',       'svg': _SVG['wifi'],      'default': True},
    'process': {'name': '프로세스 분석',         'desc': '악성 프로세스 · PPID 스푸핑',      'svg': _SVG['cpu'],       'default': True},
    'log':     {'name': '로그 분석',             'desc': 'Windows 이벤트 · SQLi/XSS 패턴',  'svg': _SVG['file-text'], 'default': True},
    'attack':  {'name': '외부 공격 탐지',        'desc': 'RDP/SMB 브루트포스 · 스캔 탐지',   'svg': _SVG['shield'],    'default': True},
    'port':    {'name': '포트 스캔',             'desc': '1040개 포트 병렬 TCP 스캔',        'svg': _SVG['search'],    'default': True},
    'pii':     {'name': '개인정보 유출 탐지',    'desc': '주민번호 · 카드번호 · API키 탐지', 'svg': _SVG['lock'],      'default': False},
    'malware': {'name': '악성코드 탐지',         'desc': 'Defender · PUP · 랜섬웨어 · RAT',  'svg': _SVG['shield'],    'default': True},
}

module_states: dict[str, bool] = {k: v['default'] for k, v in MODULES.items()}

# ── 스캔 상태 관리 ─────────────────────────────────────────────────
class ScanManager:
    def __init__(self):
        self._lock = threading.RLock()
        self.reset()

    def reset(self):
        with self._lock:
            self.status      = 'idle'    # idle | running | completed | stopped | error
            self.findings: list[dict] = []
            self.progress    = 0
            self.total       = 0
            self.current_mod = ''
            self.started_at  = ''
            self.completed_at= ''
            self.elapsed     = 0.0
            self.error       = ''
            self.mod_status: dict[str, str] = {}  # module -> idle|running|done|error
            self.last_file   = ''        # 마지막으로 처리한 파일 경로
            self.last_file_n = 0         # 마지막 파일 번호

    @property
    def summary(self) -> dict:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in self.findings:
            s = f.get('severity', 'info')
            counts[s] = counts.get(s, 0) + 1
        return counts

    def to_dict(self) -> dict:
        with self._lock:
            return {
                'status':       self.status,
                'progress':     self.progress,
                'total':        self.total,
                'current_mod':  self.current_mod,
                'started_at':   self.started_at,
                'completed_at': self.completed_at,
                'elapsed':      round(self.elapsed, 1),
                'error':        self.error,
                'finding_count':len(self.findings),
                'summary':      self.summary,
                'mod_status':   dict(self.mod_status),
                'last_file':    self.last_file,
                'last_file_n':  self.last_file_n,
            }


manager         = ScanManager()
scan_stop_event = threading.Event()
scan_thread: threading.Thread | None = None


# ── stdout 캡처 → 이벤트 브로드캐스트 ────────────────────────────
class _LogCapture(io.TextIOBase):
    def __init__(self, real_stdout):
        self._real = real_stdout

    def write(self, text: str) -> int:
        stripped = text.rstrip('\n').strip()
        if stripped.startswith('\x00FILE_SCAN\x00'):
            # 파일 스캔 진행 상태: \x00FILE_SCAN\x00<path>\x00<scanned>\x00<total>
            parts = stripped.split('\x00')
            if len(parts) == 5:
                try:
                    _emit(type='file_progress',
                          file=parts[2], scanned=int(parts[3]), total=int(parts[4]))
                except Exception:
                    pass
        elif stripped:
            _emit(type='log', text=stripped)
        return len(text)

    def flush(self):
        try:
            self._real.flush()
        except Exception:
            pass


# ── 스캔 실행 (백그라운드 스레드) ────────────────────────────────
_MODULE_FUNC = {
    'server':  ('modules.server_status',   'check',   None),
    'network': ('modules.network_analyzer','analyze',  None),
    'process': ('modules.process_analyzer','analyze',  None),
    'log':     ('modules.log_analyzer',    'analyze',  None),
    'attack':  ('modules.attack_detector', 'detect',   None),
    'port':    ('modules.port_scanner',    'scan',     'target'),
    'pii':     ('modules.pii_detector',    'scan',     'pii_dirs'),
    'malware': ('modules.malware_detector', 'scan',    None),
}


def _run_scan(selected: list[str], target: str, pii_dirs: list[str], my_stop: threading.Event):
    real_stdout = sys.stdout
    sys.stdout  = _LogCapture(real_stdout)

    t0 = time.time()
    manager.started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    manager.status     = 'running'
    manager.total      = len(selected)
    manager.mod_status = {k: 'pending' for k in selected}

    _emit(type='scan_start', modules=selected, target=target,
          started_at=manager.started_at, total=len(selected))

    all_findings: list[dict] = []
    completed_normally = True

    for idx, key in enumerate(selected, 1):
        if my_stop.is_set():
            completed_normally = False
            manager.status = 'stopped'
            _emit(type='stopped', message='사용자에 의해 중단되었습니다.')
            break

        mod_info = MODULES[key]
        manager.progress    = idx
        manager.current_mod = mod_info['name']
        manager.mod_status[key] = 'running'

        _emit(type='module_start', key=key, name=mod_info['name'],
              step=idx, total=manager.total)

        try:
            mod_path, func_name, arg_key = _MODULE_FUNC[key]
            mod  = importlib.import_module(mod_path)
            func = getattr(mod, func_name)

            # 중단 신호를 지원하는 모듈에 stop_check 주입
            if hasattr(mod, 'set_stop_check'):
                mod.set_stop_check(my_stop.is_set)

            try:
                if arg_key == 'target':
                    findings = func(target)
                elif arg_key == 'pii_dirs':
                    findings = func(pii_dirs)
                else:
                    findings = func()
            finally:
                # 스캔 완료/중단 후 stop_check 해제
                if hasattr(mod, 'set_stop_check'):
                    mod.set_stop_check(None)

            all_findings.extend(findings)
            manager.findings = all_findings[:]
            manager.mod_status[key] = 'done'

            sev_cnt = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in findings:
                s = f.get('severity', 'info')
                sev_cnt[s] = sev_cnt.get(s, 0) + 1

            _emit(type='module_done', key=key, name=mod_info['name'],
                  count=len(findings), severity=sev_cnt, findings=findings)

        except Exception as exc:
            manager.mod_status[key] = 'error'
            _emit(type='module_error', key=key, name=mod_info['name'], error=str(exc))

    if completed_normally and not my_stop.is_set():
        manager.status       = 'completed'
        manager.elapsed      = time.time() - t0
        manager.completed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        report_path = ''
        try:
            from modules.reporter import generate
            report_path = generate(all_findings, 'html', 'security_report')
            generate(all_findings, 'json', 'security_report')
        except Exception as exc:
            _emit(type='log', text=f'[보고서 오류] {exc}')

        _emit(type='scan_complete',
              elapsed=round(manager.elapsed, 1),
              summary=manager.summary,
              total=len(all_findings),
              report_saved=bool(report_path))

    sys.stdout = real_stdout


# ── REST API ──────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html',
                           modules=MODULES,
                           module_states=module_states)


@app.route('/api/state')
def api_state():
    return jsonify({
        **manager.to_dict(),
        'module_states': module_states,
    })


@app.route('/api/modules/<key>', methods=['POST'])
def api_toggle_module(key):
    if key not in MODULES:
        return jsonify({'error': 'unknown module'}), 404
    if manager.status == 'running':
        return jsonify({'error': '스캔 실행 중에는 모듈을 변경할 수 없습니다.'}), 409
    data = request.get_json(force=True) or {}
    module_states[key] = bool(data.get('enabled', not module_states[key]))
    return jsonify({'key': key, 'enabled': module_states[key]})


@app.route('/api/modules/bulk', methods=['POST'])
def api_toggle_all():
    if manager.status == 'running':
        return jsonify({'error': '스캔 실행 중'}), 409
    data = request.get_json(force=True) or {}
    enabled = bool(data.get('enabled', True))
    for k in MODULES:
        module_states[k] = enabled
    return jsonify({'enabled': enabled})


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    global scan_thread, scan_stop_event

    if manager.status == 'running':
        # 스레드가 이미 죽었으면 자동 초기화 후 진행
        if scan_thread is not None and scan_thread.is_alive():
            return jsonify({'error': '이미 스캔이 실행 중입니다.'}), 409
        manager.reset()

    data = request.get_json(force=True) or {}
    target   = data.get('target', '127.0.0.1').strip() or '127.0.0.1'
    _home = os.path.expanduser('~')
    _safe_defaults = [
        os.path.join(_home, 'Documents'),
        os.path.join(_home, 'Desktop'),
        os.path.join(_home, 'Downloads'),
    ]
    # OneDrive가 있으면 추가
    for _od in ('OneDrive', 'OneDrive - Personal', '원드라이브'):
        _od_path = os.path.join(_home, _od)
        if os.path.isdir(_od_path):
            _safe_defaults.append(_od_path)
            break
    pii_dirs = data.get('pii_dirs', _safe_defaults)
    if isinstance(pii_dirs, str):
        pii_dirs = [pii_dirs]

    selected = [k for k, v in module_states.items() if v]
    if not selected:
        return jsonify({'error': '활성화된 모듈이 없습니다.'}), 400

    scan_stop_event = threading.Event()   # 스캔마다 새 이벤트 생성
    manager.reset()

    scan_thread = threading.Thread(
        target=_run_scan,
        args=(selected, target, pii_dirs, scan_stop_event),
        daemon=True,
        name='scanner',
    )
    scan_thread.start()

    return jsonify({'status': 'started', 'modules': selected, 'target': target})


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    if manager.status != 'running':
        return jsonify({'error': '실행 중인 스캔이 없습니다.'}), 400
    scan_stop_event.set()
    kill_current_proc()
    return jsonify({'status': 'stopping'})


@app.route('/api/scan/reset', methods=['POST'])
def api_scan_reset():
    """백그라운드 스레드가 멈춰 새 스캔을 시작할 수 없을 때 강제 초기화합니다."""
    global scan_thread, scan_stop_event
    old_event  = scan_stop_event
    old_thread = scan_thread
    old_event.set()              # 구 스캔 스레드에 중단 신호
    kill_current_proc()
    if old_thread is not None:
        old_thread.join(timeout=4)
    manager.reset()
    scan_stop_event = threading.Event()  # 새 이벤트 생성 (구 이벤트는 set 상태 유지)
    scan_thread = None
    _emit(type='stopped', message='강제 초기화되었습니다. 새 스캔을 시작할 수 있습니다.')
    return jsonify({'status': 'reset'})


@app.route('/api/findings')
def api_findings():
    sev = request.args.get('severity', '')
    cat = request.args.get('category', '')
    items = manager.findings[:]
    if sev:
        items = [f for f in items if f.get('severity') == sev]
    if cat:
        items = [f for f in items if f.get('category') == cat]
    return jsonify({'findings': items, 'total': len(items), 'summary': manager.summary})


@app.route('/api/stream')
def api_stream():
    """Server-Sent Events 스트림 — 실시간 이벤트 전송"""
    def generate():
        # 현재 상태 즉시 전송 (last_file 포함으로 재연결 시 파일 진행 복원)
        yield f"data: {json.dumps({'type': 'state', **manager.to_dict(), 'module_states': module_states}, ensure_ascii=False)}\n\n"

        # 절대 인덱스 0부터 시작 → 재연결 시 링버퍼에 남아있는 기존 이벤트 히스토리 전송
        abs_idx      = 0
        last_file_n  = manager.last_file_n

        while True:
            ping_needed = False
            with event_condition:
                abs_tail = event_log_offset + len(event_log)
                while abs_tail <= abs_idx and manager.last_file_n == last_file_n:
                    notified = event_condition.wait(timeout=5)
                    if not notified:
                        ping_needed = True
                        break
                    abs_tail = event_log_offset + len(event_log)

                # 링버퍼에서 abs_idx에 해당하는 상대 위치 계산
                rel_start = max(0, abs_idx - event_log_offset)
                new_events = event_log[rel_start:]
                abs_idx    = event_log_offset + len(event_log)
                cur_file_n = manager.last_file_n
                cur_file   = manager.last_file

            # 락 해제 후 yield — 락 보유 중 yield는 스캔 스레드와 교착 상태 유발
            if ping_needed:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

            if cur_file_n != last_file_n and cur_file:
                last_file_n = cur_file_n
                yield f"data: {json.dumps({'type':'file_progress','file':cur_file,'scanned':cur_file_n,'total':cur_file_n}, ensure_ascii=False)}\n\n"

            for ev in new_events:
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/open_folder', methods=['POST'])
def api_open_folder():
    """Windows 탐색기로 해당 파일의 폴더를 엽니다."""
    import subprocess
    data   = request.get_json(force=True) or {}
    path   = data.get('path', '').strip()
    if not path:
        return jsonify({'error': '경로가 없습니다.'}), 400

    # 경로가 파일이면 부모 디렉토리, 디렉토리면 그대로
    if os.path.isfile(path):
        folder = os.path.dirname(path)
        # 탐색기에서 해당 파일을 선택 상태로 열기
        try:
            subprocess.Popen(['explorer.exe', f'/select,{path}'])
            return jsonify({'ok': True, 'folder': folder})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    elif os.path.isdir(path):
        folder = path
    else:
        # 경로가 존재하지 않으면 가장 가까운 존재하는 부모 열기
        folder = path
        while folder and not os.path.isdir(folder):
            parent = os.path.dirname(folder)
            if parent == folder:
                break
            folder = parent

    if not folder or not os.path.isdir(folder):
        return jsonify({'error': '폴더를 찾을 수 없습니다.'}), 404

    try:
        subprocess.Popen(['explorer.exe', folder])
        return jsonify({'ok': True, 'folder': folder})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/report')
def view_report():
    path = os.path.join(BASE_DIR, 'security_report.html')
    if not os.path.exists(path):
        return '<h2 style="font-family:sans-serif;padding:2rem">보고서가 없습니다. 먼저 스캔을 실행하세요.</h2>', 404
    return send_file(path)


@app.route('/report/download/<fmt>')
def download_report(fmt):
    ext_map = {'html': 'html', 'json': 'json', 'text': 'txt'}
    if fmt not in ext_map:
        return jsonify({'error': '잘못된 형식'}), 400
    path = os.path.join(BASE_DIR, f'security_report.{ext_map[fmt]}')
    if not os.path.exists(path):
        return jsonify({'error': '파일 없음. 먼저 스캔을 실행하세요.'}), 404
    return send_file(path, as_attachment=True)


if __name__ == '__main__':
    print('=' * 52)
    print('  보안 스캐너 웹 제어판 시작')
    print('  http://127.0.0.1:5001')
    print('=' * 52)
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
