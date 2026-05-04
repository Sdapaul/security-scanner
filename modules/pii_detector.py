"""개인정보 유출 탐지 모듈
──────────────────────────
파일 내 PII 패턴(주민번호, 카드번호, 패스워드 등) 탐지
· os.scandir 기반 탐색 → 중단 신호 즉시 반응
· 파일별 진행 상태 SSE 스트림
"""
import os
import re
import time
from datetime import datetime

from config.settings import PII_PATTERNS, PII_SCAN_EXTENSIONS, PII_MAX_FILE_SIZE

MODULE = 'pii'

MAX_SCAN_FILES   = 5_000   # 파일 수 상한
MAX_SCAN_SECONDS = 300     # 시간 상한 (5분)

_COMPILED = {
    key: (re.compile(pattern), sev, label)
    for key, (pattern, sev, label) in PII_PATTERNS.items()
}

# 탐색 제외 디렉토리 (이름 기준)
SKIP_DIRS = {
    # 개발 패키지
    'node_modules', '__pycache__', '.git', '.svn', '.hg',
    'venv', 'env', '.env', 'site-packages', 'dist', 'build',
    # Windows 시스템 / C:\ 루트 불필요 디렉터리
    'Windows', 'Program Files', 'Program Files (x86)',
    'ProgramData', 'System32', 'SysWOW64', 'WinSxS', 'WinSXS',
    'Recovery', 'PerfLogs', '$Recycle.Bin', '$WinREAgent',
    'Intel', 'AMD', 'NVIDIA', 'KIOXIA', 'SamsungMagician',
    # Electron/Chromium 캐시 (수백만 개 바이너리)
    'Cache', 'Caches', 'CacheStorage', 'Code Cache', 'cache',
    'GPUCache', 'ShaderCache', 'DawnCache', 'DawnWebGPUCache',
    'blob_storage', 'Local Storage', 'Session Storage',
    'IndexedDB', 'Snapshots', 'WebStorage', 'Service Worker',
    'GrShaderCache', 'VideoDecodeStats', 'BrowserMetrics',
    'databases', 'NetworkPersistency',
    # npm / yarn
    '.npm', '.yarn', 'npm-cache', '.pnpm-store',
    # 임시 / 로그
    'Temp', 'temp', 'tmp', 'Tmp', 'Logs', 'logs',
    # 대형 앱 캐시 (스캔 불필요)
    'Spotify', 'Discord', 'Slack', 'Teams', 'OneDrive',
    'Microsoft Edge', 'Google', 'chrome', 'Firefox',
    'steam', 'Steam', 'EpicGamesLauncher',
    'Zoom', 'zoom', 'Uninstall', 'Installer',
    'KakaoTalk', 'kakaotalk', 'NAVER', 'naver',
    'obs-studio', 'OBS Studio', 'Wondershare',
    'Adobe', 'Autodesk', 'JetBrains', 'Postman',
    # Claude / VS Code 관련
    'extensions', 'workspaceStorage', 'globalStorage',
}

# 경로 내 키워드로 전체 서브트리 스킵
SKIP_PATH_KEYWORDS = (
    'AppData\\Local\\Temp',
    'AppData\\Local\\Packages',       # UWP 앱 패키지 (수백만 파일)
    'AppData\\Local\\Programs',       # 사용자 설치 앱 바이너리·문서 (Python, Node 등)
    'AppData\\Local\\Microsoft\\Windows',
    'AppData\\LocalLow',
    # AppData\Roaming 하위 대형 앱 디렉토리 (앱 바이너리·캐시, PII 없음)
    'AppData\\Roaming\\npm',
    'AppData\\Roaming\\Zoom',
    'AppData\\Roaming\\discord',
    'AppData\\Roaming\\Discord',
    'AppData\\Roaming\\Slack',
    'AppData\\Roaming\\Code',
    'AppData\\Roaming\\Cursor',
    'AppData\\Roaming\\Microsoft\\Windows',
    'AppData\\Roaming\\Microsoft\\Office',
    'AppData\\Roaming\\KakaoTalk',
    'AppData\\Roaming\\obs-studio',
    'claude-cli-nodejs',
    'cloud-code',
    '.vscode',
    '.cursor',
)

MAX_SCAN_DEPTH = 8   # 최대 탐색 깊이

# ── 중단 신호 (web_app에서 주입) ──────────────────────────────────
_stop_check = None


def set_stop_check(fn):
    global _stop_check
    _stop_check = fn


def _is_stopped() -> bool:
    return _stop_check is not None and bool(_stop_check())


# ── 파일 진행 상태 SSE 전송 ───────────────────────────────────────
def _emit_progress(fpath: str, scanned: int, total: int) -> None:
    print(f'\x00FILE_SCAN\x00{fpath}\x00{scanned}\x00{total}')


# ── os.scandir 기반 탐색 (stop 즉시 반응) ────────────────────────
def _walk_dirs(base_dir: str):
    """각 파일 항목 사이에 stop 체크 — os.walk 대비 즉시 중단 가능."""
    def _recurse(path: str, depth: int):
        if depth > MAX_SCAN_DEPTH or _is_stopped():
            return
        norm = os.path.normpath(path)
        if any(kw in norm for kw in SKIP_PATH_KEYWORDS):
            return
        try:
            subdirs = []
            files   = []
            with os.scandir(path) as it:
                for entry in it:
                    if _is_stopped():
                        return
                    try:
                        name = entry.name
                        if entry.is_dir(follow_symlinks=False):
                            if name not in SKIP_DIRS and not name.startswith('.'):
                                subdirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            files.append(name)
                    except OSError:
                        pass
            if files:
                yield path, files
            for sub in subdirs:
                if _is_stopped():
                    return
                yield from _recurse(sub, depth + 1)
        except (PermissionError, OSError):
            pass

    yield from _recurse(base_dir, 0)


# ─────────────────────────────────────────────────────────────────
def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id':             f'PII-{fid:03d}',
        'category':       MODULE,
        'title':          title,
        'severity':       severity,
        'description':    description,
        'details':        details,
        'recommendation': recommendation,
        'timestamp':      datetime.now().isoformat(),
    }


def _scan_file(filepath: str, is_stopped=None) -> list[dict]:
    matches = []
    try:
        size = os.path.getsize(filepath)
        if size == 0 or size > PII_MAX_FILE_SIZE:
            return []
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                if lineno > 20000:
                    break
                # 파일 내부 stop 체크 (매 300라인)
                if is_stopped and lineno % 300 == 0 and is_stopped():
                    break
                for key, (regex, sev, label) in _COMPILED.items():
                    found = regex.findall(line)
                    if found:
                        count  = len(found)
                        sample = found[0] if isinstance(found[0], str) else found[0][0]
                        matches.append({
                            'type_key': key,
                            'label':    label,
                            'severity': sev,
                            'file':     filepath,
                            'line':     lineno,
                            'count':    count,
                            'sample':   sample,
                        })
    except (PermissionError, OSError):
        pass
    return matches


def _mask(value: str, key: str) -> str:
    if key == 'korean_rrn':
        return value[:6] + '-*******'
    if key == 'credit_card':
        return value[:4] + '-****-****-' + value[-4:]
    if key in ('password_literal', 'api_key'):
        parts = value.split('=', 1) if '=' in value else value.split(':', 1)
        return parts[0] + '=***REDACTED***'
    if len(value) > 20:
        return value[:8] + '...' + value[-4:]
    return value[:4] + '****'


def _build_findings(fid: int, type_matches: dict, scanned_files: int,
                    total_files: int, scan_dirs: list, stopped: bool) -> list[dict]:
    findings: list[dict] = []
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    for key in sorted(type_matches.keys(),
                      key=lambda k: severity_order.get(PII_PATTERNS[k][1], 9)):
        matches = type_matches[key]
        _, sev, label = PII_PATTERNS[key]
        total_count    = sum(m['count'] for m in matches)
        affected_files = list({m['file'] for m in matches})

        samples = [{
            '파일':       m['file'],
            '라인':       m['line'],
            '샘플':        m['sample'],
            '발견 건수':   m['count'],
        } for m in matches[:10]]

        findings.append(_finding(
            fid, f'{label} 탐지 ({total_count}건, {len(affected_files)}개 파일)', sev,
            f'{label} 패턴이 {len(affected_files)}개 파일에서 총 {total_count}건 발견되었습니다.',
            {'영향 파일': affected_files[:20], '샘플': samples},
            _get_recommendation(key),
        ))
        fid += 1

    pii_total = sum(sum(m['count'] for m in v) for v in type_matches.values())
    status_note = ' (스캔 중단됨)' if stopped else ''
    findings.append(_finding(
        fid, f'PII 스캔 요약{status_note}', 'info' if pii_total == 0 else 'high',
        f'{scanned_files}개 파일 스캔 완료{status_note}, 총 {pii_total}건의 개인정보 패턴 탐지.',
        {
            '스캔 기준 디렉토리': scan_dirs,
            '전체 파일 수':      total_files,
            '스캔 파일 수':      scanned_files,
            '탐지 건수':         pii_total,
            '탐지 유형':         list(type_matches.keys()),
            '중단 여부':         '예 (사용자 중단)' if stopped else '아니오 (정상 완료)',
        },
        ('개인정보보호법에 따라 수집 목적 외 개인정보 저장을 금지하고, '
         '필요한 데이터는 암호화 후 접근 권한을 최소화하세요.'),
    ))
    return findings


def scan(scan_dirs: list[str]) -> list[dict]:
    if not scan_dirs:
        scan_dirs = [os.path.expanduser('~')]

    type_matches:  dict[str, list] = {}
    total_files    = 0
    scanned_files  = 0
    pii_found      = 0
    stopped        = False
    t0             = time.time()

    for base_dir in scan_dirs:
        if not os.path.isdir(base_dir):
            print(f'  -> [PII] 경로 없음: {base_dir}')
            continue

        print(f'  -> [PII] 스캔 시작: {base_dir}')
        prev_parent = None

        for dirpath, files in _walk_dirs(base_dir):
            if _is_stopped():
                stopped = True
                break

            # 부모 디렉토리 변경 시 로그
            parent = os.path.dirname(dirpath)
            if parent != prev_parent:
                print(f'  -> [PII] 폴더 분석 중: {dirpath}')
                prev_parent = parent

            for fname in files:
                if _is_stopped():
                    stopped = True
                    break

                total_files += 1
                ext = os.path.splitext(fname)[1].lower()
                if ext not in PII_SCAN_EXTENSIONS:
                    continue

                fpath = os.path.join(dirpath, fname)
                scanned_files += 1

                if scanned_files >= MAX_SCAN_FILES:
                    print(f'  -> [PII] 최대 스캔 파일 수({MAX_SCAN_FILES:,}개) 도달, 스캔 중단.')
                    stopped = True
                    break
                if scanned_files % 50 == 0 and (time.time() - t0) > MAX_SCAN_SECONDS:
                    print(f'  -> [PII] 최대 스캔 시간({MAX_SCAN_SECONDS}초) 초과, 스캔 중단.')
                    stopped = True
                    break

                if scanned_files == 1 or scanned_files % 5 == 0:
                    _emit_progress(fpath, scanned_files, scanned_files)

                if scanned_files % 10 == 1:
                    print(f'  -> [PII] {scanned_files}번째 파일 분석 중... '
                          f'(누적 탐지 {pii_found}건)')

                matches = _scan_file(fpath, _is_stopped)
                if matches:
                    file_count = sum(m['count'] for m in matches)
                    pii_found += file_count
                    labels = list({m['label'] for m in matches})
                    print(f'  -> [발견] {fname}: {file_count}건 '
                          f'({", ".join(labels[:3])}{"..." if len(labels) > 3 else ""})')
                    for m in matches:
                        key = m['type_key']
                        type_matches.setdefault(key, []).append(m)

                # 대용량 파일 처리 후 즉시 재확인
                if _is_stopped():
                    stopped = True
                    break

            if stopped:
                break

        if stopped:
            break

    if stopped:
        print('  -> [중단] PII 스캔이 중단되었습니다.')

    status = '중단' if stopped else '완료'
    print(f'  -> [PII] 스캔 {status}: {scanned_files}개 파일 / {pii_found}건 탐지')

    return _build_findings(1, type_matches, scanned_files, total_files, scan_dirs, stopped)


def _get_recommendation(key: str) -> str:
    recs = {
        'korean_rrn':       '주민등록번호는 수집 금지가 원칙입니다. 파일을 즉시 삭제하거나 암호화하고, 데이터 마스킹 처리하세요. 개인정보보호법 위반 가능성을 법률 검토하세요.',
        'credit_card':      '카드번호는 PCI-DSS 규정에 따라 평문 저장이 금지됩니다. 즉시 삭제 후 토큰화(Tokenization) 방식으로 대체하세요.',
        'korean_phone':     '휴대폰 번호는 수집 동의 여부를 확인하고 불필요하면 삭제하세요. 저장 시 AES-256 암호화를 적용하세요.',
        'email':            '이메일 주소 수집에 대한 동의 여부를 확인하고 불필요한 파일에서 제거하세요.',
        'password_literal': '코드 또는 설정 파일에 평문 패스워드가 있습니다. 환경 변수 또는 비밀 관리 서비스(Vault, AWS Secrets Manager)로 이동하세요.',
        'api_key':          'API 키가 소스코드에 하드코딩되어 있습니다. 즉시 키를 재발급하고 환경 변수 또는 비밀 관리 서비스로 이동하세요.',
        'bank_account':     '계좌번호를 평문으로 저장하지 마세요. 필요 시 암호화하거나 접근 권한을 엄격히 제한하세요.',
        'ip_internal':      '내부 IP 주소가 공개 파일에 포함되어 있습니다. 네트워크 구조 노출을 방지하기 위해 제거하거나 마스킹하세요.',
    }
    return recs.get(key, '해당 데이터의 수집 및 저장 필요성을 검토하고 암호화 또는 마스킹을 적용하세요.')
