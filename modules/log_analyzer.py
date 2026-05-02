"""로그 분석 모듈 — Windows 이벤트 로그, 텍스트 로그에서 보안 이벤트 탐지"""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

from config.settings import EVENT_IDS, BRUTE_FORCE_THRESHOLD
from modules.utils import run_cmd

MODULE = 'log'

SQL_INJECTION_PATTERNS = [
    r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b)",
    r"(?i)(--|#|/\*.*\*/)",
    r"(?i)(\bor\b\s+['\d].*=.*['\d]|\band\b\s+['\d].*=.*['\d])",
    r"(?i)(xp_cmdshell|sp_executesql|exec\s*\()",
    r"(?i)(\bdrop\s+table\b|\btruncate\s+table\b|\bdelete\s+from\b)",
]

XSS_PATTERNS = [
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)javascript\s*:",
    r"(?i)on(?:load|click|error|mouseover|focus|blur)\s*=",
    r"(?i)<iframe[^>]*>",
    r"(?i)eval\s*\(",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[%2f%5c]",
    r"\.\.%2f",
]

_SQL_RE  = [re.compile(p) for p in SQL_INJECTION_PATTERNS]
_XSS_RE  = [re.compile(p) for p in XSS_PATTERNS]
_PATH_RE = [re.compile(p) for p in PATH_TRAVERSAL_PATTERNS]


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'LOG-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def _query_event_log(log_name: str, event_ids: list, count: int = 300) -> str:
    id_filter = ' or '.join(f'EventID={eid}' for eid in event_ids)
    query = f"*[System[({id_filter})]]"
    return run_cmd(
        ['wevtutil', 'qe', log_name, f'/q:{query}',
         f'/c:{count}', '/rd:true', '/f:text'],
        timeout=30,
    )


def _parse_events(raw: str) -> list[dict]:
    events = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith('Event['):
            if current:
                events.append(current)
            current = {}
        elif ':' in line:
            k, _, v = line.partition(':')
            current[k.strip()] = v.strip()
    if current:
        events.append(current)
    return events


def _analyze_security_events(findings: list, fid: int):
    raw = _query_event_log('Security', list(EVENT_IDS.keys()), count=500)
    if not raw.strip():
        findings.append(_finding(
            fid, 'Windows 보안 로그 접근 불가', 'medium',
            '보안 이벤트 로그를 읽을 수 없습니다. 관리자 권한이 필요합니다.',
            {},
            '관리자 권한으로 스캐너를 재실행하세요.',
        ))
        return findings, fid + 1

    events = _parse_events(raw)
    eid_counter: Counter = Counter()
    failed_logins: dict[str, list] = defaultdict(list)

    for ev in events:
        eid_str = ev.get('Event ID', ev.get('EventID', ''))
        try:
            eid = int(eid_str)
        except ValueError:
            continue
        eid_counter[eid] += 1
        if eid == 4625:
            user = ev.get('Account Name', ev.get('TargetUserName', 'unknown'))
            failed_logins[user].append(ev.get('Date', ''))

    # 브루트포스 탐지
    brute_users = [
        {'계정': user, '실패 횟수': len(times)}
        for user, times in failed_logins.items()
        if len(times) >= BRUTE_FORCE_THRESHOLD
    ]
    if brute_users:
        findings.append(_finding(
            fid, '로그인 브루트포스 공격 탐지', 'critical',
            f'{len(brute_users)}개 계정에서 반복적인 로그인 실패가 탐지되었습니다.',
            {'영향 계정': brute_users},
            '계정 잠금 정책을 설정하고(5회 실패 -> 30분 잠금), RDP를 VPN 뒤로 이동하세요.',
        ))
        fid += 1

    # 중요 이벤트 요약
    notable = {
        eid: (count, EVENT_IDS[eid])
        for eid, count in eid_counter.items()
        if eid in EVENT_IDS
    }
    if notable:
        summary = {
            f'Event {eid} - {info[0]}': f'{count}건 (심각도: {info[1]})'
            for eid, (count, info) in notable.items()
        }
        high_cnt = sum(1 for _, (_, (_, s)) in notable.items() if s in ('high', 'critical'))
        sev = 'high' if high_cnt > 0 else 'medium'
        findings.append(_finding(
            fid, f'Windows 보안 이벤트 요약 ({sum(eid_counter.values())}건)', sev,
            '최근 보안 이벤트 로그에서 주요 이벤트가 탐지되었습니다.',
            summary,
            '이상 이벤트를 SIEM 도구로 상관 분석하고 정기적으로 감사 로그를 검토하세요.',
        ))
        fid += 1

    return findings, fid


def _scan_text_log(filepath: str) -> list[dict]:
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                if lineno > 50000:
                    break
                for regex in _SQL_RE:
                    if regex.search(line):
                        issues.append({'유형': 'SQL Injection', '파일': filepath, '라인': lineno, '내용': line.strip()[:200]})
                        break
                for regex in _XSS_RE:
                    if regex.search(line):
                        issues.append({'유형': 'XSS', '파일': filepath, '라인': lineno, '내용': line.strip()[:200]})
                        break
                for regex in _PATH_RE:
                    if regex.search(line):
                        issues.append({'유형': '경로 탐색', '파일': filepath, '라인': lineno, '내용': line.strip()[:200]})
                        break
    except Exception:
        pass
    return issues


def analyze():
    findings = []
    fid = 1

    # ── Windows 이벤트 로그 분석 ──────────────────────────────────
    findings, fid = _analyze_security_events(findings, fid)

    # ── 텍스트 로그 파일 분석 ─────────────────────────────────────
    log_dirs = [
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'LogFiles'),
        'C:\\inetpub\\logs\\LogFiles',
    ]
    cwd_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ('logs', 'log'):
        candidate = os.path.join(cwd_parent, name)
        if os.path.isdir(candidate):
            log_dirs.append(candidate)

    all_issues: list[dict] = []
    scanned = 0
    for log_dir in log_dirs:
        if not os.path.isdir(log_dir):
            continue
        for root, _, files in os.walk(log_dir):
            for fname in files:
                if not fname.endswith(('.log', '.txt', '.csv')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > 100 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                all_issues.extend(_scan_text_log(fpath))
                scanned += 1

    if all_issues:
        for label, pattern_type, sev, rec in [
            ('SQL Injection', 'SQL Injection', 'critical',
             'Prepared Statement/ORM을 사용하고 WAF를 설정하세요.'),
            ('XSS', 'XSS', 'high',
             '입력값 HTML 인코딩과 Content-Security-Policy 헤더를 적용하세요.'),
            ('경로 탐색', '경로 탐색', 'high',
             '경로 정규화(canonicalize) 후 허용 범위를 검증하세요.'),
        ]:
            matched = [i for i in all_issues if i['유형'] == pattern_type]
            if matched:
                findings.append(_finding(
                    fid, f'{label} 공격 패턴 탐지 ({len(matched)}건)', sev,
                    f'로그 파일에서 {label} 시도 패턴이 발견되었습니다.',
                    matched[:10],
                    rec,
                ))
                fid += 1
    else:
        findings.append(_finding(
            fid, f'텍스트 로그 스캔 완료 (스캔: {scanned}개 파일)', 'info',
            '분석한 로그 파일에서 공격 패턴이 탐지되지 않았습니다.',
            {'스캔 파일': scanned, '검색 경로': log_dirs},
            '로그 경로를 지정하거나 로깅 정책을 활성화하세요.',
        ))
        fid += 1

    print(f'  -> 로그 분석: {len(findings)}개 항목 확인')
    return findings
