"""프로세스 분석 모듈 — 악성 키워드 프로세스, 고자원 프로세스, 이상 행위 탐지"""
import os
from datetime import datetime

import psutil

from config.settings import (
    MALICIOUS_PROCESS_KEYWORDS, TRUSTED_PROCESSES,
    PROC_CPU_THRESHOLD, PROC_MEM_THRESHOLD,
)

MODULE = 'process'

SUSPICIOUS_CMD_PATTERNS = [
    'base64', '-enc', '-encodedcommand', '-windowstyle hidden',
    '-noprofile -exec', 'iex(', 'invoke-expression',
    'downloadstring', 'webclient', 'downloadfile',
    'certutil -decode', 'bitsadmin /transfer',
    'wscript /e:jscript', 'regsvr32 /s /n /u',
    'mshta http', 'rundll32 javascript',
    'net user /add', 'net localgroup administrators',
]


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'PRC-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def _get_proc_info(proc):
    try:
        return {
            'name': proc.name(),
            'pid': proc.pid,
            'ppid': proc.ppid(),
            'username': proc.username(),
            'exe': proc.exe() if hasattr(proc, 'exe') else '',
            'cmdline': ' '.join(proc.cmdline()),
            'cpu': proc.cpu_percent(interval=0),
            'mem_mb': proc.memory_info().rss / 1024 ** 2,
            'status': proc.status(),
            'created': datetime.fromtimestamp(proc.create_time()).strftime('%H:%M:%S'),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def analyze():
    findings = []
    fid = 1

    all_procs = []
    for proc in psutil.process_iter(['name', 'pid', 'ppid', 'username', 'status', 'cpu_percent']):
        info = _get_proc_info(proc)
        if info:
            all_procs.append(info)

    # ── 악성 키워드 프로세스 탐지 ─────────────────────────────────
    malicious_found = []
    for p in all_procs:
        name_lower = p['name'].lower()
        cmd_lower = p['cmdline'].lower()
        for kw in MALICIOUS_PROCESS_KEYWORDS:
            if kw in name_lower or kw in cmd_lower:
                malicious_found.append({**p, 'matched_keyword': kw})
                break

    if malicious_found:
        findings.append(_finding(
            fid, '알려진 악성/해킹 도구 프로세스 탐지', 'critical',
            f'악성 도구로 알려진 키워드를 포함하는 프로세스 {len(malicious_found)}개를 탐지했습니다.',
            malicious_found,
            '해당 프로세스를 즉시 종료하고, 보안 솔루션으로 전체 시스템 스캔을 실행하세요.',
        ))
        fid += 1

    # ── 의심스러운 PowerShell 명령 탐지 ──────────────────────────
    suspicious_cmds = []
    for p in all_procs:
        if 'powershell' in p['name'].lower() or 'pwsh' in p['name'].lower():
            cmd_lower = p['cmdline'].lower()
            matched = [pat for pat in SUSPICIOUS_CMD_PATTERNS if pat in cmd_lower]
            if matched:
                suspicious_cmds.append({**p, 'patterns': matched})

    if suspicious_cmds:
        findings.append(_finding(
            fid, '의심스러운 PowerShell 실행 탐지', 'critical',
            f'인코딩 명령, 다운로더, 권한 상승 패턴을 포함한 PowerShell이 {len(suspicious_cmds)}개 실행 중입니다.',
            suspicious_cmds,
            '명령줄 전체를 분석하고 스크립트 소스를 확인하세요. AMSI 및 스크립트 블록 로깅을 활성화하세요.',
        ))
        fid += 1

    # ── 부모 프로세스 불일치 (PPID 스푸핑) 탐지 ─────────────────
    pid_map = {p['pid']: p['name'].lower() for p in all_procs}
    ppid_spoofing = []
    suspicious_parents = {
        'explorer.exe': {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
        'winword.exe':  {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
        'excel.exe':    {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
        'outlook.exe':  {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    }
    for p in all_procs:
        parent_name = pid_map.get(p['ppid'], '').lower()
        child_name  = p['name'].lower()
        for parent_pat, suspicious_children in suspicious_parents.items():
            if parent_pat in parent_name and child_name in suspicious_children:
                ppid_spoofing.append({
                    '부모': f'{parent_name}(PID {p["ppid"]})',
                    '자식': f'{child_name}(PID {p["pid"]})',
                    '명령줄': p['cmdline'],
                })

    if ppid_spoofing:
        findings.append(_finding(
            fid, '의심스러운 부모-자식 프로세스 관계', 'high',
            '문서 편집기/탐색기가 셸 프로세스를 직접 생성하는 것은 매크로 악성코드의 전형적 패턴입니다.',
            ppid_spoofing,
            '해당 문서를 격리하고 매크로 실행 정책을 강화하세요 (그룹 정책 → 매크로 비활성화).',
        ))
        fid += 1

    # ── 높은 CPU 프로세스 ─────────────────────────────────────────
    # cpu_percent를 다시 1초 간격으로 수집
    high_cpu = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            cpu = proc.cpu_percent(interval=0.1)
            if cpu >= PROC_CPU_THRESHOLD:
                info = _get_proc_info(proc)
                if info:
                    info['cpu'] = cpu
                    high_cpu.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if high_cpu:
        findings.append(_finding(
            fid, f'CPU 과점유 프로세스 탐지 ({len(high_cpu)}개)', 'high',
            f'CPU {PROC_CPU_THRESHOLD}% 이상을 사용하는 프로세스가 있습니다. 크립토마이너 또는 DDoS 도구일 수 있습니다.',
            [{'프로세스': p['name'], 'PID': p['pid'], 'CPU%': f'{p["cpu"]:.1f}', '명령줄': p['cmdline'][:120]} for p in high_cpu],
            '비정상 CPU 사용 프로세스를 식별하고 크립토마이닝 악성코드 여부를 확인하세요.',
        ))
        fid += 1

    # ── 높은 메모리 프로세스 ──────────────────────────────────────
    high_mem = [p for p in all_procs if p['mem_mb'] >= PROC_MEM_THRESHOLD]
    if high_mem:
        findings.append(_finding(
            fid, f'과다 메모리 사용 프로세스 ({len(high_mem)}개)', 'medium',
            f'{PROC_MEM_THRESHOLD}MB 이상 메모리를 사용하는 프로세스가 있습니다.',
            [{'프로세스': p['name'], 'PID': p['pid'], 'MB': f'{p["mem_mb"]:.0f}'} for p in high_mem[:10]],
            '메모리 누수 또는 비정상 프로세스 여부를 확인하세요.',
        ))
        fid += 1

    # ── 서명되지 않은 실행 파일 위치 탐지 ───────────────────────
    suspicious_paths = []
    unsafe_dirs = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
                   '\\downloads\\', '\\public\\', '\\recycle']
    for p in all_procs:
        exe = p.get('exe', '').lower().replace('/', '\\')
        if exe and any(d in exe for d in unsafe_dirs):
            suspicious_paths.append({
                '프로세스': p['name'],
                'PID': p['pid'],
                '경로': p.get('exe', ''),
            })

    if suspicious_paths:
        findings.append(_finding(
            fid, '임시/다운로드 폴더에서 실행 중인 프로세스', 'high',
            f'Temp/Downloads 폴더에서 {len(suspicious_paths)}개 프로세스가 실행 중입니다. 악성코드가 자주 사용하는 위치입니다.',
            suspicious_paths,
            '해당 프로세스의 실행 경로를 확인하고, 악성코드 여부를 바이러스 백신으로 스캔하세요.',
        ))
        fid += 1

    # ── 시스템 프로세스 요약 ──────────────────────────────────────
    total = len(all_procs)
    unknown = [p for p in all_procs if p['name'].lower() not in TRUSTED_PROCESSES]
    findings.append(_finding(
        fid, '프로세스 현황 요약', 'info',
        f'총 {total}개 프로세스 중 화이트리스트 외 {len(unknown)}개가 실행 중입니다.',
        {
            '전체 프로세스': total,
            '화이트리스트 외': len(unknown),
            '상위 비신뢰 프로세스': [p['name'] for p in unknown[:20]],
        },
        '정기적으로 실행 중인 프로세스 목록을 검토하고 불필요한 프로세스를 제거하세요.',
    ))

    print(f'  -> 프로세스 분석: {len(findings)}개 항목 확인')
    return findings
