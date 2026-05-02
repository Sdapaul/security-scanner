"""서버 상태 검사 모듈 — CPU/메모리/디스크/서비스 취약 설정 탐지"""
import json
import platform
from datetime import datetime

import psutil

from config.settings import HIGH_CPU_PERCENT, HIGH_MEM_PERCENT, HIGH_DISK_PERCENT
from modules.utils import run_cmd

MODULE = 'server'


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'SRV-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def check():
    findings = []
    fid = 1

    # ── 시스템 기본 정보 ──────────────────────────────────────────
    uname = platform.uname()
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_h = (datetime.now() - boot_time).total_seconds() / 3600

    findings.append(_finding(
        fid, '시스템 정보 수집', 'info',
        '대상 시스템의 기본 정보를 수집했습니다.',
        {
            'OS': f'{uname.system} {uname.release} {uname.version}',
            '호스트명': uname.node,
            '아키텍처': uname.machine,
            '부팅 시각': boot_time.strftime('%Y-%m-%d %H:%M:%S'),
            '가동 시간': f'{uptime_h:.1f}시간',
        },
        '정기적으로 OS 보안 패치를 적용하고 불필요한 재부팅을 최소화하세요.',
    ))
    fid += 1

    # ── CPU ───────────────────────────────────────────────────────
    cpu_pct = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count(logical=False)
    if cpu_pct >= HIGH_CPU_PERCENT:
        findings.append(_finding(
            fid, 'CPU 과부하 탐지', 'high',
            f'CPU 사용률이 {cpu_pct:.1f}%로 임계값({HIGH_CPU_PERCENT}%)을 초과합니다.',
            {'사용률': f'{cpu_pct:.1f}%', '물리 코어': cpu_count},
            'top/tasklist로 고CPU 프로세스를 식별하고 DDoS 또는 크립토마이너 여부를 확인하세요.',
        ))
        fid += 1

    # ── 메모리 ────────────────────────────────────────────────────
    mem = psutil.virtual_memory()
    if mem.percent >= HIGH_MEM_PERCENT:
        findings.append(_finding(
            fid, '메모리 부족', 'medium',
            f'메모리 사용률이 {mem.percent:.1f}%입니다.',
            {
                '전체': f'{mem.total / 1024**3:.1f} GB',
                '사용 중': f'{mem.used / 1024**3:.1f} GB',
                '사용률': f'{mem.percent:.1f}%',
            },
            '메모리 누수 또는 과도한 프로세스를 점검하고 필요 시 메모리를 증설하세요.',
        ))
        fid += 1

    # ── 디스크 ────────────────────────────────────────────────────
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        if usage.percent >= HIGH_DISK_PERCENT:
            findings.append(_finding(
                fid, f'디스크 공간 부족 ({part.mountpoint})', 'high',
                f'{part.mountpoint} 파티션의 사용률이 {usage.percent:.1f}%입니다.',
                {
                    '파티션': part.mountpoint,
                    '전체': f'{usage.total / 1024**3:.1f} GB',
                    '사용': f'{usage.used / 1024**3:.1f} GB',
                    '사용률': f'{usage.percent:.1f}%',
                },
                '불필요한 파일/로그를 정리하고 로그 로테이션 정책을 설정하세요.',
            ))
            fid += 1

    # ── 방화벽 상태 (Windows) ─────────────────────────────────────
    fw_out = run_cmd(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], timeout=10)
    if fw_out:
        fw_off = 'off' in fw_out.lower()
        if fw_off:
            findings.append(_finding(
                fid, '방화벽 비활성화 탐지', 'critical',
                'Windows 방화벽이 하나 이상의 프로필에서 비활성화되어 있습니다.',
                {'출력': fw_out.strip()[:500]},
                '모든 네트워크 프로필(도메인/개인/공용)에서 방화벽을 즉시 활성화하세요.',
            ))
            fid += 1

    # ── Windows Defender / AV 상태 ───────────────────────────────
    ps_out = run_cmd(
        ['powershell', '-NoProfile', '-OutputEncoding', 'UTF8', '-Command',
         'Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | ConvertTo-Json'],
        timeout=20, powershell=True,
    )
    if ps_out.strip():
        try:
            av = json.loads(ps_out.strip())
            issues = []
            if not av.get('AMServiceEnabled'):
                issues.append('맬웨어 방지 서비스 비활성화')
            if not av.get('RealTimeProtectionEnabled'):
                issues.append('실시간 보호 비활성화')
            if not av.get('AntivirusEnabled'):
                issues.append('바이러스 백신 비활성화')
            if issues:
                findings.append(_finding(
                    fid, 'Windows Defender 보호 기능 비활성화', 'critical',
                    'Windows Defender의 핵심 보호 기능이 꺼져 있습니다.',
                    {'비활성화 항목': issues},
                    'Windows 보안 설정에서 실시간 보호를 활성화하고 최신 정의 파일을 업데이트하세요.',
                ))
                fid += 1
        except Exception:
            pass

    # ── UAC 상태 ─────────────────────────────────────────────────
    uac_out = run_cmd(
        ['reg', 'query',
         r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
         '/v', 'EnableLUA'],
        timeout=5,
    )
    if uac_out and '0x0' in uac_out:
        findings.append(_finding(
            fid, 'UAC(사용자 계정 컨트롤) 비활성화', 'high',
            'UAC가 비활성화되어 있어 악성 프로그램이 권한 상승 없이 실행될 수 있습니다.',
            {'레지스트리': 'EnableLUA = 0'},
            '레지스트리에서 EnableLUA 값을 1로 설정하거나 시스템 설정에서 UAC를 활성화하세요.',
        ))
        fid += 1

    # ── 자동 업데이트 상태 ────────────────────────────────────────
    au_out = run_cmd(
        ['reg', 'query',
         r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
         '/v', 'AUOptions'],
        timeout=5,
    )
    if au_out and '0x1' in au_out:
        findings.append(_finding(
            fid, '자동 업데이트 비활성화', 'medium',
            'Windows 자동 업데이트가 비활성화되어 최신 보안 패치가 적용되지 않을 수 있습니다.',
            {'AUOptions': '1 (자동 업데이트 꺼짐)'},
            'Windows Update 설정에서 자동 업데이트를 활성화하세요.',
        ))
        fid += 1

    # ── 공유 폴더 목록 (LanmanServer 서비스 실행 중일 때만) ──────
    lanman_running = False
    try:
        import psutil as _ps
        svc = _ps.win_service_get('LanmanServer')
        lanman_running = (svc.status() == 'running')
    except Exception:
        pass

    if lanman_running:
        share_out = run_cmd(['net', 'share'], timeout=5)
        if share_out:
            lines = [l.strip() for l in share_out.splitlines() if l.strip()]
            suspicious = [
                l.split()[0] for l in lines
                if l.split() and not any(w in l.upper() for w in
                                         ['C$', 'ADMIN$', 'IPC$', 'PRINT$', 'SHARE NAME', '---'])
            ]
            if suspicious:
                findings.append(_finding(
                    fid, '사용자 정의 공유 폴더 탐지', 'medium',
                    '관리용 기본 공유 이외의 공유 폴더가 존재합니다.',
                    {'공유 목록': suspicious},
                    '불필요한 공유를 제거(`net share 이름 /delete`)하고 공유 권한을 최소화하세요.',
                ))
                fid += 1
    else:
        findings.append(_finding(
            fid, 'SMB 서버(LanmanServer) 서비스 중지됨', 'info',
            'LanmanServer 서비스가 중지되어 있어 네트워크 파일 공유가 비활성화된 상태입니다.',
            {'서비스': 'LanmanServer', '상태': '중지됨 (Disabled)'},
            '의도적으로 비활성화한 경우 정상입니다. 파일 공유가 필요하면:\n'
            'Start-Service LanmanServer',
        ))
        fid += 1

    # ── 게스트 계정 ───────────────────────────────────────────────
    guest_out = run_cmd(['net', 'user', 'guest'], timeout=5)
    if guest_out and 'Account active' in guest_out and 'Yes' in guest_out:
        findings.append(_finding(
            fid, 'Guest 계정 활성화', 'high',
            'Windows Guest 계정이 활성화되어 있어 인증 없이 접근이 가능합니다.',
            {},
            '`net user guest /active:no` 명령으로 Guest 계정을 비활성화하세요.',
        ))
        fid += 1

    print(f'  -> 서버 상태: {len(findings)}개 항목 확인')
    return findings
