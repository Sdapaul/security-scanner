"""외부 공격 탐지 모듈 — 브루트포스, 포트스캔, 이상 연결 패턴 실시간 탐지"""
import re
from collections import Counter, defaultdict
from datetime import datetime

import psutil

from config.settings import BRUTE_FORCE_THRESHOLD
from modules.utils import run_cmd

MODULE = 'attack'

PORT_SCAN_UNIQUE_PORT_THRESHOLD = 10


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'ATK-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def _parse_netstat(output: str) -> list[dict]:
    conns = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        if proto not in ('TCP', 'UDP'):
            continue
        local  = parts[1]
        remote = parts[2] if proto == 'TCP' else '*:*'
        state  = parts[3] if proto == 'TCP' else 'UDP'
        pid    = parts[-1]
        conns.append({'proto': proto, 'local': local,
                      'remote': remote, 'state': state, 'pid': pid})
    return conns


def _detect_port_scan(conns: list[dict]) -> list[dict]:
    remote_ports: dict[str, set] = defaultdict(set)
    for c in conns:
        remote = c['remote']
        if remote in ('*:*', '0.0.0.0:0', '[::]:0'):
            continue
        parts = remote.rsplit(':', 1)
        if len(parts) != 2:
            continue
        ip, port = parts
        ip = ip.strip('[]')
        if ip in ('127.0.0.1', '::1', '0.0.0.0'):
            continue
        try:
            remote_ports[ip].add(int(port))
        except ValueError:
            pass

    return [
        {'IP': ip, '접근_포트수': len(ports), '포트_목록': sorted(ports)[:20]}
        for ip, ports in remote_ports.items()
        if len(ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD
    ]


def _query_event(query: str, count: int = 200) -> str:
    return run_cmd(
        ['wevtutil', 'qe', 'Security',
         f'/q:{query}', f'/c:{count}', '/rd:true', '/f:text'],
        timeout=25,
    )


def _detect_failed_rdp() -> tuple[list, int]:
    query = ("*[System[EventID=4625] and "
             "EventData[Data[@Name='LogonType']='10']]")
    raw = _query_event(query, 200)
    ip_counter: Counter = Counter()
    for m in re.finditer(r'Source Network Address:\s+(\S+)', raw):
        ip = m.group(1)
        if ip not in ('-', '::1', '127.0.0.1', 'LOCAL', '-'):
            ip_counter[ip] += 1
    brute = [{'IP': ip, '실패횟수': cnt}
             for ip, cnt in ip_counter.items()
             if cnt >= BRUTE_FORCE_THRESHOLD]
    return brute, sum(ip_counter.values())


def _detect_failed_smb() -> list[dict]:
    query = ("*[System[EventID=4625] and "
             "EventData[Data[@Name='LogonType']='3']]")
    raw = _query_event(query, 100)
    ip_counter: Counter = Counter()
    for m in re.finditer(r'Source Network Address:\s+(\S+)', raw):
        ip = m.group(1)
        if ip not in ('-', '::1', '127.0.0.1'):
            ip_counter[ip] += 1
    return [{'IP': ip, '실패횟수': cnt}
            for ip, cnt in ip_counter.most_common(10)
            if cnt >= BRUTE_FORCE_THRESHOLD]


def _detect_scheduled_tasks() -> list[str]:
    raw = _query_event('*[System[EventID=4698]]', 50)
    return [m.group(1).strip() for m in re.finditer(r'Task Name:\s+(.+)', raw)]


def _detect_new_admins() -> list[str]:
    raw = _query_event('*[System[EventID=4732]]', 50)
    return [m.group(1).strip() for m in re.finditer(r'Member Name:\s+(.+)', raw)]


def detect():
    findings = []
    fid = 1

    # ── 포트 스캔 탐지 ────────────────────────────────────────────
    netstat_out = run_cmd(['netstat', '-ano'], timeout=15)
    conns = _parse_netstat(netstat_out)
    port_scan_suspects = _detect_port_scan(conns)
    if port_scan_suspects:
        findings.append(_finding(
            fid, f'포트 스캔 의심 IP 탐지 ({len(port_scan_suspects)}개)', 'high',
            '단일 외부 IP가 다수의 로컬 포트에 접근을 시도한 흔적이 있습니다.',
            port_scan_suspects,
            '해당 IP를 방화벽에서 차단하고 IDS/IPS를 활성화하세요.',
        ))
        fid += 1

    # ── RDP 브루트포스 탐지 ───────────────────────────────────────
    rdp_brute, rdp_total = _detect_failed_rdp()
    if rdp_brute:
        findings.append(_finding(
            fid, f'RDP 브루트포스 공격 탐지 (총 {rdp_total}회 실패)', 'critical',
            f'{len(rdp_brute)}개 외부 IP에서 반복적인 RDP 로그인 실패가 탐지되었습니다.',
            rdp_brute,
            'RDP(3389) 포트를 방화벽으로 즉시 차단하고 VPN 경유로 전환하세요. NLA(네트워크 수준 인증)를 활성화하고 계정 잠금 정책을 적용하세요.',
        ))
        fid += 1
    elif rdp_total > 0:
        findings.append(_finding(
            fid, f'RDP 로그인 실패 감지 ({rdp_total}회)', 'medium',
            'RDP 인증 실패가 발생했습니다.',
            {'총 실패 횟수': rdp_total},
            'RDP 접근을 VPN 또는 특정 IP로 제한하세요.',
        ))
        fid += 1

    # ── SMB 브루트포스 탐지 ───────────────────────────────────────
    smb_brute = _detect_failed_smb()
    if smb_brute:
        findings.append(_finding(
            fid, 'SMB 브루트포스 탐지', 'critical',
            'SMB(445)를 통한 반복 인증 실패가 탐지되었습니다.',
            smb_brute,
            'SMB 포트(445, 139)를 외부에서 차단하고 SMBv1을 비활성화하세요.',
        ))
        fid += 1

    # ── 의심스러운 예약 작업 탐지 ─────────────────────────────────
    new_tasks = _detect_scheduled_tasks()
    if new_tasks:
        findings.append(_finding(
            fid, f'최근 예약 작업 생성 감지 ({len(new_tasks)}개)', 'high',
            '최근 새로운 예약 작업이 생성되었습니다. 악성코드의 지속성 확보 기법입니다.',
            {'생성된 작업': new_tasks},
            'Task Scheduler에서 모든 예약 작업을 검토하고 불필요한 작업을 삭제하세요.',
        ))
        fid += 1

    # ── 관리자 계정 추가 탐지 ─────────────────────────────────────
    new_admins = _detect_new_admins()
    if new_admins:
        findings.append(_finding(
            fid, f'관리자 그룹 계정 추가 탐지 ({len(new_admins)}개)', 'critical',
            '최근 로컬 관리자 그룹에 계정이 추가되었습니다.',
            {'추가된 계정': new_admins},
            '해당 계정 추가의 정당성을 확인하고, 무단 추가라면 즉시 제거 후 침해사고 조사를 시작하세요.',
        ))
        fid += 1

    # ── psutil 기반 실시간 연결 이상 탐지 ────────────────────────
    try:
        all_conns = psutil.net_connections(kind='inet')
        syn_sent = [c for c in all_conns if c.status == 'SYN_SENT']
        if len(syn_sent) > 20:
            findings.append(_finding(
                fid, f'대량 SYN_SENT 연결 탐지 ({len(syn_sent)}개)', 'high',
                '아웃바운드 SYN 연결이 비정상적으로 많습니다. 포트 스캔 또는 봇넷 활동 가능성이 있습니다.',
                {'SYN_SENT 수': len(syn_sent)},
                '해당 프로세스를 식별하고 포트 스캔 도구 또는 봇넷 악성코드 여부를 확인하세요.',
            ))
            fid += 1
    except Exception:
        pass

    # ── 연결 현황 요약 ────────────────────────────────────────────
    status_map = Counter(c['state'] for c in conns)
    findings.append(_finding(
        fid, '현재 네트워크 연결 상태 요약', 'info',
        f'현재 시스템의 총 {len(conns)}개 연결 상태입니다.',
        dict(status_map.most_common()),
        '비정상적으로 많은 ESTABLISHED, SYN_SENT 상태를 지속 모니터링하세요.',
    ))

    print(f'  -> 공격 탐지: {len(findings)}개 항목 확인')
    return findings
