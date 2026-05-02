"""네트워크 트래픽 분석 모듈 — 의심 연결, 과다 연결, 알려진 악성 포트 탐지"""
import socket
from collections import Counter, defaultdict
from datetime import datetime

import psutil

from config.settings import (
    DANGEROUS_OPEN_PORTS, SUSPICIOUS_CONNECTION_COUNT, FOREIGN_LISTEN_THRESHOLD
)

MODULE = 'network'

KNOWN_MALICIOUS_PORTS = {4444, 31337, 1234, 6666, 6667, 6668, 6669, 12345, 54321, 65535}

PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                    '172.30.', '172.31.', '192.168.', '127.', '::1')


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'NET-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def analyze():
    findings = []
    fid = 1

    try:
        connections = psutil.net_connections(kind='inet')
    except Exception as e:
        findings.append(_finding(
            fid, '네트워크 연결 정보 수집 실패', 'info',
            f'관리자 권한이 필요할 수 있습니다: {e}', {}, '관리자 권한으로 재실행하세요.',
        ))
        return findings

    # ── 프로세스별 연결 집계 ──────────────────────────────────────
    proc_conns: dict[int, list] = defaultdict(list)
    for c in connections:
        if c.pid:
            proc_conns[c.pid].append(c)

    # ── 외부 연결 목록 ────────────────────────────────────────────
    external_conns = []
    malicious_port_conns = []

    for c in connections:
        raddr = c.raddr
        if not raddr:
            continue
        rip, rport = raddr.ip, raddr.port
        if not _is_private(rip):
            external_conns.append(c)
        if rport in KNOWN_MALICIOUS_PORTS:
            malicious_port_conns.append(c)

    # ── 알려진 악성 포트 연결 ─────────────────────────────────────
    if malicious_port_conns:
        items = []
        for c in malicious_port_conns:
            try:
                proc_name = psutil.Process(c.pid).name() if c.pid else 'unknown'
            except Exception:
                proc_name = 'unknown'
            items.append({
                '프로세스': f'{proc_name}(PID {c.pid})',
                '원격IP': c.raddr.ip,
                '원격포트': c.raddr.port,
                '상태': c.status,
            })
        findings.append(_finding(
            fid, '알려진 악성 포트 연결 탐지', 'critical',
            f'Metasploit/백도어 등이 사용하는 포트에 {len(malicious_port_conns)}개 연결이 있습니다.',
            {'연결 목록': items},
            '해당 프로세스를 즉시 격리 및 조사하고, 포트를 방화벽으로 차단하세요.',
        ))
        fid += 1

    # ── 과다 연결 프로세스 탐지 ───────────────────────────────────
    for pid, conns in proc_conns.items():
        if len(conns) >= SUSPICIOUS_CONNECTION_COUNT:
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
            except Exception:
                pname = 'unknown'
            findings.append(_finding(
                fid, f'비정상적으로 많은 연결 (PID {pid})', 'high',
                f'{pname}(PID {pid})이 {len(conns)}개의 네트워크 연결을 보유하고 있습니다.',
                {'프로세스': pname, 'PID': pid, '연결 수': len(conns)},
                'DDoS 도구 또는 스캐너 실행 여부를 확인하고 불필요하면 종료하세요.',
            ))
            fid += 1

    # ── 외부 노출된 위험 포트 리슨 탐지 (중복 제거: 포트번호 기준) ──
    listen_conns = [c for c in connections if c.status == psutil.CONN_LISTEN]
    reported_ports: set = set()
    for c in listen_conns:
        lport = c.laddr.port
        laddr = c.laddr.ip
        if lport in reported_ports:
            continue
        if lport in DANGEROUS_OPEN_PORTS:
            service, sev, note = DANGEROUS_OPEN_PORTS[lport]
            external_exposed = (laddr in ('0.0.0.0', '::'))
            if external_exposed:
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else 'unknown'
                except Exception:
                    pname = 'unknown'
                findings.append(_finding(
                    fid, f'위험 포트 외부 노출: {lport}/{service}', sev,
                    f'포트 {lport}({service})가 모든 인터페이스에 노출되어 있습니다. {note}',
                    {'포트': lport, '서비스': service, '바인딩': laddr, '프로세스': pname},
                    note,
                ))
                fid += 1
                reported_ports.add(lport)

    # ── 외부 IP와의 활성 연결 요약 ───────────────────────────────
    if external_conns:
        ip_counter = Counter(c.raddr.ip for c in external_conns)
        top_ips = ip_counter.most_common(10)
        est = [c for c in external_conns if c.status == 'ESTABLISHED']
        findings.append(_finding(
            fid, '외부 IP 활성 연결 목록', 'info',
            f'현재 {len(external_conns)}개의 외부 연결 중 {len(est)}개가 ESTABLISHED 상태입니다.',
            {
                '연결 수': len(external_conns),
                'ESTABLISHED': len(est),
                '상위 외부 IP': [f'{ip} ({cnt}회)' for ip, cnt in top_ips],
            },
            '알 수 없는 외부 IP에 대한 연결을 방화벽 로그로 추적하고 화이트리스트를 관리하세요.',
        ))
        fid += 1

    # ── 네트워크 인터페이스 통계 ─────────────────────────────────
    net_io = psutil.net_io_counters()
    findings.append(_finding(
        fid, '네트워크 I/O 통계', 'info',
        '시스템 시작 이후의 누적 네트워크 트래픽 통계입니다.',
        {
            '송신': f'{net_io.bytes_sent / 1024**2:.1f} MB',
            '수신': f'{net_io.bytes_recv / 1024**2:.1f} MB',
            '수신 오류': net_io.errin,
            '송신 오류': net_io.errout,
            '드롭 패킷(수신)': net_io.dropin,
        },
        '오류/드롭이 지속적으로 증가한다면 네트워크 장비 또는 NIC 드라이버를 점검하세요.',
    ))
    fid += 1

    # ── CLOSE_WAIT / TIME_WAIT 과다 ───────────────────────────────
    status_cnt = Counter(c.status for c in connections)
    close_wait = status_cnt.get('CLOSE_WAIT', 0)
    time_wait = status_cnt.get('TIME_WAIT', 0)
    if close_wait > 50:
        findings.append(_finding(
            fid, 'CLOSE_WAIT 상태 연결 과다', 'medium',
            f'CLOSE_WAIT 상태 연결이 {close_wait}개입니다. 소켓 누수 또는 응용프로그램 버그가 의심됩니다.',
            {'CLOSE_WAIT': close_wait, 'TIME_WAIT': time_wait},
            '응용프로그램에서 소켓을 명시적으로 닫는지 확인하고, KeepAlive 설정을 검토하세요.',
        ))
        fid += 1

    print(f'  -> 네트워크 분석: {len(findings)}개 항목 확인')
    return findings
