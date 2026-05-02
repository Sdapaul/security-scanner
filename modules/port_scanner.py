"""포트 스캐너 모듈 — 대상 호스트의 열린 포트 탐지 및 위험도 평가"""
import socket
import concurrent.futures
from datetime import datetime

from config.settings import SCAN_PORT_LIST, DANGEROUS_OPEN_PORTS, PORT_SCAN_TIMEOUT

MODULE = 'port'

COMMON_SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 119: 'NNTP',
    123: 'NTP', 135: 'RPC-MSRPC', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP-Submission',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1434: 'MSSQL-Browser', 1521: 'Oracle', 2181: 'ZooKeeper',
    2375: 'Docker', 2376: 'Docker-TLS', 3306: 'MySQL', 3389: 'RDP',
    4444: 'Metasploit', 5432: 'PostgreSQL', 5900: 'VNC',
    5984: 'CouchDB', 6379: 'Redis', 6443: 'K8s-API',
    7001: 'WebLogic', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9000: 'PHP-FPM', 9090: 'Prometheus',
    9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
    27018: 'MongoDB-Shard', 28017: 'MongoDB-HTTP', 31337: 'Back-Orifice',
}

# 외부 노출 시 위험한 서비스
NEVER_EXPOSE = {6379, 27017, 11211, 9200, 2375, 8888, 5984}


def _scan_port(host: str, port: int) -> tuple[int, bool, str]:
    """단일 포트 스캔. (port, is_open, banner) 반환."""
    banner = ''
    try:
        with socket.create_connection((host, port), timeout=PORT_SCAN_TIMEOUT) as s:
            s.settimeout(0.5)
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(128).decode('utf-8', errors='replace').split('\n')[0].strip()
            except Exception:
                pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ''


def _grab_banner(host: str, port: int) -> str:
    """배너 그래빙으로 서비스 버전 정보 수집."""
    try:
        with socket.create_connection((host, port), timeout=1.0) as s:
            s.settimeout(1.0)
            banner = s.recv(256).decode('utf-8', errors='replace').strip()
            return banner[:100] if banner else ''
    except Exception:
        return ''


def _finding(fid, title, severity, description, details, recommendation):
    return {
        'id': f'PORT-{fid:03d}',
        'category': MODULE,
        'title': title,
        'severity': severity,
        'description': description,
        'details': details,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat(),
    }


def scan(target: str = '127.0.0.1'):
    findings = []
    fid = 1

    print(f'    대상: {target} / 포트 수: {len(SCAN_PORT_LIST)}개')

    # ── 포트 스캔 (병렬) ─────────────────────────────────────────
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
        futures = {executor.submit(_scan_port, target, p): p for p in SCAN_PORT_LIST}
        for future in concurrent.futures.as_completed(futures):
            try:
                port, is_open, banner = future.result()
                if is_open:
                    open_ports[port] = banner
            except Exception:
                pass

    if not open_ports:
        findings.append(_finding(
            fid, f'{target} — 열린 포트 없음', 'info',
            f'{target}에서 {len(SCAN_PORT_LIST)}개 포트 중 열린 포트가 탐지되지 않았습니다.',
            {},
            '방화벽이 잘 설정되어 있습니다. 정기적으로 스캔을 반복하세요.',
        ))
        return findings

    # ── 결과 분류 ─────────────────────────────────────────────────
    critical_ports  = {}
    dangerous_ports = {}
    normal_ports    = {}

    for port, banner in open_ports.items():
        service = COMMON_SERVICE_NAMES.get(port, f'Unknown-{port}')
        if port in NEVER_EXPOSE:
            critical_ports[port] = (service, banner)
        elif port in DANGEROUS_OPEN_PORTS:
            service_name, sev, _ = DANGEROUS_OPEN_PORTS[port]
            dangerous_ports[port] = (service_name, sev, banner)
        else:
            normal_ports[port] = (service, banner)

    # ── 즉시 위험 포트 ───────────────────────────────────────────
    if critical_ports:
        details = {
            f'{port}/{svc}': f'배너: {banner}' if banner else '배너 없음'
            for port, (svc, banner) in critical_ports.items()
        }
        findings.append(_finding(
            fid, f'인증 없이 접근 가능한 위험 포트 {len(critical_ports)}개 노출', 'critical',
            'Redis, MongoDB, Elasticsearch 등 기본 설정에서 인증이 없는 서비스가 노출되어 있습니다. 데이터 탈취 및 원격 코드 실행이 가능합니다.',
            details,
            '해당 서비스를 즉시 방화벽으로 차단하고 인증을 활성화하세요. localhost(127.0.0.1)에만 바인딩하도록 설정을 변경하세요.',
        ))
        fid += 1

    # ── 위험도 높은 포트 ─────────────────────────────────────────
    if dangerous_ports:
        for port, (service, sev, banner) in dangerous_ports.items():
            _, _, note = DANGEROUS_OPEN_PORTS[port]
            findings.append(_finding(
                fid, f'위험 포트 열림: {port}/{service}', sev,
                f'{note}',
                {
                    '포트': port,
                    '서비스': service,
                    '배너': banner or '없음',
                },
                note,
            ))
            fid += 1

    # ── 전체 열린 포트 요약 ───────────────────────────────────────
    all_open_summary = {}
    for port in sorted(open_ports.keys()):
        svc = COMMON_SERVICE_NAMES.get(port, 'Unknown')
        all_open_summary[f'{port}/{svc}'] = open_ports[port] or '배너 없음'

    findings.append(_finding(
        fid, f'열린 포트 전체 목록 ({len(open_ports)}개)', 'info',
        f'{target}에서 총 {len(open_ports)}개 포트가 열려 있습니다.',
        all_open_summary,
        '불필요한 서비스는 비활성화하고 방화벽 화이트리스트 정책을 적용하세요.',
    ))

    print(f'  -> 포트 스캔: 열린 포트 {len(open_ports)}개 / 위험 {len(critical_ports) + len(dangerous_ports)}개')
    return findings
