# 보안 스캐너 설정 파일

# 포트 분류
DANGEROUS_OPEN_PORTS = {
    21:    ('FTP', 'high',     '암호화 없이 파일 전송 — SFTP/FTPS로 교체 권장'),
    23:    ('Telnet', 'critical', '평문 원격접속 — 즉시 비활성화, SSH로 대체'),
    135:   ('RPC', 'medium',   'Windows RPC — 방화벽으로 외부 노출 차단'),
    137:   ('NetBIOS-NS', 'medium', 'NetBIOS 이름 서비스 — 외부 노출 차단'),
    138:   ('NetBIOS-DGM', 'medium', 'NetBIOS 데이터그램 — 외부 노출 차단'),
    139:   ('NetBIOS-SSN', 'high', 'NetBIOS 세션 — SMB 취약점 노출 위험'),
    445:   ('SMB', 'critical', 'SMB — WannaCry/EternalBlue 공격 대상, 외부 차단 필수'),
    1433:  ('MSSQL', 'high',   'MS SQL Server — 인터넷 노출 금지, VPN/방화벽 보호'),
    1434:  ('MSSQL-Browser', 'medium', 'SQL Server Browser — 외부 노출 차단'),
    3306:  ('MySQL', 'high',   'MySQL — 인터넷 노출 금지, localhost 바인딩 권장'),
    3389:  ('RDP', 'high',     '원격 데스크톱 — 브루트포스 대상, NLA 필수 + IP 제한'),
    4444:  ('Metasploit', 'critical', 'Metasploit 기본 리버스쉘 포트 — 악성코드 감염 의심'),
    5432:  ('PostgreSQL', 'high', 'PostgreSQL — 인터넷 노출 금지'),
    5900:  ('VNC', 'high',     'VNC 원격제어 — 암호화 없음, 즉시 비활성화 또는 VPN 경유'),
    6379:  ('Redis', 'critical', 'Redis — 인증 없이 원격 코드 실행 가능, 즉시 방화벽 차단'),
    8080:  ('HTTP-Alt', 'low', 'HTTP 대체 포트 — HTTPS 전환 권장'),
    27017: ('MongoDB', 'critical', 'MongoDB — 기본 설정 시 인증 없음, 즉시 방화벽 차단'),
    31337: ('Back Orifice', 'critical', '백도어 도구 포트 — 즉각 조사 필요'),
}

SCAN_PORT_LIST = (
    list(range(1, 1025)) +
    [1433, 1434, 1521, 3306, 3389, 4444, 5432, 5900,
     6379, 8080, 8443, 8888, 9090, 27017, 27018, 31337]
)

# 프로세스 위협 키워드 (소문자)
MALICIOUS_PROCESS_KEYWORDS = [
    'mimikatz', 'meterpreter', 'beacon', 'empire', 'cobalt',
    'pwdump', 'wce.exe', 'fgdump', 'gsecdump', 'procdump',
    'netcat', 'ncat', 'nc.exe', 'psexec', 'at.exe',
    'reg.exe', 'wmic', 'powershell_ise', 'mshta',
    'regsvr32', 'rundll32', 'certutil', 'bitsadmin',
]

# 신뢰할 수 있는 프로세스 (기본 화이트리스트)
TRUSTED_PROCESSES = {
    'system', 'system idle process', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
    'svchost.exe', 'explorer.exe', 'taskmgr.exe', 'conhost.exe',
    'dwm.exe', 'sihost.exe', 'runtimebroker.exe', 'searchindexer.exe',
    'spoolsv.exe', 'audiodg.exe', 'fontdrvhost.exe', 'memory compression',
    'registry', 'msdtc.exe', 'wuauclt.exe', 'wudfhost.exe',
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    'python.exe', 'pythonw.exe', 'python3.exe', 'cmd.exe',
    'powershell.exe', 'notepad.exe', 'mspaint.exe', 'calc.exe',
    'code.exe', 'node.exe', 'git.exe', 'ssh.exe',
    'antimalware service executable', 'windows defender',
    'microsoftedge.exe', 'wmiprvse.exe', 'wbemcons.exe',
}

# PII 탐지 패턴
PII_PATTERNS = {
    'korean_rrn':       (r'\b\d{6}-[1-4]\d{6}\b',             'critical', '주민등록번호'),
    'korean_phone':     (r'\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b', 'high', '휴대폰 번호'),
    'credit_card':      (r'\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b', 'critical', '신용카드 번호'),
    'email':            (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'medium', '이메일 주소'),
    'password_literal': (r'(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*["\'][^"\']{4,}["\']', 'high', '평문 패스워드'),
    'api_key':          (r'(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', 'high', 'API 키'),
    'ip_internal':      (r'\b(?:10\.\d{1,3}|\b172\.(?:1[6-9]|2\d|3[01])|\b192\.168)\.\d{1,3}\.\d{1,3}\b', 'low', '내부 IP 주소'),
    'bank_account':     (r'\b\d{3,4}-\d{2,6}-\d{4,7}(?:-\d{2})?\b',  'high', '계좌번호 추정'),
}

# PII 스캔 대상 확장자
PII_SCAN_EXTENSIONS = {
    '.txt', '.log', '.csv', '.json', '.xml', '.yaml', '.yml',
    '.ini', '.cfg', '.conf', '.env', '.properties',
    '.py', '.js', '.ts', '.java', '.php', '.rb', '.go',
    '.html', '.sql',
}

# 로그 분석 — Windows Event ID
EVENT_IDS = {
    4625: ('로그인 실패', 'high'),
    4648: ('명시적 자격증명으로 로그온 시도', 'medium'),
    4656: ('객체 핸들 요청', 'low'),
    4663: ('객체 접근 시도', 'low'),
    4672: ('특수 권한 로그온', 'medium'),
    4688: ('새 프로세스 생성', 'low'),
    4698: ('예약 작업 생성', 'medium'),
    4720: ('사용자 계정 생성', 'medium'),
    4728: ('보안 그룹에 멤버 추가', 'medium'),
    4732: ('로컬 그룹에 멤버 추가', 'medium'),
    4756: ('유니버설 그룹에 멤버 추가', 'medium'),
    4771: ('Kerberos 사전 인증 실패', 'high'),
    4776: ('자격증명 유효성 검사 시도', 'medium'),
    5140: ('네트워크 공유 접근', 'low'),
    7034: ('서비스 예기치 않게 종료', 'medium'),
    7036: ('서비스 상태 변경', 'low'),
}

# 브루트포스 탐지 임계값
BRUTE_FORCE_THRESHOLD = 5      # 실패 횟수
BRUTE_FORCE_WINDOW_SEC = 300   # 5분 내

# 리소스 경고 임계값
HIGH_CPU_PERCENT    = 85.0
HIGH_MEM_PERCENT    = 85.0
HIGH_DISK_PERCENT   = 90.0
PROC_CPU_THRESHOLD  = 80.0
PROC_MEM_THRESHOLD  = 500      # MB

# 네트워크 의심 임계값
SUSPICIOUS_CONNECTION_COUNT = 100   # 단일 프로세스 연결 수
FOREIGN_LISTEN_THRESHOLD    = 10    # 외부 리슨 포트 수

# 스캔 타임아웃 (초)
PORT_SCAN_TIMEOUT   = 0.3
PII_MAX_FILE_SIZE   = 10 * 1024 * 1024   # 10 MB
