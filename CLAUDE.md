# 보안 스캐너 개발 지침

## 토큰 절약 규칙

- **Edit 우선** — 기존 파일은 반드시 Edit로 변경 부분만 교체. Write는 신규 파일 또는 전면 재작성 시에만.
- **Read 최소화** — 필요한 줄 범위만 `offset`/`limit` 지정. 이미 읽은 파일 재독 금지.
- **병렬 tool call** — 독립 작업(Read+Read, Edit+Edit)은 한 메시지에 동시 실행.
- **탐색은 Grep/Glob** — 파일 구조 파악에 Bash ls/find 사용 금지.
- **설명 최소** — 변경 후 1-2줄 요약. 코드 주석 추가 금지(불필요한 경우).

## 프로젝트 구조 (핵심만)

```
security_scanner/
├── web_app.py          # Flask 백엔드 (포트 5001), ScanManager, SSE
├── templates/
│   └── dashboard.html  # SPA 대시보드 (~1200줄, CSS+JS 인라인)
├── modules/
│   ├── pii_detector.py     # os.scandir 기반, set_stop_check 지원
│   ├── malware_detector.py # Defender + 레지스트리 PUP
│   ├── server_status.py
│   ├── network_analyzer.py
│   ├── process_analyzer.py
│   ├── log_analyzer.py
│   ├── attack_detector.py
│   ├── port_scanner.py
│   └── reporter.py
└── config/settings.py  # PII_PATTERNS, PII_SCAN_EXTENSIONS, PII_MAX_FILE_SIZE
```

## 새 모듈 추가 체크리스트

1. `modules/<name>.py` 작성 — `scan()` 또는 기능 함수, finding 딕셔너리 반환
2. `web_app.py` MODULES 딕셔너리에 항목 추가
3. `web_app.py` _MODULE_FUNC 딕셔너리에 `(모듈경로, 함수명, arg_key)` 추가
4. 중단 지원 필요 시: `set_stop_check` / `_is_stopped` 패턴 구현

## Finding 딕셔너리 구조

```python
{
    'id':             'XXX-001',
    'category':       'server',       # 모듈 키와 일치
    'title':          '제목',
    'severity':       'critical|high|medium|low|info',
    'description':    '설명',
    'details':        {},             # 테이블로 렌더링됨
    'recommendation': '조치 방법\nPowerShell 명령어',  # 개행으로 코드블록 구분
    'timestamp':      datetime.now().isoformat(),
}
```

## SSE 파일 진행 프로토콜

```python
print(f'\x00FILE_SCAN\x00{path}\x00{scanned}\x00{total}')
```
→ `_LogCapture`가 `file_progress` 이벤트로 변환 → 대시보드 progress bar 업데이트

## 중단 신호 패턴

```python
_stop_check = None
def set_stop_check(fn): global _stop_check; _stop_check = fn
def _is_stopped(): return _stop_check is not None and bool(_stop_check())
```

## 주의 사항

- `.bat` 파일에 한국어 echo 금지 (CMD CP949 파싱 오류)
- `os.walk` 대신 `os.scandir` 기반 탐색 (대용량 디렉토리 블로킹 방지)
- PII 스캔 SKIP_DIRS에 Cache/Temp/Logs/node_modules 등 45개+ 등록됨
- dashboard.html 수정 시 JS/CSS/HTML 각각 Edit로 분리 작업
