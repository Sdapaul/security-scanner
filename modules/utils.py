"""공통 유틸리티 — Windows 시스템 명령 실행 래퍼"""
import subprocess
import locale

# Windows 한국어 시스템의 기본 인코딩 (CP949/EUC-KR)
_SYS_ENC = locale.getpreferredencoding(False) or 'cp949'


def run_cmd(args: list, timeout: int = 15, powershell: bool = False) -> str:
    """시스템 명령을 실행하고 stdout 문자열을 반환합니다. 실패 시 빈 문자열."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
        )
        # PowerShell은 UTF-8, cmd.exe 도구는 시스템 인코딩
        enc = 'utf-8' if powershell else _SYS_ENC
        return result.stdout.decode(enc, errors='replace')
    except Exception:
        return ''
