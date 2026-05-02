"""공통 유틸리티 — Windows 시스템 명령 실행 래퍼"""
import subprocess
import locale

# Windows 한국어 시스템의 기본 인코딩 (CP949/EUC-KR)
_SYS_ENC = locale.getpreferredencoding(False) or 'cp949'

# 콘솔 창 숨김 + 새 프로세스 그룹 (타임아웃 시 자식까지 종료)
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP


def run_cmd(args: list, timeout: int = 15, powershell: bool = False) -> str:
    """시스템 명령을 실행하고 stdout 문자열을 반환합니다. 실패 시 빈 문자열."""
    proc = None
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_WIN_FLAGS,
        )
        stdout, _ = proc.communicate(timeout=timeout)
        enc = 'utf-8' if powershell else _SYS_ENC
        return stdout.decode(enc, errors='replace')
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
            proc.communicate()
        return ''
    except Exception:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return ''
