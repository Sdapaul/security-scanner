"""공통 유틸리티 — Windows 시스템 명령 실행 래퍼"""
import subprocess
import locale
import threading

_SYS_ENC = locale.getpreferredencoding(False) or 'cp949'

# CREATE_NO_WINDOW: 콘솔 창 숨김
# CREATE_NEW_PROCESS_GROUP: taskkill /T 로 프로세스 트리 종료 가능
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

_proc_lock = threading.Lock()
_current_proc: 'subprocess.Popen | None' = None


def _taskkill(pid: int) -> None:
    """프로세스 트리 전체를 강제 종료합니다 (WMI 자식 프로세스 포함)."""
    try:
        subprocess.run(
            ['taskkill', '/F', '/T', '/PID', str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def kill_current_proc() -> None:
    """현재 run_cmd가 실행 중인 서브프로세스를 외부에서 강제 종료합니다.
    스캔 중단·강제 초기화 시 호출하면 블로킹된 communicate()를 즉시 해제합니다."""
    with _proc_lock:
        p = _current_proc
    if p is not None:
        _taskkill(p.pid)


def run_cmd(args: list, timeout: int = 15, powershell: bool = False) -> str:
    """시스템 명령을 실행하고 stdout 문자열을 반환합니다. 실패 시 빈 문자열."""
    global _current_proc
    proc = None
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_WIN_FLAGS,
        )
        with _proc_lock:
            _current_proc = proc

        stdout, _ = proc.communicate(timeout=timeout)

        with _proc_lock:
            _current_proc = None

        enc = 'utf-8' if powershell else _SYS_ENC
        return stdout.decode(enc, errors='replace')

    except subprocess.TimeoutExpired:
        with _proc_lock:
            _current_proc = None
        if proc:
            # proc.kill() 후 communicate()는 WMI 자식 프로세스가
            # 파이프를 잡고 있으면 영원히 블로킹됨 → taskkill /F /T 로 트리 전체 종료
            _taskkill(proc.pid)
            try:
                proc.communicate(timeout=3)
            except Exception:
                pass
        return ''

    except Exception:
        with _proc_lock:
            _current_proc = None
        if proc:
            _taskkill(proc.pid)
        return ''
