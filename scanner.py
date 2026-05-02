#!/usr/bin/env python3
"""
보안 취약점 탐지 및 개선 시스템 (Security Scanner v1.0)
네트워크 트래픽 분석 | 로그 분석 | 프로세스 분석
서버 상태 검사 | 외부 공격 탐지 | 포트 스캔 | 개인정보 유출 탐지

사용법:
  python scanner.py               # 전체 검사 (localhost)
  python scanner.py --target IP   # 지정 IP 포트 스캔
  python scanner.py --no-pii      # 개인정보 스캔 제외
  python scanner.py --pii-dirs C:\\Users\\user\\Documents
  python scanner.py --format json --output result
  python scanner.py --modules network process port
"""

import argparse
import io
import os
import sys
import time
from datetime import datetime

# Windows 콘솔 UTF-8 출력 설정
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 모듈 경로 설정
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _check_dependencies():
    try:
        import psutil
    except ImportError:
        print('[오류] psutil이 설치되어 있지 않습니다.')
        print('       pip install psutil  을 실행한 후 다시 시도하세요.')
        sys.exit(1)


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _banner():
    print()
    print('=' * 58)
    print('  보안 취약점 탐지 및 개선 시스템  v1.0')
    print('  Security Vulnerability Scanner')
    print('=' * 58)
    print(f'  시작 시각: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    if _is_admin():
        print('  권한: 관리자 (모든 기능 사용 가능)')
    else:
        print('  권한: 일반 사용자 (일부 기능 제한될 수 있음)')
        print('  팁: 관리자 권한으로 실행하면 더 많은 정보를 수집합니다.')
    print()


def _step(num: int, total: int, name: str):
    bar = '#' * num + '-' * (total - num)
    print(f'[{bar}] {num}/{total} {name}')


def _summary(findings: list):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        s = f.get('severity', 'info')
        counts[s] = counts.get(s, 0) + 1

    print()
    print('=' * 42)
    print('           탐지 결과 요약')
    print('=' * 42)
    print(f'  [CRITICAL] 심각 : {counts["critical"]:>4}개')
    print(f'  [HIGH]     높음 : {counts["high"]:>4}개')
    print(f'  [MEDIUM]   중간 : {counts["medium"]:>4}개')
    print(f'  [LOW]      낮음 : {counts["low"]:>4}개')
    print(f'  [INFO]     정보 : {counts["info"]:>4}개')
    print(f'  {"-" * 37}')
    print(f'  전체            : {len(findings):>4}개')
    print('=' * 42)
    return counts


def main():
    _check_dependencies()

    parser = argparse.ArgumentParser(
        description='보안 취약점 탐지 및 개선 시스템',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--modules', nargs='+',
        choices=['server', 'network', 'process', 'log', 'attack', 'port', 'pii'],
        help='실행할 모듈 선택 (기본: 전체)',
    )
    parser.add_argument('--no-pii',   action='store_true', help='개인정보 스캔 제외')
    parser.add_argument('--pii-dirs', nargs='+', metavar='DIR',
                        help='개인정보 스캔 대상 디렉토리 (기본: 홈 디렉토리)')
    parser.add_argument('--target',   default='127.0.0.1',
                        help='포트 스캔 대상 IP (기본: 127.0.0.1)')
    parser.add_argument('--output',   default='security_report',
                        help='보고서 파일명 (확장자 제외, 기본: security_report)')
    parser.add_argument('--format',   choices=['html', 'json', 'text'], default='html',
                        help='보고서 형식 (기본: html)')

    args = parser.parse_args()

    _banner()

    # 실행할 모듈 결정
    run_all = args.modules is None
    run = set(args.modules or [])

    modules_plan = []
    if run_all or 'server'   in run: modules_plan.append(('server',   '서버 상태 검사'))
    if run_all or 'network'  in run: modules_plan.append(('network',  '네트워크 트래픽 분석'))
    if run_all or 'process'  in run: modules_plan.append(('process',  '프로세스 분석'))
    if run_all or 'log'      in run: modules_plan.append(('log',      '로그 분석'))
    if run_all or 'attack'   in run: modules_plan.append(('attack',   '외부 공격 탐지'))
    if run_all or 'port'     in run: modules_plan.append(('port',     f'포트 스캔 ({args.target})'))
    if (run_all or 'pii' in run) and not args.no_pii:
        modules_plan.append(('pii', '개인정보 유출 탐지'))

    total = len(modules_plan)
    findings = []
    start_time = time.time()

    for idx, (mod_key, mod_name) in enumerate(modules_plan, 1):
        _step(idx, total, mod_name)
        try:
            if mod_key == 'server':
                from modules.server_status import check
                findings.extend(check())

            elif mod_key == 'network':
                from modules.network_analyzer import analyze
                findings.extend(analyze())

            elif mod_key == 'process':
                from modules.process_analyzer import analyze
                findings.extend(analyze())

            elif mod_key == 'log':
                from modules.log_analyzer import analyze
                findings.extend(analyze())

            elif mod_key == 'attack':
                from modules.attack_detector import detect
                findings.extend(detect())

            elif mod_key == 'port':
                from modules.port_scanner import scan
                findings.extend(scan(args.target))

            elif mod_key == 'pii':
                from modules.pii_detector import scan as pii_scan
                dirs = args.pii_dirs or [os.path.expanduser('~')]
                findings.extend(pii_scan(dirs))

        except Exception as e:
            print(f'  [경고] {mod_name} 중 오류 발생: {e}')

    elapsed = time.time() - start_time
    counts = _summary(findings)

    print(f'\n  소요 시간: {elapsed:.1f}초')
    print('\n  보고서 생성 중...')

    from modules.reporter import generate
    report_path = generate(findings, args.format, args.output)

    print(f'  [OK] 보고서 저장 완료: {report_path}')

    # 즉시 조치 필요 항목 출력
    urgent = [f for f in findings if f.get('severity') in ('critical', 'high')]
    if urgent:
        print(f'\n  [!] 즉시 조치 필요 항목 ({len(urgent)}개):')
        for f in urgent[:10]:
            sev_label = '[CRITICAL]' if f['severity'] == 'critical' else '[HIGH]'
            print(f'     {sev_label} [{f["id"]}] {f["title"]}')
        if len(urgent) > 10:
            print(f'     ... 외 {len(urgent) - 10}개 (보고서 참조)')

    print()
    return 0 if (counts['critical'] + counts['high']) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
