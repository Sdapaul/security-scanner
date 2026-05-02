@echo off
chcp 65001 > nul
title Security Scanner v1.0

echo ================================================
echo   Security Vulnerability Scanner  [Web UI]
echo   http://127.0.0.1:5001
echo ================================================
echo.

python -c "import psutil, flask" 2>nul
if errorlevel 1 (
    echo [Install] Installing required packages...
    pip install psutil flask -q
)

echo [Start] Open http://127.0.0.1:5001 in your browser.
echo [Stop]  Press Ctrl+C to stop the server.
echo.

start /min "" cmd /c "timeout /t 2 > nul && start http://127.0.0.1:5001"

cd /d "%~dp0"
python -X utf8 web_app.py
pause
