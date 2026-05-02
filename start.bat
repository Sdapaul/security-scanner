@echo off
chcp 65001 > nul
title Security Scanner v1.0

echo ====================================================
echo   Security Vulnerability Scanner - Web Dashboard
echo   http://127.0.0.1:5001
echo ====================================================
echo.

cd /d "%~dp0"

python --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed.
    pause & exit /b 1
)

echo [Check] Installing packages if needed...
pip install flask psutil > nul 2>&1

echo [Start] Server starting...
echo [Stop]  Press Ctrl+C to quit.
echo.
python -X utf8 web_app.py

pause
