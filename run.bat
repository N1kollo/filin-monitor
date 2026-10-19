@echo off
cd /d "%~dp0"
echo ================================================
echo   Server Signal Desk
echo   Dashboard: http://localhost:8081
echo   Stop: Ctrl+C
echo ================================================
echo.
python monitor.py
pause
