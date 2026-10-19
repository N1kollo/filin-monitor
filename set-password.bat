@echo off
cd /d "%~dp0"

REM The office box has no Python - it runs the frozen exe. Prefer it when present.
if exist "ServerSignalDesk.exe" (
    ServerSignalDesk.exe --set-password
) else (
    python monitor.py --set-password
)

echo.
echo Restart the monitor for the password to take effect:
echo   scheduled task:  schtasks /End /TN "ServerSignalDesk"  then  schtasks /Run /TN "ServerSignalDesk"
echo   or run.bat if you started it by hand
pause
