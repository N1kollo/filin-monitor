@echo off
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Run as administrator. & pause & exit /b 1 )
schtasks /End /TN "ServerSignalDesk" >nul 2>&1
schtasks /Delete /TN "ServerSignalDesk" /F
echo Removed. (The monitor process may keep running until reboot or manual kill.)
pause
