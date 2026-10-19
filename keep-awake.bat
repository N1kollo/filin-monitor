@echo off
REM Stops the PC from sleeping/hibernating so the monitor keeps running 24/7.
REM This is REQUIRED — a sleeping PC monitors nothing.
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Zapusti ot imeni administratora. & pause & exit /b 1 )
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change disk-timeout-ac 0
powercfg /hibernate off >nul 2>&1
echo.
echo Son i gibernaciya otklyucheny (pri pitanii ot seti).
echo Ekran gasnut mozhet - eto normalno, monitor prodolzhaet rabotat.
echo.
pause
