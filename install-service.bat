@echo off
REM Installs Server Signal Desk as an auto-starting scheduled task.
REM Runs at every system boot, even with no user logged in. Requires admin.
setlocal
cd /d "%~dp0"
set "TASK=ServerSignalDesk"

net session >nul 2>&1
if errorlevel 1 goto noadmin

if exist "%~dp0ServerSignalDesk.exe" goto fromexe
if exist "%~dp0dist\ServerSignalDesk.exe" goto fromdist
goto frompython

:fromexe
echo Ustanovka iz exe ryadom...
schtasks /Create /TN "%TASK%" /TR "\"%~dp0ServerSignalDesk.exe\"" /SC ONSTART /RU SYSTEM /F
goto created

:fromdist
echo Ustanovka iz dist exe...
schtasks /Create /TN "%TASK%" /TR "\"%~dp0dist\ServerSignalDesk.exe\"" /SC ONSTART /RU SYSTEM /F
goto created

:frompython
where pythonw >nul 2>&1
if errorlevel 1 goto noexe
echo Ustanovka cherez Python...
schtasks /Create /TN "%TASK%" /TR "wscript.exe \"%~dp0start-hidden.vbs\"" /SC ONSTART /RU SYSTEM /F
goto created

:created
if errorlevel 1 goto createfail
schtasks /Run /TN "%TASK%"
echo.
echo ================================================
echo   Ustanovleno i zapushcheno.
echo   Avtostart pri kazhdoy zagruzke.
echo   Dashboard: http://localhost:8081
echo   Udalit: uninstall-service.bat
echo ================================================
echo.
pause
exit /b 0

:noadmin
echo [!] Nuzhny prava administratora.
echo     Zakroy eto okno, nazhmi na fayle PKM, vyberi "Run as administrator".
echo.
pause
exit /b 1

:noexe
echo [!] Ryadom net ni ServerSignalDesk.exe, ni Python.
echo     Polozhi ServerSignalDesk.exe v etu papku i zapusti snova.
echo.
pause
exit /b 1

:createfail
echo [!] Ne udalos sozdat zadachu. Tekst oshibki schtasks vyshe.
echo.
pause
exit /b 1
