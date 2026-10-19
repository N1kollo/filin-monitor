@echo off
REM Builds a single standalone ServerSignalDesk.exe (no Python needed on the target).
REM Run this once on a machine that HAS Python. Copy dist\ServerSignalDesk.exe +
REM config.json to the server. That's the whole deploy.
REM
REM oui.txt = IEEE OUI registry (MAC -> vendor), bundled so inventory works offline.
cd /d "%~dp0"
REM Known-answer tests gate the build: a red suite never becomes an exe.
python -m unittest discover -s tests
if errorlevel 1 (
  echo.
  echo TESTS FAILED - exe not built.
  pause
  exit /b 1
)
python -m pip install --quiet pyinstaller
python -m PyInstaller --onefile --name ServerSignalDesk --icon assets\filin.ico ^
  --add-data "dashboard.html;." ^
  --add-data "oui.txt;." ^
  --hidden-import http.server ^
  monitor.py
for /f %%v in ('python -c "print(open('ssd/core.py', encoding='utf-8').read().split('__version__ = ')[1].split(chr(10))[0].strip(chr(34)+chr(13)))"') do set VER=%%v
copy /y dist\ServerSignalDesk.exe dist\ServerSignalDesk-v%VER%.exe >nul
echo.
echo Done. Standalone exe: dist\ServerSignalDesk.exe (+ dist\ServerSignalDesk-v%VER%.exe to ship)
echo Copy it + config.json to the server and run install-service.bat there.
pause
