@echo off
REM Known-answer tests. Each test runs on its own copy of monitor.py + ssd\ in a temp
REM dir, so the local config.json / monitor.db are never touched.
cd /d "%~dp0"
python -m unittest discover -s tests -v
pause
