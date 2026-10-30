@echo off
cd /d "%~dp0"
echo Hermes startet auf http://localhost:8000 ...
start "" http://localhost:8000
".venv\Scripts\python.exe" -m uvicorn server:app --host 127.0.0.1 --port 8000
pause