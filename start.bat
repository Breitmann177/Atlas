@echo off
title Namik
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo FEHLER: Die Python-Umgebung .venv fehlt in %~dp0
  pause
  exit /b 1
)

rem Laeuft Namik schon? Dann nur den Browser oeffnen.
curl.exe -s -o nul --max-time 2 http://127.0.0.1:8000/auth-status
if not errorlevel 1 (
  echo Namik laeuft schon, oeffne den Browser ...
  start "" http://localhost:8000
  exit /b 0
)

rem Ollama starten, falls es noch nicht laeuft
curl.exe -s -o nul --max-time 2 http://127.0.0.1:11434/api/version
if errorlevel 1 (
  echo Starte Ollama ...
  if exist "%LOCALAPPDATA%\Programs\Ollama\ollama app.exe" (
    start "" "%LOCALAPPDATA%\Programs\Ollama\ollama app.exe"
  ) else (
    start "Ollama" /min ollama serve
  )
)

rem Browser erst oeffnen, wenn der Server wirklich antwortet (sonst zeigt er eine Fehlerseite)
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "for($i=0;$i -lt 120;$i++){try{Invoke-WebRequest http://127.0.0.1:8000/auth-status -UseBasicParsing -TimeoutSec 2 | Out-Null; break}catch{if($_.Exception.Response){break}; Start-Sleep 1}}; Start-Process http://localhost:8000"

echo.
echo  NAMIK
echo  Laeuft auf http://localhost:8000
echo  Dieses Fenster offen lassen. Schliessen = Namik beenden.
echo.
".venv\Scripts\python.exe" -m uvicorn server:app --host 127.0.0.1 --port 8000

echo.
echo Namik wurde beendet.
pause
