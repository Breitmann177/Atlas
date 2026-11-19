#!/usr/bin/env bash
# Startet Hermes unter Linux (getestet für Fedora). Das Gegenstück zu start.bat unter Windows.
# Aufruf: ./start.sh   (einmalig vorher: chmod +x start.sh, falls es nicht ausführbar ist)
cd "$(dirname "$0")" || exit 1

if [ ! -x ".venv/bin/python" ]; then
  echo "FEHLER: Die Python-Umgebung .venv fehlt in $(pwd)"
  echo "Einrichten: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

# Läuft Hermes schon? Dann nur den Browser öffnen.
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:8000/auth-status; then
  echo "Hermes läuft schon, öffne den Browser ..."
  xdg-open http://localhost:8000 >/dev/null 2>&1 &
  exit 0
fi

# Ollama starten, falls es noch nicht läuft (nach der offiziellen Installation läuft es meist schon als Dienst)
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:11434/api/version; then
  if command -v ollama >/dev/null 2>&1; then
    echo "Starte Ollama ..."
    ollama serve >/dev/null 2>&1 &
  else
    echo "WARNUNG: Ollama ist nicht installiert (siehe README). Ohne Ollama geht nur Claude mit API-Schlüssel."
  fi
fi

# Browser erst öffnen, wenn der Server wirklich antwortet (sonst zeigt er eine Fehlerseite)
(
  for _ in $(seq 120); do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://127.0.0.1:8000/auth-status)
    if [ "$code" != "000" ]; then xdg-open http://localhost:8000 >/dev/null 2>&1; break; fi
    sleep 1
  done
) &

echo
echo " HERMES BOX"
echo " Läuft auf http://localhost:8000"
echo " Dieses Fenster offen lassen. Strg+C = Hermes beenden."
echo
exec .venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port 8000
