#!/usr/bin/env bash
# App-Start unter Linux: startet den Atlas-Dienst und öffnet Atlas in einem eigenen Fenster.
# Fenster zu = Atlas beendet (gibt Grafikkarte und Speicher wieder frei). Kein Autostart.
cd "$(dirname "$0")" || exit 1
URL=http://localhost:8000

if systemctl --user cat hermes.service >/dev/null 2>&1; then
  systemctl --user start hermes.service
  DIENST=1
else
  .venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port 8000 &
  SERVER_PID=$!
fi
for _ in $(seq 120); do
  curl -s -o /dev/null --max-time 1 http://127.0.0.1:8000/auth-status && break
  sleep 0.5
done

BROWSER=""
for b in chromium-browser chromium google-chrome brave-browser microsoft-edge; do
  command -v "$b" >/dev/null && BROWSER="$b" && break
done

if [ -n "$BROWSER" ]; then
  # Eigenes Profil: Das Fenster ist ein eigener Prozess, das Skript wartet, bis es geschlossen wird.
  "$BROWSER" --app="$URL" --user-data-dir="${XDG_DATA_HOME:-$HOME/.local/share}/hermes-fenster" \
             --class=hermes --no-first-run --no-default-browser-check >/dev/null 2>&1
  if [ -n "$DIENST" ]; then systemctl --user stop hermes.service; else kill "$SERVER_PID" 2>/dev/null; fi
else
  # Kein Chromium-Browser: normaler Browser-Tab, Atlas läuft weiter bis zur Abmeldung.
  xdg-open "$URL"
  [ -n "$SERVER_PID" ] && wait "$SERVER_PID"
fi
