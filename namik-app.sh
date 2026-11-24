#!/usr/bin/env bash
# App-Start unter Linux: startet den Namik-Dienst und öffnet Namik in einem eigenen Fenster.
# Fenster zu = Namik beendet (gibt Grafikkarte und Speicher wieder frei). Kein Autostart.
cd "$(dirname "$0")" || exit 1
URL=http://localhost:8000

DIENST=""
if systemctl --user cat namik.service >/dev/null 2>&1; then
  DIENST=namik.service
elif systemctl --user cat hermes.service >/dev/null 2>&1; then
  DIENST=hermes.service
fi
if [ -n "$DIENST" ]; then
  systemctl --user start "$DIENST"
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

# Schon offen? Dann kein zweites Fenster. (Das App-Menü holt das offene Fenster selbst nach vorne,
# weil StartupWMClass im App-Eintrag zur Fenster-ID "chrome-localhost__-Default" passt.)
PROFIL="${XDG_DATA_HOME:-$HOME/.local/share}/hermes-fenster"
if pgrep -f -- "--user-data-dir=$PROFIL" >/dev/null; then exit 0; fi

if [ -n "$BROWSER" ]; then
  # Eigenes Profil: Das Fenster ist ein eigener Prozess, das Skript wartet, bis es geschlossen wird.
  "$BROWSER" --app="$URL" --user-data-dir="$PROFIL" \
             --class=namik --no-first-run --no-default-browser-check >/dev/null 2>&1
  if [ -n "$DIENST" ]; then systemctl --user stop "$DIENST"; else kill "$SERVER_PID" 2>/dev/null; fi
else
  # Kein Chromium-Browser: normaler Browser-Tab, Namik läuft weiter bis zur Abmeldung.
  xdg-open "$URL"
  [ -n "$SERVER_PID" ] && wait "$SERVER_PID"
fi
