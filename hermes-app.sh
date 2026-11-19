#!/usr/bin/env bash
# App-Start unter Linux: Hermes läuft als systemd-Dienst im Hintergrund (eingerichtet von install.sh).
# Startet ihn, falls nötig, und öffnet den Browser – ohne Terminalfenster.
systemctl --user start hermes.service
for _ in $(seq 120); do
  curl -s -o /dev/null --max-time 1 http://127.0.0.1:8000/auth-status && break
  sleep 0.5
done
exec xdg-open http://localhost:8000
