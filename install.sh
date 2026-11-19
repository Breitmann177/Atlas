#!/usr/bin/env bash
# Hermes – Installer für Linux (Fedora; kennt auch Ubuntu/Debian, Arch, openSUSE)
# Ausführen als normaler Nutzer:  ./install.sh   (fragt bei Bedarf nach sudo)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
green() { printf '\e[1;32m==>\e[0m %s\n' "$*"; }
warn()  { printf '\e[1;33m!! \e[0m %s\n' "$*"; }

if [[ $EUID -eq 0 ]]; then
    echo "Bitte als normaler Nutzer starten (nicht mit sudo) – das Skript fragt selbst nach sudo."
    exit 1
fi

# --- Systempakete: curl (Downloads), zstd (für den Ollama-Installer) --------------------------
green "Systempakete installieren"
if command -v dnf >/dev/null; then
    sudo dnf install -y curl zstd uv
elif command -v apt-get >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y curl zstd pipx
elif command -v pacman >/dev/null; then
    sudo pacman -S --needed --noconfirm curl zstd uv
elif command -v zypper >/dev/null; then
    sudo zypper install -y curl zstd
else
    warn "Unbekannter Paketmanager – bitte curl selbst installieren."
fi

# --- Python 3.12 in eigener Umgebung (uv lädt es, egal welches Python das System hat) -----------
UV="$(command -v uv || true)"
if [[ -z "$UV" && -x "$HOME/.local/bin/uv" ]]; then UV="$HOME/.local/bin/uv"; fi
if [[ -z "$UV" ]]; then
    green "uv (Python-Paketmanager) installieren"
    if command -v pipx >/dev/null; then
        pipx install uv
    else
        curl -LsSf https://astral.sh/uv/install.sh | sh
    fi
    UV="$HOME/.local/bin/uv"
fi

green "Python-Umgebung anlegen (.venv, Python 3.12)"
"$UV" venv --python 3.12 --allow-existing .venv
REQ=requirements.txt
if command -v nvidia-smi >/dev/null && nvidia-smi -L >/dev/null 2>&1; then
    green "NVIDIA-Grafikkarte gefunden: GPU-Pakete werden mitinstalliert"
    REQ=requirements-gpu.txt
elif command -v lspci >/dev/null && lspci | grep -qi nvidia; then
    warn "NVIDIA-Grafikkarte erkannt, aber kein Treiber aktiv (nvidia-smi fehlt). Hermes läuft dann auf dem"
    warn "Prozessor, deutlich langsamer. Treiber für Fedora: siehe README, danach ./install.sh erneut starten."
fi
"$UV" pip install --python .venv/bin/python -r "$REQ"

# --- Ollama (lokale KI) --------------------------------------------------------------------------
if ! command -v ollama >/dev/null; then
    green "Ollama installieren (offizielles Skript von ollama.com)"
    curl -fsSL https://ollama.com/install.sh | sh
fi
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:11434/api/version; then
    (ollama serve >/dev/null 2>&1 &)
    sleep 5
fi
green "KI-Modelle laden (einmalig, zusammen etwa 8,5 GB)"
ollama pull qwen3:8b
ollama pull qwen3.5:4b

# --- App-Menü-Eintrag (öffnet ein Terminal, schließen = Hermes beenden) ---------------------------
green "Eintrag im App-Menü"
chmod +x "$DIR/start.sh"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS"
cat > "$APPS/hermes.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Hermes
Comment=Lokaler KI-Assistent
Exec="$DIR/start.sh"
Path=$DIR
Icon=$DIR/hermes.png
Terminal=true
Categories=Utility;
Keywords=ki;assistent;jarvis;hermes;
EOF
update-desktop-database "$APPS" 2>/dev/null || true

green "Fertig! Hermes startet jetzt (später: App-Menü → Hermes, oder ./start.sh)."
warn "Tipp: Ein Passwort kommt in die Datei .env (siehe README), sobald das Handy zugreifen soll."
exec "$DIR/start.sh"
