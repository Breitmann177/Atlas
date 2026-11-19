# Hermes Box – lokaler KI-Assistent

Ein selbst gehosteter Sprachassistent im Stil von Jarvis, der auf dem eigenen Rechner läuft: Chat mit Verlauf und
Erinnerungen, Websuche mit Quellen, Sprache rein und raus, dazu kleine Werkzeuge wie Wetter, Routen und Umrechner.
Läuft unter **Windows** und **Linux (Fedora)**. Langfristig soll daraus eine physische "Hermes Box" werden.

> **Hinweis:** Die Idee, das Konzept, die Hardware-Planung, das Testen und der Betrieb sind von mir.
> Der Großteil des Codes wurde mit KI (Claude) geschrieben. Ich lerne ihn Schritt für Schritt und
> passe ihn selbst an.

## Funktionen
- **Lokale KI über Ollama** (`qwen3:8b`, für Bilder `qwen3.5:4b`), Modus *Schnell* oder *Gründlich* (mit Nachdenken)
- **Optional Claude** über einen eigenen API-Schlüssel, umschaltbar in den Einstellungen unter *KI*
- Jede Frage wird erst eingeordnet: Muss gesucht werden, ist es Wetter, eine Route, eine Rechnung oder Smalltalk?
- **Websuche** (DuckDuckGo und Wikipedia) mit Quellenliste; die besten Seiten werden gelesen
- **Werkzeuge:** Wetter mit 7-Tage-Vorschau, Rechner, Währungs- und Einheiten-Umrechner (EZB-Kurse),
  Routen mit Karte (OpenStreetMap) und Google-Maps-Link, Timer, Münzwurf und Würfel
- **Sprache:** Spracheingabe mit Whisper (auf der Grafikkarte, falls vorhanden), Live-Gespräch und "Hey Hermes",
  Sprachausgabe mit Microsoft-Stimmen, ohne Internet lokal mit Piper, optional ElevenLabs
- Bilder verstehen, PDFs lesen (nur Text-PDFs) und PDFs erstellen
- Erinnerungen, die du bestätigst und bearbeiten kannst
- Halftone-Auge, das zeigt, ob Hermes zuhört, nachdenkt, sucht oder spricht
- Passwortschutz und Zugriff vom Handy (z. B. über Tailscale)

## Voraussetzungen
- Python **3.12** (neuere Versionen haben teils noch keine fertigen Pakete für die Spracherkennung)
- [Ollama](https://ollama.com)
- Empfohlen: NVIDIA-Grafikkarte mit 8 GB Speicher. Ohne läuft alles auf dem Prozessor, nur deutlich langsamer.

## Installieren unter Windows
```
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
ollama pull qwen3:8b
ollama pull qwen3.5:4b
```
Danach `start.bat` doppelklicken. Der Browser öffnet `http://localhost:8000` von selbst.

## Installieren unter Linux (Fedora)
1. Grundpakete:
   ```
   sudo dnf install python3.12 git curl
   ```
2. NVIDIA-Treiber über RPM Fusion (nur mit NVIDIA-Grafikkarte):
   ```
   sudo dnf install https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
   sudo dnf install akmod-nvidia xorg-x11-drv-nvidia-cuda
   ```
   Danach ein paar Minuten warten (der Treiber wird gebaut) und neu starten. `nvidia-smi` muss die Karte zeigen.
   Ist Secure Boot an, muss der Treiber zusätzlich signiert werden (siehe RPM-Fusion-Anleitung).
3. Ollama und die Modelle:
   ```
   curl -fsSL https://ollama.com/install.sh | sh
   ollama pull qwen3:8b
   ollama pull qwen3.5:4b
   ```
4. Hermes:
   ```
   git clone https://github.com/Breitmann177/hermes-box.git
   cd hermes-box
   python3.12 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ./start.sh
   ```

Ob die KI wirklich auf der Grafikkarte läuft, zeigt `ollama ps` während einer Antwort ("100% GPU").

## Einstellungen in `.env`
Eine Datei `.env` im Hermes-Ordner anlegen. Sie wird nie hochgeladen (steht in `.gitignore`). Alle Zeilen sind optional:
```
HERMES_PASSWORT=dein-langes-passwort      # empfohlen, sobald andere Geräte zugreifen
HERMES_HOSTS=mein-laptop.tailnet.ts.net   # weitere Adressen für Zugriff von anderen Geräten, mit Komma getrennt
ANTHROPIC_API_KEY=...                      # schaltet Claude in den Einstellungen frei
CLAUDE_MODELL=claude-sonnet-5-5            # Standard; z. B. claude-opus-5-5 für schwierigere Aufgaben
ELEVENLABS_API_KEY=...                     # schaltet die Stimme "George" frei
```
Ohne Passwort ist Hermes ohne Login erreichbar. Dann sollte der Server nur auf `127.0.0.1` laufen (so starten ihn
`start.bat` und `start.sh`).

**Mit Claude** gehen Nachricht, Verlauf, Erinnerungen und Suchergebnisse an Anthropic, und jede Frage kostet etwas.
Mit *Lokal* verlässt nichts davon den Rechner (außer den Suchanfragen selbst).

## Stimmen
Die lokale Piper-Stimme liegt nicht im Repository. Lade eine Stimme (z. B. `de_DE-thorsten-high.onnx` mit der
passenden `.json`) von den [Piper-Stimmen](https://huggingface.co/rhasspy/piper-voices) herunter und lege sie in den
Ordner `stimmen/`. Bitte die Lizenz der jeweiligen Stimme beachten.

## Sicherheit
- Alle Seiten außer dem Login sind passwortgeschützt, falsche Versuche werden begrenzt
- Es werden nur bekannte Host-Namen bedient (Schutz vor DNS-Rebinding)
- Inhalte von Webseiten und PDFs gelten als unvertraut und werden nicht als Anweisung behandelt
- Die KI kann nichts auf dem Rechner ausführen und hat keinen Zugriff auf Dateien

## Testen
```
python testliste.py          # schnelle Prüfungen ohne KI-Antworten
python testliste.py --voll   # mit echten Antworten (dauert länger, Ollama muss laufen)
```

## Bekannte Grenzen
- Kleine lokale Modelle machen Fehler. Bei Fakten gilt: Quellen prüfen
- Lange PDFs werden gekürzt, gescannte PDFs werden nicht gelesen
- Karten und Darstellungs-Bibliotheken kommen aus dem Internet
- Das Login ist für den privaten Gebrauch gedacht (kein HTTPS, keine Benutzerverwaltung)

## Geplant
- Box mit Display und LED-Ring
- Smart Mirror
