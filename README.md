<p align="center"><img src="hermes.png" width="88" alt=""></p>

<h1 align="center">Hermes Box</h1>

<p align="center">Ein lokaler Sprachassistent im Stil von Jarvis: Chat, Websuche mit Quellen, Sprache rein und raus,<br>
Wetter, Routen und Umrechner. Läuft auf dem eigenen Rechner unter Windows und Linux.</p>

---

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
- Windows 10/11 oder Linux (getestet wird auf Fedora)
- Empfohlen: NVIDIA-Grafikkarte mit 8 GB Speicher. Ohne läuft alles auf dem Prozessor, nur deutlich langsamer.
- Etwa 12 GB freier Speicherplatz (KI-Modelle und Pakete)

## Installation

<details open><summary><b>Linux (Fedora)</b></summary>

```bash
git clone https://github.com/Breitmann177/hermes-box.git
cd hermes-box
./install.sh
```

Das Skript installiert ein paar Systempakete, legt eine eigene Python-Umgebung an (über `uv`), installiert
Ollama mit dem offiziellen Skript, lädt die KI-Modelle (einmalig etwa 8,5 GB) und trägt Hermes ins App-Menü ein.
Danach startest du Hermes über das App-Menü → Hermes. Es öffnet sich in einem eigenen Fenster (mit Chromium,
sonst im normalen Browser). Fenster schließen = Hermes beenden. Hermes startet nicht beim Hochfahren,
aber von selbst, sobald es aufgerufen wird (z. B. vom Handy über Tailscale).
Ausgaben ansehen: `journalctl --user -u hermes -f`.

**NVIDIA-Treiber:** Fedora bringt ohne Zusatz nur den freien Treiber mit, damit läuft die KI auf dem Prozessor.
Den NVIDIA-Treiber gibt es über RPM Fusion:
```bash
sudo dnf install https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install akmod-nvidia xorg-x11-drv-nvidia-cuda
```
Danach ein paar Minuten warten (der Treiber wird gebaut), neu starten und `./install.sh` noch einmal ausführen.
`nvidia-smi` muss die Karte zeigen. Ist Secure Boot an, muss der Treiber zusätzlich signiert werden
(siehe Anleitung von RPM Fusion).
</details>

<details><summary><b>Windows</b></summary>

1. **Python 3.12 (64-bit)** von [python.org](https://www.python.org/downloads/) und [Ollama](https://ollama.com) installieren.
2. Im Hermes-Ordner (am besten ein kurzer Pfad wie `C:\Hermes`, Windows erlaubt nur kurze Dateipfade):
   ```
   py -3.12 -m venv .venv
   .venv\Scripts\pip install -r requirements-gpu.txt
   ollama pull qwen3:8b
   ollama pull qwen3.5:4b
   ```
   Ohne NVIDIA-Grafikkarte `requirements.txt` statt `requirements-gpu.txt`.
3. `start.bat` doppelklicken. Der Browser öffnet `http://localhost:8000` von selbst.
</details>

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

## Auf dem iPhone (über Tailscale)
1. Auf dem Laptop einmalig: `tailscale serve --bg --https=443 http://127.0.0.1:8000`
   (beim ersten Mal zeigt Tailscale einen Link, um „Serve“ im Konto freizuschalten).
2. In `.env`: `HERMES_PASSWORT=...` und `HERMES_HOSTS=<laptop>.<tailnet>.ts.net`, dann Hermes neu starten.
3. Auf dem iPhone die Tailscale-App installieren, mit demselben Konto anmelden, in Safari
   `https://<laptop>.<tailnet>.ts.net` öffnen, Passwort eingeben, dann Teilen → „Zum Home-Bildschirm“.
Ist Hermes auf dem Laptop aus, startet es beim Aufruf vom Handy von selbst (Linux, mit install.sh eingerichtet). Über HTTPS funktioniert auch das Mikrofon.
