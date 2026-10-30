# Hermes Box – lokaler KI-Assistent

Ein selbst gehosteter Assistent, der komplett auf dem eigenen Rechner läuft: Chat mit Verlauf und Erinnerungen,
Websuche mit Quellen, Bilder und PDFs verstehen, PDFs erstellen und Spracheingabe. Langfristig soll daraus eine
physische "Hermes Box" werden (Raspberry Pi, Display, LED-Ring, Wake-Word).

> **Hinweis:** Die Idee, das Konzept, die Hardware-Planung, das Testen und der Betrieb sind von mir.
> Der Großteil des Codes wurde mit KI (Claude) geschrieben. Ich lerne ihn Schritt für Schritt und
> passe ihn selbst an.

## Funktionen
- Zwei Modi: **Schnell** (`qwen3:8b`) und **Gründlich** (`qwen3.8-27b`, mit Nachdenken, versteht Bilder)
- Websuche (DuckDuckGo) mit Quellenliste; die besten Seiten werden gelesen
- Schutz vor Zugriff auf interne Adressen bei der Websuche
- Bild-Upload, PDF lesen (nur Text-PDFs, kein OCR) und PDF erstellen
- Erinnerungen, die du bestätigst und bearbeiten kannst
- Spracheingabe (Browser oder Whisper), Stopp-Knopf, drei Designs
- Optionaler Passwortschutz

## Voraussetzungen
- Python 3.11 oder neuer
- [Ollama](https://ollama.com) mit den Modellen aus `server.py` (Abschnitt `MODELLE`)
- Empfohlen: NVIDIA-GPU

## Installieren und starten
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen3:8b
```
Danach `start.bat` doppelklicken (oder `python -m uvicorn server:app --port 8000`) und
`http://localhost:8000` im Browser öffnen.

## Passwort (empfohlen, sobald andere Geräte zugreifen)
Eine Datei `.env` anlegen mit der Zeile:
```
HERMES_PASSWORT=dein-langes-passwort
```
Ohne Passwort ist Hermes ohne Login erreichbar. Dann sollte der Server nur auf `127.0.0.1` laufen
(so startet ihn `start.bat`). Für Zugriff von anderen Geräten (z. B. über Tailscale) muss deren Adresse in der
`.env` bei `HERMES_HOSTS` stehen, mit Komma getrennt.

## Sicherheit
- Alle Seiten außer dem Login sind passwortgeschützt, falsche Versuche werden begrenzt
- Es werden nur bekannte Host-Namen bedient (Schutz vor DNS-Rebinding)
- Inhalte von Webseiten und PDFs gelten als unvertraut und werden nicht als Anweisung behandelt
- Das Modell kann selbst nichts auf dem Rechner ausführen

## Bekannte Grenzen
- Kleine lokale Modelle machen Fehler. Bei Fakten gilt: Quellen prüfen
- Lange PDFs werden gekürzt, gescannte PDFs werden nicht gelesen
- Erstellte PDFs sind einfacher Text ohne Formeln
- Das Login ist für den privaten Gebrauch gedacht (kein HTTPS, keine Benutzerverwaltung)
- Die Bibliotheken für die Darstellung kommen von einem CDN und brauchen Internet

## Geplant
- Sprachausgabe (TTS) und Wake-Word
- Raspberry-Pi-Box mit Display und LED-Ring
- Zugriff vom Handy und Smart Mirror über Tailscale
