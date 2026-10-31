"""Werkzeuge, die Hermes benutzen darf: Websuche, Seiten lesen, Wetter, Rechner, PDF erstellen.

Alles, was aus dem Internet kommt, ist UNVERTRAUTE Eingabe. Deshalb:
- nur http/https
- keine internen Adressen (localhost, 192.168.x.x, ...) -> sonst könnte eine
  Webseite Hermes dazu bringen, dein Heimnetz oder Ollama abzufragen
- Größen- und Zeitlimit
- PDFs werden nur in einen festen Ordner geschrieben, Dateiname wird bereinigt
"""
import ast
import ipaddress
import math
import operator
import re
import socket
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import trafilatura
from ddgs import DDGS
from fpdf import FPDF

MAX_BYTES = 2_000_000
MAX_SEKUNDEN = 20  # Gesamtzeit pro Seite
HEADERS = {"User-Agent": "Mozilla/5.0 (HermesBox; +lokal)"}

PDF_ORDNER = Path("pdfs")


def suche(frage: str, n: int = 5) -> list[dict]:
    with DDGS() as d:
        treffer = d.text(frage, region="de-de", max_results=n)
    return [
        {"titel": t.get("title", ""), "url": t.get("href", ""), "text": t.get("body", "")}
        for t in treffer
    ]


def url_erlaubt(url: str) -> bool:
    """True nur für öffentliche http(s)-Adressen."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
        return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)
    except Exception:
        return False


def seite_lesen(url: str, max_zeichen: int = 6000) -> str:
    """Lädt eine Seite und gibt den Haupttext zurück (oder 'FEHLER: ...')."""
    ende = time.monotonic() + MAX_SEKUNDEN
    for _ in range(5):  # Weiterleitungen selbst verfolgen, jede einzeln prüfen
        if not url_erlaubt(url):
            return "FEHLER: Diese Adresse ist nicht erlaubt."
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, stream=True, allow_redirects=False)
        except requests.RequestException as e:
            return f"FEHLER: {type(e).__name__}"
        try:
            if r.is_redirect or r.is_permanent_redirect:
                url = urljoin(url, r.headers.get("Location", ""))
                continue
            typ = r.headers.get("Content-Type", "")
            if "text" not in typ and "html" not in typ:
                return "FEHLER: Kein lesbarer Text (Typ: " + typ[:40] + ")."
            daten = b""
            try:
                for stueck in r.iter_content(65536):
                    daten += stueck
                    if len(daten) > MAX_BYTES or time.monotonic() > ende:
                        break
            except requests.RequestException as e:
                return f"FEHLER: {type(e).__name__}"
        finally:
            r.close()
        # Rohe Bytes an trafilatura: erkennt das Encoding selbst (wichtig für Umlaute)
        text = trafilatura.extract(daten) or ""
        if not text.strip():
            return "FEHLER: Kein Text auf der Seite gefunden."
        return text[:max_zeichen]
    return "FEHLER: Zu viele Weiterleitungen."


# ---------- Wetter (Open-Meteo: kostenlos, ohne Schlüssel) ----------
WETTERCODES = {
    0: "klar", 1: "überwiegend klar", 2: "teils bewölkt", 3: "bedeckt", 45: "Nebel", 48: "Reifnebel",
    51: "leichter Nieselregen", 53: "Nieselregen", 55: "starker Nieselregen", 56: "gefrierender Niesel",
    57: "gefrierender Niesel", 61: "leichter Regen", 63: "Regen", 65: "starker Regen", 66: "gefrierender Regen",
    67: "gefrierender Regen", 71: "leichter Schneefall", 73: "Schneefall", 75: "starker Schneefall",
    77: "Schneegriesel", 80: "leichte Schauer", 81: "Schauer", 82: "heftige Schauer", 85: "Schneeschauer",
    86: "starke Schneeschauer", 95: "Gewitter", 96: "Gewitter mit Hagel", 99: "schweres Gewitter mit Hagel",
}


def wetter(ort: str) -> str:
    """Aktuelles Wetter + 3 Tage Vorhersage als kurzer Text (oder 'FEHLER: ...')."""
    try:
        g = requests.get("https://geocoding-api.open-meteo.com/v1/search", timeout=10,
                         params={"name": ort, "count": 1, "language": "de"}).json().get("results") or []
        if not g:
            return f"FEHLER: Ort '{ort}' nicht gefunden."
        o = g[0]
        w = requests.get("https://api.open-meteo.com/v1/forecast", timeout=10, params={
            "latitude": o["latitude"], "longitude": o["longitude"], "timezone": "auto", "forecast_days": 3,
            "current": "temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m",
            "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max",
        }).json()
    except (requests.RequestException, ValueError, KeyError) as e:
        return f"FEHLER: {type(e).__name__}"
    c, d = w["current"], w["daily"]
    zeilen = [f"Ort: {o['name']} ({o.get('admin1', '')}, {o.get('country', '')})",
              f"Jetzt: {c['temperature_2m']} °C (gefühlt {c['apparent_temperature']} °C), "
              f"{WETTERCODES.get(c['weather_code'], 'unbekannt')}, Wind {c['wind_speed_10m']} km/h, "
              f"Luftfeuchtigkeit {c['relative_humidity_2m']} %"]
    for i, tag in enumerate(d["time"]):
        zeilen.append(f"{tag}: {d['temperature_2m_min'][i]} bis {d['temperature_2m_max'][i]} °C, "
                      f"{WETTERCODES.get(d['weather_code'][i], 'unbekannt')}, "
                      f"Regenwahrscheinlichkeit {d['precipitation_probability_max'][i]} %")
    return "\n".join(zeilen)


# ---------- Rechner (sicher: nur Zahlen, Operatoren und ein paar Funktionen, kein eval) ----------
_FUNKTIONEN = {"sqrt": math.sqrt, "sin": math.sin, "cos": math.cos, "tan": math.tan, "log": math.log10,
               "ln": math.log, "abs": abs, "round": round, "exp": math.exp, "fakultaet": math.factorial}
_KONSTANTEN = {"pi": math.pi, "e": math.e}
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
        ast.USub: operator.neg, ast.UAdd: operator.pos}


def _auswerten(k):
    if isinstance(k, ast.Constant) and isinstance(k.value, (int, float)):
        return k.value
    if isinstance(k, ast.Name) and k.id in _KONSTANTEN:
        return _KONSTANTEN[k.id]
    if isinstance(k, ast.UnaryOp) and type(k.op) in _OPS:
        return _OPS[type(k.op)](_auswerten(k.operand))
    if isinstance(k, ast.BinOp) and type(k.op) in _OPS:
        links, rechts = _auswerten(k.left), _auswerten(k.right)
        if isinstance(k.op, ast.Pow) and abs(rechts) > 1000:
            raise ValueError("Exponent zu groß")
        return _OPS[type(k.op)](links, rechts)
    if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in _FUNKTIONEN and not k.keywords:
        argumente = [_auswerten(a) for a in k.args]
        if k.func.id == "fakultaet" and argumente and argumente[0] > 500:
            raise ValueError("Zahl zu groß")
        return _FUNKTIONEN[k.func.id](*argumente)
    raise ValueError("nicht erlaubt")


def rechnen(ausdruck: str) -> str:
    """Rechnet einen Ausdruck wie '17.5 * 3 + sqrt(16)' aus. Gibt das Ergebnis oder 'FEHLER: ...' zurück."""
    a = ausdruck.replace("^", "**").replace("×", "*").replace("÷", "/")[:200]
    a = re.sub(r"(?<![\d.])(\d+),(\d+)", r"\1.\2", a)  # deutsches Komma "3,5" -> "3.5"
    try:
        ergebnis = _auswerten(ast.parse(a, mode="eval").body)
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError, OverflowError) as e:
        return f"FEHLER: {type(e).__name__}"
    if isinstance(ergebnis, float):
        ergebnis = round(ergebnis, 10)
        if ergebnis.is_integer():
            ergebnis = int(ergebnis)
    return str(ergebnis)


def _latin1(text: str) -> str:
    """Standard-PDF-Schrift kann nur Latin-1 (Umlaute ok), Rest wird ersetzt."""
    ersatz = {"„": '"', "“": '"', "”": '"', "‚": "'", "‘": "'", "’": "'",
              "–": "-", "—": "-", "…": "...", "•": "-", "€": "EUR", "\u00a0": " "}
    for a, b in ersatz.items():
        text = text.replace(a, b)
    return text.encode("latin-1", errors="replace").decode("latin-1")


# Unicode-Schriften (Windows, dann Raspberry Pi/Linux). Damit klappen auch ş, ğ, ı, € usw.
SCHRIFTEN = [
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
]


def _schrift(pdf: FPDF) -> tuple[str, bool]:
    """Bindet die erste vorhandene Unicode-Schrift ein. Ohne eine fällt es auf Helvetica (nur Latin-1) zurück."""
    for normal, fett in SCHRIFTEN:
        if Path(normal).is_file() and Path(fett).is_file():
            pdf.add_font("Text", "", normal)
            pdf.add_font("Text", "B", fett)
            return "Text", True
    return "Helvetica", False


def pdf_erstellen(titel: str, inhalt: str, dateiname: str = "") -> str:
    """Erstellt ein PDF im Ordner 'pdfs' und gibt den Pfad zurück (oder 'FEHLER: ...')."""
    try:
        PDF_ORDNER.mkdir(exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9_-]", "_", dateiname or titel)[:40].strip("_") or "dokument"
        # Zeitstempel: gleicher Titel überschreibt sonst ein älteres PDF, auf das ein alter Chat noch verlinkt
        pfad = PDF_ORDNER / f"{name}_{time.strftime('%Y%m%d-%H%M%S')}.pdf"

        pdf = FPDF()
        pdf.set_auto_page_break(True, 15)
        pdf.add_page()
        schrift, unicode = _schrift(pdf)
        sauber = (lambda t: t) if unicode else _latin1
        pdf.set_font(schrift, "B", 16)
        pdf.multi_cell(0, 9, sauber(titel), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font(schrift, size=11)
        for zeile in inhalt.splitlines():
            if zeile.strip():
                pdf.multi_cell(0, 6, sauber(zeile), new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.ln(4)
        pdf.output(str(pfad))
        return str(pfad)
    except Exception as e:
        return f"FEHLER: {type(e).__name__}"