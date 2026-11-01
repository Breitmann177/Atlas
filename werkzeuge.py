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
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import trafilatura
from ddgs import DDGS
from fpdf import FPDF

MAX_BYTES = 2_000_000
MAX_SEKUNDEN = 20  # Gesamtzeit pro Seite
HEADERS = {"User-Agent": "Mozilla/5.0 (HermesBox; +lokal)"}

PDF_ORDNER = Path("pdfs")
WOCHENTAGE = ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"]


# Quellen-Qualität: seriöse Seiten nach vorn, Foren/Social Media/Content-Farmen raus
SERIOES = ("wikipedia.org", "tagesschau.de", "zdf.de", "zdfheute.de", "deutschlandfunk.de", "br.de", "ndr.de",
           "wdr.de", "swr.de", "mdr.de", "hr.de", "rbb24.de", "sportschau.de", "spiegel.de", "zeit.de", "faz.net",
           "sueddeutsche.de", "handelsblatt.com", "tagesspiegel.de", "welt.de", "n-tv.de", "dw.com", "reuters.com",
           "apnews.com", "bbc.com", "bbc.co.uk", "heise.de", "golem.de", "kicker.de", "bundesregierung.de",
           "bund.de", "destatis.de", "europa.eu", "who.int", "duden.de", "britannica.com", "nasa.gov")
UNSERIOES = ("pinterest.", "quora.com", "gutefrage.net", "youtube.com", "tiktok.com", "facebook.com",
             "instagram.com", "x.com", "twitter.com", "reddit.com", "wikihow.", "answers.", "brainly.",
             "lyrics", "fandom.com")
# Bei solchen Fragen zählt Aktualität: dann zusätzlich die Nachrichtensuche (mit Datum)
ZEITNAH = re.compile(r"\b(aktuell\w*|heute|gestern|neueste\w*|letzte\w*|gerade|news|diese woche|wahl\w*|ergebnis\w*|"
                     r"gewonnen|gestorben|tot|spiel\w*|tabelle\w*|kurs\w*|preis\w*|kostet|20\d\d)\b", re.I)


MAX_MELDUNG_TAGE = 60


def _datum_iso(wert) -> str:
    """'2026-10-12T08:00:00+00:00' -> '2026-10-12'; Unbrauchbares wie 'Vor einem Tag' -> ''."""
    try:
        return date.fromisoformat(str(wert)[:10]).isoformat()
    except ValueError:
        return ""


def _domain(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def _seriositaet(url: str) -> int:
    d = _domain(url)
    if any(u in d for u in UNSERIOES):
        return -1
    return 2 if any(d == s or d.endswith("." + s) for s in SERIOES) or d.endswith(".gov") else 0


def suche(frage: str, n: int = 6) -> list[dict]:
    """Websuche mit Qualitätsfilter. Unseriöse Seiten fliegen raus, seriöse kommen nach vorn; bei zeitnahen
    Fragen kommen Nachrichten mit Datum dazu. Bei Fehlern wird einmal neu versucht."""
    treffer, meldungen = [], []
    for versuch in range(2):
        try:
            with DDGS() as d:
                treffer = d.text(frage, region="de-de", max_results=12) or []
                if ZEITNAH.search(frage):
                    try:
                        meldungen = d.news(frage, region="de-de", max_results=5) or []
                    except Exception:
                        meldungen = []
            if treffer or meldungen:
                break
        except Exception:
            treffer = []
        time.sleep(1)
    liste, gesehen = [], set()
    for m in meldungen:  # Nachrichten zuerst, mit Datum, damit das Modell das Neueste erkennt
        url = m.get("url", "")
        datum = _datum_iso(m.get("date"))
        if not datum or (date.today() - date.fromisoformat(datum)).days > MAX_MELDUNG_TAGE:
            continue  # ohne verlässliches Datum oder veraltet: als "aktuelle Meldung" wertlos
        if url.startswith(("http://", "https://")) and _seriositaet(url) >= 0 and url not in gesehen:
            gesehen.add(url)
            liste.append({"titel": m.get("title", ""), "url": url, "datum": datum,
                          "text": m.get("body", ""), "rang": _seriositaet(url) + 1})
    for t in treffer:
        url = t.get("href", "")
        if url.startswith(("http://", "https://")) and _seriositaet(url) >= 0 and url not in gesehen:
            gesehen.add(url)
            liste.append({"titel": t.get("title", ""), "url": url, "datum": "", "text": t.get("body", ""),
                          "rang": _seriositaet(url)})
    liste.sort(key=lambda x: -x["rang"])  # stabil: innerhalb gleicher Qualität bleibt die Suchreihenfolge
    # höchstens zwei Treffer pro Seite, damit das Modell wirklich verschiedene Quellen vergleichen kann
    auswahl, pro_seite = [], {}
    for x in liste:
        d = _domain(x["url"])
        if pro_seite.get(d, 0) < 2:
            pro_seite[d] = pro_seite.get(d, 0) + 1
            auswahl.append(x)
    return auswahl[:n]


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


# ---------- Weltzeit (Zeitzone kommt aus der Open-Meteo-Ortssuche) ----------
def weltzeit(ort: str) -> str:
    """Aktuelle Uhrzeit an einem Ort als kurzer Satz, oder '' wenn der Ort nicht gefunden wird."""
    try:
        g = requests.get("https://geocoding-api.open-meteo.com/v1/search", timeout=10,
                         params={"name": ort, "count": 1, "language": "de"}).json().get("results") or []
        if not g or not g[0].get("timezone"):
            return ""
        jetzt = datetime.now(ZoneInfo(g[0]["timezone"]))
    except (requests.RequestException, ValueError, KeyError, ZoneInfoNotFoundError):
        return ""
    return f"In {g[0]['name']} ist es gerade {jetzt:%H:%M} Uhr ({WOCHENTAGE[jetzt.weekday()]}, {jetzt:%d.%m.})."


# ---------- Nachrichten (Tagesschau-RSS: frei, seriös, ohne Konto) ----------
NACHRICHTEN_URL = "https://www.tagesschau.de/index~rss2.xml"


def nachrichten(n: int = 6) -> list[dict]:
    """Die wichtigsten Schlagzeilen der Tagesschau-Startseite: [{titel, text, url}] (leer bei Fehlern)."""
    import xml.etree.ElementTree as ET

    try:
        r = requests.get(NACHRICHTEN_URL, headers=HEADERS, timeout=10)
        eintraege = ET.fromstring(r.content).findall(".//item")
    except (requests.RequestException, ET.ParseError):
        return []
    liste, gesehen = [], set()
    for e in eintraege:
        titel = (e.findtext("title") or "").strip()
        # Sendungen ("tagesschau 20:00 Uhr", "tagesthemen") sind keine Meldungen
        if not titel or re.match(r"(tagesschau|tagesthemen|nachtmagazin)\b", titel, re.I):
            continue
        schluessel = titel.lower()[:30]
        if schluessel in gesehen:
            continue
        gesehen.add(schluessel)
        text = re.sub(r"<[^>]+>", "", e.findtext("description") or "").strip()
        liste.append({"titel": titel, "text": text[:300], "url": (e.findtext("link") or "").strip()})
        if len(liste) >= n:
            break
    return liste


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
    # Daten wie 19.11.2026 werden zu Tageszahlen, damit "19.11.2026 - 31.10.2026" die Tage dazwischen ergibt
    try:
        a = re.sub(r"\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b",
                   lambda m: str(date(int(m.group(3)), int(m.group(2)), int(m.group(1))).toordinal()), a)
    except ValueError:
        return "FEHLER: ungültiges Datum"
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