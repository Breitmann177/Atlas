"""Werkzeuge, die Hermes benutzen darf: Websuche, Seiten lesen, Wetter, Rechner, Umrechner, Route, PDF erstellen.

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
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse
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


def _web_suche(frage: str) -> list[dict]:
    with DDGS() as d:
        return d.text(frage, region="de-de", max_results=12) or []


def _news_suche(frage: str) -> list[dict]:
    try:
        with DDGS() as d:
            return d.news(frage, region="de-de", max_results=5) or []
    except Exception:
        return []


def suche(frage: str, n: int = 6) -> list[dict]:
    """Websuche mit Qualitätsfilter. Unseriöse Seiten fliegen raus, seriöse kommen nach vorn; bei zeitnahen
    Fragen kommen Nachrichten mit Datum dazu. Bei Fehlern wird einmal neu versucht."""
    treffer, meldungen = [], []
    for versuch in range(2):
        try:
            # Web- und Nachrichtensuche gleichzeitig: spart etwa eine Sekunde, ohne etwas wegzulassen
            with ThreadPoolExecutor(2) as pool:
                nachrichten_lauf = pool.submit(_news_suche, frage) if ZEITNAH.search(frage) else None
                treffer = _web_suche(frage)
                meldungen = nachrichten_lauf.result() if nachrichten_lauf else []
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


def wetter_einordnung(hoechst: float, regen: float | None) -> tuple[str, str]:
    """Einordnung und Rat rechnet der Code: Das Modell nannte 2 bis 10 Grad "nicht kalt"."""
    wort = "kalt" if hoechst < 10 else "kühl" if hoechst < 16 else "mild" if hoechst < 24 else "warm" if hoechst < 30 else "heiß"
    dinge = (["eine Jacke"] if hoechst < 16 else []) + (["einen Schirm"] if (regen or 0) >= 50 else [])
    rat = f"Ich würde Ihnen {' und '.join(dinge)} empfehlen." if dinge else "Viel trinken und Sonnencreme nicht vergessen." if hoechst >= 30 else ""
    return wort, rat


def wetter(ort: str) -> str:
    """Aktuelles Wetter + 7 Tage Vorhersage als kurzer Text (oder 'FEHLER: ...')."""
    try:
        g = requests.get("https://geocoding-api.open-meteo.com/v1/search", timeout=10,
                         params={"name": ort, "count": 1, "language": "de"}).json().get("results") or []
        if not g:
            return f"FEHLER: Ort '{ort}' nicht gefunden."
        o = g[0]
        w = requests.get("https://api.open-meteo.com/v1/forecast", timeout=10, params={
            "latitude": o["latitude"], "longitude": o["longitude"], "timezone": "auto", "forecast_days": 7,
            "current": "temperature_2m,apparent_temperature,weather_code,wind_speed_10m,relative_humidity_2m",
            "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max,wind_speed_10m_max",
        }).json()
    except (requests.RequestException, ValueError, KeyError) as e:
        return f"FEHLER: {type(e).__name__}"
    c, d = w["current"], w["daily"]
    zeilen = [f"Ort: {o['name']} ({o.get('admin1', '')}, {o.get('country', '')})",
              f"Jetzt: {c['temperature_2m']} °C (gefühlt {c['apparent_temperature']} °C), "
              f"{WETTERCODES.get(c['weather_code'], 'unbekannt')}, Wind {c['wind_speed_10m']} km/h, "
              f"Luftfeuchtigkeit {c['relative_humidity_2m']} %"]
    # "Morgen" rechnet der Code aus: Mit reinen Daten wie 2026-11-02 verrutschte das Modell im Test um einen Tag
    for i, tag in enumerate(d["time"]):
        t = date.fromisoformat(tag)
        name = ["Heute", "Morgen", "Übermorgen"][i] + ", " if i < 3 else ""
        wort, rat = wetter_einordnung(d["temperature_2m_max"][i], d["precipitation_probability_max"][i])
        zeilen.append(f"{name}{WOCHENTAGE[t.weekday()]}, {t:%d.%m.}: {d['temperature_2m_min'][i]} bis {d['temperature_2m_max'][i]} °C, {wort}, "
                      f"{WETTERCODES.get(d['weather_code'][i], 'unbekannt')}, "
                      f"Regenwahrscheinlichkeit {d['precipitation_probability_max'][i]} %, Wind bis {d['wind_speed_10m_max'][i]} km/h"
                      + (f", Rat: {rat}" if rat else ""))
    return "\n".join(zeilen)


# ---------- Umrechnen: Einheiten rechnet der Code, Kurse kommen täglich von der EZB (frankfurter.dev, ohne Konto) ----------
EINHEITEN = {
    "Länge": {"Kilometer": 1000, "Meter": 1, "Zentimeter": 0.01, "Millimeter": 0.001, "Meilen": 1609.344, "Yard": 0.9144, "Fuß": 0.3048, "Zoll": 0.0254},
    "Gewicht": {"Tonnen": 1e6, "Kilogramm": 1000, "Gramm": 1, "Milligramm": 0.001, "Pfund (lb)": 453.59237, "Unzen": 28.349523125},
    "Volumen": {"Kubikmeter": 1000, "Liter": 1, "Milliliter": 0.001, "Gallonen (US)": 3.785411784},
    "Fläche": {"Quadratkilometer": 1e6, "Hektar": 1e4, "Quadratmeter": 1, "Quadratfuß": 0.09290304},
    "Geschwindigkeit": {"km/h": 1, "m/s": 3.6, "mph": 1.609344, "Knoten": 1.852},
    "Zeit": {"Sekunden": 1, "Minuten": 60, "Stunden": 3600, "Tage": 86400, "Wochen": 604800},
    "Daten": {"Byte": 1, "Kilobyte": 1e3, "Megabyte": 1e6, "Gigabyte": 1e9, "Terabyte": 1e12},
}
# Code: (Anzeige, Adjektiv ohne Endung oder leer, Hauptwörter)
_WAEHRUNG_NAMEN = {
    "EUR": ("Euro", "", ["euro", "euros", "eur", "€"]), "USD": ("US-Dollar", "amerikanisch", ["dollar", "dollars", "usd", "$"]), "GBP": ("Britische Pfund", "britisch", ["pfund", "gbp", "£"]),
    "CHF": ("Schweizer Franken", "", ["franken", "chf", "schweizer franken"]), "TRY": ("Türkische Lira", "türkisch", ["lira", "liras", "tl", "try"]),
    "JPY": ("Japanische Yen", "japanisch", ["yen", "jpy"]), "CAD": ("Kanadische Dollar", "kanadisch", ["dollar", "cad"]), "AUD": ("Australische Dollar", "australisch", ["dollar", "aud"]),
    "NZD": ("Neuseeland-Dollar", "neuseeländisch", ["dollar", "nzd"]), "HKD": ("Hongkong-Dollar", "", ["hongkong-dollar", "hkd"]), "SGD": ("Singapur-Dollar", "", ["singapur-dollar", "sgd"]),
    "SEK": ("Schwedische Kronen", "schwedisch", ["kronen", "krone", "sek"]), "NOK": ("Norwegische Kronen", "norwegisch", ["kronen", "krone", "nok"]),
    "DKK": ("Dänische Kronen", "dänisch", ["kronen", "krone", "dkk"]), "CZK": ("Tschechische Kronen", "tschechisch", ["kronen", "krone", "czk"]),
    "ISK": ("Isländische Kronen", "isländisch", ["kronen", "krone", "isk"]), "PLN": ("Polnische Złoty", "polnisch", ["zloty", "złoty", "pln"]), "HUF": ("Ungarische Forint", "ungarisch", ["forint", "huf"]),
    "RON": ("Rumänische Leu", "rumänisch", ["leu", "ron"]), "INR": ("Indische Rupien", "indisch", ["rupien", "rupie", "inr"]), "IDR": ("Indonesische Rupiah", "indonesisch", ["rupiah", "idr"]),
    "CNY": ("Chinesische Yuan", "chinesisch", ["yuan", "renminbi", "cny"]), "KRW": ("Südkoreanische Won", "südkoreanisch", ["won", "krw"]), "MXN": ("Mexikanische Pesos", "mexikanisch", ["pesos", "peso", "mxn"]),
    "PHP": ("Philippinische Pesos", "philippinisch", ["pesos", "peso", "php"]), "BRL": ("Brasilianische Real", "brasilianisch", ["real", "brl"]), "ZAR": ("Südafrikanische Rand", "südafrikanisch", ["rand", "zar"]),
    "THB": ("Thailändische Baht", "thailändisch", ["baht", "thb"]), "ILS": ("Israelische Schekel", "israelisch", ["schekel", "ils"]), "MYR": ("Malaysische Ringgit", "malaysisch", ["ringgit", "myr"]),
}
WAEHRUNGEN = {code: werte[0] for code, werte in _WAEHRUNG_NAMEN.items()}
NAMEN = {
    "km": "Kilometer", "kilometer": "Kilometer", "m": "Meter", "meter": "Meter", "cm": "Zentimeter", "zentimeter": "Zentimeter", "mm": "Millimeter",
    "millimeter": "Millimeter", "meile": "Meilen", "meilen": "Meilen", "miles": "Meilen", "yard": "Yard", "fuß": "Fuß", "fuss": "Fuß", "feet": "Fuß", "ft": "Fuß",
    "zoll": "Zoll", "inch": "Zoll", "inches": "Zoll", "t": "Tonnen", "tonne": "Tonnen", "tonnen": "Tonnen", "kg": "Kilogramm", "kilo": "Kilogramm",
    "kilogramm": "Kilogramm", "g": "Gramm", "gramm": "Gramm", "mg": "Milligramm", "milligramm": "Milligramm", "lb": "Pfund (lb)", "lbs": "Pfund (lb)",
    "unze": "Unzen", "unzen": "Unzen", "oz": "Unzen", "l": "Liter", "liter": "Liter", "ml": "Milliliter", "milliliter": "Milliliter", "kubikmeter": "Kubikmeter",
    "gallone": "Gallonen (US)", "gallonen": "Gallonen (US)", "qkm": "Quadratkilometer", "km²": "Quadratkilometer", "quadratkilometer": "Quadratkilometer",
    "hektar": "Hektar", "qm": "Quadratmeter", "m²": "Quadratmeter", "quadratmeter": "Quadratmeter", "quadratfuß": "Quadratfuß", "km/h": "km/h", "kmh": "km/h",
    "m/s": "m/s", "mph": "mph", "knoten": "Knoten", "sekunde": "Sekunden", "sekunden": "Sekunden", "minute": "Minuten", "minuten": "Minuten", "stunde": "Stunden",
    "stunden": "Stunden", "tag": "Tage", "tage": "Tage", "tagen": "Tage", "woche": "Wochen", "wochen": "Wochen", "byte": "Byte", "kb": "Kilobyte", "kilobyte": "Kilobyte",
    "mb": "Megabyte", "megabyte": "Megabyte", "gb": "Gigabyte", "gigabyte": "Gigabyte", "tb": "Terabyte", "terabyte": "Terabyte",
    "°c": "Celsius", "grad celsius": "Celsius", "celsius": "Celsius", "°f": "Fahrenheit", "grad fahrenheit": "Fahrenheit", "fahrenheit": "Fahrenheit", "kelvin": "Kelvin",
}
for _code, (_, _adjektiv, _woerter) in reversed(_WAEHRUNG_NAMEN.items()):  # reversed: Bei "dollar" und "krone" gewinnt die erste, also USD
    for _wort in _woerter:
        NAMEN[_wort] = _code
        if _adjektiv:  # "türkische lira", "türkischen lira", "türkischer lira", "türkisch lira"
            NAMEN.update({f"{_adjektiv}{_endung} {_wort}": _code for _endung in ("", "e", "en", "er")})
NAMEN.update({"us dollar": "USD", "us-dollar": "USD", "pfund sterling": "GBP"})
_MUSTER_EINHEIT = "|".join(sorted((re.escape(n) for n in NAMEN), key=len, reverse=True))
UMRECHNUNG = re.compile(rf"(?<![\w.,])(\d+(?:[.,]\d+)?)\s*({_MUSTER_EINHEIT})(?![\w²/])\s+(?:in|nach|zu|auf)\s+({_MUSTER_EINHEIT})(?![\w²/])", re.I)
UMRECHNUNG_FRAGE = re.compile(rf"\bwie ?viel\w*\s+({_MUSTER_EINHEIT})\s+(?:sind|ist|entsprechen|entspricht|ergeben|ergibt)\s+(\d+(?:[.,]\d+)?)\s*({_MUSTER_EINHEIT})(?![\w²/])", re.I)
UMRECHNER_OEFFNEN = re.compile(r"\b(öffne|zeig\w*|mach|gib|brauch\w*)\b.*\b(umrechner|währungsrechner)\b|^\W*(umrechner|währungsrechner)\W*$", re.I)
_kurse = {"zeit": 0.0, "datum": "", "werte": {}}


def kurse() -> dict:
    """Tageskurse, eine Stunde zwischengespeichert: {'datum': ..., 'werte': {'USD': 1.08, ...}} je 1 Euro, bei Fehlern leer."""
    if time.time() - _kurse["zeit"] < 3600 and _kurse["werte"]:
        return _kurse
    try:
        d = requests.get("https://api.frankfurter.dev/v1/latest", params={"base": "EUR"}, headers=HEADERS, timeout=8).json()
        _kurse.update(zeit=time.time(), datum=d["date"], werte={"EUR": 1.0, **d["rates"]})
    except (requests.RequestException, ValueError, KeyError):
        pass
    return _kurse


def umrechner_daten() -> dict:
    """Alles, was das Fenster im Chat zum Rechnen braucht. Währungen sind wie alle anderen Einheiten Faktoren zu einer Grundeinheit."""
    k = kurse()
    return {"einheiten": {**({"Währung": {c: 1 / r for c, r in k["werte"].items()}} if k["werte"] else {}), **EINHEITEN},
            "namen": WAEHRUNGEN, "kursdatum": k["datum"]}


def _temperatur(x: float, von: str, nach: str) -> float:
    c = x if von == "Celsius" else (x - 32) * 5 / 9 if von == "Fahrenheit" else x - 273.15
    return c if nach == "Celsius" else c * 9 / 5 + 32 if nach == "Fahrenheit" else c + 273.15


def zahl_text(x: float) -> str:
    """Deutsche Schreibweise ohne unnötige Stellen: 1234.5 -> '1.234,5'."""
    stellen = 2 if abs(x) >= 1 else 4
    t = f"{x:,.{stellen}f}".rstrip("0").rstrip(".") if "." in f"{x:,.{stellen}f}" else f"{x:,.{stellen}f}"
    return t.replace(",", "§").replace(".", ",").replace("§", ".")


def umrechnung_erkennen(text: str) -> dict | None:
    """'50 Dollar in Euro' -> Werte fürs Fenster und ein fertiger Antwortsatz. Nur wenn beide Einheiten sicher bekannt sind."""
    if UMRECHNER_OEFFNEN.search(text):
        return {"antwort": "Bitte sehr, hier ist der Umrechner.", "kategorie": "", "wert": "", "von": "", "nach": ""}
    m, f = UMRECHNUNG.search(text), UMRECHNUNG_FRAGE.search(text)
    if not m and not f:
        return None
    wert_text, von_wort, nach_wort = m.groups() if m else (f.group(2), f.group(3), f.group(1))
    wert = float(wert_text.replace(",", "."))
    von, nach = NAMEN[von_wort.lower()], NAMEN[nach_wort.lower()]
    # "Pfund" ist Währung oder Gewicht: Das andere Wort entscheidet
    gewichte = EINHEITEN["Gewicht"]
    if von == "GBP" and nach in gewichte:
        von = "Pfund (lb)"
    if nach == "GBP" and von in gewichte:
        nach = "Pfund (lb)"
    temperatur = {"Celsius", "Fahrenheit", "Kelvin"}
    if von in temperatur and nach in temperatur:
        return {"antwort": f"{zahl_text(wert)} {von} sind {zahl_text(_temperatur(wert, von, nach))} {nach}.", "kategorie": "Temperatur", "wert": wert, "von": von, "nach": nach}
    k = kurse() if von in NAMEN.values() and len(von) == 3 and von.isupper() else {"werte": {}}
    if von.isupper() and nach.isupper() and len(von) == 3 and len(nach) == 3:
        if von not in k["werte"] or nach not in k["werte"]:
            return {"antwort": "Die aktuellen Kurse konnte ich gerade nicht abrufen.", "kategorie": "", "wert": "", "von": "", "nach": ""}
        ergebnis = wert / k["werte"][von] * k["werte"][nach]
        datum = date.fromisoformat(k["datum"])
        name = lambda c: WAEHRUNGEN.get(c, c)
        return {"antwort": f"{zahl_text(wert)} {name(von)} sind {zahl_text(ergebnis)} {name(nach)} (Kurs der EZB vom {datum:%d.%m.}).",
                "kategorie": "Währung", "wert": wert, "von": von, "nach": nach}
    for kategorie, einheiten in EINHEITEN.items():
        if von in einheiten and nach in einheiten:
            return {"antwort": f"{zahl_text(wert)} {von} sind {zahl_text(wert * einheiten[von] / einheiten[nach])} {nach}.",
                    "kategorie": kategorie, "wert": wert, "von": von, "nach": nach}
    return None


# ---------- Route: Ort über Photon, Strecke über OSRM (beide offen, ohne Konto). Den Verkehr zeigt der Link zu Google Maps ----------
def _ort_daten(name: str) -> dict | None:
    f = []
    for _ in range(2):  # Der Dienst antwortet manchmal beim ersten Mal nicht
        try:
            f = requests.get("https://photon.komoot.io/api/", timeout=8, headers=HEADERS,
                             params={"q": name, "limit": 1, "lang": "de"}).json().get("features") or []
            break
        except (requests.RequestException, ValueError):
            time.sleep(1)
    if not f:
        return None
    p = {k: v.strip(" .,") if isinstance(v, str) else v for k, v in f[0]["properties"].items()}
    # Mit Hausnummer gefragt oder ohne Namen: Die Adresse zählt, sonst stünde dort die Firma im Haus. Sonst der Name ("TechCampus")
    haus = f"{p['street']} {p['housenumber']}" if p.get("street") and p.get("housenumber") else ""
    if not (re.search(r"\d", name) or not p.get("name")):
        haus = ""
    titel = haus or p.get("name") or p.get("street") or ""
    teile = [titel, p.get("city") if p.get("city") != titel else None, p.get("state") if not p.get("city") else None,
             p.get("country") if p.get("country") not in (None, "Deutschland") else None]
    voll = ", ".join(t for t in teile if t)
    # Photon liefert auch zu Unsinn irgendeinen Treffer: Das längste Wort der Eingabe muss im Ergebnis vorkommen
    wichtig = max(re.findall(r"[\wäöüß-]{2,}", name.lower()) or [""], key=len)
    if not re.search(rf"\b{re.escape(wichtig)}\b", voll.lower()):  # als ganzes Wort: "Eile" ist nicht "Eilean Siar"
        return None
    lon, lat = f[0]["geometry"]["coordinates"]
    return {"name": voll, "kurz": f"{haus}, {p['city']}" if haus and p.get("city") else titel or name, "lat": lat, "lon": lon}


def kuerzester_weg(wege: list[dict]) -> dict:
    """Der Dienst nahm bei gleicher Fahrzeit auch mal den längeren Weg (13,2 statt 11,2 km). Unter den fast gleich schnellen
    (höchstens 2 Minuten oder 10 % länger) gilt deshalb der kürzeste."""
    schnellste = min(w["duration"] for w in wege)
    return min((w for w in wege if w["duration"] <= max(schnellste + 120, schnellste * 1.1)), key=lambda w: w["distance"])


def route(start: str, ziel: str) -> dict:
    """Strecke mit dem Auto. km und minuten fehlen, wenn ein Dienst nicht antwortet; der Google-Link funktioniert trotzdem."""
    a, b = _ort_daten(start), _ort_daten(ziel)
    name_a, name_b = a["name"] if a else start, b["name"] if b else ziel
    ergebnis = {"start": name_a, "ziel": name_b, "start_kurz": a["kurz"] if a else start, "ziel_kurz": b["kurz"] if b else ziel, "km": None, "minuten": None,
                "linie": None,
                "link": "https://www.google.com/maps/dir/?" + urlencode({"api": 1, "origin": name_a, "destination": name_b, "travelmode": "driving"})}
    if not a or not b:
        return ergebnis
    try:
        wege = requests.get(f"https://router.project-osrm.org/route/v1/driving/{a['lon']},{a['lat']};{b['lon']},{b['lat']}",
                            params={"overview": "simplified", "geometries": "geojson", "alternatives": "true"}, headers=HEADERS, timeout=10).json()["routes"]
        r = kuerzester_weg(wege)
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return ergebnis
    # Für die Karte als [Breite, Länge]
    ergebnis.update(km=round(r["distance"] / 1000, 1), minuten=max(1, round(r["duration"] / 60)),
                    linie=[[lat, lon] for lon, lat in r["geometry"]["coordinates"]])
    return ergebnis


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