"""Werkzeuge, die Hermes benutzen darf: Websuche, Seiten lesen, PDF erstellen.

Alles, was aus dem Internet kommt, ist UNVERTRAUTE Eingabe. Deshalb:
- nur http/https
- keine internen Adressen (localhost, 192.168.x.x, ...) -> sonst könnte eine
  Webseite Hermes dazu bringen, dein Heimnetz oder Ollama abzufragen
- Größen- und Zeitlimit
- PDFs werden nur in einen festen Ordner geschrieben, Dateiname wird bereinigt
"""
import ipaddress
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


def _latin1(text: str) -> str:
    """Standard-PDF-Schrift kann nur Latin-1 (Umlaute ok), Rest wird ersetzt."""
    ersatz = {"„": '"', "“": '"', "”": '"', "‚": "'", "‘": "'", "’": "'",
              "–": "-", "—": "-", "…": "...", "•": "-", "€": "EUR", "\u00a0": " "}
    for a, b in ersatz.items():
        text = text.replace(a, b)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def pdf_erstellen(titel: str, inhalt: str, dateiname: str = "") -> str:
    """Erstellt ein PDF im Ordner 'pdfs' und gibt den Pfad zurück (oder 'FEHLER: ...')."""
    try:
        PDF_ORDNER.mkdir(exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9_-]", "_", dateiname or titel)[:50].strip("_") or "dokument"
        pfad = PDF_ORDNER / f"{name}.pdf"

        pdf = FPDF()
        pdf.set_auto_page_break(True, 15)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.multi_cell(0, 9, _latin1(titel), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=11)
        for zeile in inhalt.splitlines():
            if zeile.strip():
                pdf.multi_cell(0, 6, _latin1(zeile), new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.ln(4)
        pdf.output(str(pfad))
        return str(pfad)
    except Exception as e:
        return f"FEHLER: {type(e).__name__}"