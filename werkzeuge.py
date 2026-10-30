"""Werkzeuge, die Hermes benutzen darf: Websuche und Seiten lesen.

Alles, was aus dem Internet kommt, ist UNVERTRAUTE Eingabe. Deshalb:
- nur http/https
- keine internen Adressen (localhost, 192.168.x.x, ...) -> sonst könnte eine
  Webseite Hermes dazu bringen, dein Heimnetz oder Ollama abzufragen
- Größen- und Zeitlimit
"""
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
import trafilatura
from ddgs import DDGS

MAX_BYTES = 2_000_000
HEADERS = {"User-Agent": "Mozilla/5.0 (HermesBox; +lokal)"}


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
    for _ in range(5):  # Weiterleitungen selbst verfolgen, jede einzeln prüfen
        if not url_erlaubt(url):
            return "FEHLER: Diese Adresse ist nicht erlaubt."
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, stream=True, allow_redirects=False)
        except requests.RequestException as e:
            return f"FEHLER: {type(e).__name__}"
        if r.is_redirect or r.is_permanent_redirect:
            url = urljoin(url, r.headers.get("Location", ""))
            continue
        typ = r.headers.get("Content-Type", "")
        if "text" not in typ and "html" not in typ:
            return "FEHLER: Kein lesbarer Text (Typ: " + typ[:40] + ")."
        daten = b""
        for stueck in r.iter_content(65536):
            daten += stueck
            if len(daten) > MAX_BYTES:
                break
        html = daten.decode(r.encoding or "utf-8", errors="replace")
        text = trafilatura.extract(html) or ""
        if not text.strip():
            return "FEHLER: Kein Text auf der Seite gefunden."
        return text[:max_zeichen]
    return "FEHLER: Zu viele Weiterleitungen."