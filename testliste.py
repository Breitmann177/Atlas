"""Feste Testliste für Hermes. Fängt ab, dass etwas kaputtgeht, das vorher lief.

    python testliste.py          schnell: nur die Wege der Fragen, ohne KI (Sekunden)
    python testliste.py --voll   zusätzlich echte Antworten mit Ollama und Internet (einige Minuten)

Nutzt eine eigene leere Datenbank: Deine Chats und Erinnerungen bleiben unberührt.
Die Vollprüfung sucht nur nach Stichwörtern. Ein Treffer heißt: wahrscheinlich richtig, nicht sicher richtig.
"""
import json
import os
import sys
import tempfile
import time

ordner = tempfile.mkdtemp(prefix="hermes-test-")

import server  # noqa: E402

server.DB = os.path.join(ordner, "test.db")
fehler = []


def pruefe(name, ist, soll):
    if ist != soll:
        fehler.append(name)
        print(f"  FEHLER: {name}\n     erwartet {soll!r}, bekam {ist!r}")


def weg(text, verlauf=()):
    """Wohin geht eine Frage? Dieselbe Reihenfolge wie im Chat, ohne das Modell zu fragen."""
    if server.timer_erkennen(text):
        return "timer"
    if server.MUENZE.search(text):
        return "münze"
    if server.WUERFEL.search(text):
        return "würfel"
    if server.VORSTELLUNG.search(text):
        return "vorstellung"
    if server.HERKUNFT.search(text):
        return "herkunft"
    if server.FAEHIGKEIT.search(text):
        return "fähigkeiten"
    if server.UHRZEIT_ORT.search(text):
        return "weltzeit"
    if server.UHRZEIT.search(text) or server.DATUM_FRAGE.search(text):
        return "uhr"
    if server.BRIEFING.search(text):
        return "briefing"
    if server.NACHRICHTEN.search(text):
        return "nachrichten"
    if server.ist_smalltalk(text) or server.plauderei(text):
        return "smalltalk"
    if server.WETTER.search(text):
        return "wetter"
    if server.ohne_router(text, []):
        return "kein werkzeug"
    if server.direkte_suche(text, []):
        return "suche"
    return "router"


WEGE = [
    ("Hallo, wie geht's?", "smalltalk"), ("hallo wie gehts", "smalltalk"), ("Danke dir", "smalltalk"),
    ("Poah, heute muss ich echt viel machen", "smalltalk"), ("Guten Morgen", "briefing"), ("Gib mir die Nachrichten", "nachrichten"),
    ("Wie spät ist es?", "uhr"), ("wie viel uhr ist es gerade", "uhr"), ("Welcher Tag ist heute?", "uhr"),
    ("Wie spät ist es in Tokio?", "weltzeit"), ("Wie wird das Wetter morgen in Köln?", "wetter"),
    ("Wie viel Grad ist es gerade in Heilbronn?", "wetter"), ("Regnet es heute?", "wetter"),
    ("wie viel grad hat die sonne", "suche"), ("Stell einen Timer auf 5 Minuten", "timer"), ("Timer stopp", "timer"),
    ("Wirf eine Münze", "münze"), ("Kannst du eine Münze werfen?", "münze"), ("Kopf oder Zahl?", "münze"),
    ("Was ist eine Münze?", "suche"), ("Würfel mal", "würfel"), ("Was ist ein Würfel?", "suche"),
    ("Was kannst du so alles?", "fähigkeiten"), ("Was sind die Fähigkeiten von Hermes?", "fähigkeiten"),
    ("Welche Fähigkeiten hast du?", "fähigkeiten"), ("hermes wie funktioniert das Thema grenzwerte", "suche"),
    ("hermes wir sind hier in einem bewerbungsgespräch sag mal was über dich was du kannst etc", "vorstellung"),
    ("Wer bist du?", "vorstellung"), ("Stell dich mal kurz vor", "vorstellung"), ("Erzähl mir was über dich", "vorstellung"),
    ("Hermes, wer hat dich gebaut?", "herkunft"), ("Von wem wurdest du entwickelt?", "herkunft"),
    ("Hat Alex dich komplett selbst programmiert?", "herkunft"), ("Wer hat das iPhone erfunden?", "suche"),
    ("Kannst du dich vorstellen?", "vorstellung"), ("Kannst du dir vorstellen, dass es regnet?", "wetter"),
    ("Erzähl mir was über Rom", "router"), ("Mach einfach, was du kannst", "router"),
    ("Hermes, wie funktioniert ein Motor?", "suche"), ("Welche Funktionen hat das iPhone 16?", "suche"), ("Wer ist Bundeskanzler?", "suche"),
    ("Wer ist Hermes in der griechischen Mythologie?", "suche"), ("Wie hoch ist der Eiffelturm?", "suche"),
    ("Was sind 18 Prozent von 2450?", "router"), ("Wie schreibe ich eine Schleife in Python?", "router"),
    ("Schreib mir ein Gedicht über Katzen", "kein werkzeug"), ("Stimmt das?", "router"),
]
SPRUCH_ERLAUBT = {"Poah, heute muss ich echt viel machen": True, "Ich bin so müde": True,
                  "Mein Opa ist gestorben, ich bin traurig": False, "Was muss ich für die Klausur lernen?": False}
PDF_WUNSCH = {"Mach mir ein PDF über Istanbul": True, "Schreib mir aus dem PDF raus, wann meine Tests sind": False,
              "Was steht im PDF?": False, "Kannst du das als PDF speichern?": True}
STIL = {"Antworte ab jetzt kürzer": True, "Hermes, sei in Zukunft lockerer": True, "Sprich nicht mehr so förmlich": True,
        "Ich möchte, dass du ab jetzt ausführlicher antwortest": True, "Schreib das kürzer": False,
        "Schreib mir einen Text, der immer lustig ist": False, "Ab jetzt regnet es immer": False}
KORREKTUREN = {"Nein, das stimmt nicht, der Eiffelturm ist 330 Meter hoch": True, "Das ist falsch": True,
               "Nicht Scholz, sondern Merz": True, "Danke, das war hilfreich": False}
ORTE = {"Wie wird das Wetter morgen in Bad Homburg?": "Bad Homburg", "Wetter in Frankfurt am Main": "Frankfurt am Main",
        "wetter in köln": "Köln", "Regnet es in der Nacht?": ""}
# Stichwort: Eins davon muss vorkommen. falsch: Das darf nicht vorkommen.
ANTWORTEN = [
    ("Wer ist aktuell Bundeskanzler?", ["Merz"], ["Scholz ist"]),
    ("Wer ist Bundespräsident von Deutschland?", ["Steinmeier"], []),
    ("Was ist die Hauptstadt von Australien?", ["Canberra"], []),
    ("Wer hat die Fußball-WM 2022 gewonnen?", ["Argentinien"], []),
    ("Wer hat die Fußball-WM 2098 gewonnen?", ["nicht", "keine"], ["hat die Fußball-WM 2098 gewonnen."]),
    ("Wann hat Albert Einstein mit 50 Cent When It Rains It Pours geschrieben?", ["nicht", "keine"], []),
    ("Was sind 18 Prozent von 2450?", ["441"], []),
    ("Wie spät ist es in Tokio?", ["Tokio"], []),
    ("Was kannst du so alles?", ["Das kann ich"], ["Felo", "Cron"]),
    ("hermes wie funktioniert das Thema grenzwerte", ["grenzwert"], ["Sperrgut", "Versand", "Das kann ich"]),
    ("hermes wir sind in einem bewerbungsgespräch sag mal was über dich was du kannst etc", ["Ich bin Hermes"], ["Ich bin Alex", "studiere"]),
]
GESPRAECHE = [
    (["Wer ist aktuell Bundeskanzler?", "Wo wurde er geboren?"], ["Brilon"]),
    (["Wie wird das Wetter morgen in Köln?", "Und in Hamburg?"], ["Hamburg"]),
    (["Wie hoch ist der Eiffelturm?", "Und wann wurde er gebaut?"], ["1887", "1889"]),
]


def frag(text, cid=None):
    a = ""
    for z in server.chat_stream(server.Frage(text=text, chat_id=cid, live=False)):
        e = json.loads(z)
        if e["typ"] == "start":
            cid = e["chat_id"]
        elif e["typ"] == "token":
            a += e["text"]
        elif e["typ"] == "fehler":
            a += " [FEHLER: " + e["text"] + "]"
    return a.split("\n\n---")[0].strip(), cid


print("Wege der Fragen:")
for text, soll in WEGE:
    pruefe(f"Weg: {text}", weg(text), soll)
server.SPRUCH_CHANCE = 100
for text, soll in SPRUCH_ERLAUBT.items():
    pruefe(f"Spruch: {text}", server.humor_spruch(text) is not None, soll)
for text, soll in PDF_WUNSCH.items():
    pruefe(f"PDF: {text}", server.pdf_gewuenscht(text), soll)
for text, soll in ORTE.items():
    pruefe(f"Ort: {text}", server.ort_aus_text(text), soll)
for text, soll in STIL.items():
    pruefe(f"Stil: {text}", bool(server.STIL_WUNSCH.search(server.ANREDE.sub("", text))), soll)
for text, soll in KORREKTUREN.items():
    pruefe(f"Korrektur: {text}", bool(server.KORREKTUR.search(text)), soll)
server.erinnerung_speichern("Korrektur: Der Hund von Alex heißt Bello.")
pruefe("Gelernt passt", server.gelerntes_passt("Wie heißt der Hund von Alex?"), True)
pruefe("Gelernt passt nicht", server.gelerntes_passt("Wie heißt der Hund von Obama?"), False)
pruefe("Gelernt passt nicht zum Thema", server.gelerntes_passt("Wie hoch ist der Eiffelturm?"), False)
for e in server.alle_erinnerungen():
    with server.db() as c:
        c.execute("DELETE FROM erinnerungen WHERE id=?", (e["id"],))
pruefe("Rechner 18 % von 2450", server.werkzeuge.rechnen("2450*0.18"), "441")
pruefe("Rechner führt keinen Code aus", server.werkzeuge.rechnen("__import__('os')").startswith("FEHLER"), True)
pruefe("Passwort wird nicht gemerkt", server.merken("Mein Passwort ist abc123, merk dir das", [])[1], None)
server.SPRUCH_CHANCE = 0

if "--voll" in sys.argv:
    print("\nEchte Antworten (dauert einige Minuten):")
    for text, muss, darf_nicht in ANTWORTEN:
        t = time.time()
        a, _ = frag(text)
        ok = any(w.lower() in a.lower() for w in muss) and not any(w.lower() in a.lower() for w in darf_nicht) and "[FEHLER" not in a
        print(f"  {'ok    ' if ok else 'FEHLER'} [{time.time() - t:3.0f}s] {text}\n         {a[:150]!r}", flush=True)
        if not ok:
            fehler.append(f"Antwort: {text}")
    for fragen, muss in GESPRAECHE:
        cid = None
        t = time.time()
        for f in fragen:
            a, cid = frag(f, cid)
        ok = any(w.lower() in a.lower() for w in muss) and "[FEHLER" not in a
        print(f"  {'ok    ' if ok else 'FEHLER'} [{time.time() - t:3.0f}s] {' -> '.join(fragen)}\n         {a[:150]!r}", flush=True)
        if not ok:
            fehler.append(f"Gespräch: {fragen[-1]}")

print(f"\n{'ALLES OK' if not fehler else str(len(fehler)) + ' FEHLER'}")
for f in fehler:
    print(" -", f)
sys.exit(1 if fehler else 0)
