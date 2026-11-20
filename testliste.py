"""Feste Testliste für Atlas. Fängt ab, dass etwas kaputtgeht, das vorher lief.

    python testliste.py          schnell: Werkzeuge und Bausteine, ohne KI (Sekunden)
    python testliste.py --voll   zusätzlich echte Gespräche mit Ollama und Internet (einige Minuten)

Nutzt eine eigene leere Datenbank: Deine Chats und Erinnerungen bleiben unberührt.
Die Vollprüfung schaut, ob das richtige Werkzeug benutzt wurde und ob Stichwörter in der Antwort stehen.
Ein Treffer heißt: wahrscheinlich richtig, nicht sicher richtig.
"""
import json
import os
import sys
import tempfile
import time

ordner = tempfile.mkdtemp(prefix="atlas-test-")

import server  # noqa: E402

server.DB = os.path.join(ordner, "test.db")
server.WURF_SEKUNDEN = 0
server.STANDARD_ORT = ""
os.environ.pop("ATLAS_NUTZER", None)
fehler = []


def pruefe(name, ist, soll):
    if ist != soll:
        fehler.append(name)
        print(f"  FEHLER: {name}\n     erwartet {soll!r}, bekam {ist!r}")


def ausfuehren(name, args):
    """Führt ein Werkzeug aus wie im Chat: (Events, Ergebnis fürs Modell)."""
    events, gen = [], server.werkzeug_ausfuehren(name, args, server.Lauf(1, False))
    try:
        while True:
            events.append(json.loads(next(gen)))
    except StopIteration as e:
        return events, e.value


print("Werkzeuge:")
pruefe("Rechner 18 % von 2450", ausfuehren("rechnen", {"ausdruck": "2450*0.18"})[1], "2450*0.18 = 441")
pruefe("Rechner führt keinen Code aus", server.werkzeuge.rechnen("__import__('os')").startswith("FEHLER"), True)
ev, text = ausfuehren("timer", {"sekunden": 300})
pruefe("Timer-Event", [e["typ"] for e in ev], ["timer"])
pruefe("Timer-Text", text, "Timer läuft: 5 Minuten.")
ev, text = ausfuehren("muenze_werfen", {})
pruefe("Münze: Animation zuerst", ev[0]["typ"] == "wurf" and ev[0]["ergebnis"] in ("Kopf", "Zahl"), True)
ev, _ = ausfuehren("wuerfeln", {})
pruefe("Würfel 1-6", ev[0]["ergebnis"] in list("123456"), True)
pruefe("Wetter ohne Ort und Wohnort fragt nach", "Frag den Nutzer" in ausfuehren("wetter", {})[1], True)
pruefe("Unbekanntes Werkzeug", ausfuehren("gibtsnicht", {})[1].startswith("FEHLER"), True)

print("Erinnerungen:")
ev, text = ausfuehren("erinnerung_speichern", {"fakt": "Der Nutzer wohnt in Freiburg.", "art": "nutzer"})
pruefe("Fakt wird nur angeboten", [e["typ"] for e in ev], ["vorschlag"])
ev, text = ausfuehren("erinnerung_speichern", {"fakt": "Der Nutzer heißt Alex.", "art": "nutzer", "ausdruecklich": True})
pruefe("'Merk dir' speichert direkt", [e["typ"] for e in ev], ["gemerkt"])
pruefe("Doppelt wird nicht gespeichert", ausfuehren("erinnerung_speichern", {"fakt": "Der Nutzer heißt Alex.", "ausdruecklich": True})[1],
       "War schon gespeichert.")
pruefe("Vorübergehendes nicht", ausfuehren("erinnerung_speichern", {"fakt": "Der Nutzer lernt gerade Mathe.", "ausdruecklich": True})[0], [])
pruefe("Passwort nicht", ausfuehren("erinnerung_speichern", {"fakt": "Das Passwort ist abc123", "ausdruecklich": True})[0], [])
pruefe("Stil wird direkt gespeichert", [e["typ"] for e in ausfuehren("erinnerung_speichern", {"fakt": "Antworte kürzer.", "art": "stil"})[0]],
       ["gemerkt"])
pruefe("Nur angeboten heißt nicht gespeichert", server.wohnort(), "")

print("Bausteine:")
pruefe("Quellen fürs Modell entfernt", server.fuers_modell(1, "assistant", "Merz.\n\n---\n**Quellen**\n- [a](b)", None),
       [{"role": "assistant", "content": "Merz."}])
m = server.fuers_modell(2, "assistant", "Kopf.", '[{"name": "muenze_werfen", "args": {}, "ergebnis": "Ergebnis: Kopf."}]')
pruefe("Werkzeug im Verlauf als echter Aufruf", [x["role"] for x in m], ["assistant", "tool", "assistant"])
pruefe("Alte Einträge (nur Namen)", server.fuers_modell(3, "assistant", "Zahl.", "muenze_werfen")[0]["tool_calls"][0]["function"]["name"], "muenze_werfen")
pruefe("Verlauf beginnt nicht mitten im Aufruf", server.kuerzen(m + [{"role": "user", "content": "nochmal"}], 10)[0]["role"], "user")
sys_, cl = server.claude_nachrichten([{"role": "system", "content": "s"}, {"role": "user", "content": "wirf"}] + m + [{"role": "user", "content": "nochmal"}])
pruefe("Claude-Format mit Verlauf-Aufrufen", [x["role"] for x in cl], ["user", "assistant", "user", "assistant", "user"])
system, nachrichten = server.claude_nachrichten([
    {"role": "system", "content": "S"}, {"role": "user", "content": "Wirf eine Münze"},
    {"role": "assistant", "content": "", "tool_calls": [{"id": "t1", "function": {"name": "muenze_werfen", "arguments": {}}}]},
    {"role": "tool", "tool_name": "muenze_werfen", "tool_call_id": "t1", "content": "Kopf"}])
pruefe("Claude: Werkzeug-Aufruf übersetzt", [b["type"] for b in nachrichten[1]["content"]], ["tool_use"])
pruefe("Claude: Ergebnis übersetzt", nachrichten[2]["content"][0], {"type": "tool_result", "tool_use_id": "t1", "content": "Kopf"})
pruefe("Werkzeug-Schemas gültig", all(t["function"]["parameters"]["type"] == "object" for t in server.WERKZEUGE), True)
_ollama = server.OLLAMA_URL
server.OLLAMA_URL = "http://127.0.0.1:9"  # dort läuft nichts
pruefe("Ollama aus: sofortige Meldung", [json.loads(z)["typ"] for z in server.chat_stream(server.Frage(text="Wer ist Bundeskanzler?", chat_id=None, live=False))],
       ["start", "fehler", "fertig"])
server.OLLAMA_URL = _ollama


def frag(text, cid=None):
    """Eine Frage wie im Browser. Gibt (Antwort, chat_id, benutzte Werkzeuge) zurück."""
    antwort, werkzeuge = "", []
    for z in server.chat_stream(server.Frage(text=text, chat_id=cid, live=False)):
        e = json.loads(z)
        if e["typ"] == "start":
            cid = e["chat_id"]
        elif e["typ"] == "token":
            antwort += e["text"]
        elif e["typ"] == "fehler":
            antwort += "[FEHLER " + e["text"] + "]"
        elif e["typ"] == "status" and e["text"] in ("sucht", "wetter", "rechnet"):
            werkzeuge.append(e["text"])
        elif e["typ"] in ("wurf", "timer", "umrechner", "route", "vorschlag", "gemerkt"):
            werkzeuge.append(e["typ"])
    return antwort, cid, werkzeuge


# (Gespräch, Werkzeug bei der letzten Frage oder None für "keine Suche/kein Wetter", Stichwörter (eins reicht), verbotene)
GESPRAECHE = [
    (["Wer ist aktuell Bundeskanzler?"], "sucht", ["Merz"], ["Scholz ist"]),
    (["Wer ist aktuell Bundeskanzler?", "Wo wurde er geboren?"], "sucht", ["Brilon"], []),
    (["Wer hat die Fußball-WM 2098 gewonnen?"], "egal", ["noch nicht", "Zukunft", "kein"], ["Frankreich hat die", "wurde von Frankreich"]),
    (["Was sind 18 Prozent von 2450?"], None, ["441"], []),
    (["Wie wird das Wetter morgen in Köln?", "Und in Hamburg?"], "wetter", ["Hamburg"], []),
    (["Wirf eine Münze", "nochmal"], "wurf", ["Kopf", "Zahl"], []),
    (["Stell einen Timer auf 5 Minuten"], "timer", ["5 Minuten", "fünf Minuten"], []),
    (["Rechne 100 Euro in Dollar um"], "umrechner", ["Dollar"], []),
    (["atlas wie gehts dir"], None, ["gut", "danke"], ["Dokument"]),
    (["atlas wie gehts dir", "welches dokument"], None, ["kein", "nicht"], ["Quellen"]),
    (["Was kannst du?"], None, ["Wetter", "Internet"], []),
    (["Wer hat dich gebaut?"], None, ["Projekt"], ["Team"]),
    (["Ich bin 25 Jahre alt"], "vorschlag", [""], []),
    (["ich lerne gerade mathe"], None, ["Mathe", "Thema", "Aufgabe", "helfen"], []),
    (["Erkläre kurz, was ein Grenzwert in der Mathematik ist."], None, ["Grenzwert"], []),
]

if "--voll" in sys.argv:
    print("\nEchte Gespräche (dauert einige Minuten):")
    for fragen, werkzeug, muss, nicht in GESPRAECHE:
        cid, t = None, time.time()
        for f in fragen:
            a, cid, benutzt = frag(f, cid)
        ok_werkzeug = True if werkzeug == "egal" else (werkzeug in benutzt) if werkzeug else not any(w in benutzt for w in ("sucht", "wetter", "vorschlag"))
        ok = ok_werkzeug and any(w.lower() in a.lower() for w in muss) and not any(w.lower() in a.lower() for w in nicht) \
            and "[FEHLER" not in a
        print(f"  {'ok    ' if ok else 'FEHLER'} [{time.time() - t:3.0f}s] {' -> '.join(fragen)}  {benutzt}\n         {a[:150]!r}", flush=True)
        if not ok:
            print(f"         ganz: {a!r}", flush=True)
            fehler.append(f"Gespräch: {' -> '.join(fragen)}")

print(f"\n{'ALLES OK' if not fehler else str(len(fehler)) + ' FEHLER'}")
for f in fehler:
    print(" -", f)
sys.exit(1 if fehler else 0)
