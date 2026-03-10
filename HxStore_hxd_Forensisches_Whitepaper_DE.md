# HxStore.hxd — Forensisches Whitepaper

**Hochschule für Polizei Baden-Württemberg**  
**Stand: März 2026 | Marc Brandt**

---

## 1. Einleitung und forensische Relevanz

`HxStore.hxd` ist die primäre Offline-Cache-Datei der Microsoft Outlook-App für iOS. Sie enthält alle lokal gespeicherten E-Mails, MAPI-Metadaten, Anhänge und Indexstrukturen eines Outlook-Profils. Bei forensischen Mobilgerät-Untersuchungen ist sie typischerweise unter folgendem Pfad zu finden:

```
/private/var/mobile/Containers/Data/Application/
  <APP-UUID>/Library/Application Support/
  outlookcore/HxCoreStore/
  <ACCOUNT-UUID>/HxStore.hxd
```

Die Datei ist nicht im Klartext lesbar — sie erfordert proprietäre Dekomprimierung und Tokendecodierung, die in diesem Dokument vollständig beschrieben wird.

---

## 2. Dateiformat-Übersicht

### 2.1 Gesamtstruktur

```
Offset 0x00000000 ┌─────────────────────────────────┐
                  │  File Header (≥ 0x6D00 Bytes)   │
                  │  Magic: "Nostromoi" (9 Bytes)    │
Offset 0x5020     │  Page Bitmap (7384 Bytes)        │
                  │  Block Size, Mgmt-Ptr ...        │
                  ├─────────────────────────────────┤
Offset ~0x000E0400│  Descriptor Blocks (512 B each)  │
                  │  Jeder Block endet mit 512 B     │
                  │  LZNT1-komprimierter Payload     │
                  │  ...                             │
                  ├─────────────────────────────────┤
                  │  Weitere Descriptor-Blöcke       │
                  │  (aktiv, shadow, deleted)        │
Offset 0x02000000 └─────────────────────────────────┘
```

### 2.2 File Header (Offset 0x00000000)

```
Offset  Größe  Wert               Bedeutung
------  -----  -----------------  ----------------------------------
0x0000  9 B    "Nostromoi\x00"    Magic-Bytes (proprietärer Marker)
0x0001  7 B    (padding/meta)     Dateiversion / interne IDs
0x0010  8 B    0x01BBDA00 ...     Interne Pointer (nicht vollst. reversiert)
0x0038  4 B    0x00001000         Block Size (= 4096 Bytes / 0x1000)
0x0058  4 B    0x00025000         Mgmt-Ptr (physical offset Management-Tabelle)
0x0060  ...    0xDEADBEEF-Marker  Guard/Sentinel-Werte (mehrfach)
0x5020  7384 B Bitmap             Seitenallokations-Bitmap (je Bit = 512-B-Seite)
```

**Beispiel (Hex-Dump offset 0x0000–0x007F):**

```
0x0000: 4e 6f 73 74 72 6f 6d 6f 69 00 00 00 00 00 00 00  |Nostromoi.......|
0x0010: 00 da bb 01 00 00 00 00 00 50 00 00 00 00 00 00  |.........P......|
0x0020: 00 50 0c 00 00 00 00 00 c0 12 00 00 01 00 00 00  |.P..............|
0x0030: 62 85 cd 78 00 00 00 00 00 10 00 00 00 00 00 00  |b..x............|
0x0040: 00 30 00 00 00 00 00 00 f1 ff 00 00 01 00 00 00  |.0..............|
0x0050: ef be ad de 00 00 00 00 00 50 02 00 00 00 00 00  |.........P......|
0x0060: ef be ad de ef be ad de 5c 18 00 00 22 01 00 00  |........\..."...|
0x0070: 60 20 1b 89 00 00 00 00 00 50 07 00 00 00 00 00  |` .......P......|
```

### 2.3 Seiten-Bitmap (Offset 0x5020)

```
Offset 0x5020  Länge 7384 B

Struktur: 1 Bit = 1 physische 512-B-Seite
  Seite N: Byte[N/8] & (1 << (N%8)) → 1=belegt, 0=frei

Statistik der Beispieldatei:
  Gesamtseiten:   59.072
  Belegte Seiten: 56.813  (96,2 %)
  Freie Seiten:    2.259   (3,8 %)
  Belegte Bytes: 29.088.256 (ca. 27,7 MB)

Erste 4 Bitmap-Bytes: ff ff ff ff  (alle Seiten 0–31 belegt)
```

---

## 3. Descriptor-Blöcke — das zentrale Indexformat

### 3.1 Identifikation

Jeder Descriptor-Block ist **512 Bytes** groß. Erkennung erfolgt über das Feld `w10` an Byte-Offset +40 innerhalb des Blocks:

```
CHUNK_ID = 0x00010013

Prüfbedingung: uint32_LE(block[off+40]) == 0x00010013
```

Der gesamte Scan traversiert die Datei in 512-Byte-Schritten und prüft diese Bedingung.

### 3.2 Descriptor-Block Layout (512 Bytes)

```
Word-  Byte-       Wert        Bedeutung
Index  Offset
-----  ----------  ----------  ----------------------------------------
w0     0x00        variabel    Interne Prüfsumme / Hash (nicht vollst. reversiert)
w1–w7  0x04–0x1F  variabel    Weitere interne Metadaten
w8     0x20        variabel    File-Offset-Referenz (shifted)
w9     0x24        0x00000000  Padding / reserviert
w10    0x28        0x00010013  CHUNK_ID — festes Erkennungsmerkmal
w11    0x2C        variabel    lenflag: flags[7:0] | (compressed_pages[31:8])
w12    0x30        variabel    dst — virtuelle Zieladresse des Blocks
w13    0x34        variabel    src — virtuelle Quelladresse (0x60000 = mgmt_base)
w14    0x38        variabel    Weitere interne Pointer
w15    0x3C        variabel    Weitere interne Pointer
w16    0x40        variabel    node_ptr — physischer Offset der Node-Struktur
...    0x44–0x1FF  ...         Erweiterungsdaten / nicht reversiert
```

Der 65536-Byte große LZNT1-komprimierte Payload schließt **unmittelbar nach** dem 512-Byte-Header an (ab `file_off + 512`).

**Beispiel Descriptor bei 0x00632E00:**

```
0x00632e00: 07 a2 3d 4d 25 f7 0d a6 05 6a 70 3b 64 45 02 5d  |..=M%....jp;dE.]|
0x00632e10: 08 00 00 00 f9 05 00 00 c8 0c 00 00 04 00 00 00  |................|
0x00632e20: 7c 8a aa 00 00 00 00 00 13 00 01 00 f1 00 01 00  ||...............| ← w10=0x00010013
0x00632e30: 00 00 b8 0c 00 00 06 00 70 01 7c 8a aa 16 00 11  |........p.|.....|
               ^^^^^^^^^^^           ^^^^^^^^^^^
               dst=0x000CB800        src=0x00060000 (mgmt_base)
```

Felder (LE-Auslesung):
- `w10 @ 0x00632e28 = 0x00010013` ← CHUNK_ID ✓
- `w11 @ 0x00632e2C = 0x000100F1` → lenflag
- `w12 @ 0x00632e30 = 0x000CB800` → dst
- `w13 @ 0x00632e34 = 0x00060000` → src = mgmt_base
- `w16 @ 0x00632e40 = 0x00000604` → node_ptr

### 3.3 lenflag-Dekodierung

```
lenflag = w11 (uint32 LE)

flags        = lenflag & 0xFF
logical_len  = (lenflag >> 8) * 0x10000

Beispiel: lenflag=0x000100F1
  flags       = 0xF1
  logical_len = 0x00010 * 0x10000 = 0x100000 = 1 MB (max. Nutzlast)
```

### 3.4 Shadow-Copies (WAL-Prinzip)

HxStore verwendet ein Write-Ahead-Log-ähnliches Prinzip. Pro `dst`-Adresse können **mehrere Descriptor-Blöcke** existieren:

- Der Block mit dem **höchsten `file_off`** ist die aktuelle (primäre) Version.
- Alle früheren Instanzen desselben `dst` sind **Shadow Copies** — forensisch relevant als Vorgängerversionen (z.B. gelöschte/veränderte E-Mails).

**Statistik der Beispieldatei:**

```
Gesamte Descriptor-Blöcke: 3.436
Unique DST-Werte:              657
Shadow Copies:               2.779  (= 3436 - 657)
```

---

## 4. Dekomprimierungs-Pipeline

### 4.1 Zweistufige LZNT1-Dekomprimierung

Jeder Payload durchläuft eine zweistufige Komprimierung:

```
raw_bytes (65536 B max.)
    → LZNT1 decompress → L1 (~10.000–60.000 B)
    → LZNT1 decompress → L2 (Token-Stream, 2.000–30.000 B)
    → Token-Decoder    → HTML/MAPI (Klartext)
```

**Beispiel (DST 0x000CB800):**

```
raw:      65.536 B  (komprimierter Slot)
L1:       13.423 B  (Kompressionsrate 0,20×)
L2:        6.324 B  (Kompressionsrate 0,47× gegenüber L1)
decoded:   6.416 B  (Token-expandierter Klartext)
<html>-Position in decoded: Byte 571
```

### 4.2 LZNT1 Chunk-Header

Jeder LZNT1-Stream besteht aus verketteten Chunks:

```
Chunk-Header: 2 Bytes (uint16 LE)
  Bit 15:      0 = unkomprimiert, 1 = komprimiert
  Bits [11:0]: data_length - 1  (max. 4096 Bytes Ausgabe je Chunk)
  Bit 14:      immer 1 (Reserved)
  Header 0x0000 = End-of-Stream

Beispiel L1-Header an file_off+512:
  Bytes: 80 0f
  uint16_LE = 0x0F80
  Bit 15 = 0 → unkomprimierter Chunk
  Länge  = (0x0F80 & 0x0FFF) + 1 = 0xF81 = 3969 Bytes
```

### 4.3 LZNT1 Back-Reference-Kodierung

Bei komprimierten Chunks gilt die dynamische Bit-Split-Regel:

```
Flag-Byte gibt an: Bit=0 → nächstes Byte ist Literal
                   Bit=1 → nächste 2 Bytes sind Back-Reference

Back-Reference uint16 LE:
  pos = len(output)
  o_shift = 12; l_mask = 0x0F
  while pos >= (1 << o_shift):
    l_mask = (l_mask >> 1) | 0x08
    o_shift -= 1
  offset = (ref >> (16 - o_shift)) + 1
  length = (ref & l_mask) + 3
```

---

## 5. Token-Stream-Format (L2 → Klartext)

### 5.1 Grammatik

Das L2-Format ist ein proprietäres Microsoft-Token-Encoding mit fünf Token-Typen:

```
Typ       Erkennung                                     Verhalten
--------  --------------------------------------------  --------------------------
LITERAL   Einzelnes Byte                                → Window + Output
CTRL      b0 in [0x01–0x1F] ohne {0x09, 0x0A, 0x0D}   → überspringen (kein Window!)
STATIC1   b0 >= 0x80                                    → Lookup STATIC1 (73 Einträge)
STATIC4   [b0][0x00][fN][bN] mit fN >= 0xF0             → Lookup STATIC4 (136 Einträge)
LZ77      [b0][0x00] mit folgendem Byte < 0xF0           → Window[-b0] → Output
```

**Kritisch:** CTRL-Bytes dürfen **nicht** ins Window geschrieben werden — sonst korrumpiert der LZ77-Fensterstatus alle nachfolgenden Back-References (kaskadierender Fehler).

### 5.2 Verarbeitungsreihenfolge

```python
while i < len(l2):
    b0 = l2[i]
    if b0 >= 0x80:                    # STATIC1
        expand(_STATIC1[b0]); i += 1
    elif l2[i+1] == 0x00:
        if l2[i+2] >= 0xF0:           # STATIC4
            expand(_STATIC4[l2[i:i+4]]); i += 4
        else:                         # LZ77
            copy_window(dist=b0); i += 2
    elif 0x01 <= b0 <= 0x1F and b0 not in (9, 10, 13):
        i += 1                        # CTRL: skip, kein Window-Write
    else:
        literal(b0); i += 1           # LITERAL
```

### 5.3 Annotiertes Token-Stream-Beispiel

Aus L2 eines realen E-Mail-Records (DST 0x000CB800):

```
L2-Bytes:  02 00 05 dd 01 07 02 00 f2 01 dc 02 00 00 a0 00 00 80 ...

[  0] 0x02 0x00            LZ77:    dist=2 → Window[-2]
[  2] 0x05                 LITERAL: 0x05 (ctrl-ähnlich, ins Window)
[  3] 0xDD                 STATIC1: → b'' (leere Expansion, noch nicht reversiert)
[  4] 0x01                 CTRL:    überspringen, kein Window-Write
[  5] 0x07                 LITERAL: 0x07
[  6] 0x02 0x00 0xF2 0x01  STATIC4: Key=0200f201 → b'' (nicht reversiert)
[ 10] 0xDC                 STATIC1: → b''
[ 11] 0x02 0x00            LZ77:    dist=2
...
[ 17] 0x80                 STATIC1: → b'<br>'
[ 26] 0xB7                 STATIC1: → b'><meta name="'
[ 28] 0xFF                 STATIC1: → b'-equiv="Content-Type"'
```

### 5.4 STATIC1-Tabelle (Auswahl, 73 Einträge gesamt)

```
Token  Expansion
-----  --------------------------------------------------
0x80   b'<br>'
0x81   b'h2 a:visited'
0x84   b'IE=edge"><meta'
0x87   b'https://c.apple.com/r?v=2&amp;a='
0x89   b",BlinkMacSystemFont,'SFNSText','Segoe UI'"
0x96   b' content="text/html; charset=utf-8"><base href="'
0xA0   b' erhalten,'
0xB7   b'><meta name="'
0xBA   b'elvetica'
0xF8   b'x-apple-disable-message-reformatting'
0xFF   b'-equiv="Content-Type"'
```

### 5.5 STATIC4-Tabelle (Auswahl, 136 Einträge gesamt)

```
Token (4B hex)  Expansion
--------------  --------------------------------------------------
0f 00 f0 35     b'\r\n'
0f 00 f1 03     b'\r\n'
6a 00 f5 0e     b' align="center" class="appl_lowbrow" style="'
39 00 f1 01     b'" content="'
3c 00 f1 0a     b'" content="'
7b 00 f4 07     b' und '
f7 00 f3 00     b' Sie '
74 00 f1 25     b' Schul'
4d 00 f1 0f     b' erforder'
0e 00 f1 0e     b'ontent'
```

---

## 6. Record-Typen und Inhaltsklassifikation

### 6.1 Typen nach Inhalt

```
Typ          Erkennung im decoded-Output          Typischer Inhalt
-----------  ------------------------------------  --------------------------------
html_body    decoded[0:100] enthält b'<html'      Nur HTML-E-Mail-Body
mixed        decoded[50:] enthält b'<html'        MAPI-Prefix + HTML-Body
mapi_blob    b'I\x00P\x00M\x00' in L2             MAPI-Property-Store (UTF-16LE)
binary       keines der obigen                    Attachment, Index, unbekannt
```

### 6.2 MAPI-Blob-Struktur

MAPI-Blobs enthalten UTF-16LE-kodierte Strings in einem proprietären Property-Store-Format. Die Strings sind im L2-Stream durch LZ77/STATIC-Token unterbrochen (fragmentiert):

```
L2-Rohdaten enthalten UTF-16LE-Fragmente:
  "WG: BMW X5"               → Betreff (Subject)
  "info@boatsman-logistic.de" → From-Adresse
  "IPM.Note"                 → Message Class
  "<abc123@domain.de>"       → Message-ID
  "16.09.2024"               → Datum
```

**Extraktion:** Regex-Scan auf `(?:[\x20-\x7e]\x00){3,}` in L2, Adjacent-Stitching bei Gap ≤ 12 Bytes, dann Heuristik-Klassifikation.

### 6.3 Gemischter Record (mixed)

```
L2: [MAPI-Präfix (Token-kodierte UTF-16LE Metadaten)]
         ↓ Token-Decode
decoded: [binäre MAPI-Properties][...]<html><head>...E-Mail-Body...</html>
```

Der HTML-Offset variiert zwischen 50 und mehreren tausend Bytes.

---

## 7. Gelöschte und unindexierte Records

### 7.1 Scan-Strategien im Überblick

```
Strategie       Quelle                Forensische Relevanz
--------------  --------------------  ------------------------------------
A) active       Descriptor Index      Aktuelle Primär-Records (495 Stück)
B) shadow       Ältere Desc-Copies    Vorherige Versionen / gelöschte Mails
C) bitmap_alloc Bitmap-Seiten außer-  Mails nach Index-Entfernung
                halb des Index
D) carve        Alle Seiten           Maximale Extraktion (hohe FP-Rate)
```

### 7.2 Bitmap-Scan (Strategie C)

Seiten die im Bitmap als belegt markiert, aber von **keinem aktiven Descriptor referenziert** werden:

```
Vorgehen:
1. Alle file_off und Datenbereiche aller Descriptors als "covered" markieren
2. Alle Bitmap-Seiten außerhalb von "covered" verarbeiten
3. LZNT1-Dekompressions-Versuch an jedem 512-B-Page-Boundary
4. Qualitätsprüfung: ≥ 8 druckbare ASCII-Bytes in ersten 256 Bytes decoded

Ergebnis Beispieldatei:
  Bitmap-Seiten geprüft: ~6.600+
  Verwertbare Records:   6.661 (html_body, mixed, mapi_blob)
```

### 7.3 Statistische Auswertung der Beispieldatei

```
Quelle    Records  Anteil   Typischer Inhalt
--------  -------  ------   --------------------------------
active        495   5,4 %   Aktive E-Mails, aktueller Index
shadow      2.075  22,5 %   Ältere Versionen / WAL-Copies
bitmap      6.661  72,2 %   Gelöschte / überschriebene Daten
          -------
          9.231 gesamt

  → HTML-Records (inkl. mixed):  3.936
  → MAPI-Blobs:                  3.193
  → Binär:                       2.102
```

---

## 8. Ausgabe-Formate

### 8.1 Flat-Decompressed (.decompressed)

**Dateiheader (64 Bytes):**

```
Offset  Größe  Inhalt
------  -----  -------------------------------------------
0x00    24 B   ASCII "HXSTORE_DECOMPRESSED_V3\x00"
0x18     4 B   uint32 LE: Originaldateigröße
0x1C     4 B   uint32 LE: Reserviert (0)
0x20    44 B   Padding auf 64 Bytes
```

**Record-Header (16 Bytes pro Record):**

```
Offset  Größe  Typ       Bedeutung
------  -----  --------  -------------------------------------------
0x00     4 B   ASCII     Magic "HXR\x01"
0x04     4 B   uint32 LE file_off (physischer Origin in HxStore.hxd)
0x08     4 B   uint32 LE dst (virtuelle Adresse, 0 = unbekannt)
0x0C     4 B   uint32 LE payload_len (Länge des folgenden Payloads)
0x10     N B   bytes     Token-decodierter Payload
```

### 8.2 SQLite-Datenbank (.db)

Die Datenbank ist das primäre Analyse-Artefakt und enthält alle Records inklusive dekomprimierter HTML-Bodies:

```
Tabelle: records
  id           INTEGER  Fortlaufende ID
  file_off     TEXT     Physischer Offset in HxStore.hxd ("0x00167800")
  file_off_int INTEGER  Numerisch (indiziert, für Sortierung)
  dst          TEXT     Virtuelle DST-Adresse
  source       TEXT     "active" | "shadow" | "bitmap" | "carved"
  record_type  TEXT     "html_body" | "mixed" | "mapi_blob" | "binary"
  has_html     INTEGER  1 = HTML-Body vorhanden
  decoded_len  INTEGER  Länge des dekomprimierten Payloads
  subject      TEXT     Betreff (aus UTF-16LE-Extraktion)
  from_addr    TEXT     Absender-E-Mail-Adresse
  to_addrs     TEXT     Empfänger (kommagetrennt)
  message_id   TEXT     RFC-5322 Message-ID
  html_body    TEXT     Vollständiger HTML-Body (nur wenn has_html=1)

Tabelle: meta
  key / value: Statistiken, Quelldatei, Parser-Version
```

**Größenvergleich:**

```
Artefakt                          Größe   Inhalt
---------------------------------  ------  ----------------------------------------
HxStore.hxd (Original)             32 MB  Komprimiert, tokenisiert
Cellebrite .decompressed           128 MB  Flat-dekomprimiert (UTF-16 raw, kein Decode)
Parser v3 .decompressed            246 MB  Alle Records + Token-decode + Record-Header
Parser v3 .db (SQLite)              91 MB  Strukturiert, HTML-Bodies, volltext-suchbar
```

### 8.3 Interaktiver HTML-Report (.report.html)

Der Report wird automatisch aus der SQLite-DB generiert (1,6 MB) und enthält alle Records als paginierte, filterbare Tabelle. Filter-Chips ermöglichen die direkte Auswahl nach Quelle und Inhalt:

```
INHALT-Filter:  Mit HTML-Body | MAPI-Blobs 
                Gemischt | Binär 
QUELLE-Filter:  Aktiv | Shadow Copies | Bitmap/gelöscht
```

Zeilen mit HTML-Body sind durch **●** markiert. Die HTML-Bodies selbst sind über die SQLite-DB abrufbar.

---

## 9. Identifizierte Limitierungen (offene Reverse-Engineering-Aufgaben)

### 9.1 Unvollständige STATIC1/STATIC4-Tabellen

```
Status:
  STATIC1: 73/256 Einträge bekannt 
  STATIC4: 136/? Einträge bekannt

Symptom: Unbekannte Token produzieren leere Expansionen (b'')
Auswirkung: Teile des HTML-Body erscheinen leer statt mit korrektem Text

Methodik zur Erweiterung (GT-Alignment):
  Für jeden unbekannten Token b0 in L2:
    → Position im decoded ermitteln
    → Cellebrite-Referenztext an äquivalenter Position nachschlagen
    → Mapping konstruieren
```

### 9.2 LZ77-Fenster-Korrumpierung

```
Problem: CTRL-Bytes (0x01–0x1F) stellen möglicherweise eigenständige
         Token-Typen dar, deren Semantik unbekannt ist.

Beobachtung:
  - CTRL-Bytes unterbrechen den window-State
  - Nachfolgende LZ77-Back-References referenzieren dann falsche
    window-Positionen → "cascading corruption"
  - Sichtbar als: korrekte Keywords + umgebender Nonsens-HTML

Hypothesen:
  a) CTRL = 2-Byte-Token [ctrl_byte][param] mit unbekannter Expansion
  b) CTRL = Steuersequenz (flush window, reset, etc.)
  c) CTRL-Bytes sind tatsächlich Datenbytes in anderen Kontexten
```

### 9.3 Unbekannte Node/Extent-Struktur

```
Felder w16 (node_ptr) in Descriptors verweisen auf eine Node-Struktur.
Diese Node enthält (key, count)-Paare die auf den mgmt_base-Extent-Pool
verweisen — ein alternativer Rekonstruktionspfad für größere E-Mails.

Status: Struktur identifiziert, aber Verwendung liefert keine besseren
        Ergebnisse als der direkte Inline-Pfad. Möglicherweise für
        Multi-Extent-Records (>64 KB) relevant.
```

### 9.4 MAPI-Property-IDs

```
Bekannte MAPI-PropertyIDs in binären Strukturen:
  0x0037 001F → Subject (PT_UNICODE)
  0x0C1A 001F → SenderName
  0x0039 0040 → ClientSubmitTime (PT_SYSTIME)
  0x0E04 001F → DisplayTo
  0x0E06 0040 → MessageDeliveryTime (PT_SYSTIME)
  0x001A 001E → MessageClass

Status: Parsing der Fixed-Size-Property-Structs noch nicht vollständig.
        UTF-16LE-Strings werden aktuell über Regex-Stitching extrahiert,
        nicht über strukturiertes Property-Store-Parsing.
```

---

## 10. Forensische Handlungsempfehlungen


### 10.1 Empfohlene Toolchain

```
1. HxStore.hxd extrahieren (Cellebrite/UFED oder manuell via AFC2)

2. Parser v3 ausführen:
     python3 hxstore_parse.py \
       --hx HxStore.hxd \
       --out output/HxStore.hxd.decompressed \
       --deleted

3. HTML-Report öffnen: output/HxStore.hxd.report.html
   (Filterung nach Quelle, Typ, Betreff, Absender direkt im Browser)

4. SQLite-DB für strukturierte Abfragen: output/HxStore.hxd.db
   (Empfohlen: DB Browser for SQLite oder DBeaver)

5. Einzelne HTML-Bodies exportieren:
     python3 export_body.py list
     python3 export_body.py show <id>
     python3 export_body.py search "Stichwort"
```

---

## 11. Anhang: Dateisystem-Artefakte

### 11.1 Verwandte Dateien im iOS Dateisystem

```
Pfad                                    Inhalt
--------------------------------------  --------------------------------
HxStore.hxd                             Primärer E-Mail-Cache (diese Datei)
HxStore.hxd-journal                     SQLite WAL (wenn vorhanden)
HxCoreStore/*/EFMData/*.dat             Attachment-Binärdaten (164.dat–275.dat)
HxCoreStore/*/Metadata.db               SQLite: Ordner, Accounts, Flags
HxCoreStore/*/SyncState/                Sync-Status mit Server
outlookcore/account_store.db            Konten-Konfiguration
```

### 11.2 Timestamps

```
Die Datei selbst enthält keine POSIX-Timestamps in den Headern.
Zeitstempel-Informationen sind zu finden in:
  - MAPI-Property 0x0039 (ClientSubmitTime)     — nur im MAPI-Blob-Parsing
  - MAPI-Property 0x0E06 (MessageDeliveryTime)  — nur im MAPI-Blob-Parsing
  - iOS-Dateisystem-Metadaten (mtime von HxStore.hxd = letzte App-Aktivität)
  - Cellebrite extrahiert diese aus dem MAPI-Binärformat
```

---

*Dieses Dokument basiert auf Reverse Engineering an einer realen HxStore.hxd-Datei (Outlook macOS 26). Alle Strukturen wurden durch Byte-Level-Analyse, LZNT1-Dekompressionsverfolgung und Vergleich mit dem Cellebrite Ground-Truth-Output verifiziert.*

*Versionen: Parser v3.0 (2026-03)*  
*Autor: Marc Brandt*
