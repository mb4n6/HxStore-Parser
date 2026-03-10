# HxStore.hxd — Forensic Whitepaper

**Hochschule für Polizei Baden-Württemberg**  
**As of: March 2026 | Marc Brandt**

---

## 1. Introduction and Forensic Relevance

`HxStore.hxd` is the primary offline cache file of the Microsoft Outlook app for iOS. It contains all locally stored e-mails, MAPI metadata, attachments and index structures of an Outlook profile. In forensic mobile device examinations it is typically found at the following path:

```
/private/var/mobile/Containers/Data/Application/
  <APP-UUID>/Library/Application Support/
  outlookcore/HxCoreStore/
  <ACCOUNT-UUID>/HxStore.hxd
```

The file is not human-readable in plain text — it requires proprietary decompression and token decoding, both of which are fully described in this document.

---

## 2. File Format Overview

### 2.1 Overall Structure

```
Offset 0x00000000 ┌─────────────────────────────────┐
                  │  File Header (≥ 0x6D00 Bytes)   │
                  │  Magic: "Nostromoi" (9 Bytes)    │
Offset 0x5020     │  Page Bitmap (7384 Bytes)        │
                  │  Block Size, Mgmt-Ptr ...        │
                  ├─────────────────────────────────┤
Offset ~0x000E0400│  Descriptor Blocks (512 B each)  │
                  │  Each block followed by 512 B    │
                  │  LZNT1-compressed payload        │
                  │  ...                             │
                  ├─────────────────────────────────┤
                  │  Further descriptor blocks       │
                  │  (active, shadow, deleted)       │
Offset 0x02000000 └─────────────────────────────────┘
```

### 2.2 File Header (Offset 0x00000000)

```
Offset  Size   Value              Meaning
------  -----  -----------------  ----------------------------------
0x0000  9 B    "Nostromoi\x00"    Magic bytes (proprietary marker)
0x0001  7 B    (padding/meta)     File version / internal IDs
0x0010  8 B    0x01BBDA00 ...     Internal pointers (not fully reversed)
0x0038  4 B    0x00001000         Block size (= 4096 bytes / 0x1000)
0x0058  4 B    0x00025000         Mgmt-Ptr (physical offset of management table)
0x0060  ...    0xDEADBEEF marker  Guard/sentinel values (multiple)
0x5020  7384 B Bitmap             Page allocation bitmap (1 bit = 1 × 512-B page)
```

**Example (hex dump offset 0x0000–0x007F):**

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

### 2.3 Page Bitmap (Offset 0x5020)

```
Offset 0x5020  Length 7384 B

Structure: 1 bit = 1 physical 512-B page
  Page N: Byte[N/8] & (1 << (N%8)) → 1=allocated, 0=free

Statistics of the sample file:
  Total pages:      59,072
  Allocated pages:  56,813  (96.2 %)
  Free pages:        2,259   (3.8 %)
  Allocated bytes:  29,088,256 (approx. 27.7 MB)

First 4 bitmap bytes: ff ff ff ff  (all pages 0–31 allocated)
```

---

## 3. Descriptor Blocks — the Central Index Format

### 3.1 Identification

Every descriptor block is **512 bytes** in size. Detection is based on field `w10` at byte offset +40 within the block:

```
CHUNK_ID = 0x00010013

Condition: uint32_LE(block[off+40]) == 0x00010013
```

The full scan traverses the file in 512-byte steps and checks this condition at every position.

### 3.2 Descriptor Block Layout (512 Bytes)

```
Word   Byte        Value       Meaning
Index  Offset
-----  ----------  ----------  ----------------------------------------
w0     0x00        variable    Internal checksum / hash (not fully reversed)
w1–w7  0x04–0x1F  variable    Further internal metadata
w8     0x20        variable    File offset reference (shifted)
w9     0x24        0x00000000  Padding / reserved
w10    0x28        0x00010013  CHUNK_ID — fixed recognition marker
w11    0x2C        variable    lenflag: flags[7:0] | (compressed_pages[31:8])
w12    0x30        variable    dst — virtual destination address of the block
w13    0x34        variable    src — virtual source address (0x60000 = mgmt_base)
w14    0x38        variable    Further internal pointers
w15    0x3C        variable    Further internal pointers
w16    0x40        variable    node_ptr — physical offset of the node structure
...    0x44–0x1FF  ...         Extension data / not reversed
```

The 65536-byte LZNT1-compressed payload begins **immediately after** the 512-byte header (at `file_off + 512`).

**Example descriptor at 0x00632E00:**

```
0x00632e00: 07 a2 3d 4d 25 f7 0d a6 05 6a 70 3b 64 45 02 5d  |..=M%....jp;dE.]|
0x00632e10: 08 00 00 00 f9 05 00 00 c8 0c 00 00 04 00 00 00  |................|
0x00632e20: 7c 8a aa 00 00 00 00 00 13 00 01 00 f1 00 01 00  ||...............| ← w10=0x00010013
0x00632e30: 00 00 b8 0c 00 00 06 00 70 01 7c 8a aa 16 00 11  |........p.|.....|
               ^^^^^^^^^^^           ^^^^^^^^^^^
               dst=0x000CB800        src=0x00060000 (mgmt_base)
```

Fields (LE read-out):
- `w10 @ 0x00632e28 = 0x00010013` ← CHUNK_ID ✓
- `w11 @ 0x00632e2C = 0x000100F1` → lenflag
- `w12 @ 0x00632e30 = 0x000CB800` → dst
- `w13 @ 0x00632e34 = 0x00060000` → src = mgmt_base
- `w16 @ 0x00632e40 = 0x00000604` → node_ptr

### 3.3 lenflag Decoding

```
lenflag = w11 (uint32 LE)

flags        = lenflag & 0xFF
logical_len  = (lenflag >> 8) * 0x10000

Example: lenflag=0x000100F1
  flags       = 0xF1
  logical_len = 0x00010 * 0x10000 = 0x100000 = 1 MB (max. payload)
```

### 3.4 Shadow Copies (WAL Principle)

HxStore uses a Write-Ahead-Log-like principle. For each `dst` address **multiple descriptor blocks** may exist:

- The block with the **highest `file_off`** is the current (primary) version.
- All earlier instances of the same `dst` are **shadow copies** — forensically relevant as predecessor versions (e.g. deleted or modified e-mails).

**Statistics of the sample file:**

```
Total descriptor blocks:   3,436
Unique DST values:           657
Shadow copies:             2,779  (= 3436 - 657)
```

---

## 4. Decompression Pipeline

### 4.1 Two-Stage LZNT1 Decompression

Every payload passes through two stages of compression:

```
raw_bytes (65536 B max.)
    → LZNT1 decompress → L1 (~10,000–60,000 B)
    → LZNT1 decompress → L2 (token stream, 2,000–30,000 B)
    → Token decoder    → HTML/MAPI (plain text)
```

**Example (DST 0x000CB800):**

```
raw:      65,536 B  (compressed slot)
L1:       13,423 B  (compression ratio 0.20×)
L2:        6,324 B  (compression ratio 0.47× relative to L1)
decoded:   6,416 B  (token-expanded plain text)
<html> position in decoded: byte 571
```

### 4.2 LZNT1 Chunk Header

Every LZNT1 stream consists of chained chunks:

```
Chunk header: 2 bytes (uint16 LE)
  Bit 15:      0 = uncompressed, 1 = compressed
  Bits [11:0]: data_length - 1  (max. 4096 bytes output per chunk)
  Bit 14:      always 1 (reserved)
  Header 0x0000 = end-of-stream

Example L1 header at file_off+512:
  Bytes: 80 0f
  uint16_LE = 0x0F80
  Bit 15 = 0 → uncompressed chunk
  Length = (0x0F80 & 0x0FFF) + 1 = 0xF81 = 3969 bytes
```

### 4.3 LZNT1 Back-Reference Encoding

For compressed chunks the dynamic bit-split rule applies:

```
Flag byte: Bit=0 → next byte is a literal
           Bit=1 → next 2 bytes are a back-reference

Back-reference uint16 LE:
  pos = len(output)
  o_shift = 12; l_mask = 0x0F
  while pos >= (1 << o_shift):
    l_mask = (l_mask >> 1) | 0x08
    o_shift -= 1
  offset = (ref >> (16 - o_shift)) + 1
  length = (ref & l_mask) + 3
```

---

## 5. Token Stream Format (L2 → Plain Text)

### 5.1 Grammar

The L2 format is a proprietary Microsoft token encoding with five token types:

```
Type      Detection                                     Behaviour
--------  --------------------------------------------  --------------------------
LITERAL   Single byte                                   → window + output
CTRL      b0 in [0x01–0x1F] excluding {0x09,0x0A,0x0D} → skip (no window write!)
STATIC1   b0 >= 0x80                                    → lookup STATIC1 (73 entries)
STATIC4   [b0][0x00][fN][bN] with fN >= 0xF0            → lookup STATIC4 (136 entries)
LZ77      [b0][0x00] with next byte < 0xF0              → window[-b0] → output
```

**Critical:** CTRL bytes must **not** be written to the window — otherwise the LZ77 window state corrupts all subsequent back-references (cascading error).

### 5.2 Processing Order

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
        i += 1                        # CTRL: skip, no window write
    else:
        literal(b0); i += 1           # LITERAL
```

### 5.3 Annotated Token Stream Example

From the L2 of a real e-mail record (DST 0x000CB800):

```
L2 bytes:  02 00 05 dd 01 07 02 00 f2 01 dc 02 00 00 a0 00 00 80 ...

[  0] 0x02 0x00            LZ77:    dist=2 → window[-2]
[  2] 0x05                 LITERAL: 0x05 (ctrl-like, written to window)
[  3] 0xDD                 STATIC1: → b'' (empty expansion, not yet reversed)
[  4] 0x01                 CTRL:    skip, no window write
[  5] 0x07                 LITERAL: 0x07
[  6] 0x02 0x00 0xF2 0x01  STATIC4: key=0200f201 → b'' (not yet reversed)
[ 10] 0xDC                 STATIC1: → b''
[ 11] 0x02 0x00            LZ77:    dist=2
...
[ 17] 0x80                 STATIC1: → b'<br>'
[ 26] 0xB7                 STATIC1: → b'><meta name="'
[ 28] 0xFF                 STATIC1: → b'-equiv="Content-Type"'
```

### 5.4 STATIC1 Table (selection, 73 entries total)

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

### 5.5 STATIC4 Table (selection, 136 entries total)

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

## 6. Record Types and Content Classification

### 6.1 Types by Content

```
Type         Detection in decoded output          Typical content
-----------  ------------------------------------  --------------------------------
html_body    decoded[0:100] contains b'<html'     HTML e-mail body only
mixed        decoded[50:] contains b'<html'       MAPI prefix + HTML body
mapi_blob    b'I\x00P\x00M\x00' in L2             MAPI property store (UTF-16LE)
binary       none of the above                    Attachment, index, unknown
```

### 6.2 MAPI Blob Structure

MAPI blobs contain UTF-16LE-encoded strings in a proprietary property store format. The strings are fragmented within the L2 stream by LZ77/STATIC tokens:

```
L2 raw data contains UTF-16LE fragments:
  "WG: BMW X5"               → subject
  "info@boatsman-logistic.de" → from address
  "IPM.Note"                 → message class
  "<abc123@domain.de>"       → message-ID
  "16.09.2024"               → date
```

**Extraction:** Regex scan on `(?:[\x20-\x7e]\x00){3,}` in L2, adjacent stitching at gap ≤ 12 bytes, then heuristic classification.

### 6.3 Mixed Record

```
L2: [MAPI prefix (token-encoded UTF-16LE metadata)]
         ↓ token decode
decoded: [binary MAPI properties][...]<html><head>...e-mail body...</html>
```

The HTML offset varies between 50 and several thousand bytes.

---

## 7. Deleted and Unindexed Records

### 7.1 Scan Strategies Overview

```
Strategy        Source                Forensic relevance
--------------  --------------------  ------------------------------------
A) active       Descriptor index      Current primary records (495)
B) shadow       Older desc copies     Previous versions / deleted mails
C) bitmap_alloc Bitmap pages outside  Mails after index removal
                the index
D) carve        All pages             Maximum extraction (high FP rate)
```

### 7.2 Bitmap Scan (Strategy C)

Pages that are marked as allocated in the bitmap but are **not referenced by any active descriptor**:

```
Procedure:
1. Mark all file_off ranges of all descriptors as "covered"
2. Process all bitmap pages outside "covered"
3. Attempt LZNT1 decompression at every 512-B page boundary
4. Quality check: ≥ 8 printable ASCII bytes in first 256 bytes decoded

Result on the sample file:
  Bitmap pages checked: ~6,600+
  Usable records:       6,661 (html_body, mixed, mapi_blob)
```

### 7.3 Statistics of the Sample File

```
Source    Records  Share    Typical content
--------  -------  ------   --------------------------------
active        495   5.4 %   Active e-mails, current index
shadow      2,075  22.5 %   Older versions / WAL copies
bitmap      6,661  72.2 %   Deleted / overwritten data
          -------
          9,231 total

  → HTML records (incl. mixed):  3,936
  → MAPI blobs:                  3,193
  → Binary:                      2,102
```

---

## 8. Output Formats

### 8.1 Flat-Decompressed (.decompressed)

**File header (64 bytes):**

```
Offset  Size   Content
------  -----  -------------------------------------------
0x00    24 B   ASCII "HXSTORE_DECOMPRESSED_V3\x00"
0x18     4 B   uint32 LE: original file size
0x1C     4 B   uint32 LE: reserved (0)
0x20    44 B   padding to 64 bytes
```

**Record header (16 bytes per record):**

```
Offset  Size   Type      Meaning
------  -----  --------  -------------------------------------------
0x00     4 B   ASCII     magic "HXR\x01"
0x04     4 B   uint32 LE file_off (physical origin in HxStore.hxd)
0x08     4 B   uint32 LE dst (virtual address, 0 = unknown)
0x0C     4 B   uint32 LE payload_len (length of the following payload)
0x10     N B   bytes     token-decoded payload
```

### 8.2 SQLite Database (.db)

The database is the primary analysis artefact and contains all records including decompressed HTML bodies:

```
Table: records
  id           INTEGER  Sequential ID
  file_off     TEXT     Physical offset in HxStore.hxd ("0x00167800")
  file_off_int INTEGER  Numeric (indexed, for sorting)
  dst          TEXT     Virtual DST address
  source       TEXT     "active" | "shadow" | "bitmap" | "carved"
  record_type  TEXT     "html_body" | "mixed" | "mapi_blob" | "binary"
  has_html     INTEGER  1 = HTML body present
  decoded_len  INTEGER  Length of decompressed payload
  subject      TEXT     Subject (from UTF-16LE extraction)
  from_addr    TEXT     Sender e-mail address
  to_addrs     TEXT     Recipients (comma-separated)
  message_id   TEXT     RFC-5322 message-ID
  html_body    TEXT     Full HTML body (only when has_html=1)

Table: meta
  key / value: statistics, source file, parser version
```

**Size comparison:**

```
Artefact                          Size    Content
---------------------------------  ------  ----------------------------------------
HxStore.hxd (original)             32 MB  Compressed, tokenised
Cellebrite .decompressed           128 MB  Flat-decompressed (UTF-16 raw, no decode)
Parser v3 .decompressed            246 MB  All records + token decode + record header
Parser v3 .db (SQLite)              91 MB  Structured, HTML bodies, full-text searchable
```

### 8.3 Interactive HTML Report (.report.html)

The report is generated automatically from the SQLite DB (1.6 MB) and contains all records as a paginated, filterable table. Filter chips allow direct selection by source and content:

```
CONTENT filters:  With HTML body | MAPI blobs
                  Mixed          | Binary
SOURCE filters:   Active | Shadow copies | Bitmap/deleted
```

Rows with an HTML body are marked with **●**. The HTML bodies themselves are retrievable via the SQLite DB.

---

## 9. Identified Limitations (Open Reverse-Engineering Tasks)

### 9.1 Incomplete STATIC1/STATIC4 Tables

```
Status:
  STATIC1: 73/256 entries known
  STATIC4: 136/? entries known

Symptom:    Unknown tokens produce empty expansions (b'')
Impact:     Parts of the HTML body appear empty instead of correct text

Extension method (GT alignment):
  For each unknown token b0 in L2:
    → determine position in decoded output
    → look up Cellebrite reference text at equivalent position
    → construct mapping
```

### 9.2 LZ77 Window Corruption

```
Problem: CTRL bytes (0x01–0x1F) may represent independent token types
         whose semantics are unknown.

Observation:
  - CTRL bytes interrupt the window state
  - Subsequent LZ77 back-references then point to wrong window positions
    → "cascading corruption"
  - Visible as: correct keywords + surrounding nonsense HTML

Hypotheses:
  a) CTRL = 2-byte token [ctrl_byte][param] with unknown expansion
  b) CTRL = control sequence (flush window, reset, etc.)
  c) CTRL bytes are actually data bytes in other contexts
```

### 9.3 Unknown Node/Extent Structure

```
Fields w16 (node_ptr) in descriptors point to a node structure.
This node contains (key, count) pairs that reference the mgmt_base
extent pool — an alternative reconstruction path for larger e-mails.

Status: Structure identified, but using it yields no better results
        than the direct inline path. May be relevant for
        multi-extent records (>64 KB).
```

### 9.4 MAPI Property IDs

```
Known MAPI property IDs in binary structures:
  0x0037 001F → Subject (PT_UNICODE)
  0x0C1A 001F → SenderName
  0x0039 0040 → ClientSubmitTime (PT_SYSTIME)
  0x0E04 001F → DisplayTo
  0x0E06 0040 → MessageDeliveryTime (PT_SYSTIME)
  0x001A 001E → MessageClass

Status: Parsing of fixed-size property structs not yet complete.
        UTF-16LE strings are currently extracted via regex stitching,
        not via structured property store parsing.
```

---

## 10. Forensic Recommendations

### 10.1 Recommended Toolchain

```
1. Extract HxStore.hxd (Cellebrite/UFED or manually via AFC2)

2. Run parser v3:
     python3 hxstore_parse.py \
       --hx HxStore.hxd \
       --out output/HxStore.hxd.decompressed \
       --deleted

3. Open HTML report: output/HxStore.hxd.report.html
   (filter by source, type, subject, sender directly in the browser)

4. SQLite DB for structured queries: output/HxStore.hxd.db
   (recommended: DB Browser for SQLite or DBeaver)

5. Export individual HTML bodies:
     python3 export_body.py list
     python3 export_body.py show <id>
     python3 export_body.py search "keyword"
```

---

## 11. Appendix: File System Artefacts

### 11.1 Related Files in the iOS File System

```
Path                                    Content
--------------------------------------  --------------------------------
HxStore.hxd                             Primary e-mail cache (this file)
HxStore.hxd-journal                     SQLite WAL (if present)
HxCoreStore/*/EFMData/*.dat             Attachment binary data (164.dat–275.dat)
HxCoreStore/*/Metadata.db              SQLite: folders, accounts, flags
HxCoreStore/*/SyncState/               Sync status with server
outlookcore/account_store.db            Account configuration
```

### 11.2 Timestamps

```
The file itself contains no POSIX timestamps in its headers.
Timestamp information can be found in:
  - MAPI property 0x0039 (ClientSubmitTime)     — MAPI blob parsing only
  - MAPI property 0x0E06 (MessageDeliveryTime)  — MAPI blob parsing only
  - iOS file system metadata (mtime of HxStore.hxd = last app activity)
  - Cellebrite extracts these from the MAPI binary format
```

---

*This document is based on reverse engineering of a real HxStore.hxd file (Outlook iOS / macOS). All structures have been verified through byte-level analysis, LZNT1 decompression tracing and comparison with the Cellebrite ground-truth output.*

*Version: Parser v3.0 (2026-03)*  
*Author: Marc Brandt*
