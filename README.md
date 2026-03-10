# HxStore.hxd Parser v3

**HfPolBW | Marc Brandt | mb4n6**  
Educational Tool (PoC) for analysing the Microsoft Outlook iOS e-mail cache

---

## Overview

`HxStore.hxd` is the proprietary offline cache of the Outlook app for iOS. The parser extracts all e-mails, MAPI metadata and deleted records via two-stage LZNT1 decompression and token decoding.

**Output:**
- `.decompressed` — Flat-decompressed records
- `.db` — SQLite database with HTML bodies, full-text searchable
- `.report.html` — Interactive browser report with filter chips

---

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

---

## Quick Start

```bash
# Extract all records including deleted data
python3 hxstore_parse.py \
  --hx HxStore.hxd \
  --out output/HxStore.hxd.decompressed \
  --deleted

# Open the report in a browser
open output/HxStore.hxd.report.html
```

---

## Parameters

```
hxstore_parse.py --hx <FILE> --out <OUTPUT> [options]

Required:
  --hx PATH       Path to the HxStore.hxd input file
  --out PATH      Output path for .decompressed (DB and report are created alongside)

Options:
  --deleted       Include shadow copies and bitmap-allocated deleted records
                  (recommended for full forensic extraction)
  --carved        Additional LZNT1 carving pass over all pages
                  (slower, higher false-positive rate)
  -v, --verbose   Progress output during extraction
  --list-descriptors
                  Print all descriptor blocks and exit
```

---

## Output Files

Three files are created side by side after running:

| File | Content | Size |
|------|---------|------|
| `*.decompressed` | Flat binary, all records with 16-byte header | ~246 MB |
| `*.db` | SQLite: records + HTML bodies + metadata | ~91 MB |
| `*.report.html` | Interactive browser-based report | ~1.6 MB |

---

## HTML Report

Open the report in a browser:

```bash
open output/HxStore.hxd.report.html
# or
firefox output/HxStore.hxd.report.html
```

**Filter chips** at the top of the toolbar allow direct selection:

- **CONTENT:** `With HTML Body` · `MAPI Blobs` · `Mixed` · `Binary`
- **SOURCE:** `Active` · `Shadow Copies` · `Bitmap/Deleted`
- Free-text search by subject, sender, message-ID, or offset

Rows with `●` contain an HTML body retrievable from the SQLite DB.

---

## SQLite Database

Open with DB Browser for SQLite, DBeaver, or via CLI:

```bash
sqlite3 output/HxStore.hxd.db
```

**Key queries:**

```sql
-- All e-mails with HTML body
SELECT id, file_off, subject, from_addr, html_body
FROM records WHERE has_html = 1;

-- Deleted mails (shadow + bitmap) with subject
SELECT file_off, source, subject, from_addr
FROM records
WHERE source IN ('shadow', 'bitmap') AND subject IS NOT NULL
ORDER BY file_off_int;

-- Statistics by source
SELECT source, record_type, COUNT(*) as n, SUM(has_html) as with_html
FROM records GROUP BY source, record_type ORDER BY n DESC;
```

---

## HTML Body Export (export_body.py)

```bash
# List all mails with HTML body
python3 export_body.py list

# Full-text search
python3 export_body.py search "keyword"

# Open body with ID 42 directly in browser
python3 export_body.py show 42

# Save body as HTML file
python3 export_body.py save 42 mail_42.html
```

---

## Module Overview

```
parser/
├── hxstore_parse.py      CLI entry point
├── flat_exporter.py      Main export: .decompressed + .db + .report.html
├── btree_scanner.py      4 scan strategies (active/shadow/bitmap/carve)
├── token_decoder.py      STATIC1 (73) + STATIC4 (136) token tables + decoder
├── descriptor_index.py   Descriptor block scan and index
├── decompressor.py       Two-stage LZNT1 decompression
├── models.py             Data classes (Descriptor, ScannedRecord, MailArtifact)
└── hxstore_io.py         File I/O and bitmap access
```

---

## Scan Strategies

| Strategy | `--deleted` | Records (example) | Description |
|----------|------------|-------------------|-------------|
| active | no | 495 | Current descriptor index |
| shadow | yes | 2,075 | Older versions / WAL |
| bitmap | yes | 6,661 | Pages remaining after index removal |
| carve | `--carved` | variable | Maximum extraction, higher FP rate |

---

## Limitations

- **STATIC1/STATIC4:** Token mappings only partially known. Unknown tokens produce empty expansions → parts of the HTML body are missing (to do!)
- **CTRL bytes (0x01–0x1F):** Semantics unknown. Can corrupt the LZ77 window → cascading decode errors.
- **MAPI timestamps:** `ClientSubmitTime` (0x0039) and `MessageDeliveryTime` (0x0E06) are not yet parsed structurally.
- **Multi-extent records:** E-mails > 64 KB may use the node/extent structure (w16), which has not yet been fully reverse-engineered.

---

## Technical Reference

Documentation of the HxStore format, all hex structures and current reversing status:

→ `HxStore_hxd_Forensisches_Whitepaper.tex`

---

## License

This tool is provided for educational and forensic research purposes.  
Use only on systems you own or have explicit authorisation to examine.  
It is not a replacement for certified forensic software and must not be used in operational casework or legal evidence processing.

*Parser v3.0 · March 2026 · Marc Brandt | mb4n6*
