import json, struct, sqlite3, os
from datetime import datetime
from pathlib import Path
from decompressor import sha256
from btree_scanner import full_scan

MAGIC    = b'HXR\x01'
HDR_SIZE = 16


def _write_rec(fh, file_off, dst, payload):
    fh.write(struct.pack('<4sIII', MAGIC, file_off & 0xFFFFFFFF,
                         dst & 0xFFFFFFFF, len(payload)))
    fh.write(payload)


def _build_report(db_path, report_path):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    meta = dict(cur.execute("SELECT key,value FROM meta").fetchall())
    stats = {
        'total':  int(meta.get('total_records', 0)),
        'html':   int(meta.get('html_records',  0)),
        'mapi':   int(meta.get('mapi_blobs',    0)),
        'binary': int(meta.get('binary_records',0)),
        'shadow': cur.execute("SELECT COUNT(*) FROM records WHERE source='shadow'").fetchone()[0],
        'active': cur.execute("SELECT COUNT(*) FROM records WHERE source='active'").fetchone()[0],
        'bitmap': cur.execute("SELECT COUNT(*) FROM records WHERE source='bitmap'").fetchone()[0],
        'carved': cur.execute("SELECT COUNT(*) FROM records WHERE source='carved'").fetchone()[0],
        'mixed':  cur.execute("SELECT COUNT(*) FROM records WHERE record_type='mixed'").fetchone()[0],
    }

    rows = cur.execute("""
        SELECT id, file_off, dst, source, record_type, has_html,
               decoded_len, subject, from_addr, to_addrs, message_id
        FROM records ORDER BY file_off_int
    """).fetchall()

    senders = cur.execute("""
        SELECT from_addr, COUNT(*) as n FROM records
        WHERE from_addr IS NOT NULL GROUP BY from_addr ORDER BY n DESC LIMIT 20
    """).fetchall()
    con.close()

    rows_json = json.dumps([{
        'id':   r['id'],    'off': r['file_off'],  'dst': r['dst'],
        'src':  r['source'],'typ': r['record_type'],'html': r['has_html'],
        'sz':   r['decoded_len'], 'subj': r['subject'],
        'from': r['from_addr'],   'to':   r['to_addrs'],
        'mid':  r['message_id'],
    } for r in rows], ensure_ascii=False)

    senders_json = json.dumps([[r['from_addr'], r['n']] for r in senders], ensure_ascii=False)

    def e(s):
        if not s: return ''
        return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

    def fc(key, label, count, cls):
        return (f'<span class="fchip fc-{cls}" data-key="{key}" '
                f'onclick="toggleFilter(\'{key}\')">'
                f'{label} <b style="opacity:.65">({count:,})</b></span>')

    stat_html = ''.join(
        f'<div class="stat"><div class="n">{v:,}</div><div class="l">{k}</div></div>'
        for k, v in [
            ('Gesamt',          stats['total']),
            ('Mit HTML-Body',   stats['html']),
            ('MAPI-Blobs',      stats['mapi']),
            ('Aktiv',           stats['active']),
            ('Shadow Copies',   stats['shadow']),
            ('Bitmap/gelöscht', stats['bitmap']),
        ]
    )

    filter_chips = (
        '<span class="flabel">INHALT:</span>'
        + fc('html',   'Mit HTML-Body',  stats['html'],   'html')
        + fc('mapi',   'MAPI-Blobs',     stats['mapi'],   'mapi')
        + fc('mixed',  'Gemischt',       stats['mixed'],  'mixed')
        + fc('binary', 'Binär',          stats['binary'], 'binary')
        + '<span class="sep"></span>'
        + '<span class="flabel">QUELLE:</span>'
        + fc('active', 'Aktiv',           stats['active'], 'active')
        + fc('shadow', 'Shadow Copies',   stats['shadow'], 'shadow')
        + fc('bitmap', 'Bitmap/gelöscht', stats['bitmap'], 'bitmap')
    )
    if stats['carved'] > 0:
        filter_chips += fc('carved', 'Carved', stats['carved'], 'carved')

    CSS = """
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:0;background:#f0f2f5;color:#222}
header{background:#1a237e;color:#fff;padding:.9em 2em;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px rgba(0,0,0,.35)}
header h1{margin:0;font-size:1.25em;letter-spacing:.01em}
header p{margin:.15em 0 0;opacity:.7;font-size:.78em}
.container{padding:1em 2em 3em}
.stats{display:flex;gap:.8em;flex-wrap:wrap;margin:1em 0}
.stat{background:#fff;border-radius:10px;padding:.55em 1em;box-shadow:0 1px 4px rgba(0,0,0,.1);text-align:center;min-width:80px}
.stat .n{font-size:1.65em;font-weight:700;color:#1a237e}
.stat .l{font-size:.68em;color:#666;margin-top:.05em}
.filter-bar{display:flex;gap:.45em;align-items:center;flex-wrap:wrap;margin:.8em 0;background:#fff;padding:.65em 1em;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
.filter-bar input{flex:1;min-width:200px;padding:.35em .65em;border:1px solid #ccd;border-radius:6px;font-size:.85em;outline:none}
.filter-bar input:focus{border-color:#1a237e}
.sep{width:1px;height:22px;background:#e0e0e0;flex-shrink:0}
.flabel{font-size:.74em;color:#888;font-weight:600;white-space:nowrap}
.fchip{display:inline-flex;align-items:center;gap:.25em;padding:.26em .68em;border-radius:20px;font-size:.77em;font-weight:600;cursor:pointer;border:2px solid transparent;transition:all .12s;user-select:none;white-space:nowrap}
.fchip:hover{filter:brightness(.92)}
.fchip.active{border-color:#222!important;box-shadow:inset 0 0 0 1px #222}
.fc-html{background:#c8e6c9;color:#1b5e20}
.fc-mapi{background:#bbdefb;color:#0d47a1}
.fc-binary{background:#f5f5f5;color:#757575;border-color:#ddd}
.fc-mixed{background:#d1c4e9;color:#4a148c}
.fc-active{background:#c8e6c9;color:#1b5e20}
.fc-shadow{background:#e1bee7;color:#4a148c}
.fc-bitmap{background:#ffcdd2;color:#b71c1c}
.fc-carved{background:#ffe0b2;color:#e65100}
.clear-btn{padding:.28em .65em;border:1px solid #ccc;border-radius:6px;background:#fff;cursor:pointer;font-size:.77em;color:#555}
.clear-btn:hover{background:#e8eaf6}
.count-bar{font-size:.79em;color:#666;margin:.3em 0 .4em;padding-left:.2em}
.pager{display:flex;gap:.3em;align-items:center;margin:.35em 0;flex-wrap:wrap}
.pager button{padding:.2em .52em;border:1px solid #ccc;border-radius:5px;background:#fff;cursor:pointer;font-size:.8em;min-width:26px}
.pager button:hover:not(:disabled){background:#e8eaf6}
.pager button:disabled{opacity:.38;cursor:default}
.pager button.active{background:#1a237e;color:#fff;border-color:#1a237e}
.pager .pinfo{color:#777;font-size:.8em;margin:0 .25em}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;background:#fff;font-size:.78em;box-shadow:0 1px 4px rgba(0,0,0,.1)}
th{background:#1a237e;color:#fff;padding:.38em .5em;text-align:left;white-space:nowrap;position:sticky;top:3.1em;z-index:5}
td{padding:.28em .5em;border-bottom:1px solid #eee;vertical-align:top}
tr:hover td{background:#e8eaf6}
.t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.badge{display:inline-block;border-radius:8px;padding:.05em .4em;font-size:.75em;font-weight:600;white-space:nowrap}
.b-active{background:#c8e6c9;color:#1b5e20}
.b-shadow{background:#e1bee7;color:#4a148c}
.b-bitmap{background:#ffcdd2;color:#b71c1c}
.b-carved{background:#ffe0b2;color:#e65100}
.b-html_body{background:#c8e6c9;color:#1b5e20}
.b-mixed{background:#d1c4e9;color:#4a148c}
.b-mapi_blob{background:#bbdefb;color:#0d47a1}
.b-binary{background:#f5f5f5;color:#757575}
.html-dot{color:#2e7d32;font-weight:700;margin-left:.2em}
.section{margin:1.4em 0}
.section-title{font-size:.8em;font-weight:600;color:#888;margin-bottom:.4em;text-transform:uppercase;letter-spacing:.05em}
.senders-list{display:flex;gap:.3em;flex-wrap:wrap}
.sender-chip{background:#e3f2fd;color:#0d47a1;border-radius:12px;padding:.1em .5em;font-size:.75em;cursor:pointer;border:1px solid transparent}
.sender-chip:hover{background:#1a237e;color:#fff}
"""

    JS = (
        f"const ROWS={rows_json};\n"
        f"const SENDERS={senders_json};\n"
        """
const PAGE_SIZE = 100;
let filtered = ROWS, page = 0, activeFilters = new Set();

function e(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function badge(c,t){ return `<span class="badge ${c}">${t}</span>`; }

function toggleFilter(key){
  activeFilters.has(key) ? activeFilters.delete(key) : activeFilters.add(key);
  document.querySelectorAll('.fchip').forEach(c => c.classList.toggle('active', activeFilters.has(c.dataset.key)));
  page = 0; applyFilters();
}

function applyFilters(){
  const q   = document.getElementById('search').value.toLowerCase().trim();
  const src = ['active','shadow','bitmap','carved'].filter(k => activeFilters.has(k));
  const typ = ['html','mapi','mixed','binary'].filter(k => activeFilters.has(k));
  filtered = ROWS.filter(r => {
    if(src.length && !src.includes(r.src)) return false;
    if(typ.length){
      const ok =
        (typ.includes('html')   && r.html) ||
        (typ.includes('mapi')   && r.typ==='mapi_blob') ||
        (typ.includes('mixed')  && r.typ==='mixed') ||
        (typ.includes('binary') && r.typ==='binary');
      if(!ok) return false;
    }
    if(q){ const h=[r.subj,r.from,r.to,r.mid,r.off,r.dst].filter(Boolean).join(' ').toLowerCase(); if(!h.includes(q)) return false; }
    return true;
  });
  render();
}

function clearFilters(){
  activeFilters.clear();
  document.getElementById('search').value='';
  document.querySelectorAll('.fchip').forEach(c=>c.classList.remove('active'));
  filtered=ROWS; page=0; render();
}

function render(){
  const total=filtered.length, pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  if(page>=pages) page=pages-1;
  const slice=filtered.slice(page*PAGE_SIZE,(page+1)*PAGE_SIZE);
  document.getElementById('countBar').textContent=`${total.toLocaleString()} von ${ROWS.length.toLocaleString()} Records`;
  let html='';
  for(const r of slice){
    const dot=r.html?'<span class="html-dot" title="HTML-Body in DB">●</span>':'';
    html+=`<tr>
      <td><span class="t" style="width:90px">${e(r.off)}</span></td>
      <td><span class="t" style="width:90px">${e(r.dst)}</span></td>
      <td>${badge('b-'+r.typ,r.typ)}</td>
      <td>${badge('b-'+r.src,r.src)}</td>
      <td><span class="t" style="width:165px">${e(r.from||'')}</span></td>
      <td><span class="t" style="width:120px">${e(r.to||'')}</span></td>
      <td><span class="t" style="width:265px">${e(r.subj||'')+dot}</span></td>
      <td><span class="t" style="width:155px;font-size:.74em;color:#aaa">${e(r.mid||'')}</span></td>
      <td style="text-align:right;color:#bbb;white-space:nowrap">${(r.sz||0).toLocaleString()}</td>
    </tr>`;
  }
  document.getElementById('tbody').innerHTML=html;
  const h=buildPager(pages);
  document.getElementById('pager').innerHTML=h;
  document.getElementById('pager2').innerHTML=h;
}

function buildPager(pages){
  const p=page;
  let h=`<span class="pinfo">Seite ${p+1}/${pages}</span>`;
  h+=`<button onclick="gp(0)" ${p===0?'disabled':''}>«</button>`;
  h+=`<button onclick="gp(${p-1})" ${p===0?'disabled':''}>‹</button>`;
  const s=Math.max(0,p-2),en=Math.min(pages,s+5);
  for(let i=s;i<en;i++) h+=`<button class="${i===p?'active':''}" onclick="gp(${i})">${i+1}</button>`;
  h+=`<button onclick="gp(${p+1})" ${p>=pages-1?'disabled':''}>›</button>`;
  h+=`<button onclick="gp(${pages-1})" ${p>=pages-1?'disabled':''}>»</button>`;
  return h;
}

function gp(p){ if(p>=0 && p<Math.ceil(filtered.length/PAGE_SIZE)){page=p;render();} }
function filterSender(a){ document.getElementById('search').value=a; applyFilters(); document.getElementById('tbl').scrollIntoView({behavior:'smooth'}); }

window.onload=()=>{
  let chips='';
  for(const [addr,n] of SENDERS)
    chips+=`<span class="sender-chip" onclick="filterSender('${addr.replace(/'/g,"\\'")}'">${e(addr)} <b style="opacity:.6">(${n})</b></span>`;
  document.getElementById('senderChips').innerHTML=chips;
  render();
};
"""
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>HxStore Forensic Report v3</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>🔍 HxStore Forensic Report v3</h1>
  <p>Outlook iOS Cache · Parser v3.0 · HTML-Bodies → <b>hxstore_forensic.db</b></p>
</header>
<div class="container">

<div class="stats">{stat_html}</div>

<div class="section">
  <div class="section-title">Top Absender — Klick zum Filtern</div>
  <div class="senders-list" id="senderChips"></div>
</div>

<div id="tbl">
  <div class="filter-bar">
    <input type="text" id="search"
           placeholder="Suche: Betreff, Von, An, Message-ID, Offset …"
           oninput="applyFilters()">
    <span class="sep"></span>
    {filter_chips}
    <span class="sep"></span>
    <button class="clear-btn" onclick="clearFilters()">✕ Reset</button>
  </div>
  <div class="count-bar" id="countBar"></div>
  <div class="pager" id="pager"></div>
  <div class="wrap">
    <table>
      <thead><tr>
        <th>file_off</th><th>DST</th><th>Typ</th><th>Quelle</th>
        <th>Von</th><th>An</th>
        <th>Betreff <span style="color:#90caf9;font-weight:400">● = HTML-Body</span></th>
        <th>Message-ID</th><th>Bytes</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <div class="pager" id="pager2"></div>
</div>

</div>
<script>{JS}</script>
</body>
</html>"""

    with open(report_path, 'w', encoding='utf-8') as fh:
        fh.write(html_doc)


def write_flat(hx, idx, out_path, include_deleted=True,
               include_carved=False, verbose=False):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    db_path     = out_path.with_suffix('.db')
    report_path = out_path.with_suffix('.report.html')

    if db_path.exists():
        os.remove(db_path)

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE records (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            file_off     TEXT NOT NULL,
            file_off_int INTEGER NOT NULL,
            dst          TEXT NOT NULL,
            source       TEXT NOT NULL,
            record_type  TEXT NOT NULL,
            has_html     INTEGER NOT NULL DEFAULT 0,
            decoded_len  INTEGER NOT NULL DEFAULT 0,
            subject      TEXT,
            from_addr    TEXT,
            to_addrs     TEXT,
            message_id   TEXT,
            html_body    TEXT
        );
        CREATE INDEX idx_source      ON records(source);
        CREATE INDEX idx_type        ON records(record_type);
        CREATE INDEX idx_has_html    ON records(has_html);
        CREATE INDEX idx_from_addr   ON records(from_addr);
        CREATE INDEX idx_subject     ON records(subject);
        CREATE INDEX idx_file_off    ON records(file_off_int);
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    """)

    stats = {'total':0,'html_body':0,'mapi_blob':0,'mixed':0,'binary':0}
    batch = []

    with open(out_path, 'wb') as fh:
        hdr = b'HXSTORE_DECOMPRESSED_V3\x00' + struct.pack('<II', hx.size, 0)
        fh.write(hdr.ljust(64, b'\x00'))

        for rec in full_scan(hx, idx, include_deleted=include_deleted,
                              include_carved=include_carved, verbose=verbose):
            _write_rec(fh, rec.file_off, rec.dst, rec.decoded)
            stats['total'] += 1
            stats[rec.record_type] = stats.get(rec.record_type, 0) + 1

            html_body = None
            if rec.has_html:
                try:    html_body = rec.html_body.decode('utf-8',  errors='replace')
                except: html_body = rec.html_body.decode('latin-1',errors='replace')

            batch.append((
                f'0x{rec.file_off:08x}', rec.file_off,
                f'0x{rec.dst:08x}', rec.source, rec.record_type,
                1 if rec.has_html else 0, len(rec.decoded),
                rec.subject, rec.from_addr,
                ', '.join(rec.to_addrs) if rec.to_addrs else None,
                rec.message_id, html_body
            ))

            if len(batch) >= 500:
                cur.executemany("""
                    INSERT INTO records
                      (file_off,file_off_int,dst,source,record_type,has_html,decoded_len,
                       subject,from_addr,to_addrs,message_id,html_body)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, batch)
                con.commit(); batch.clear()

            if verbose and stats['total'] % 500 == 0:
                print(f'  [{stats["total"]:6d}] off=0x{rec.file_off:08x}'
                      f' type={rec.record_type:<10} src={rec.source}')

    if batch:
        cur.executemany("""
            INSERT INTO records
              (file_off,file_off_int,dst,source,record_type,has_html,decoded_len,
               subject,from_addr,to_addrs,message_id,html_body)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, batch)
        con.commit()

    out_mb = out_path.stat().st_size / 1024 / 1024
    db_mb  = db_path.stat().st_size  / 1024 / 1024

    meta = {
        'source_file':    str(hx.path),
        'total_records':  stats['total'],
        'html_records':   stats.get('html_body',0) + stats.get('mixed',0),
        'mapi_blobs':     stats.get('mapi_blob',0),
        'binary_records': stats.get('binary',0),
        'shadow_copies':  sum(1 for d in idx._all if not idx.is_primary(d)),
        'parser_version': 'v3.0',
        'generated_at':   datetime.now().isoformat(),
    }
    for k, v in meta.items():
        cur.execute("INSERT INTO meta VALUES (?,?)", (k, str(v)))
    con.commit(); con.close()

    _build_report(db_path, report_path)

    if verbose:
        html_n = stats.get('html_body',0) + stats.get('mixed',0)
        print(f'\n[+] {out_path}        {out_mb:.1f} MB')
        print(f'    {db_path}          {db_mb:.1f} MB')
        print(f'    {report_path}')
        print(f'    total={stats["total"]}  html={html_n}'
              f'  mapi={stats.get("mapi_blob",0)}')

    return {**stats, 'out_mb': out_mb, 'db_mb': db_mb}


if __name__ == '__main__':
    import argparse, sys, time
    sys.path.insert(0, str(Path(__file__).parent))
    from hxstore_io import HxStoreFile
    from descriptor_index import DescriptorIndex

    ap = argparse.ArgumentParser(
        prog='flat_exporter',
        description='HxStore.hxd → flat decompressed + SQLite DB + HTML Report'
    )
    ap.add_argument('--hx',      required=True)
    ap.add_argument('--out',     required=True)
    ap.add_argument('--deleted', action='store_true')
    ap.add_argument('--carved',  action='store_true')
    ap.add_argument('-v','--verbose', action='store_true')
    args = ap.parse_args()

    t0 = time.time()
    with HxStoreFile(args.hx) as hx:
        idx   = DescriptorIndex.build(hx, verbose=args.verbose)
        print(f'[+] {idx.stats()}')
        stats = write_flat(hx, idx, args.out,
                           include_deleted=args.deleted,
                           include_carved=args.carved,
                           verbose=args.verbose)
    print(f'[+] Done in {time.time()-t0:.1f}s — {stats}')
