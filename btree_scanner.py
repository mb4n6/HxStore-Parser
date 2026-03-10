import struct
from hxstore_io import HxStoreFile
from descriptor_index import DescriptorIndex
from decompressor import lznt1_decompress
from token_decoder import decode_tokens, extract_utf16_strings, classify_mapi_strings
from models import ScannedRecord


def _classify(decoded, l2):
    html_off = decoded.find(b'<html')
    if html_off < 0: html_off = decoded.find(b'<HTML')
    if html_off >= 0:
        return 'mixed' if html_off > 50 else 'html_body', html_off
    if b'\x00I\x00P\x00M\x00' in l2 or b'I\x00P\x00M\x00' in l2:
        return 'mapi_blob', -1
    return 'binary', -1


def _enrich(rec):
    strings = extract_utf16_strings(rec.l2_bytes)
    meta    = classify_mapi_strings(strings)
    rec.subject    = meta.get('subject')
    rec.from_addr  = meta.get('from_addr')
    rec.to_addrs   = meta.get('to_addrs', [])
    rec.message_id = meta.get('message_id')
    return rec


def _try_decode(raw, file_off, dst, source):
    try:
        l1 = lznt1_decompress(raw[:65536])
        if not l1 or len(l1) < 32: return None
        l2 = lznt1_decompress(l1)
        if not l2 or len(l2) < 16: return None
        decoded  = decode_tokens(l2)
        if sum(1 for b in decoded[:256] if 0x20 <= b <= 0x7e) < 8: return None
        rtype, html_off = _classify(decoded, l2)
        rec = ScannedRecord(
            source=source, file_off=file_off, dst=dst,
            l2_bytes=l2, decoded=decoded,
            html_offset=html_off, record_type=rtype
        )
        return _enrich(rec)
    except Exception:
        return None


def scan_active(hx, idx, verbose=False):
    count = 0
    for d in sorted(idx._by_dst.values(), key=lambda d: d.file_off):
        avail = hx.size - d.data_off
        if avail < 8: continue
        rec = _try_decode(hx.read(d.data_off, min(65536, avail)),
                          d.file_off, d.dst, 'active')
        if rec:
            count += 1
            if verbose and count % 100 == 0: print(f'  [active] {count}')
            yield rec
    if verbose: print(f'[active] {count} records')


def scan_shadows(hx, idx, verbose=False):
    primary = {d.file_off for d in idx._by_dst.values()}
    count = 0
    for d in idx._all:
        if d.file_off in primary: continue
        avail = hx.size - d.data_off
        if avail < 8: continue
        rec = _try_decode(hx.read(d.data_off, min(65536, avail)),
                          d.file_off, d.dst, 'shadow')
        if rec:
            count += 1
            if verbose and count % 200 == 0: print(f'  [shadow] {count}')
            yield rec
    if verbose: print(f'[shadow] {count} records')


def scan_bitmap(hx, idx, verbose=False):
    covered = set()
    for d in idx._all:
        covered.add(d.file_off)
        for pg in range(d.data_off, d.data_off + 65536, 512):
            covered.add(pg)
    count = 0
    bm = hx.bitmap
    for byte_idx in range(hx.BITMAP_SIZE):
        byt = bm[byte_idx]
        if not byt: continue
        for bit in range(8):
            if not (byt & (1 << bit)): continue
            off = (byte_idx * 8 + bit) * 512
            if off + 512 > hx.size or off in covered: continue
            try:
                raw = hx.read(off, min(65536, hx.size - off))
            except Exception: continue
            rec = _try_decode(raw, off, 0, 'bitmap')
            if rec and rec.record_type in ('html_body', 'mapi_blob', 'mixed'):
                count += 1
                if verbose and count % 500 == 0: print(f'  [bitmap] {count}')
                yield rec
    if verbose: print(f'[bitmap] {count} records')


def scan_carve(hx, idx, step=512, verbose=False):
    indexed = {d.file_off for d in idx._all}
    count = 0
    for off in range(0, hx.size - 512, step):
        if off in indexed: continue
        try:
            hdr = struct.unpack_from('<H', hx._mm, off)[0]
        except Exception: break
        if hdr == 0: continue
        sz = (hdr & 0x0FFF) + 1
        if sz < 4 or sz > 4096: continue
        try:
            raw = hx.read(off, min(65536, hx.size - off))
        except Exception: continue
        rec = _try_decode(raw, off, 0, 'carved')
        if rec and rec.record_type in ('html_body', 'mapi_blob', 'mixed'):
            count += 1
            if verbose and count % 1000 == 0: print(f'  [carve] {count}')
            yield rec
    if verbose: print(f'[carve] {count} records')


def full_scan(hx, idx, include_deleted=True, include_carved=False, verbose=False):
    seen = set()
    def emit(rec):
        if rec and rec.file_off not in seen:
            seen.add(rec.file_off)
            return rec

    for rec in scan_active(hx, idx, verbose):
        r = emit(rec)
        if r: yield r
    if include_deleted:
        for rec in scan_shadows(hx, idx, verbose):
            r = emit(rec)
            if r: yield r
        for rec in scan_bitmap(hx, idx, verbose):
            r = emit(rec)
            if r: yield r
    if include_carved:
        for rec in scan_carve(hx, idx, verbose=verbose):
            r = emit(rec)
            if r: yield r
