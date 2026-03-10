#!/usr/bin/env python3
import argparse, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from hxstore_io      import HxStoreFile
from descriptor_index import DescriptorIndex
from flat_exporter   import write_flat


def main():
    ap = argparse.ArgumentParser(
        prog='hxstore_parse',
        description='HxStore.hxd Forensic Parser v3 — Hochschule für Polizei BW'
    )
    ap.add_argument('--hx',      required=True,  help='HxStore.hxd input file')
    ap.add_argument('--out',     required=True,  help='Output .decompressed file')
    ap.add_argument('--deleted', action='store_true',
                    help='Include shadow copies and bitmap-allocated deleted records')
    ap.add_argument('--carved',  action='store_true',
                    help='LZNT1 carving pass (slow, more false positives)')
    ap.add_argument('-v','--verbose', action='store_true')
    ap.add_argument('--list-descriptors', action='store_true',
                    help='Print all descriptor blocks and exit')
    args = ap.parse_args()

    t0 = time.time()
    print(f'[+] HxStore Forensic Parser v3')
    print(f'    Input:  {args.hx}')
    print(f'    Output: {args.out}')

    with HxStoreFile(args.hx) as hx:
        print(f'    {hx}')
        idx = DescriptorIndex.build(hx, verbose=args.verbose)
        print(f'    {idx.stats()}')

        if args.list_descriptors:
            for d in sorted(idx._all, key=lambda d: d.file_off):
                primary = '*' if idx.is_primary(d) else ' '
                print(f'  {primary} off=0x{d.file_off:08x}  dst=0x{d.dst:08x}'
                      f'  lenflag=0x{d.lenflag:08x}  w16=0x{d.w16:08x}')
            return

        stats = write_flat(
            hx, idx, args.out,
            include_deleted=args.deleted,
            include_carved=args.carved,
            verbose=args.verbose,
        )

    elapsed = time.time() - t0
    print(f'\n[+] Fertig in {elapsed:.1f}s')
    print(f'    Records: {stats["total"]} gesamt')
    print(f'      HTML:    {stats.get("html_body", 0) + stats.get("mixed", 0)}')
    print(f'      MAPI:    {stats.get("mapi_blob", 0)}')
    print(f'      Binär:   {stats.get("binary", 0)}')
    print(f'    Ausgabe: {stats.get("out_mb", 0):.1f} MB (.decompressed)'
          f'  |  DB: {stats.get("db_mb", 0):.1f} MB')


if __name__ == '__main__':
    main()
