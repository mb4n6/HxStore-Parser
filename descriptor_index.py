import struct
from hxstore_io import HxStoreFile
from models import Descriptor

CHUNK_ID = 0x00010013

class DescriptorIndex:
    def __init__(self):
        self._all       = []
        self._by_dst    = {}
        self._by_off    = {}
        self._by_page   = {}

    @classmethod
    def build(cls, hx, verbose=False):
        idx = cls()
        for off in range(0, hx.size - 512, 512):
            try:
                if hx.u32(off + 40) != CHUNK_ID: continue
                words = hx.words128(off)
            except Exception: break
            d = Descriptor(
                file_off=off, chunk_id=words[10], lenflag=words[11],
                dst=words[12], src=words[13], w16=words[16]
            )
            idx._all.append(d)
            idx._by_off[off] = d
            idx._by_page.setdefault(d.page_base, []).append(d)
            ex = idx._by_dst.get(d.dst)
            if ex is None or off > ex.file_off:
                idx._by_dst[d.dst] = d
        if verbose:
            print(f'[idx] {len(idx._all)} descriptors, {len(idx._by_dst)} unique DST')
        return idx

    def by_dst(self, dst):      return self._by_dst.get(dst)
    def all_by_dst(self, dst):  return sorted([d for d in self._all if d.dst == dst], key=lambda d: d.file_off)
    def is_primary(self, d):    return self._by_dst.get(d.dst) is d

    def stats(self):
        return {'total': len(self._all), 'unique_dst': len(self._by_dst),
                'shadow_copies': len(self._all) - len(self._by_dst)}
