import mmap, struct, os
from pathlib import Path

class HxStoreReadError(Exception): pass

class HxStoreFile:
    MAGIC        = b'Nostromoi'
    OFF_BLOCKSIZE = 0x38
    OFF_MGMTPTR   = 0x58
    OFF_BITMAP    = 0x5020
    BITMAP_SIZE   = 7384

    def __init__(self, path):
        self.path = Path(path)
        self._f   = open(self.path, 'rb')
        self._mm  = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.size = self._mm.size()
        if self.size < 0x6D00 or self._mm[0:9] != self.MAGIC:
            raise HxStoreReadError(f'Invalid HxStore: {path}')

    def read(self, off, n):
        if off < 0 or off + n > self.size:
            raise HxStoreReadError(f'read({off:#x},{n}) OOB')
        return self._mm[off:off+n]

    def u32(self, off):
        return struct.unpack_from('<I', self._mm, off)[0]

    def u16(self, off):
        return struct.unpack_from('<H', self._mm, off)[0]

    def words128(self, off):
        return struct.unpack_from('<128I', self._mm, off)

    @property
    def block_size(self): return self.u32(self.OFF_BLOCKSIZE)
    @property
    def mgmt_ptr(self):   return self.u32(self.OFF_MGMTPTR)
    @property
    def bitmap(self):     return bytes(self._mm[self.OFF_BITMAP:self.OFF_BITMAP+self.BITMAP_SIZE])

    def bitmap_allocated(self, page):
        bi, bt = divmod(page, 8)
        return bi < self.BITMAP_SIZE and bool(self.bitmap[bi] & (1 << bt))

    def close(self):
        self._mm.close(); self._f.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def __repr__(self):
        return f'HxStoreFile({self.path.name!r} size={self.size:#x})'
