import struct, hashlib

class DecompressError(Exception): pass

def _lznt1_chunk(data, compressed):
    if not compressed:
        return bytes(data[:4096])
    out = bytearray()
    j = 0
    while j < len(data) and len(out) < 4096:
        if j >= len(data): break
        flags = data[j]; j += 1
        for bit in range(8):
            if j >= len(data) or len(out) >= 4096: break
            if flags & (1 << bit):
                if j + 1 >= len(data): break
                ref = struct.unpack_from('<H', data, j)[0]; j += 2
                pos = len(out)
                l_mask, o_shift = 0xF, 12
                while pos >= (1 << o_shift):
                    l_mask = (l_mask >> 1) | 0x8
                    o_shift -= 1
                length = (ref & l_mask) + 3
                offset = (ref >> (16 - o_shift)) + 1
                for _ in range(length):
                    out.append(out[-offset] if offset <= len(out) else 0)
            else:
                out.append(data[j]); j += 1
    return bytes(out)

def lznt1_decompress(buf, max_out=0x400000):
    buf = bytes(buf) if isinstance(buf, memoryview) else buf
    result = bytearray()
    i = 0
    while i + 1 < len(buf) and len(result) < max_out:
        hdr = struct.unpack_from('<H', buf, i)[0]
        if hdr == 0: break
        i += 2
        compressed = bool(hdr & 0x8000)
        data_len   = min((hdr & 0x0FFF) + 1, len(buf) - i)
        chunk      = buf[i:i+data_len]; i += data_len
        out        = _lznt1_chunk(chunk, compressed)
        result.extend(out[:max_out - len(result)])
    return bytes(result)

def decompress_extent(raw):
    raw = bytes(raw) if isinstance(raw, memoryview) else raw
    l1  = lznt1_decompress(raw)
    if not l1: return b''
    l2  = lznt1_decompress(l1)
    if l2 and len(l2) >= max(len(l1) // 4, 256):
        return l2
    return l1

def sha256(data):
    return hashlib.sha256(data).hexdigest()
