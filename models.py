from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Descriptor:
    file_off: int
    chunk_id: int
    lenflag:  int
    dst:      int
    src:      int
    w16:      int

    @property
    def page_base(self):   return self.dst & ~0xFFF
    @property
    def flags(self):        return self.lenflag & 0xFF
    @property
    def logical_len(self):  return (self.lenflag >> 8) * 0x10000
    @property
    def data_off(self):     return self.file_off + 512

@dataclass
class ScannedRecord:
    source:      str
    file_off:    int
    dst:         int
    l2_bytes:    bytes
    decoded:     bytes
    html_offset: int = -1
    record_type: str = 'binary'
    subject:     Optional[str] = None
    from_addr:   Optional[str] = None
    to_addrs:    list = field(default_factory=list)
    message_id:  Optional[str] = None

    @property
    def has_html(self): return self.html_offset >= 0
    @property
    def html_body(self):
        return self.decoded[self.html_offset:] if self.html_offset >= 0 else None

@dataclass
class MailArtifact:
    record_id:   int
    dst:         int
    source:      str
    file_off:    int
    from_:       Optional[str] = None
    to:          Optional[str] = None
    subject:     Optional[str] = None
    date:        Optional[str] = None
    message_id:  Optional[str] = None
    body_html:   Optional[str] = None
    body_text:   Optional[str] = None
    sha256_body: Optional[str] = None

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v is not None}
