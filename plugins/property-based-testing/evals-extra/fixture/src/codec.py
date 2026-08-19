"""Wire format codec."""

import struct
from urllib.parse import quote


def pack(msg: dict) -> bytes:
    body = msg["body"].encode("utf-8")
    return struct.pack("!IH", msg["id"], len(body)) + body


def unpack(data: bytes) -> dict:
    mid, n = struct.unpack("!IH", data[:6])
    return {"id": mid, "body": data[6 : 6 + n].decode("utf-8")}


def canonicalize_url(u: str) -> str:
    """Canonicalize a URL: trim, lowercase, percent-encode unsafe characters."""
    return quote(u.strip().lower(), safe="/:?#[]@!$&'()*+,;=")
