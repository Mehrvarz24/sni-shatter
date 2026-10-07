"""sni-shatter — DPI desynchronization strategies.

Every strategy here is original code written for this project. The underlying
ideas (TCP segmentation at the SNI boundary, TLS-record fragmentation, fake
packets with a wrong sequence number) are public, published techniques; no
source code was copied from other projects.

Tier 1 (default) works with an ordinary user-space TCP socket: no admin rights,
no driver, no raw sockets. It only needs to *segment* the ClientHello so the
censor's middlebox never sees the whole hostname in one message.
"""
import socket
import time

from .clienthello import find_sni_offsets

# ---------------------------------------------------------------- positions ---


def resolve_position(pos, hello: bytes) -> int:
    """Turn a symbolic split position into a byte offset in `hello`."""
    if isinstance(pos, int):
        return max(1, min(pos, len(hello) - 1))
    off = find_sni_offsets(hello)
    name = hello[off["sni_start"]:off["sni_end"]]
    if pos in ("sni", "sniext"):
        base = off["sni_start"]
    elif pos in ("sni+1", "sniext+1"):
        base = off["sni_start"] + 1
    elif pos in ("snilen",):
        base = off["sni_len_pos"]
    elif pos == "midsld":
        # middle of the second-level domain label (e.g. examp|le.com)
        dot = name.rfind(b".", 0, name.rfind(b"."))
        base = off["sni_start"] + (dot // 2 if dot > 0 else 1)
    elif pos == "host":
        base = off["sni_start"] + len(name) // 2
    else:
        raise ValueError("unknown split position: %r" % (pos,))
    return max(1, min(base, len(hello) - 1))


# ---------------------------------------------------------------- strategies ---


class Strategy:
    """Base class. A strategy writes the client's first payload upstream."""
    name = "base"

    def __init__(self, cfg):
        self.cfg = cfg

    def send(self, sock, data: bytes) -> int:
        sock.sendall(data)
        return len(data)


class SplitStrategy(Strategy):
    """Split the ClientHello across TCP segments at one or more offsets."""
    name = "split"

    def send(self, sock, data: bytes) -> int:
        if not data or data[0] != 0x16:
            return super().send(sock, data)
        positions = self.cfg.get("split_positions") or ["sni+1"]
        offsets, prev = [], 0
        for p in positions:
            try:
                off = resolve_position(p, data)
            except ValueError:
                continue
            if off > prev:
                offsets.append(off)
                prev = off
        if not offsets:
            return super().send(sock, data)
        chunks, prev = [], 0
        for off in sorted(offsets):
            chunks.append(data[prev:off])
            prev = off
        chunks.append(data[prev:])
        sent = 0
        for i, c in enumerate(chunks):
            sock.sendall(c)
            sent += len(c)
            if i < len(chunks) - 1 and self.cfg.get("split_delay"):
                time.sleep(self.cfg["split_delay"])
        return sent


class SegmentStrategy(Strategy):
    """Re-send the ClientHello in tiny TCP segments (n bytes each)."""
    name = "segment"

    def send(self, sock, data: bytes) -> int:
        if not data or data[0] != 0x16:
            return super().send(sock, data)
        size = int(self.cfg.get("segment_size", 2))
        size = max(1, min(size, 64))
        delay = float(self.cfg.get("split_delay", 0))
        sent = 0
        for i in range(0, len(data), size):
            c = data[i:i + size]
            sock.sendall(c)
            sent += len(c)
            if delay:
                time.sleep(delay)
        return sent


class TlsRecordStrategy(Strategy):
    """Re-frame the ClientHello handshake into small TLS records.

    Unlike TCP segmentation this survives middleboxes that reassemble TCP but
    not the TLS layer, and it needs no packet injection at all.
    """
    name = "tlsrec"

    def send(self, sock, data: bytes) -> int:
        if not data or data[0] != 0x16:
            return super().send(sock, data)
        size = int(self.cfg.get("tlsrec_size", 5))
        size = max(1, min(size, 512))
        handshake = data[5:]
        sent = 0
        for i in range(0, len(handshake), size):
            part = handshake[i:i + size]
            rec = b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part
            sock.sendall(rec)
            sent += len(rec)
            if self.cfg.get("split_delay"):
                time.sleep(self.cfg["split_delay"])
        return sent


class CombinedStrategy(Strategy):
    """TLS-record framing first, then TCP-level split of the first record."""
    name = "combined"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._tls = TlsRecordStrategy(cfg)
        self._split = SplitStrategy(cfg)

    def send(self, sock, data: bytes) -> int:
        if not data or data[0] != 0x16:
            return super().send(sock, data)
        size = int(self.cfg.get("tlsrec_size", 5))
        handshake = data[5:]
        parts = [handshake[i:i + size] for i in range(0, len(handshake), size)]
        first = b"\x16\x03\x01" + len(parts[0]).to_bytes(2, "big") + parts[0]
        # the split must land inside the *first small record*; compute it from the
        # full handshake's SNI location and map it into this record.
        try:
            full = resolve_position(
                (self.cfg.get("split_positions") or ["sni+1"])[0], data)
            cut = 5 + max(1, min(full - 5, len(parts[0]) - 1))
        except (ValueError, KeyError):
            cut = max(1, len(first) // 2)
        cut = max(1, min(cut, len(first) - 1))
        sock.sendall(first[:cut])
        if self.cfg.get("split_delay"):
            time.sleep(self.cfg["split_delay"])
        sock.sendall(first[cut:])
        sent = len(first)
        for p in parts[1:]:
            rec = b"\x16\x03\x01" + len(p).to_bytes(2, "big") + p
            sock.sendall(rec)
            sent += len(rec)
        return sent


class HttpTamperStrategy(Strategy):
    """Case-swap and space-insert the Host header of a plain HTTP request."""
    name = "httptamper"

    def send(self, sock, data: bytes) -> int:
        if not data[:8].upper().startswith((b"GET ", b"POST ", b"HEAD ")):
            return super().send(sock, data)
        out = bytearray()
        for line in data.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"host:"):
                val = line.split(b":", 1)[1].strip()
                out += b"hoSt: " + val + b"\r\n"
            else:
                out += line + b"\r\n"
        sock.sendall(bytes(out))
        return len(out)


STRATEGIES = {
    "split": SplitStrategy,
    "segment": SegmentStrategy,
    "tlsrec": TlsRecordStrategy,
    "combined": CombinedStrategy,
    "httptamper": HttpTamperStrategy,
    "none": Strategy,
}


def build_strategy(cfg):
    name = (cfg.get("strategy") or "combined").lower()
    cls = STRATEGIES.get(name)
    if cls is None:
        raise ValueError("unknown strategy %r (choose from %s)"
                         % (name, ", ".join(sorted(STRATEGIES))))
    return cls(cfg)
