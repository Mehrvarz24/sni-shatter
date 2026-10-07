"""sni-shatter Tier 2 — fake-packet injection via raw sockets.

Technique (public, published research — Bock et al. 2020, Niere et al. 2025):
before the real ClientHello is sent through the normal TCP socket, one or more
*forged* packets carrying the same ClientHello are injected on the wire with
either a very low IP TTL (they die at the first hop, so the real server never
sees them) or an out-of-window TCP sequence number (the server's stack drops
them as duplicates/retransmits outside the receive window).

A DPI middlebox sitting between the client and the server — close to the
client, as the Iranian filter is — *does* see the fake packet and records its
content. When the real ClientHello then arrives fragmented (Tier 1) or with a
different sequence number, the middlebox believes the connection was already
established with data it already judged, and lets it pass. Against filters
that drop based on the *first* thing they see, sending a plausible-but-fake
first packet and then the real one desynchronizes their state machine.

This needs raw-socket privileges (root, CAP_NET_RAW on Linux, Administrator on
Windows). Without them the strategy degrades gracefully: it logs the problem
and falls back to sending only the real payload (Tier 1 behaviour).

Ethical scope: this is a tool for restoring access to information blocked by
state censorship. It is not for attacking, cracking, or abusing services.
"""
import os
import socket
import struct

# ---------------------------------------------------------------- helpers ----


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data: bytes) -> int:
    return (~_ones_complement_sum(data)) & 0xFFFF


def build_ipv4_header(src: str, dst: str, payload_len: int, ttl: int, ident: int = 0) -> bytes:
    total_len = 20 + payload_len
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,                      # version/IHL, DSCP
        total_len, ident, 0x4000,     # total len, id, flags=DF
        ttl, socket.IPPROTO_TCP, 0,   # ttl, proto, checksum placeholder
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    csum = checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]


def build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, ack: int, payload_len: int, flags: int,
                     window: int = 65535) -> bytes:
    """TCP header with a valid checksum (the pseudo-header is included)."""
    off_flags = (5 << 12) | flags
    hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack,
                      off_flags, window, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20 + payload_len)
    csum = checksum(pseudo + hdr + b"\x00" * payload_len)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:]


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# ------------------------------------------------------------- injection -----


def local_ip_for(dst_ip: str) -> str:
    """The source address the kernel would pick for a connection to dst_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


class RawInjector:
    """Sends hand-crafted IPv4+TCP packets via a raw socket (IP_HDRINCL)."""

    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.sock = None
        self.error = None

    def open(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except (PermissionError, OSError) as exc:
            self.error = str(exc)
            return False
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError as exc:
            s.close()
            self.error = str(exc)
            return False
        self.sock = s
        return True

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_fake(self, dst_ip: str, dst_port: int, src_port: int, seq: int,
                  payload: bytes, ttl: int, flags: int = PSH | ACK,
                  window: int = 65535, ident: int = 0) -> bool:
        try:
            src_ip = local_ip_for(dst_ip)
        except OSError as exc:
            self.error = str(exc)
            return False
        tcp = build_tcp_header(src_ip, dst_ip, src_port, dst_port,
                               seq, 0, len(payload), flags, window)
        ip = build_ipv4_header(src_ip, dst_ip, 20 + len(payload), ttl, ident)
        try:
            self.sock.sendto(ip + tcp + payload, (dst_ip, dst_port))
            return True
        except OSError as exc:
            self.error = str(exc)
            return False


def inject_fake_hello(dst_ip: str, dst_port: int, src_port: int, hello: bytes,
                      cfg) -> dict:
    """Inject the decoy ClientHello. Returns a small report dict."""
    inj = RawInjector(cfg)
    if not inj.open():
        return {"ok": False, "error": inj.error or "raw socket unavailable"}
    try:
        ttl = int(cfg.get("fake_ttl", 3))
        ttl = max(1, min(ttl, 255))
        count = int(cfg.get("fake_count", 1))
        seq_mode = (cfg.get("fake_seq_mode") or "lowttl").lower()
        # A "normal-looking" ISN: forged packets must not collide with the real
        # connection's sequence space unless out-of-window is intended.
        seq = 0x10000000
        sent = 0
        for i in range(max(1, count)):
            if seq_mode == "outofwindow":
                # far beyond the server's window: the server drops it, the
                # censor (which does not track the window) accepts it
                s = seq + 0x40000000 + i
            else:
                s = seq + i
            if inj.send_fake(dst_ip, dst_port, src_port, s, hello, ttl,
                             ident=i + 1):
                sent += 1
        return {"ok": sent > 0, "sent": sent, "ttl": ttl, "mode": seq_mode}
    finally:
        inj.close()


def raw_sockets_available() -> bool:
    """Cheap capability probe (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True
    except (PermissionError, OSError):
        return False
