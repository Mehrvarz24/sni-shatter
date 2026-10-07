#!/usr/bin/env python3
"""TLS ClientHello utilities for SNI-shatter.
Builds and parses real TLS ClientHello records — original code, no copied sources.
"""
import struct


def build_client_hello(sni: str, padding_to: int = 0) -> bytes:
    """Build a complete TLS 1.2-style ClientHello handshake message with one SNI.

    padding_to: if > 0, pad the handshake to roughly that many bytes with a
    padding extension so the message length is stable (useful for fake packets).
    Returns the full TLS record (0x16 + len + handshake).
    """
    # --- extensions ---
    def ext(t: int, data: bytes) -> bytes:
        return struct.pack(">HH", t, len(data)) + data

    # server_name: list_len(2) + entry_type(1) + name_len(2) + name
    sni_b = sni.encode()
    host = struct.pack(">H", len(sni_b) + 3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    exts = ext(0x0000, host)
    # supported_groups
    exts += ext(0x000A, struct.pack(">H", 4) + b"\x00\x1d\x00\x17")
    # ec_point_formats
    exts += ext(0x000B, b"\x01\x00")
    # signature_algorithms
    exts += ext(0x000D, struct.pack(">H", 4) + b"\x04\x03\x08\x04")
    # supported_versions: TLS 1.3 + 1.2
    exts += ext(0x002B, b"\x02\x03\x04\x03\x03")
    # key_share (x25519 placeholder 32 bytes)
    exts += ext(0x0033, struct.pack(">H", 36) + struct.pack(">H", 0x001D) + struct.pack(">H", 32) + bytes(range(32)))

    if padding_to:
        target = padding_to - 4 - len(exts) - 43  # rough accounting
        pad_len = max(0, padding_to - (2 + 32 + 1 + 2 + 2 + 10 + 2 + len(exts)) - 4)
        if pad_len > 0:
            exts += ext(0x0015, b"\x00" * pad_len)

    # --- handshake body ---
    random_bytes = bytes(((i * 7 + 13) & 0xFF) for i in range(32))
    body = (
        b"\x03\x03"                      # client_version TLS1.2
        + random_bytes                    # random
        + b"\x20" + b"\x11" * 32          # session id
        + struct.pack(">H", 3)            # cipher suites len
        + b"\x13\x01\x13\x02"             # TLS_AES_128_GCM_SHA256, TLS_CHACHA20
        + b"\x01\x00"                     # compression: null
        + struct.pack(">H", len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body

    # --- TLS record(s) ---
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def find_sni_offsets(record: bytes) -> dict:
    """Locate byte offsets of interest inside a ClientHello record.

    Returns dict with:
      sni_len_pos: position of the 2-byte SNI length field
      sni_start / sni_end: start and end of the hostname bytes
      total_len: length of record
    """
    # record header: 5 bytes; handshake header: 4 bytes
    p = 5 + 4
    p += 2          # client_version
    p += 32         # random
    sid_len = record[p]; p += 1 + sid_len
    cs_len = struct.unpack(">H", record[p:p + 2])[0]; p += 2 + cs_len
    comp_len = record[p]; p += 1 + comp_len
    ext_total = struct.unpack(">H", record[p:p + 2])[0]; p += 2
    ext_end = p + ext_total
    out = {"total_len": len(record)}
    while p + 4 <= ext_end:
        etype, elen = struct.unpack(">HH", record[p:p + 4]); p += 4
        if etype == 0x0000:
            # server_name list: 2B list len, then entries: 1B type, 2B len, name
            out["sni_list_pos"] = p
            name_len = struct.unpack(">H", record[p + 3:p + 5])[0]
            out["sni_len_pos"] = p + 3
            out["sni_start"] = p + 5
            out["sni_end"] = p + 5 + name_len
            return out
        p += elen
    return out


def split_record(record: bytes, positions: list) -> list:
    """Split a TLS record's *handshake payload* into byte chunks at given offsets
    (relative to record start). Returns a list of bytes chunks (re-joinable)."""
    chunks, prev = [], 0
    for pos in sorted(positions):
        pos = max(prev + 1, min(pos, len(record)))
        chunks.append(record[prev:pos])
        prev = pos
    if prev < len(record):
        chunks.append(record[prev:])
    return chunks
