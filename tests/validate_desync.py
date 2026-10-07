#!/usr/bin/env python3
"""Real-server validation of the desync techniques used by sni-shatter.

Sends real ClientHello records to a public TLS endpoint while applying
the same manipulations the tool applies (fragmentation at the SNI boundary,
2-byte segmentation, TLS-record fragmentation) and reports whether the
server completes a valid ServerHello — i.e. the technique is lossless.
"""
import socket
import ssl
import sys
import time

from clienthello import build_client_hello, find_sni_offsets, split_record

HOST = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
PORT = 443


def load_real_hello(host: str) -> bytes:
    """Use the captured real ClientHello when its SNI matches the target host;
    otherwise fall back to the builder."""
    try:
        data = open("/opt/sni-shatter/tests/real_clienthello.bin", "rb").read()
        o = find_sni_offsets(data)
        name = data[o["sni_start"]:o["sni_end"]].decode()
        if name == host:
            return data
    except (OSError, KeyError):
        pass
    return build_client_hello(host)


def tls_reply(sock, timeout=6.0):
    sock.settimeout(timeout)
    try:
        data = sock.recv(4096)
    except (socket.timeout, ConnectionError, OSError):
        return b""
    return data


def is_server_hello(data: bytes) -> bool:
    # TLS record type 0x16 (handshake) + handshake type 0x02 (ServerHello)
    return len(data) > 5 and data[0] == 0x16 and data[5] == 0x02


def run_case(name, chunks, delay=0.0):
    ch = load_real_hello(HOST)
    if chunks is None:
        out = [ch]
    else:
        out = chunks(ch)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.settimeout(8)
        s.connect((HOST, PORT))
        for c in out:
            s.sendall(c)
            if delay:
                time.sleep(delay)
        reply = tls_reply(s)
        ok = is_server_hello(reply)
    except Exception as e:  # noqa: BLE001
        ok, reply = False, ("ERR:" + str(e)).encode()
    finally:
        s.close()
    print(f"[{'PASS' if ok else 'FAIL'}] {name:42s} chunks={len(out):2d} "
          f"reply={len(reply):4d}B first_type=0x{reply[0]:02x}" if reply else
          f"[{'PASS' if ok else 'FAIL'}] {name:42s} chunks={len(out):2d} reply=0B")
    return ok


def at_sni(ch):
    o = find_sni_offsets(ch)
    return split_record(ch, [o["sni_start"], o["sni_start"] + len(HOST) // 2])


def two_byte(ch):
    return [ch[i:i + 2] for i in range(0, len(ch), 2)]


def tls_record_frag(ch):
    """Wrap the handshake payload into 5-byte TLS records (valid record framing)."""
    handshake = ch[5:]
    out = []
    for i in range(0, len(handshake), 5):
        part = handshake[i:i + 5]
        out.append(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part)
    return out


if __name__ == "__main__":
    print(f"== sni-shatter desync validation against {HOST}:{PORT} ==")
    res = []
    res.append(run_case("baseline (single ClientHello)", None))
    res.append(run_case("split at SNI start", lambda c: split_record(c, [find_sni_offsets(c)["sni_start"]])))
    res.append(run_case("split at mid-SNI", at_sni))
    res.append(run_case("2-byte TCP segmentation", two_byte, delay=0.001))
    res.append(run_case("TLS-record fragmentation (5B)", tls_record_frag))
    res.append(run_case("split before SNI (1B before name)", lambda c: split_record(c, [find_sni_offsets(c)["sni_len_pos"]])))
    print(f"\n== result: {sum(res)}/{len(res)} techniques preserved a valid ServerHello ==")
