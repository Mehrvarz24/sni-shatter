"""Unit tests for sni-shatter (no network required)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shatter.clienthello import build_client_hello, find_sni_offsets, split_record
from shatter.desync import resolve_position, SplitStrategy, TlsRecordStrategy, SegmentStrategy
from shatter.proxy import hostname_of


HELLO = build_client_hello("example.com", padding_to=400)


def test_builder_roundtrip():
    o = find_sni_offsets(HELLO)
    name = HELLO[o["sni_start"]:o["sni_end"]]
    assert name == b"example.com"
    assert HELLO[0] == 0x16


def test_parser_on_real_hello():
    path = os.path.join(os.path.dirname(__file__), "real_clienthello.bin")
    if not os.path.exists(path):
        return
    real = open(path, "rb").read()
    o = find_sni_offsets(real)
    assert real[o["sni_start"]:o["sni_end"]] == b"cloudflare.com"


def test_resolve_positions():
    o = find_sni_offsets(HELLO)
    assert resolve_position("sni", HELLO) == o["sni_start"]
    assert resolve_position("sni+1", HELLO) == o["sni_start"] + 1
    assert resolve_position(10, HELLO) == 10
    assert resolve_position("midsld", HELLO) > o["sni_start"]


def test_split_rejoin():
    chunks = split_record(HELLO, [50, 120, 300])
    assert b"".join(chunks) == HELLO
    assert len(chunks) == 4


def test_split_strategy_fakesock():
    o = find_sni_offsets(HELLO)
    sent = []

    class FakeSock:
        def sendall(self, b):
            sent.append(b)

    strat = SplitStrategy({"split_positions": ["sni+1"]})
    strat.send(FakeSock(), HELLO)
    assert b"".join(sent) == HELLO                     # lossless
    assert HELLO[o["sni_start"] - 1:o["sni_start"] + 1] not in sent  # name cut


def test_tlsrec_strategy_framing():
    sent = []

    class FakeSock:
        def sendall(self, b):
            sent.append(b)

    TlsRecordStrategy({"tlsrec_size": 5}).send(FakeSock(), HELLO)
    assert all(c[:3] == b"\x16\x03\x01" for c in sent)
    joined = b"".join(c[5:] for c in sent)
    assert joined == HELLO[5:]                          # handshake intact
    for c in sent[:-1]:
        assert len(c) == 10                             # 5-byte records


def test_segment_strategy_lossless():
    sent = []

    class FakeSock:
        def sendall(self, b):
            sent.append(b)

    SegmentStrategy({"segment_size": 2}).send(FakeSock(), HELLO)
    assert b"".join(sent) == HELLO
    assert all(len(c) == 2 for c in sent[:-1])


def test_hostname_of():
    assert hostname_of(HELLO) == "example.com"
    http = b"GET / HTTP/1.1\r\nHost: sample.org\r\n\r\n"
    assert hostname_of(http) == "sample.org"
