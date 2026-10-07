"""Tests for Tier 2 (fake-packet) helpers and hostlist matching.

No raw sockets are opened and no packets are sent in these tests: they check
header construction correctness, graceful degradation and the hostlist engine.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shatter.clienthello import build_client_hello
from shatter.fakepkt import (build_ipv4_header, build_tcp_header, checksum,
                             _ones_complement_sum)
from shatter.desync import FakePacketStrategy
from shatter.hostlist import host_allowed, load_hostlist


def test_checksum_known_value():
    # RFC 1071 worked example
    data = b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"
    assert checksum(data) == 0x220d


def test_ipv4_header_roundtrip():
    h = build_ipv4_header("192.168.1.2", "1.2.3.4", 25, ttl=3)
    assert len(h) == 20
    assert h[0] >> 4 == 4 and h[0] & 0xF == 5        # v4, IHL 5
    assert h[8] == 3                                  # ttl
    assert h[9] == 6                                  # proto TCP
    total = int.from_bytes(h[2:4], "big")
    assert total == 45                                # 20 IP + 20 TCP + 5 payload
    # checksum must verify
    from shatter.fakepkt import _ones_complement_sum  # noqa: F811
    assert _ones_complement_sum(h) == 0xFFFF


def test_tcp_header_checksum_with_pseudo():
    from shatter.fakepkt import PSH, ACK, local_ip_for
    try:
        src = local_ip_for("1.2.3.4")
    except OSError:
        src = "192.168.1.2"
    t = build_tcp_header(src, "1.2.3.4", 40000, 443, seq=12345, ack=0,
                         payload_len=10, flags=PSH | ACK)
    assert len(t) == 20
    assert t[13] == (PSH | ACK)
    assert int.from_bytes(t[0:2], "big") == 40000
    assert int.from_bytes(t[2:4], "big") == 443


def test_fakepkt_strategy_fallback_without_raw(monkeypatch=None):
    """Without raw privileges the strategy must still send the full hello
    through the inner Tier-1 strategy (graceful degradation)."""
    hello = build_client_hello("example.com", padding_to=300)
    sent = []

    class FakeSock:
        def getpeername(self):
            return ("93.184.216.34", 443)
        def getsockname(self):
            return ("10.0.0.5", 51000)
        def sendall(self, b):
            sent.append(b)

    cfg = {"strategy": "fakepkt", "fake_ttl": 3, "split_positions": ["sni+1"],
           "fake_inner_strategy": "split"}
    strat = FakePacketStrategy(cfg)
    n = strat.send(FakeSock(), hello)
    assert n == len(hello)                # split is lossless
    assert b"".join(sent) == hello        # lossless
    assert cfg["_fakepkt_injected"] is False


def test_fakepkt_strategy_non_tls_passthrough():
    sent = []

    class FakeSock:
        def sendall(self, b):
            sent.append(b)

    cfg = {"strategy": "fakepkt"}
    FakePacketStrategy(cfg).send(FakeSock(), b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n")
    assert b"".join(sent).startswith(b"GET /")


def test_hostlist_matching():
    cfg = {"_hostlist_inc": ["youtube.com", "*.google.com", "142.250.0.0/15"],
           "_hostlist_exc": ["*.analytics.google.com"]}
    assert host_allowed("youtube.com", cfg)
    assert host_allowed("www.youtube.com", cfg)
    assert host_allowed("www.google.com", cfg)
    assert host_allowed("google.com", cfg)          # plain matches subdomains too
    assert not host_allowed("example.com", cfg)
    assert host_allowed("142.250.10.5", cfg)        # inside CIDR
    assert not host_allowed("8.8.8.8", cfg)
    assert not host_allowed("sub.analytics.google.com", cfg)  # excluded
    # exclusion beats inclusion
    assert not host_allowed("a.analytics.google.com",
                            {"_hostlist_inc": ["*.google.com"],
                             "_hostlist_exc": ["*.analytics.google.com"]})
    assert host_allowed("a.google.com", {"_hostlist_inc": ["*.google.com"],
                                         "_hostlist_exc": []})


def test_hostlist_exclude_only_mode():
    cfg = {"_hostlist_exc": ["bad.example"]}
    assert host_allowed("good.example", cfg)
    assert not host_allowed("bad.example", cfg)


def test_hostlist_empty_and_unknown():
    assert host_allowed("anything.org", {})            # no lists: allow all
    assert host_allowed("", {"_hostlist_inc": ["x.com"]})  # unknown host: allow
