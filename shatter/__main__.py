#!/usr/bin/env python3
"""sni-shatter — a portable DPI desynchronization proxy.

Runs as an HTTP CONNECT / SOCKS5 proxy on localhost. Browsers (or any app with
proxy settings) point at it, and it rewrites how the TLS ClientHello is placed
on the wire so a DPI middlebox cannot read the hostname.

Tier 1 (default): user-space TCP only — NO admin rights, NO kernel driver.
Tier 2 (optional): fake-packet injection is a separate module and is off by
default because it needs raw-socket privileges.

Usage:
    python -m shatter                    # uses config.json next to the package
    python -m shatter -c my-config.json
    python -m shatter --port 40443 --strategy tlsrec --verbose
    python -m shatter --check            # auto-test strategies against a target
"""
import argparse
import json
import os
import socket
import sys
import threading
import time

from .proxy import ProxyServer, hostname_of
from .desync import build_strategy

DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 40443,
    "strategy": "combined",
    "split_positions": ["sni+1"],
    "segment_size": 2,
    "tlsrec_size": 5,
    "split_delay": 0.0,
    "block_quic_hint": True,
}


def find_config(explicit=None):
    if explicit:
        return explicit
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cand = os.path.join(here, "config.json")
    return cand if os.path.exists(cand) else None


def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


# ------------------------------------------------------------ self-test -------

def _fetch_via_proxy(proxy, host, timeout=8.0):
    """CONNECT to host:443 through the proxy and return the first TLS reply."""
    s = socket.create_connection(proxy, timeout=timeout)
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
    head = s.recv(1024)
    if b"200" not in head.split(b"\r\n", 1)[0]:
        s.close()
        return b""
    # send a ClientHello captured from the real TLS stack
    try:
        hello = open("/opt/sni-shatter/tests/real_clienthello.bin", "rb").read()
        o = hostname_of(hello)
        if o != host:
            hello = None
    except OSError:
        hello = None
    if hello is None:
        from .clienthello import build_client_hello
        hello = build_client_hello(host)
    s.sendall(hello)
    s.settimeout(timeout)
    try:
        reply = s.recv(4096)
    except (socket.timeout, OSError):
        reply = b""
    s.close()
    return reply


def auto_check(target="cloudflare.com", port=40443, verbose=True):
    """Try every Tier-1 strategy against `target` and report which ones work."""
    strategies = [
        {"strategy": "none"},
        {"strategy": "split", "split_positions": ["sni+1"]},
        {"strategy": "split", "split_positions": ["snilen", "midsld"]},
        {"strategy": "segment", "segment_size": 2, "split_delay": 0.001},
        {"strategy": "tlsrec", "tlsrec_size": 5},
        {"strategy": "combined", "split_positions": ["sni+1"], "tlsrec_size": 5},
    ]
    results = []
    for i, scfg in enumerate(strategies):
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(scfg)
        cfg["listen_port"] = 0          # ephemeral: no reuse conflicts between runs
        srv = ProxyServer(cfg, logger=lambda *a: None).start()
        actual_port = srv._srv.getsockname()[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        time.sleep(0.3)
        try:
            reply = _fetch_via_proxy(("127.0.0.1", actual_port), target)
        except OSError as e:
            reply = b""
            if verbose:
                print("  error:", e)
        ok = bool(reply) and reply[0] == 0x16 and len(reply) > 5 and reply[5] == 0x02
        results.append((scfg["strategy"], ok, len(reply)))
        if verbose:
            print("  [%s] %-9s  reply=%dB" % ("PASS" if ok else "FAIL",
                                             scfg["strategy"], len(reply)))
        srv.stop()
        time.sleep(0.2)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shatter",
                                 description="Portable DPI-desync proxy (sni-shatter)")
    ap.add_argument("-c", "--config", help="path to config.json")
    ap.add_argument("--port", type=int, help="listen port (default 40443)")
    ap.add_argument("--strategy", help="split|segment|tlsrec|combined|httptamper|none")
    ap.add_argument("--check", nargs="?", const="cloudflare.com", metavar="HOST",
                    help="test all strategies against HOST and exit")
    ap.add_argument("--verbose", action="store_true", default=True)
    args = ap.parse_args(argv)

    cfg = load_config(find_config(args.config))
    if args.port:
        cfg["listen_port"] = args.port
    if args.strategy:
        cfg["strategy"] = args.strategy

    if args.check:
        print("sni-shatter --check  target=%s" % args.check)
        res = auto_check(args.check, port=cfg["listen_port"])
        good = [r[0] for r in res if r[1]]
        print("\nworking strategies: %s" % (", ".join(good) or "none"))
        return 0 if good else 1

    srv = ProxyServer(cfg, logger=print).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
