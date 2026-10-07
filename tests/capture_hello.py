#!/usr/bin/env python3
"""Capture a REAL ClientHello from this machine's TLS stack (no third-party code).

Starts a tiny recording relay, points the standard-library TLS client at it and
saves the first TLS record the client sends. Used as ground truth for the
fragmentation experiments (a hand-built hello is easy to get wrong).
"""
import socket
import ssl
import threading
import sys

TARGET = ("cloudflare.com", 443)
LISTEN = ("127.0.0.1", 0)


def relay(conn, out):
    try:
        up = socket.create_connection(TARGET, timeout=8)
    except OSError:
        conn.close(); return
    def pump(a, b, record=False):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if record:
                    out.append(d)
                b.sendall(d)
        except OSError:
            pass
        finally:
            try: b.shutdown(socket.SHUT_WR)
            except OSError: pass
    t = threading.Thread(target=pump, args=(up, conn), daemon=True)
    t.start()
    pump(conn, up, record=True)
    t.join(timeout=3)
    up.close(); conn.close()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN); srv.listen(1)
    host, port = srv.getsockname()
    captured = []

    def serve():
        c, _ = srv.accept()
        relay(c, captured)

    th = threading.Thread(target=serve, daemon=True); th.start()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((host, port), timeout=8)
        ss = ctx.wrap_socket(s, server_hostname=TARGET[0])
        ss.close()
    except Exception as e:  # noqa: BLE001
        print("client note:", e, file=sys.stderr)
    th.join(timeout=4)

    hello = captured[0] if captured else b""
    if hello:
        open("/opt/sni-shatter/tests/real_clienthello.bin", "wb").write(hello)
    print("captured bytes:", len(hello), "record type: 0x%02x" % hello[0] if hello else "NONE")


if __name__ == "__main__":
    main()
