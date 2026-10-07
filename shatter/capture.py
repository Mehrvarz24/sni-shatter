"""Capture a *real* TLS ClientHello from this machine's TLS stack.

Why: hand-built ClientHellos are easy to get subtly wrong and real servers
reject them with a fatal alert. For both `--check` and any strategy test we
want a byte-exact hello that the target will actually accept. This module
starts a tiny recording relay on localhost, points the standard library's TLS
client at it and returns the first record the real stack emitted.
"""
import socket
import ssl
import threading


def capture_client_hello(host: str, port: int = 443, timeout: float = 8.0) -> bytes:
    """Return the first TLS record sent by this machine's TLS stack to `host`.

    Empty bytes if the handshake could not be started at all.
    """
    target = (host, port)
    captured = []

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(timeout)
    listen_host, listen_port = srv.getsockname()

    def relay(conn):
        try:
            up = socket.create_connection(target, timeout=timeout)
        except OSError:
            conn.close()
            return
        done = threading.Event()

        def pump(src, dst, record):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    if record and not captured:
                        captured.append(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                done.set()
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(up, conn, True), daemon=True)
        t.start()
        pump(conn, up, True)
        done.wait(timeout)
        try:
            up.close()
        finally:
            conn.close()

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        relay(conn)

    th = threading.Thread(target=serve, daemon=True)
    th.start()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((listen_host, listen_port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.close()
    except Exception:  # noqa: BLE001 — any TLS failure still leaves us the hello
        pass
    th.join(timeout=timeout)
    try:
        srv.close()
    except OSError:
        pass
    return captured[0] if captured else b""
