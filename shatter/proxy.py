"""sni-shatter — a censorship-resistant local proxy that desynchronizes DPI.

The proxy accepts local connections (HTTP CONNECT / SOCKS5), reads the client's
first payload, applies the configured desynchronization strategy to the first
outbound payload and then relays the connection untouched.

Original implementation. Ideas only from public research.
"""
import socket
import threading

from .desync import build_strategy
from .clienthello import find_sni_offsets
from .hostlist import HostList

BUFSIZE = 65536


def peek_payload(sock: socket.socket, timeout=1.0) -> bytes:
    """Read the client's first payload without consuming it (MSG_PEEK)."""
    sock.settimeout(timeout)
    try:
        return sock.recv(BUFSIZE, socket.MSG_PEEK)
    except (socket.timeout, OSError):
        return b""
    finally:
        sock.settimeout(None)


def hostname_of(data: bytes, default: str = "") -> str:
    """Extract the destination hostname from a TLS ClientHello or HTTP request."""
    if data[:1] == b"\x16":
        try:
            o = find_sni_offsets(data)
            name = data[o["sni_start"]:o["sni_end"]]
            if name:
                try:
                    return name.decode("ascii")
                except UnicodeDecodeError:
                    return name.decode("latin1")
        except (KeyError, ValueError):
            pass
        return default
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        low = line.lower()
        if low.startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode("latin1")
    return default


class Relay:
    def __init__(self, cfg, stats=None):
        self.cfg = cfg
        self.stats = stats if stats is not None else {}
        self.log = cfg.get("_log") or (lambda *a: None)
        self.hostlist = HostList(cfg)

    def _send_first(self, up, hostname, data):
        """Apply the strategy to the first outbound payload, honouring the
        hostlist and passing the target host to the strategy (Tier 2)."""
        if not self.hostlist.allowed(hostname):
            self._bump("hostlist_bypass", 1)
            up.sendall(data)
            return
        self.cfg["_target_host"] = hostname
        strat = build_strategy(self.cfg)
        strat.send(up, data)

    def _bump(self, key, n=1):
        self.stats[key] = self.stats.get(key, 0) + n

    def pipe(self, a: socket.socket, b: socket.socket, close_other=None):
        try:
            while True:
                data = a.recv(BUFSIZE)
                if not data:
                    break
                self._bump("up" if close_other is None else "down", len(data))
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(self, client: socket.socket, target=None):
        """target: (host, port). When None, parse it from the first bytes.

        Relay mode: if self.cfg has connect_ip, every connection is forwarded
        there (raw byte relay with desync on the first payload) regardless of
        what the client asked for — this is the v2rayN-style upstream mode:
        point a VLESS/VMess client at 127.0.0.1:40443 and set connect_ip to
        your CDN endpoint.
        """
        try:
            if self.cfg.get("connect_ip"):
                return self._relay_raw(client,
                                       (self.cfg["connect_ip"],
                                        int(self.cfg.get("connect_port", 443))))
            if target is None:
                client.settimeout(10)
                first = client.recv(1, socket.MSG_PEEK)
                if first == b"\x05":
                    return self._handle_socks5(client)
                target = self._parse_http_head(client)
                if target is None:
                    return
                if getattr(self, "_http_pending", b""):
                    up = None
                    try:
                        up = socket.create_connection(target, timeout=10)
                    except OSError:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        return
                    self._relay_plain_http(client, up, self._http_pending)
                    return
            self._connect_and_relay(client, target)
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _parse_http_head(self, client):
        head = b""
        while b"\r\n\r\n" not in head and len(head) < BUFSIZE:
            part = client.recv(4096)
            if not part:
                return None
            head += part
        first_line = head.split(b"\r\n", 1)[0].decode("latin1")
        if first_line.startswith("CONNECT"):
            hp = first_line.split()[1]
            host, _, port = hp.rpartition(":")
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self._http_pending = b""
            return (host, int(port or 443))
        host = hostname_of(head)
        if not host:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return None
        # plain HTTP: head is the payload; hand it to the strategy then relay
        self._http_pending = head
        self.cfg["_last_host"] = host
        return (host, 80)

    def _handle_socks5(self, client):
        """Minimal SOCKS5 (no auth, CONNECT) — the standard mode for apps."""
        hdr = client.recv(2)
        if len(hdr) < 2 or hdr[0] != 0x05:
            return
        n = hdr[1]
        client.recv(n)                       # methods offered
        client.sendall(b"\x05\x00")          # no auth
        req = client.recv(4)
        if len(req) < 4 or req[1] != 0x01:   # only CONNECT
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        atyp = req[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(client.recv(4))
        elif atyp == 0x03:
            ln = client.recv(1)[0]
            host = client.recv(ln).decode("latin1")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(client.recv(2), "big")
        try:
            up = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        self._http_pending = b""
        self._relay_established(client, up)

    def _pipe_http(self, client, target, pending):
        try:
            up = socket.create_connection(target, timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        try:
            self._send_first(up, target[0], pending)
            self._bump("first_payload", len(pending))
            t = threading.Thread(target=self.pipe, args=(up, client), daemon=True)
            t.start()
            self.pipe(client, up)
            t.join(timeout=30)
        finally:
            up.close()

    def _relay_raw(self, client, target):
        """Pure relay: connect to `target` and pipe bytes both ways, applying
        the desync strategy to the first client payload. Used when the client
        speaks its own protocol (VLESS/VMess/Trojan/tunnel) and only the
        transport must be disguised."""
        try:
            up = socket.create_connection(target, timeout=10)
        except OSError:
            self._bump("relay_connect_fail")
            return
        self._bump("relay_connections")
        self._relay_established(client, up)

    def _relay_plain_http(self, client, up, pending):
        try:
            self._send_first(up, self.cfg.get("_last_host", ""), pending)
            self._bump("first_payload", len(pending))
            t = threading.Thread(target=self.pipe, args=(up, client), daemon=True)
            t.start()
            self.pipe(client, up)
            t.join(timeout=30)
        finally:
            up.close()

    def _relay_established(self, client, up):
        """Shared relay for protocols whose target is already resolved
        (SOCKS5, HTTP-CONNECT and raw relay share this path)."""
        peer = "%s:%d" % client.getpeername()[:2]
        up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            first = peek_payload(client)
            if first:
                data = client.recv(len(first))
                hostname = hostname_of(first) if first[:1] == b"\x16" else ""
                self._send_first(up, hostname, data)
                self._bump("first_payload", len(data))
                if first[:1] == b"\x16":
                    h = hostname_of(first)
                    if h:
                        self._bump("tls_sni:" + h)
                        self.log("[conn] %s -> %s (tls, %dB first payload, strategy=%s)"
                                 % (peer, h, len(data), self.cfg.get("strategy")))
                    else:
                        self.log("[conn] %s -> tls first payload %dB (strategy=%s)"
                                 % (peer, len(data), self.cfg.get("strategy")))
                else:
                    self.log("[conn] %s -> raw %dB first payload (strategy=%s)"
                             % (peer, len(data), self.cfg.get("strategy")))
            else:
                self.log("[conn] %s -> connected, no first payload" % peer)
            t = threading.Thread(target=self.pipe, args=(up, client), daemon=True)
            t.start()
            self.pipe(client, up)
            t.join(timeout=60)
            self.log("[done] %s closed" % peer)
        finally:
            up.close()

    def _connect_and_relay(self, client, target):
        try:
            up = socket.create_connection(target, timeout=10)
        except OSError as exc:
            self.log("[fail] %s:%d -> %s" % (target[0], target[1], exc))
            return
        self._relay_established(client, up)


class ProxyServer:
    def __init__(self, cfg, logger=print):
        self.cfg = cfg
        self.log = logger
        self.stats = {}
        self._srv = None
        self._stop = threading.Event()

    def start(self):
        host = self.cfg.get("listen_host", "127.0.0.1")
        port = int(self.cfg.get("listen_port", 40443))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(128)
        mode = ("relay -> %s:%s" % (self.cfg["connect_ip"], self.cfg.get("connect_port", 443))
                if self.cfg.get("connect_ip") else "local proxy (HTTP CONNECT + SOCKS5)")
        self.log("sni-shatter listening on %s:%d  [%s]  strategy=%s"
                 % (host, self._srv.getsockname()[1], mode,
                    self.cfg.get("strategy", "combined")))
        return self

    def serve_forever(self):
        self.cfg["_log"] = self.log
        relay = Relay(self.cfg, self.stats)
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._one, args=(relay, conn, addr),
                             daemon=True).start()

    def _one(self, relay, conn, addr):
        try:
            relay.handle(conn)
        except Exception as exc:  # noqa: BLE001
            self.log("connection error from %s: %s" % (addr, exc))

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass
