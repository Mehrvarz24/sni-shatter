# sni-shatter

**A portable, user-space DPI desynchronization proxy.** It makes an encrypted
TLS handshake unreadable to censoring middleboxes that match hostnames (SNI)
on the wire — without a VPN, without a kernel driver and without administrator
rights.

- License: MIT (see [LICENSE](LICENSE))
- Language: Python 3.8+ (standard library only — zero dependencies)
- Platforms: Windows, Linux, macOS, Android (Termux)

---

## How it works

When your browser connects to an HTTPS site, the destination hostname travels
in **plain text** inside the TLS ClientHello (the SNI extension). A censoring
middlebox reads it and drops or throttles the connection.

sni-shatter is a local proxy (HTTP CONNECT + SOCKS5). It rewrites **how** the
ClientHello is placed on the wire, never **what** it contains:

| Strategy | Effect |
|---|---|
| `split` | sends the ClientHello in 2+ TCP segments cut at the SNI boundary |
| `segment` | re-sends it in tiny 2-byte TCP segments |
| `tlsrec` | re-frames it into several small, valid TLS records |
| `combined` | TLS-record framing **plus** a TCP cut inside the first record |
| `httptamper` | case-tampers `Host:` in plain HTTP requests |
| `none` | pass-through (baseline for testing) |

A censoring middlebox that does not reassemble fragmented data sees no
complete hostname anywhere; the real server reassembles everything normally
and the TLS handshake succeeds. This matches the published field research on
the Iranian national filter (Bock et al. 2020, Niere et al. 2025): the
middleboxes there inspect single segments and do not reassemble — so
segmentation is the highest-value, lowest-cost technique, needing no admin
rights on any platform.

## Quick start

```bash
# run with defaults (listens on 127.0.0.1:40443)
python3 -m shatter

# pick a strategy and port
python3 -m shatter --port 40443 --strategy combined

# test every strategy against a real target and show which ones work here
python3 -m shatter --check cloudflare.com
```

Then point your browser (or any application) at:

- **SOCKS5 proxy:** `127.0.0.1:40443`
- **HTTP proxy:** `127.0.0.1:40443`

Windows users: see [windows/run.bat](windows/run.bat).

## Configuration

`config.json` next to the package (or `-c path`):

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 40443,
  "strategy": "combined",
  "split_positions": ["sni+1"],
  "segment_size": 2,
  "tlsrec_size": 5,
  "split_delay": 0.0
}
```

`split_positions` accepts byte offsets or symbols: `sni`, `sni+1`, `snilen`,
`midsld`, `host`.

## Verifying

```bash
python3 -m shatter --check cloudflare.com
```

runs every strategy through the proxy against the real target and reports
whether a valid TLS ServerHello came back:

```
  [PASS] none       reply=1424B
  [PASS] split      reply=1424B
  [PASS] segment    reply=1424B
  [PASS] tlsrec     reply=1424B
  [PASS] combined   reply=1424B
```

Automated tests: `python3 -m pytest tests/` (unit tests for the ClientHello
parser and strategy splitter; no network needed) and
`tests/validate_desync.py HOST` (live end-to-end against a real server).

## Honest limits

- This tool does **not** encrypt traffic and does **not** hide your IP. It is
  not a VPN. If your threat model requires hiding *that you are connecting*,
  use a proper tunnel (e.g. VLESS/Reality behind a CDN).
- It defeats **SNI-based filtering only**. IP-blocked or protocol-blocked
  destinations need other tools.
- Censors that fully reassemble TCP *and* TLS (rare on client ISPs today, e.g.
  some national systems) defeat every strategy here; `--check` tells you
  honestly what works on your network.
- QUIC/UDP 443 is untouched. Where QUIC is filtered (Iran drops it almost
  entirely), disable QUIC in your browser so traffic falls back to TCP/TLS.

## Design principles

1. **User-space first** — no driver, no admin, cross-platform by construction.
2. **Strategies are composable and testable** — `--check` before you trust.
3. **No third-party dependencies** — auditable in one sitting.
4. **Original code** — ideas come from public research; no source was copied
   from GPL or other projects. See [docs/techniques.md](docs/techniques.md)
   for the technical background and references.

## Project layout

```
shatter/            the proxy, desync strategies, ClientHello parser
tests/              unit tests + live validation + captured hello recorder
windows/            run.bat / install-service.bat / remove-service.bat
docs/               technique reference (byte-level) and research links
config.json         default configuration
```
