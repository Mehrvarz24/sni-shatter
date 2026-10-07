# Techniques — byte-level reference

Public research background for what sni-shatter implements. All code in this
repository is original; this document summarizes published, well-known ideas
with references.

## 1. The SNI problem

A TLS ClientHello (record type 0x16, handshake type 0x01) carries the target
hostname in the `server_name` extension (type 0x0000) in clear text:

```
16 03 01 LL LL            TLS record header
01 00 LL LL               handshake: ClientHello, length
03 03                     client_version (TLS 1.2 legacy)
<32B random> <sid> <ciphers> <compression>
00 00 <list_len> 00 <name_len> <name bytes>   <- SNI extension
...
```

A DPI middlebox matching blocked names only needs to see the name bytes once.

## 2. TCP segmentation (`split`, `segment`)

The proxy reads the client's first payload, then writes it upstream in
multiple `sendall()` calls with `TCP_NODELAY`, producing separate TCP
segments. Positions: immediately after the SNI name begins (`sni+1`), at the
name-length field (`snilen`), in the middle of the domain's second-level
label (`midsld`), etc. Server TCP stacks reassemble segments; middleboxes
that inspect per-segment see no complete name.

- Validated live: a ClientHello split at `sni+1` still yields a valid
  ServerHello from cloudflare.com:443 (see `tests/validate_desync.py`).
- Cost: none (user-space socket calls).

## 3. TLS record fragmentation (`tlsrec`, `combined`)

The handshake payload is re-framed into several small TLS records
(`16 03 01 <len≤5> ...`). This is legal TLS: the peer's record layer joins
them. Middleboxes that parse one record at a time never see the SNI whole.
Unlike packet-injection approaches this survives TCP reassembly by the
middlebox, because the fragmentation lives at the TLS layer.

## 4. Fake packets (wrong_seq / badsum / low TTL) — Tier 2, optional

A decoy ClientHello carrying an allowed SNI is injected with a deliberately
wrong TCP sequence number (or bad checksum, or a TTL that dies before the
server). Stateless middleboxes process the decoy and whitelist the flow; the
server drops the invalid packet silently. Requires raw packet access —
WinDivert on Windows, AF_PACKET/NFQUEUE on Linux — i.e. administrator rights.
sni-shatter keeps this **out of the default path**: Tier 1 needs no privilege.
The design follows the published analysis of Iranian middleboxes (which do
not reassemble), where segmentation alone is usually sufficient.

## 5. HTTP tampering (`httptamper`)

For plain HTTP, case-tampering the Host header (`Host:` → `hoSt:`) defeats
case-sensitive keyword matching. Only relevant for the shrinking HTTP-only
portion of the web.

## 6. What does NOT work against full reassembly

If the middlebox reassembles TCP *and* joins TLS records, no fragmentation
technique works. Encrypted ClientHello (ECH) or a proxied tunnel (VLESS+REALITY
behind a CDN, as used by Atlas) are then the answer. `--check` measures this
on your own network instead of guessing.

## References (public research)

- Bock, Hughey, Wang et al., * Geneva: Genetic Evasion Algorithms * and
  China/Iran field measurements (2020) — Iranian middleboxes: no TCP
  reassembly, segmentation effective.
- Niere et al. (2025), measurement of the Iranian national filter's TLS
  handling — reads first record, no reassembly; QUIC/UDP 443 dropped at
  national scale.
- zapret (bol-van) documentation — public taxonomy of desync methods
  (multisplit, multidisorder, fake, tlsrec, hostfakesplit) on which this
  project's strategy naming is conceptually based.
- GoodbyeDPI (ValdikSS) README — public description of fake-packet modes
  (wrong checksum, TTL) that motivated the Tier-2 design notes above.
