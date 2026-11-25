# TLS client interop set

Regression tests for the TLS 1.3 client (`_net/ssftlsc`) against independent implementations:
OpenSSL `s_server` and GnuTLS `gnutls-serv` over loopback, and optionally the public broker
test.mosquitto.org. Each row states its expected outcome and is checked automatically.

These are not part of the unit tests (`./ssf`): they need real TLS servers, and `--public` needs
the internet. The deterministic tests, including RFC 8448 replays and negative tests on the server
flight, are in `_net/ssftlsc_ut.c`.

## Requirements

Linux, `gcc`, `ninja`, `python3`, `openssl` (1.1.1 or later) and `gnutls-serv` (`gnutls-utils`).

## Running

```
tools/tlsc-interop/run.sh               # local rows, about 30 s
tools/tlsc-interop/run.sh --public      # also test.mosquitto.org
tools/tlsc-interop/run.sh --self-test   # a client with AES-128-CCM broken must fail exactly the CCM rows
tools/tlsc-interop/run.sh --asan        # drivers built against the ASan / UBSan objects
tools/tlsc-interop/run.sh --only TEXT   # rows whose name contains TEXT
```

`run.sh` builds the unit-test objects (`ninja`), compiles `tlsc_interop.c` against them (twice:
once with `SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS=3` for the rekeying rows), generates fresh
certificates (`gen-certs.sh`, valid 30 days, in a temporary directory) and runs `interop.py`.

## Rows

| Set | Rows | What |
|-----|------|------|
| matrix | 120 | {s_server, gnutls-serv} x 4 suites x 3 groups (x25519, P-384, P-256 through a HelloRetryRequest) x 5 server keys (P-256, P-384, RSA-2048, RSA-4096, Ed25519): the forced suite and group negotiated, data echoed |
| alpn | 10 | server choices, no overlap (`no_application_protocol`), none offered, after an HRR |
| mtls | 14 | client certificates of every key type, a chain with an intermediate, schemes the server refuses (empty Certificate, `certificate_required`), another CA (`unknown_ca`) |
| trust | 5 | trust anchors loaded from the system CA bundle and the test CAs with `SSFTLSCTrustFromPEM()` |
| keyupdate | 5 | server KeyUpdates (requested or not), the client rekeying every 3 records |
| record size | 2 | server records of at most 512 bytes; a 512-byte `record_size_limit` splitting an RSA-4096 client flight |
| public | 6 | test.mosquitto.org: 8886 (Let's Encrypt, system roots) with MQTT CONNACK; 8883 (refused: its certificate is X.509 v1); 8884 mutual TLS |

## test.mosquitto.org

`--public` runs `public-certs.sh`, which fetches the Mosquitto CA and, for port 8884, generates a
P-256 and an RSA-2048 key and requests client certificates from test.mosquitto.org/ssl with
placeholder subjects only (`C=XX, O=SSF Test, CN=ssf-tlsc-interop-*`). They are cached in
`.cache/` (git-ignored) and requested again within 7 days of expiry (they last 90 days).
Port 8884 serves the same X.509 v1 certificate as 8883, which the client refuses by design, so
its rows run with the server unauthenticated (the unit-test build's opt-in).
