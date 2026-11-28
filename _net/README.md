# Network

[SSF](../README.md)

Network protocol clients and the byte stream transport interface they run on.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfawsprov | AWS IoT Core Fleet Provisioning over MQTT (CreateCertificateFromCsr, RegisterThing); not yet validated against a live AWS account; needs thread support 1 until ssfmqttc is fixed (G14) | ssfawsprov.c, ssfawsprov.h | [ssfawsprov.md](ssfawsprov.md) |
| ssfhttphdr | HTTP/1.1 request head builder and strict response head parser (RFC 9112); shared by HTTP users | ssfhttphdr.c, ssfhttphdr.h | [ssfhttphdr.md](ssfhttphdr.md) |
| ssfmqttc | MQTT 3.1.1 client, QoS 0 and 1, single connection | ssfmqttc.c, ssfmqttc.h | [ssfmqttc.md](ssfmqttc.md) |
| ssfmqttpkt | MQTT 3.1.1 control packet framing, encoding and decoding | ssfmqttpkt.c, ssfmqttpkt.h | — |
| ssfnet | Non-blocking byte stream transport interface | ssfnet.h | [below](#ssfnet-transport-interface) |
| ssfnetsock | Plaintext TCP transport over BSD sockets or Winsock, with non-blocking name resolution | ssfnetsock.c, ssfnetsock.h | [below](#ssfnetsock-tcp-transport) |
| ssftlsc | TLS 1.3 client transport (RFC 8446) over another transport; carries MQTT over TLS | ssftlsc.c, ssftlsc.h | [below](#ssftlsc-tls-13-client) |
| ssfnetws | WebSocket client transport (RFC 6455) over another transport: ws:// on ssfnetsock, wss:// on ssftlsc; carries MQTT over WebSockets | ssfnetws.c, ssfnetws.h | [ssfnetws.md](ssfnetws.md) |

## ssfnet Transport Interface

- A transport is a table of six non-blocking operations plus an implementation context. A client
  holds a pointer to it and never looks inside; an implementation embeds the table as the first
  member of its own struct and recovers itself from the pointer.
- Every call returns immediately, name resolution included: an implementation must resolve a host
  name asynchronously and report progress through `pollOpen()`. A result of `WANT_READ` or
  `WANT_WRITE` means nothing was done and the caller should try again after the transport becomes
  readable or writable, or after a short delay while opening.
- Lifecycle: `open()` starts a connection; `pollOpen()` is called until it stops returning `WANT_*`
  and reports `SUCCESS` or failure; `send()` and `recv()` are valid only after `SUCCESS`; `close()`
  is valid any time after `open()` and ends the connection unconditionally. After `close()` the
  transport may be opened again.
- Graceful end: bytes `send()` accepted may still be buffered inside the transport (TLS holds a
  partly written record). `close()` never waits, so it may drop them. A caller that needs them
  delivered calls `shutdown()` until it stops returning `WANT_WRITE`, then `close()`. `shutdown()`
  is valid only after `pollOpen()` `SUCCESS`; `send()` is not valid after it, `recv()` still is.
- IPv4 only. SSF is not designed for an IPv6 stack: a host is a DNS name or a dotted IPv4 address,
  a name is resolved to IPv4 addresses only, and `open()` returns false for an IPv6 literal (any
  host containing `':'`). A host with no IPv4 address fails to open.
- `CLOSED` is an orderly end by the peer or a reset; `ERROR` is anything else. Callers treat both
  as fatal for the connection.
- All calls come from one thread.

| Operation | Results |
|-----------|---------|
| `open(t, hostStr, hostSize, port)` | `hostStr` is NUL terminated within `hostSize`. Returns false if the attempt could not be started (bad or IPv6 host, no resources); true once it is in progress or done. |
| `pollOpen(t)` | `SUCCESS` when connected; `WANT_READ`/`WANT_WRITE` while in progress; `CLOSED` or `ERROR` when the attempt failed. |
| `send(t, buf, bufLen, sentOut)` | `SUCCESS` with `*sentOut >= 1` bytes accepted (may be fewer than `bufLen`); `WANT_WRITE` with `*sentOut == 0` when the transport cannot take any right now. |
| `recv(t, buf, bufSize, gotOut)` | `SUCCESS` with `*gotOut >= 1` bytes received; `WANT_READ` with `*gotOut == 0` when none are available; `CLOSED` when the peer has finished sending. |
| `shutdown(t)` | Delivers every byte `send()` accepted and ends this side of the stream (for TLS, close_notify). `SUCCESS` when done; `WANT_WRITE` while bytes remain (retry when writable); `CLOSED` or `ERROR` if they cannot be delivered. A transport whose accepted bytes are already committed (a socket) returns `SUCCESS` at once. Repeating it after `SUCCESS` returns `SUCCESS`. |
| `close(t)` | Ends the connection or attempt and releases its resources. Never waits; see `shutdown()`. |

## ssfnetsock TCP Transport

- Plaintext TCP: no TLS, no authentication. For hosted builds (Windows, Linux, macOS) and as the
  reference for porting the transport to an embedded IP stack.
- A literal IPv4 address is parsed in `open()`. Because names resolve to IPv4 addresses only, a
  dual-stack host never connects over IPv6.
- A host name is resolved with the OS asynchronous resolver and polled by `pollOpen()`:
  `GetAddrInfoExW` with an event on Windows, `DNSServiceGetAddrInfo` on macOS, `getaddrinfo_a` on
  glibc. Elsewhere only literal addresses are accepted and `open()` of a name returns false.
- `close()` during a lookup returns at once. A lookup the OS cannot cancel keeps its slot until it
  finishes and is reclaimed by a later call.
- One socket per instance. The instance must outlive the client that holds its transport.
- On Windows, Winsock is started by the first `SSFNetSockInit()` and stopped once the last instance
  is deinitialized and no abandoned lookup remains.

ssfnetsock is configured in `_opt/ssfnetsock_opt.h`:

- `SSF_NETSOCK_CONFIG_MAX_HOST_SIZE` bounds the host string, NUL included (2..256). A DNS name is
  at most 253 characters; a longer host makes `open()` return false.
- `SSF_NETSOCK_CONFIG_MAX_ADDRS` is the number of resolved addresses kept per `open()` (1..255).
  Connect attempts walk them in order, moving to the next when one fails; addresses beyond this
  are ignored.
- `SSF_NETSOCK_CONFIG_MAX_LOOKUPS` is the number of name lookups that may be in progress at once
  across all instances (1..255), including lookups still finishing after `close()` abandoned them
  because the OS could not cancel them. When all are in use, `open()` of a host name returns false.
- `SSF_NETSOCK_CONFIG_CLOSE_DRAIN_MAX` is the number of bytes `close()` reads and discards, without
  blocking, before closing a connected socket. A socket closed with received data unread is reset
  (RST) rather than closed (FIN), and the peer may then drop the last bytes sent, such as a TLS
  alert. 0 disables the drain.

## ssftlsc TLS 1.3 Client

### Design

- TLS 1.3 client (RFC 8446) over any byte-stream `SSFNetTransport_t`, normally ssfnetsock. The
  session is itself an `SSFNetTransport_t`: pass `&session->transport` to a client such as
  ssfmqttc. `open()` opens the inner transport; `pollOpen()` drives the inner open and then the
  handshake; `send()`/`recv()` carry application data; `shutdown()` writes out a partly written
  record and close_notify; `close()` ends both and never waits, so bytes `send()` accepted can be
  lost without a `shutdown()` first.
- No I/O blocks and no threads are used. Public-key work runs inline in `pollOpen()`, in three
  steps: key exchange (X25519 or P-256 ECDH), certificate chain verification, and the
  CertificateVerify signature. A call runs at most one step, then returns `WANT_READ`; the call
  that completes the triggering message (ServerHello, Certificate, CertificateVerify) also runs its
  step. Each step occupies the caller for the whole computation: there is no finer split. Chain
  verification is the longest: it checks every signature in the chain plus the trust anchor's in
  one call, so its time grows with the chain length and is set by the slowest algorithms involved
  (P-384 and RSA-3072/4096 well above P-256, Ed25519 and RSA-2048). Size a single-threaded
  application's latency budget for that call.
- RSA keys are 2048 to 4096 bits ([ssfrsa.md](../_crypto/ssfrsa.md)): a server or CA key larger
  than 4096 bits fails the handshake. The largest size enabled in `ssfrsa_opt.h` sets the RSA
  verify stack (about 8.8 KB at 4096, 4.7 KB at 2048 on Cortex-M4 -Os), whatever key size the
  server uses.
- Stack: `pollOpen()` needs about 12.4 KB below its caller's frame (Cortex-M4, gcc -Os, static call
  graph, `SSF_X509_CONFIG_MAX_CHAIN_DEPTH` 6). The peak is chain verification: the 2.1 KB
  `SSFX509VerifyChainPurpose` frame (two parsed certificates) over an RSA signature check. Largest
  enabled RSA size 3072: 11.0 KB; 2048: 10.4 KB (an ECDSA check is then the deepest). Not
  included: the inner transport's functions, the trace callback, libc and the port layer. Key
  exchange and the other steps need less. Each chain entry adds 2 bytes. With an RSA client key
  the client CertificateVerify signature sets the peak instead: about 23.1 KB at the default
  RSA-4096 cap (RSA-PSS signing); P-256 / P-384 / Ed25519 signing stays below 10.4 KB.
- Client mode, full handshake only (no PSK resumption or 0-RTT). One connection per session.
- After the handshake, `recv()` parses handshake records: NewSessionTicket is checked only for its
  minimum length and skipped, its contents unparsed (no resumption, so no ticket is used);
  KeyUpdate (RFC 8446 4.6.3) moves receiving to the server's next key, and when the server asks,
  the client's own KeyUpdate goes out at the start of the next `send()`, before any data. The
  client also updates its key every `SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS` records (default 2^24,
  under the AES-GCM limit of 5.5). Anything else is unexpected_message.
- Client certificate (mutual TLS) is optional: `SSFTLSCSetClientCert()` with a chain and its
  ssfpkey key. When a server sends a CertificateRequest, the client signs with the first scheme in
  the server's signature_algorithms its key can make (P-256 / P-384 ECDSA, Ed25519, RSA-PSS rsae
  SHA-256 / SHA-384) and sends Certificate, CertificateVerify and Finished; the Certificate is
  streamed from the caller's memory record by record, so any chain fits any record size. The
  signature is a fourth inline crypto step (`SIGN_CV`). With no certificate set, or no scheme the
  server accepts, the client answers with an empty Certificate (RFC 8446 4.4.2): a server that only
  asks carries on. One that requires a certificate sends certificate_required (or rejects the
  chain) after the client Finished, so `pollOpen()` has already reported success; the first
  `recv()` fails, and for certificate_required the trace says the server requires a client
  certificate.
- Trust anchors are DER certificates in caller memory (`SSFTLSCTrustStore_t`). From PEM, a single
  certificate or a CA bundle, `SSFTLSCTrustFromPEM()` builds the store; it fails closed on anything
  that is not a certificate.
- The server's certificate must be X.509 v3 with a subjectAltName for the host name (or IP
  address) connected to; the Common Name is never used (RFC 9525). Public CAs always issue such
  certificates. A self-made broker certificate often lacks them (older `openssl x509 -req` without
  an extension file gives v1): issue it with e.g. `-addext "subjectAltName=DNS:broker.example"`
  (req) or an `-extfile` line (x509). The trace says which rule a refused certificate broke.
- ALPN (RFC 7301) is optional: `SSFTLSCSetALPN()` with the protocols to offer, `SSFTLSCGetALPN()`
  for the server's choice after the handshake.
- Cipher suites are offered in this order: ChaCha20-Poly1305 first (ssfchacha20 is constant-time
  while ssfaes, under AES-GCM and AES-CCM, is not, and it is fast without AES hardware), then
  AES-128-GCM (mandatory to implement; SHA-256 is cheaper than SHA-384 on 32-bit cores),
  AES-256-GCM and AES-128-CCM.
- IPv4 only (ssfnet.h): `open()` refuses an IPv6 literal host whatever the inner transport.
- Chain limit: `SSF_X509_CONFIG_MAX_CHAIN_DEPTH`, the verifier's own. Certificates a server sends
  past it are dropped; if verification then fails, the trace says the chain was cut.
- The handshake has no timer of its own; the caller bounds it (ssfmqttc's connectTimeout).
- Certificate validity needs the time. `SSFRTCInit()` must have been called before a handshake
  with trust anchors; using ssfrtc uninitialized is a programming error and asserts (ssfrtc.md). A
  time that is not valid, or before `SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC` (the simulated RTC reads
  1970 until `SSFRTCSet()`), fails the handshake with internal_error rather than checking
  certificates against it.
- `SSF_TLSC_CONFIG_MAX_RECV_RECORD` (default 16384, 64..16384) is the largest record plaintext
  received and is advertised to the server as record_size_limit (RFC 8449); it sizes the
  session's receive buffer (this + 17 bytes). RFC 8446 5.1 lets a peer send up to 2^14 unless a
  smaller limit is negotiated, so keep 16384 unless the server and its certificate chain are
  known. It must hold: the server's largest handshake message whole, however it splits it into
  records, usually its Certificate (a few hundred bytes for one EC certificate, 2-5 KB with a
  public CA; test.mosquitto.org's Let's Encrypt chain is 4,106 bytes); its plaintext ServerHello /
  HelloRetryRequest (90-200 bytes; record_size_limit does not apply to them); and every record it
  sends, unless it honors record_size_limit (GnuTLS does; OpenSSL s_server was seen sending larger
  records). Too small, the handshake fails with internal_error and a trace ("fragment too large",
  "do not fit").
- `SSF_TLSC_CONFIG_MAX_SEND_RECORD` (default 8192) sizes the session's send buffer; a sender may
  always use smaller records.
- `SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS` (default 2^24, 1..2^24): AES-GCM must not exceed 2^24.5
  full-size records per key (RFC 8446 5.5), so the default stays below that for every suite;
  ChaCha20-Poly1305's limit is far higher, so updating early there costs one small record.
- `SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED` defaults to 1 only when the ssftlsc unit test is built;
  override with -D. At 0 a session with no trust anchors can never connect.
- `SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC` (default 2025-01-01T00:00:00Z): an RTC reading before it,
  such as a device that booted at 0 (1970) or a failed read, means no trusted time.
- `SSF_TLSC_CONFIG_MAX_SEND_RECORD` must be at least `SSF_TLSC_CH_SIZE` (768): the ClientHello
  goes out as one plaintext record. `SSF_TLS_CONFIG_MAX_ALPN_LEN` may be at most
  `SSF_TLSC_CH_SIZE - 6 - SSF_TLSC_CH1_MAX_NO_ALPN` (219): the largest ClientHello1 without ALPN
  (a 255-byte host name in server_name) is 543 bytes, and ALPN adds 6 bytes plus the list.
- DBC exemption: the per-field encoding helpers `_SSFTLSCPut16`, `_SSFTLSCPut24`,
  `_SSFTLSCGet16`, `_SSFTLSCGet24`, `_SSFTLSCWBytes`, `_SSFTLSCW8` and `_SSFTLSCW16` carry no
  assertions; their callers validate the buffers.
- Known gaps are tracked in [ssftlsc_punchlist.md](ssftlsc_punchlist.md); this module is not yet
  production ready.

### Functions

- `SSFTLSCInit(session, inner, trustStoreOpt)` initializes a session over `inner`, which must
  outlive it. `trustStoreOpt` is copied by value; the arrays it points to must stay valid. Pass
  `&session->transport` to the client. A session with no trust anchors fails closed: `open()`
  returns false, unless `SSFTLSCSetUnauthenticated()` has opted in (only possible when
  `SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED` is 1).
- `SSFTLSCTrustFromPEM(pem, pemLen, poolOpt, poolSize, dersOpt, lensOpt, maxCount, storeOpt,
  poolUsedOut, countOut)` builds a trust store from PEM text: one certificate or a bundle of them
  (RFC 7468), with text allowed between blocks if it holds no `-----BEGIN` / `-----END` marker.
  Each certificate is decoded as DER into `poolOpt` (one after another; it must not overlap `pem`,
  which asserts), `dersOpt[i]` / `lensOpt[i]` are set for each (both arrays hold `maxCount`
  entries), and `*storeOpt` is `{ dersOpt, lensOpt, count }`, ready for `SSFTLSCInit()`; pool and
  arrays must stay valid while the session uses it.
  - It fails closed: every block must be a CERTIFICATE that parses as exactly one X.509
    certificate, so a stray key, a malformed block (a damaged BEGIN line included: its END line is
    then a stray marker), one more certificate than `maxCount`, or a pool too small, rejects the
    whole input. `*poolUsedOut` gets the pool bytes used and `*countOut` the certificates loaded.
    On an error the store is `{ NULL, NULL, 0 }`, `*poolUsedOut` is 0 and `*countOut` is the
    0-based index of the certificate block at fault.
  - Measuring: with `poolOpt` NULL (`dersOpt`, `lensOpt` and `storeOpt` are then ignored and may be
    NULL) the pool size and count needed are reported, with up to 255 certificates; this checks the
    PEM and labels but cannot parse the certificates.
  - Anchors are not checked for the CA flag or validity here; the chain verifier does that on
    every handshake. On a host, read the file into a buffer first, e.g. `fread()` of a CA bundle.
  - Results: `SSF_TLSC_TRUST_ERR_PEM` a malformed PEM block (BEGIN / END lines, Base64);
    `_LABEL` a block that is not a CERTIFICATE; `_CERT` a CERTIFICATE that is not exactly one X.509
    certificate; `_COUNT` more certificates than `maxCount` (255 when measuring); `_SIZE` the
    certificates do not fit `poolSize` bytes; `_EMPTY` no certificate in the input.
- `SSFTLSCDeInit(session)` closes any connection, wipes the session and releases it.
- `SSFTLSCSetUnauthenticated(session, allow)` opts in (`allow` true) to connecting with no trust
  anchors. The server certificate chain and host name are then NOT verified, so any party able to
  intercept the connection can impersonate the server. For tests and development only. Has no
  effect when trust anchors are configured: they are always used. Call while the session is not
  open. With `SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED` 0 it is compiled out and any call is a
  compile error.
- `SSFTLSCSetClientCert(session, chainDerOpt, chainLensOpt, chainCount, keyOpt)` sets the client
  certificate presented when a server asks for one (mutual TLS): `chainDerOpt[0]` is the
  end-entity certificate, then any intermediates, each `chainLensOpt[i]` bytes of DER; `keyOpt` is
  its private key (ssfpkey). Nothing is copied: the arrays, certificates and key must stay valid
  while the session can connect. Returns false, leaving no certificate set, if the chain is
  malformed, the leaf does not parse, or its public key is not the key's. Pass NULL, NULL, 0, NULL
  to clear. Call while the session is not open.
  - The key must come from `SSFPKeyDecodeDER()` / `SSFPKeyDecodePEM()` / `SSFPKeyFromECPriv()`,
    which validate it and fill every field consistently. Only the type and public key are
    compared here; a hand-built `SSFPKey_t` whose other fields disagree (e.g. a scalar length
    that is not the curve's) is a programming error and asserts when the CertificateVerify is
    signed.
  - When a server asks for a certificate, the chain is sent only if every certificate in it is
    signed with a scheme the server lists (signature_algorithms_cert, else signature_algorithms;
    RFC 8446 4.4.2.3), a self-signed last certificate excepted; otherwise an empty Certificate. A
    leaf the server is likely to refuse (expired, Key Usage without digitalSignature, EKU without
    clientAuth) is traced as a warning and still sent: the server decides.
- `SSFTLSCSetALPN(session, protosOpt, count)` sets the protocols offered with ALPN (RFC 7301), in
  preference order: e.g. `"x-amzn-mqtt-ca"` for AWS IoT MQTT on port 443. Nothing is copied: the
  array and strings must stay valid and unchanged while the session can connect. Each name is a
  NUL-terminated string of 1..255 bytes; the names, each plus one length byte, must total at most
  `SSF_TLS_CONFIG_MAX_ALPN_LEN` (default 32, at most 219). Returns false, leaving none set,
  otherwise. Pass NULL, 0 to clear. Call while the session is not open.
  - The server's answer must be exactly one of the offered names (else illegal_parameter). A
    server may also answer with none: the handshake still succeeds, and `SSFTLSCGetALPN()` says
    so; whether to carry on is the caller's decision. A server that requires ALPN and supports
    none of the names ends the handshake with no_application_protocol.
- `SSFTLSCGetALPN(session)` returns the protocol the server chose (the caller's own string from
  `SSFTLSCSetALPN()`), or NULL if it chose none or the handshake is not complete: the choice
  arrives before the server is authenticated, so it is reported only once `pollOpen()` has
  succeeded. Cleared when the connection closes and when `SSFTLSCSetALPN()` is called.
- `SSFTLSCSetTrace(session, traceFnOpt, traceCtxOpt)` sets an optional per-connection trace
  callback; a NULL `traceFnOpt` disables tracing.
- `SSFTLSCGetHandshakeState(session)` returns the current handshake state. The `_DERIVE_HS_KEYS`
  (ECDH and the handshake key schedule), `_VERIFY_CHAIN`, `_VERIFY_SIG` and `_SIGN_CV` (the client
  CertificateVerify signature) states are the inline crypto steps. `_RECV_FIN_SEND_FIN` also sends
  the client Finished when there is no client authentication; with it, `_SEND_CLIENT_CERT` and
  `_SEND_CV_FIN` send the client flight.

## See Also

- [Finite State Machine](../_fsm/README.md) — ssfsm runs the MQTT client protocol logic and timers
- [Data Structures](../_struct/README.md) — ssfmpool and ssfll back the client's packet pools and queues
