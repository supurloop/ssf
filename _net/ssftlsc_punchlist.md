# ssftlsc — TLS 1.3 Client Punch List

[SSF](../README.md) | [Network](README.md)

Working list for bringing `ssftlsc` from its original form to a TLS transport for `ssfmqttc`.

**Background.** `ssftlsc` was first written against a custom, non-socket IP stack (`ssftcp`,
`ssfipv4`, `SSFNetStackTask`), which is not part of this repository. Going forward only a
sockets-compatible stack interface is supported: `ssftlsc` runs over any byte-stream
[`SSFNetTransport_t`](ssfnet.h) (normally [`ssfnetsock`](ssfnetsock.h)) and is itself an
`SSFNetTransport_t`, so `ssfmqttc` uses it without change. The custom-stack code paths are
dropped, not kept alongside. `ssflptask` is not used: public-key work runs inline on the
caller's thread, one heavy step per `pollOpen()` call, so no threads are required.

Line references are to `ssftlsc.c` as first added; they drift as items are fixed.

## Step 1 — Transport restructure (done)

Verified over loopback against `openssl s_server` (OpenSSL 4.0): AES-256-GCM/SHA-384,
ChaCha20-Poly1305 and AES-128-GCM with an HRR to P-256; a certificate not issued for the host
is rejected.

- [x] Replace the `ssftcp` socket with an inner `SSFNetTransport_t`; remove `ssfipv4.h`,
      `ssftcp.h`, `SSFTCPTask`, `SSFNetStackTask` and IPv4 addressing.
- [x] Expose the session as an `SSFNetTransport_t` (`open`, `pollOpen`, `send`, `recv`,
      `close`); the handshake runs inside `pollOpen()`.
- [x] Copy the host name at `open()` (SNI and certificate name), reject an empty host.
- [x] Delete the blocking API and helpers: `SSFTLSCConnect`, `SSFTLSCConnectAsync`, the public
      `SSFTLSCTask`, `SSFTLSCSend`/`Recv`/`SendOnce`/`RecvOnce`, `_TcpSend`, `_TcpRecv`,
      `_SendPlainRecord`, `_SendEncRecord`, `_RecvRecord`, `_RecvHandshake`, `_SendClientHello`,
      `_TlscTcpEvent`.
- [x] `recv()` buffers a decrypted record and returns it across calls of any size.
- [x] `send()` accepts up to one record per call; a partly written record is finished first.
- [x] Remove `ssflptask`: run ECDH, chain verification and CertificateVerify inline, one per
      `pollOpen()` call (the `*_WAIT` states become crypto steps). Removes the worker-thread
      race on the completion flag and the unchecked `SSFLPTaskQueue` result.
- [x] `close()` never blocks: best-effort `close_notify`, then close the inner transport.
- [x] Reset all per-connection state on `open()` so a session can reconnect.
- [x] Pulled forward to make step 1 testable: record states are de-initialized before re-init
      (every handshake asserted in `SSFTLSRecordStateInit`); entropy from `SSFPortGetEntropy`
      (Windows always failed).
- [x] Build: `SSF_CONFIG_TLSC_UNIT_TEST`, `main.c`, ninja files, Visual Studio project.

## Step 2 — Security fixes

- [x] Verify the server Finished (constant-time compare) before deriving application keys.
      Spot-checked: a corrupted verify_data (unit-test hook `_ssfTLSCUTCorruptServerFinished`)
      is rejected; good Finished accepted for SHA-256 and SHA-384. The `decrypt_error` alert
      the RFC requires is part of the fatal-alert item below. Exhaustive run pending.
- [x] Fail closed on an empty trust store; explicit opt-in for an unauthenticated test mode.
      `open()` returns false with no trust anchors (NULL or empty store) before any traffic, so
      no ClientHello / SNI leaks; `SSFTLSCSetUnauthenticated()` is the only way to connect
      without anchors (traced as "Server NOT authenticated"), and never weakens a configured
      store; the verify step re-checks so verification cannot be skipped silently. Unit tests:
      no store, empty store, opt-in then opt-out, opt-in only while idle. Spot-checked with
      `s_server`: refused / unauthenticated / verified / wrong-host rejected even with opt-in.
      Exhaustive run pending.
- [x] Compile-time switch (e.g. `SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED`, default 0 outside unit
      tests) so production builds cannot contain the unauthenticated mode. Found during 2.2.
      New `_opt/ssftlsc_opt.h`: default 1 only when the ssftlsc unit test is built. With 0 the
      opt-in and its code paths are compiled out and a call to `SSFTLSCSetUnauthenticated()`
      is a compile error naming the option. Build check (6/6): no symbol, no "NOT
      authenticated" path in the object, caller fails to compile, default build unchanged.
      Production-configuration spot check: no trust store refused, trusted connects, wrong host
      rejected (42). Exhaustive run pending.
- [x] After `recvEncrypted`, reject plaintext handshake and alert records; accept
      ChangeCipherSpec only as a single `0x01` byte, only during the handshake. Also (same code,
      RFC 8446 5): plaintext `application_data` or unknown types before keys, protected
      ChangeCipherSpec or unknown inner types, empty handshake records, alert length != 2.
      Spot-checked with an on-path injector (`mitm.py`): bad-value and two-byte CCS, plaintext
      handshake after ServerHello and after the handshake, forged plaintext `close_notify`
      (was reported as an orderly CLOSED: truncation), post-handshake CCS and type 24 are all
      rejected; OpenSSL's real compatibility CCS is still accepted. Protected-record checks need
      keys and are not injectable: covered by RFC 8448 negative tests (step 5). Exhaustive run
      pending.
- [x] Reject `rsa_pkcs1_*` in CertificateVerify. (Revised: RFC 8446 4.2.3 allows PKCS#1 in
      `signature_algorithms`, which also covers certificate signatures when
      `signature_algorithms_cert` is absent; browsers and OpenSSL send it there, and most CA
      chains need it. The ClientHello is unchanged; the fix is on receipt.) CertificateVerify
      parsing moved to `_ParseCertificateVerify()`: only offered TLS 1.3 handshake schemes
      (ECDSA P-256/P-384, RSA-PSS-RSAE SHA-256/384, Ed25519); PKCS#1 also removed from the
      hashing and verify paths. Unit tests via `_SSFTLSCParseCertificateVerifyForTest()`.
      Spot-checked: RSA-PSS SHA-256 and SHA-384 (RSA leaf with a PKCS#1-signed chain), Ed25519,
      P-384, P-256 all verify. OpenSSL will not send PKCS#1 in TLS 1.3, so that rejection is
      unit-tested only. Exhaustive run pending.
- [x] ServerHello validation: `supported_versions == 0x0304`, session ID echo, compression 0,
      group was offered, exact key-share length per group, cipher suite unchanged after HRR,
      HRR must not name a group already in `key_share`. Also (RFC 8446 4.2): unsolicited
      extensions (incl. `pre_shared_key`), duplicate extensions, missing `supported_versions` /
      `key_share`, extension list must end exactly at the message end, HRR group must be in
      `supported_groups`, cookie length checked. Spot-checked with `mitm.py` rewriting the
      ServerHello / HRR (16 cases, each now rejected at the field with its own reason; before,
      each failed later at decryption/ECDH or by server alert). Exhaustive run pending.
- [x] Bounds checks: Certificate `reqCtxLen` then list length. (Done with 2.5: the HRR cookie
      loop is replaced by the validating parser; ServerHello / HRR message length must equal
      the record length.) Certificate parsing moved to `_ParseCertificate()` with RFC 8446 4.4.2
      rules: empty request context, list fills the message exactly, non-empty list and
      `cert_data`, extensions within the entry and none unsolicited, every entry validated
      even past `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH`. Permanent unit tests through
      `_SSFTLSCParseCertificateForTest()` (14 cases; before the fix 5 were wrongly accepted and
      one read past the message under ASan). Two-certificate chain from `s_server` verified.
      Exhaustive run pending.
- [x] CertificateVerify: reject bytes after the signature (`4 + sigLen` must equal the body
      length, `decode_error`), and an empty signature. Found during 2.6; done with 2.4, same
      unit tests (15 cases; before the fix PKCS#1 SHA-256/384, trailing bytes and an empty
      signature were accepted).
- [x] EncryptedExtensions is not parsed: validate its structure and reject extensions the
      ClientHello did not offer (`unsupported_extension`); needed for ALPN. Found during 2.6.
      `_ParseEncryptedExtensions()`: exact framing (`decode_error`); `server_name` only as an
      empty acknowledgement; `supported_groups` framing checked; offered extensions not valid
      in EE (`supported_versions`, `key_share`, `signature_algorithms`,
      `psk_key_exchange_modes`) and duplicates `illegal_parameter`; anything not offered
      `unsupported_extension`. 21 unit tests via `_SSFTLSCParseEncryptedExtensionsForTest()`
      (17 were accepted before). `s_server` EE accepted for EC, RSA, Ed25519, HRR and server
      group-preference configurations. Exhaustive run pending.
- [x] Zeroization with `SSFCryptSecureZero`: stack `key`/`iv`, handshake / derived / master
      secrets, `savedHandshakeSecret`, ephemeral keys on every path, record states and buffers
      on close. `_SSF_TLSC_SCRUB` wipes each secret at the end of its life and, in unit-test
      builds, reports it to `_SSFTLSCScrubTestHook` (the `ssftls` finished-key pattern).
      `_DeriveHandshakeKeys` has a single exit so failures wipe too. Session lifetimes:
      ephemeral keys after ECDH (any outcome), handshake secret after the master secret,
      handshake traffic secrets after the client Finished; application secrets kept for
      KeyUpdate until close. A failed connection wipes every secret, plaintext buffer and record
      state at once (`_SSFTLSCWipeKeys`), not at `close()`. Unit test: ephemeral keys wiped
      when the peer hangs up after ClientHello. Spot-checked: 0 of ~33 reported buffers live
      after X25519, HRR-to-P-256 and failed handshakes (22 of 23 were live before).
      Exhaustive run pending.
- [x] Fatal alerts sent on protocol errors (`unexpected_message`, `decode_error`,
      `bad_record_mac`, `bad_certificate`, `decrypt_error`). Each failure site records its
      alert (`_SSF_TLSC_ALERT`, first wins; parsers return theirs); `_SSFTLSCFail` sends it
      before the key wipe, `internal_error` when none was recorded. No alert after a transport
      failure or a peer alert; a peer close_notify is answered with close_notify. Alerts after
      ServerHello are protected: client handshake send keys are now installed with the
      handshake keys (RFC 8446 6, 7.3), not at Finished. Mapping: Finished / CertificateVerify
      signature `decrypt_error`; record-type violations `unexpected_message`; bad record
      `bad_record_mac`; over 2^14+256 `record_overflow`; ServerHello field errors
      `illegal_parameter`, unsolicited extension `unsupported_extension`, missing key_share
      `missing_extension`, missing supported_versions `protocol_version`; certificate problems
      `bad_certificate`; framing `decode_error`. Unknown record types are rejected from the
      header, before the fragment is read. Unit test: plaintext `unexpected_message` alert
      bytes on the wire. Spot-checked: OpenSSL receives the expected alert number for every
      rejection reachable over the wire (bad Finished 51, wrong-host cert 42, ServerHello cases
      47/70/109/110, injected records 10); a post-handshake alert is one protected record.
      Exhaustive run pending.
- [x] Alerts can be lost to a TCP reset: when the client aborts with the server's flight still
      unread, closing the socket sends RST and the server may drop the alert unread (seen
      intermittently, 2 of 23 rows in one run). Drain readable bytes (or half-close) in
      `ssfnetsock` close. Found during 2.8. `ssfnetsock` close() now reads and discards what has
      already arrived (non-blocking, `SSF_NETSOCK_CONFIG_CLOSE_DRAIN_MAX`, default 64 KiB)
      before closing. ssfnetsock unit test: close with unread data gives the peer the last byte
      and an orderly EOF (was ECONNRESET, 5/5). Alert delivery when aborting at ServerHello:
      10/10 for three cases and 20/20 for a fourth. Data still in flight at close() can still
      cause an RST. Exhaustive run pending.
- [x] `close()` during the handshake sends nothing; RFC 8446 6.1 expects `user_canceled` then
      `close_notify`. Found during 2.8. Once the ClientHello is out, close() mid-handshake sends
      both at warning level, protected when handshake send keys exist. Unit test reads the exact
      plaintext records then EOF; `s_server -msg` decrypts both after ServerHello. A connected
      close still sends close_notify only. Exhaustive run pending.

## Step 3 — Correctness and interop

- [ ] Certificate failures all map to `bad_certificate`; RFC 8446 6.2 has `unknown_ca`,
      `certificate_expired`, `unsupported_certificate`, which need the failure reason from
      `SSFX509VerifyChain`. Found during 2.8. Moved from step 2 to a later batch.
- [ ] Stack secrets inside the crypto modules ssftlsc calls (`ssfhkdf`, `ssfhmac`,
      `ssfx25519`, `ssfecdsa`, `ssfaesgcm`, ...) are outside this audit; review each module's
      own zeroization. Found during 2.7. Moved from step 2 to a later batch.
- [ ] Build ClientHello in one function (currently three copies, already diverged).
- [ ] Cipher suites: support AES-128-CCM in ServerHello or stop offering it. Prefer
      ChaCha20-Poly1305 (constant time; `ssfaes` is not).
- [ ] Reassemble handshake messages that span records.
- [ ] Records up to 2^14 + 256 bytes, or negotiate `record_size_limit` (RFC 8449).
- [ ] Decrypt in place in `recvBuf`; drop the 8 KB stack copy in `_RecvRecordOnce`.
- [ ] Remove 8 KB `buf` from every handler stack frame.
- [ ] Chains longer than `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH` keep only the first entries; an
      intermediate past the limit is lost and verification fails. Document, or raise the default.
- [ ] Long single steps: P-384/RSA chain verification can take a long time inline on small
      targets; consider splitting verification per certificate across `pollOpen()` calls.
- [ ] Do not send SNI for a literal IP address (RFC 6066).
- [ ] Check the CertificateVerify scheme against the leaf key type and curve explicitly
      (`illegal_parameter`); today a mismatch is caught only as a failed verification. Found
      during 2.4.
- [x] P-384 HRR uses the wrong private key offset. Moot: 2.5 rejects an HRR for a group that
      already has a key share, so only P-256 can be selected by an HRR.
- [ ] RTC unavailable: distinct error rather than verifying at time 0.
- [ ] A record still partly written when `close()` runs is dropped (`close_notify`, or the tail
      of application data). Found during step 1.

## Step 4 — Features

- [ ] CertificateRequest and client authentication (mutual TLS: AWS IoT, Azure).
- [ ] Private key loading: PKCS#8 / SEC 1 / PEM.
- [ ] KeyUpdate: install new receive keys, answer `update_requested`; send-side KeyUpdate before
      the AEAD record limit.
- [ ] ALPN (e.g. `x-amzn-mqtt-ca` for AWS IoT on 443).
- [ ] Trust store loading: CA bundles (multiple certificates per file), no silent truncation,
      no filesystem requirement in the core (`ssftls_certs.c` is POSIX-only).

## Step 5 — Tests and cleanup

- [ ] RFC 8448 handshake traces as deterministic vectors (needs injectable random and keys).
- [ ] Deterministic parser unit tests like `_SSFTLSCParseCertificateForTest` for the ServerHello
      parser (2.5 is covered only through `mitm.py` today).
- [ ] Interop with `openssl s_server` over loopback; test.mosquitto.org:8883 with its CA.
- [ ] Negative tests for every step 2 check.
- [ ] Bring the loopback `openssl s_server` interop harness into the repo (spot checks for step 2
      currently run from a scratch driver, which sets the unit-test hooks).
- [ ] The leaf public key is parked in `clientHelloMsg` between handshake steps; give it its own
      field.
- [ ] SSF conventions: `_SSFTLSC*` static names, 99-column comment boxes, copyright year,
      remove "Phase / M3" milestone comments; documentation `ssftlsc.md`; update `ssftls.md`
      ("no X.509 in SSF" is out of date).
