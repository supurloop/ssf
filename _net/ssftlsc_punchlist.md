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
      even past the chain limit (now the x509 depth). Permanent unit tests through
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
      cause an RST. Exhaustive run pending. Residual race measured later through the proxy
      (`ks_missing`, server flight forwarded in separate writes): alert delivered 36/40 at the
      step 2 commit and 39/40 after step 3 item 3 -- same race, not a regression.
- [x] `close()` during the handshake sends nothing; RFC 8446 6.1 expects `user_canceled` then
      `close_notify`. Found during 2.8. Once the ClientHello is out, close() mid-handshake sends
      both at warning level, protected when handshake send keys exist. Unit test reads the exact
      plaintext records then EOF; `s_server -msg` decrypts both after ServerHello. A connected
      close still sends close_notify only. Exhaustive run pending.

## Step 3 — Correctness and interop

- [x] Certificate failures all map to `bad_certificate`; RFC 8446 6.2 has `unknown_ca`,
      `certificate_expired`, `unsupported_certificate`, which need the failure reason from
      `SSFX509VerifyChain`. Found during 2.8. Moved from step 2 to a later batch. Fixed (3B item D,
      approved, outside the client): `SSFX509VerifyChain()` / `SSFX509VerifyChainPurpose()`
      take a required `SSFX509VerifyErr_t *errOut` = { code, certIdx } naming the first check
      that failed (17 codes, one per failure point; `certIdx` is the rejected chain index,
      `chainLen` for the anchor's own pathLen). `ssfcms` passes a local and traces it;
      `ssfx509.md` documents the codes. ssftlsc maps: corrupt / signature / issuer / key-id /
      host name -> `bad_certificate` (host name as OpenSSL and GnuTLS clients send), version /
      critical extension -> `unsupported_certificate`, not yet valid / expired ->
      `certificate_expired`, CA and usage rules -> `certificate_unknown`, no anchor ->
      `unknown_ca`. Alerts 43/45/48 added to `ssftls.h` (46 was already there). Unit:
      all 139 `ssfx509_ut` verify calls check code and index (88 failure expectations derived
      independently of the implementation, all matched first run), NULL `errOut` asserts, a
      code -> alert table test. Wire (`s_server` received): expired 45, not yet valid 45,
      untrusted CA 48, clientAuth-only EKU 46, unknown critical extension 43, issued by a
      non-CA 46, wrong host 42 (all 42 before).
- [x] `ssfx509_ut` cases that pass for a reason other than the one they describe (found while
      deriving D's expected codes): the "192.168.1.1" IP host case uses time 1775000000,
      before `_utTestCertDER`'s notBefore (1775422718), so it fails NOT_YET_VALID and never
      reaches host matching; the name-constraint "excluded name retained" case still has
      MAX_SAN_ENTRIES + 1 SANs and fails at PARSE. Comments in the expired / not-yet-valid
      cases state 1775000000 where the code uses 1780000000. Outside the TLS client. Fixed (3B item N, approved): the IP host case
      now verifies at 1780000000 (inside the validity) and expects `ERR_HOSTNAME`; the
      constraint case uses exactly MAX_SAN_ENTRIES SANs with `evil.com` first, asserts the leaf
      parses, and expects `ERR_NAME_CONSTRAINTS`; the two comments read 1780000000. Mutation
      check: letting IPv4 hosts skip host matching is now caught first by the fixed IP case
      (before the fix it got past it to a later test).
- [ ] Stack secrets inside the crypto modules ssftlsc calls (`ssfhkdf`, `ssfhmac`,
      `ssfx25519`, `ssfecdsa`, `ssfaesgcm`, ...) are outside this audit; review each module's
      own zeroization. Found during 2.7. Moved from step 2 to a later batch.
- [x] Build ClientHello in one function (currently three copies, already diverged).
      `_BuildClientHello()` is the only builder (bounded writer into `clientHelloMsg`);
      ClientHello2 is built in place with ClientHello1's random and session id, the one share
      the HRR selected, and the cookie. The divergence it fixes, found by the new test:
      ClientHello2 used a NEW random (RFC 8446 4.1.2 requires the same ClientHello; OpenSSL does
      not check), and a cookie too large to echo was silently dropped (ClientHello2 sent without
      it); now the handshake aborts with `internal_error`. Unit tests (fake server sends a crafted
      HRR): ClientHello2 equals ClientHello1 field by field except `key_share` (one P-256 share)
      and the cookie (byte-exact echo); oversized cookie aborts with the alert. The 1 KB HRR stack
      buffer is gone (`_TlscHandleSendCH` frame 1744 -> 832 bytes). Spot-checked against
      `s_server`: all handshake types, HRR, and an HRR from `-stateless` (same random on the wire;
      OpenSSL sent no cookie there, so cookie echo is unit-tested only). Exhaustive run pending.
- [x] Cipher suites: support AES-128-CCM in ServerHello or stop offering it. Prefer
      ChaCha20-Poly1305 (constant time; `ssfaes` is not).
      - [x] AES-128-CCM supported: `_ParseServerHello` maps 0x1304 to SHA-256 / 16-byte key (was
        an `internal_error` abort for a suite the client offers); the record layer already
        handled CCM. Unit test: a HelloRetryRequest selecting each offered suite gets
        ClientHello2 (CCM failed before). `s_server` with CCM only: handshake + data direct,
        after HRR, with RSA-PSS, and under ASan (all aborted with alert 80 before). CCM_8, not
        offered, is still rejected (`illegal_parameter`). Exhaustive run pending.
      - [x] Preference order: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM, AES-128-CCM (in
        `_BuildClientHello`). Unit test checks the ClientHello order; a default `s_server` now
        negotiates ChaCha20 (was AES-256-GCM); servers forcing a suite, and `-serverpref`, still
        get theirs. Exhaustive run pending.
      - [x] `ssftls.md` says ChaCha20-Poly1305 is "the CPU-constant-time option", but
        `ssfpoly1305` is not constant-time (its use in TLS, a MAC over public ciphertext with a
        per-record key, is what its docs call acceptable). Outside the TLS client; needs approval. Fixed (3B item M, approved):
        reading `ssfpoly1305.c` (MulR, block, Update, End, Verify) and its Cortex-M4 / M0 -Os
        code shows no secret-dependent branches (End's six branches are five SSF_REQUIRE asserts
        and the public partial-length test; the final reduction is masked) and no tables: it is
        constant-time given a constant-latency 32x32->64 multiply (UMULL/UMLAL on M4; not the
        early-terminating Cortex-M3; M0 calls __aeabi_lmul). `ssfpoly1305.md` said "not
        constant-time" with reasoning that did not match the code (r is used in every block);
        both docs now state the multiplier condition.
- [x] CertificateVerify used the transcript hash length, not the signature scheme's, when
      passing the signed-content hash to the verifier: ECDSA P-384 and RSA-PSS-SHA384 signatures
      failed under every SHA-256 suite (ChaCha20, AES-128-GCM). Exposed by the ChaCha20-first
      order. Now carries `sigHashLen`. Signature scheme x suite matrix against `s_server`
      (5 schemes x 3 suites): 4 failed before, 15/15 after; P-384 + ChaCha20 clean under ASan.
      Exhaustive run pending.
- [x] Reassemble handshake messages that span records. `_RecvHandshakeOnce` reassembles in
      place in `hsBuf` (unread bytes moved to the front, the next record decrypted after them;
      `ssfbfifo` was considered but only copies in/out, so messages could not be parsed in
      place). ServerHello / HRR now use the same path. RFC 8446 5.1 rules: no record may be
      interleaved in a fragmented message (`unexpected_message`); ServerHello, HRR and the
      server Finished must end their record (bytes after Finished were silently discarded
      before); a message larger than the buffer, or a record that no longer fits, is this
      build's limit (`internal_error`, was `decode_error` / `bad_record_mac`). Unit tests (fake
      server): HRR with a split header and in 1-byte records gets ClientHello2; CCS mid-message
      and bytes after the HRR give `unexpected_message`; an oversized message gives
      `internal_error` (5/5 were wrong before). Wire: `s_server -max_send_frag 512` with EC,
      P-384 and RSA chains, and 1024 with RSA, now connect (were alert 80); proxy re-splitting
      the ServerHello / HRR into 7- and 1-byte records connects. Exhaustive run pending.
- [x] Records up to 2^14 + 256 bytes, or negotiate `record_size_limit` (RFC 8449).
      - [x] Step 1, full-size receive: new `SSF_TLSC_CONFIG_MAX_RECV_RECORD` (default 16384,
        RFC 8446 5.1) sizes `recvBuf` / `hsBuf`; `SSF_TLSC_CONFIG_MAX_SEND_RECORD` (default 8192)
        sizes `sendRecordBuf` and outgoing records. Plaintext records over 2^14 are always
        `record_overflow`; a legal record larger than a reduced build's buffer is
        `internal_error`. `SSF_TLS_CONFIG_MAX_RECORD_SIZE` removed from `_opt/ssftls_opt.h` and
        `ssftls.md` (approved; the client was its only user). Session 26,944 -> 43,336 bytes;
        stack unchanged. Unit test: a 16,385-byte plaintext record gets `record_overflow` (was
        `internal_error`, then accepted until the check was made unconditional). Wire, all
        previously alert 80: OpenSSL 12 KB and 20 KB echoes (a full 16,384-byte record), padded
        records, a 10 KB certificate chain in one record; GnuTLS 3.8.13 10 KB chain and 12 KB
        echo. Exhaustive run pending.
      - [x] Step 2, `record_size_limit` (RFC 8449): always offered in the ClientHello as
        `SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1` (identical in ClientHello2). EncryptedExtensions
        accepts it: not 2 bytes is `decode_error`, below 64 or duplicated is `illegal_parameter`,
        above 2^14+1 is capped (the RFC's "MAY abort" not taken). Outgoing records are capped at
        the server's limit minus the content type byte. Once negotiated, a protected record over
        the advertised limit is `record_overflow`; not negotiated, a legal record larger than a
        reduced build's buffer stays `internal_error`. Unit: 8 EncryptedExtensions cases, the
        ClientHello value. Wire: `gnutls-serv --recordsize 1024` advertises 1025 and all 14
        client records stay within it (largest exactly 1025); a 4 KB-receive build gets a 12 KB
        echo from GnuTLS in records that fit (was alert 80); an oversized record injected by a
        proxy is `record_overflow` (GnuTLS, negotiated) / `internal_error` (OpenSSL 4.0, which
        does not implement RFC 8449). Exhaustive run pending.
- [x] Decrypt in place in `recvBuf`; drop the 8 KB stack copy in `_RecvRecordOnce`.
- [x] Remove 8 KB `buf` from every handler stack frame. Done together: the record header and
      fragment are read contiguously into `recvBuf` and decrypted in place;
      `_RecvHandshakeOnce` returns the message in place in `hsBuf` (the Certificate /
      CertificateVerify pointer remapping is gone). Gate (`-fstack-usage`, per function): five
      frames of 8.5-10 KB before, largest now 1.95 KB. Whole-handshake stack high-water: EC
      paths 35.0 KB -> 28.3 KB, RSA 40.1 KB -> 33.4 KB; the remaining depth is in the called
      modules (next item). Spot-checked: all handshake types, 2-cert chain, ASan, injection and
      ServerHello cases, zeroization. Exhaustive run pending.
- [x] Stack depth now set by called modules: `SSFX509VerifyChainPurpose` has a 14.5 KB frame
      (sets the 28 KB EC peak); RSA adds `SSFRSAVerifyPSS` 6 KB and `SSFBNModExpMont` 10.6 KB
      (33 KB peak). Review in `ssfx509` / `ssfrsa` / `ssfbn`. Found during step 3 item 5.
      Re-measured (3B item G; Cortex-M4 -Os, depth 6): those figures were x86 -O1 at depth 8.
      Verifier frame 6.6 KB (the 6 parsed certificates). `SSFBNModExpMont` (10.4 KB) is
      private-key only; verify uses `SSFBNModExpMontPub`: verify path 9.7 KB at the 4096 maximum
      (7.4 KB at 3072, 5.1 KB at 2048). RSA documented (approved): 4096 is the deliberate
      ceiling, larger keys are not practical on SSF targets, and the largest enabled size sets
      the stack (`ssfrsa.md` key-size note with the table; `ssftlsc.h` design note). Also fixed
      the `SSFBN_CONFIG_MAX_BITS` typo in `ssfrsa.md`. Closed (3B item G): whole-handshake peak
      from a static call graph (`arm-none-eabi-gcc -Os -fstack-usage -fcallgraph-info=su`,
      deepest path from `_SSFTLSCPollOpen`, the non-NIST fallback `SSFBNModMulNIST` ->
      `SSFBNModMul` pruned as unreachable): 18.9 KB at the RSA-4096 maximum (RSA signature in the
      chain), 16.3 KB at 3072, 14.9 KB at 2048 (ECDSA in the chain). Method checked against the
      README's call-graph figures (ECDSA verify 7.9 vs 7.8 KB, RSA verify 10.9 vs 10.4 KB). The
      RSA verify path is 10.9 / 8.3 / 5.7 KB (the earlier 9.7 / 7.4 / 5.1 KB omitted two leaf
      frames); `ssfrsa.md` corrected. `ssftlsc.h` gains a stack design note (excludes the inner
      transport, trace callback, libc and port layer). Moving the verifier's certificate array
      to caller RAM (option B) is not planned: it trades about 6.6 KB of stack for the same RAM;
      revisit with a resumable chain verify (item I). `README.md` (approved): X.509 stack ~12 -> ~18 KB
      (13.9 KB RSA-2048-only), CMS ~15 -> ~20 KB (16.1 KB); footnote 58's "halving the depth
      roughly halves it" replaced by about 1.1 KB per chain entry.
- [x] Remaining ssftlsc locals: the leaf `SSFX509Cert_t` (1.5 KB) in the Certificate handler
      (the 1 KB HRR ClientHello buffer went with the single ClientHello builder). At -O1
      gcc inlines the handlers into `_SSFTLSCDrive` and their locals add up to a 2.4 KB frame;
      keep handlers out of line or move the leaf certificate off the stack. Found during step 3
      item 5. Fixed: the leaf parse moved into `_SaveLeafKey()`, marked
      `SSF_NOINLINE` (`ssfport.h`), so the parsed certificate exists only during that call and
      no longer sits under chain verification. `_SSFTLSCDrive` 2,400 / 2,384 / 2,400 -> 992 /
      976 / 976 bytes at -O1 / -O2 / -Os (new gate: Drive with inlining, limit 1024). Runtime
      peak 28,312 -> 26,904 bytes (EC), RSA-PSS 31,944. No RAM cost. Unit: P-256 leaf saved
      (65-byte key, P256), RSA-8192 leaf refused (key over the 768-byte space), truncated and
      damaged DER refused. Compilers other than GCC/Clang/MSVC get an empty `SSF_NOINLINE` and
      may inline it again. Exhaustive run pending.
- [x] Chains longer than `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH` keep only the first entries; an
      intermediate past the limit is lost and verification fails. Document, or raise the default.
      Fixed (3B item H, approved): `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH` removed (`ssftls_opt.h`,
      `ssftls.md`; a build still defining it gets an `#error`); the client's chain limit is the
      verifier's `SSF_X509_CONFIG_MAX_CHAIN_DEPTH`, so no relationship needs enforcing, and its
      default is 8 -> 6 (`ssfx509_opt.h`, `ssfx509.md`; ssfcms still needs >= 5). Extra
      certificates are still kept-first-N (harmless trailing roots verify); `_ParseCertificate`
      reports how many were sent, and a failure on a cut chain traces "Certificate chain
      truncated: N of M certs kept". The chain is parsed straight into `cryptoWork` (no local
      arrays, no copy). Stack peak 26,904 -> 23,768 (EC), 31,944 -> 28,808 (RSA); session +24 B.
      Unit: kept / seen counts. Wire, before all `unknown_ca`: leaf + 4 int + root (6) verifies;
      leaf + 5 int + root (7, root dropped) verifies; leaf + 6 int (7) fails `unknown_ca` with
      the truncation trace. `README.md` updated afterwards (3B item R): footnote 58
      default 6, X.509 stack ~14 -> ~12 KB, CMS ~18 -> ~16 KB (the verifier frame measured
      -1,776 B on Cortex-M4 -Os at depth 6 vs 8).
- [x] Out-of-order or extraneous certificates: RFC 8446 4.4.2 says receivers SHOULD handle
      "potentially extraneous certificates and arbitrary orderings" (leaf first). `ssfx509`
      requires cert[i] to be issued by cert[i + 1], so such chains fail. Needs path building in
      `ssfx509`. Outside the TLS client. Fixed (3B item P, approved, both parts):
      `SSFX509VerifyChainPurpose` builds the path from the leaf. A step ends the path when a
      trust anchor issued the current certificate; otherwise it takes the first unused
      certificate sent that names the issuer, agrees on key ids, passes its own checks (v3,
      signature algorithms, validity) and verifies the signature; no backtracking past a
      completed step. Only path certificates are checked, so extra ones (cross-signed root,
      unrelated CA, duplicate, unparseable, expired) do no harm; a sent copy of an anchor is never
      on the path. `ERR_ISSUER_MISMATCH` removed (a name mismatch only means "not this one");
      a failed step reports the most specific reason (candidate's own check, SIGNATURE,
      KEY_ID_MISMATCH, else UNKNOWN_CA on the top of the path). `ssfx509.md` describes it.
      Unit: 15 path cases (long chain, expired extra, unrelated extra, unused critical extension,
      out of order, duplicate, same-name decoy, key-id choice, missing issuer, a loop, decoy
      only, key id only); four old expectations changed as predicted (two ISSUER_MISMATCH ->
      UNKNOWN_CA; two tests that made a non-CA the trust anchor now put it under a real root to
      keep NOT_CA coverage). Wire, all failing before: long chain, unrelated extra, out of order
      now verify. Cortex-M4 -Os: ssfx509 text -241 B, verifier frame +8 B.
- [x] `ssfcms` builds its own signer chain (`_SSFCMSBuildChain`) before calling the verifier,
      which now builds paths itself; dropping it may save code. Measure first. Outside the TLS
      client. Done (3B item Q, approved): ssfcms passes
      the signer then every other embedded certificate to the verifier; `_SSFCMSBuildChain`,
      `_SSFCMSIssuerIsAnchor` and the 1.5 KB scratch certificate removed. Cortex-M4 -Os: ssfcms
      text 5,184 -> 4,864 B, `_SSFCMSVerifySigner` frame 2,776 -> 1,864 B. The rollover fixture
      without key ids now verifies (the verifier chooses by signature; the old builder took the
      first name match and failed). `ssfcms.md` and the README CMS stack figure (~16 -> ~15 KB,
      footnote 60) updated.
- [x] Long single steps: P-384/RSA chain verification can take a long time inline on small
      targets; consider splitting verification per certificate across `pollOpen()` calls. Closed (3B item I) by
      documenting the current design, per the user; not measured on a target. `ssftlsc.h`
      describes the three inline steps, at most one per call, the whole chain (every signature
      plus the anchor's) in one call, and what makes it long. `_SSFTLSCDrive`'s comment
      corrected: it claimed no call does both I/O and a public-key step, but the call that
      completes ServerHello / Certificate / CertificateVerify runs its step too. Splitting per
      signature would need a resumable `ssfx509` chain API (parsed chain in session RAM rather
      than on the stack; see G) and is not planned.
- [x] Do not send SNI for a literal IP address (RFC 6066). `_IsIPLiteral()` (strict dotted-quad
      IPv4; any ':' with hex/'.' and optional `%zone` is IPv6, since DNS names never contain ':')
      gates `server_name` in `_BuildClientHello`. Unit tests: 14 literal/name cases, and a
      ClientHello to 127.0.0.1 has no `server_name`. On the wire: no SNI to 127.0.0.1 (was
      `server_name: '127.0.0.1'`); an IP-SAN certificate verifies. Exhaustive run pending.
- [x] IPv6 literal hosts: `ssfx509` documents hostname / IPv4 SAN matching only, so a server
      reached by IPv6 literal likely cannot be verified. Not tested. Outside the TLS client. Resolved (3B item J,
      approved) by the opposite: SSF is IPv4 only, enforced at every layer. `ssfnet.h` states
      it in the transport contract. `ssfnetsock` resolves IPv4 only on all three resolvers
      (`AF_INET`, `kDNSServiceProtocol_IPv4`), refuses a host containing ':' in `open()`, and
      stores 4-byte IPv4 addresses (`SSF_NETSOCK_ADDR_SIZE` 28 -> 4). `ssftlsc` `open()` refuses
      an IPv6 literal itself, before connecting or sending a ClientHello. `ssfx509` unchanged:
      it already fails closed for an IPv6 host; a certificate with DNS and IPv6 SANs verifies by
      its DNS name (unit test added). Docs: `ssfnet.h`, `ssfnetsock.h`, `ssfmqttc.md`,
      `ssftlsc.h`. Unit: IPv6 literals refused (ssfnetsock, ssftlsc); with only `[::1]`
      listening, `localhost` (which resolves to ::1 and 127.0.0.1 here) fails, where the
      previous ssfnetsock connected over IPv6. Wire: `s_server` on `[::1]` only is never
      reached. The DNS-SD (macOS) and Windows resolver edits are not compiled or run here.
- [x] Check the CertificateVerify scheme against the leaf key type and curve explicitly
      (`illegal_parameter`); today a mismatch is caught only as a failed verification. Found
      during 2.4. The leaf key type is recorded when the Certificate is parsed (RSA, P-256,
      P-384, Ed25519); `_SchemeMatchesKey()` requires the scheme to fit it (ECDSA schemes fix the
      curve). Unit test: 5 schemes x 5 key types, exactly 5 pairs match (20 mismatches were
      accepted before). Signature matrix against `s_server` still 15/15. Exhaustive run pending.
- [x] `SSFX509IsEd25519()` tests the certificate's signature algorithm, unlike its siblings
      `SSFX509IsRSA/IsP256/IsP384`, which test the key; ssftlsc compares the Ed25519 key OID
      itself. Naming trap in `ssfx509`, outside the TLS client. Fixed (3B item K, approved,
      breaking): the helpers are renamed by what they test. Key: `SSFX509IsKeyRSA`,
      `IsKeyP256`, `IsKeyP384` and new `IsKeyEd25519`. Signature algorithm:
      `SSFX509IsSigECDSASHA256` (was `IsECDSA`, a second trap: SHA-256 only),
      `IsSigECDSASHA384`, `IsSigRSAPSSSHA256/384`, `IsSigRSAPKCS1SHA256/384/512`,
      `IsSigEd25519`. `ssfx509.h` groups and comments them; `ssfx509.md` table, listing and
      prose updated. ssftlsc `_LeafKeyType()` uses `IsKeyEd25519` and drops its own OID
      compare. Unit: an Ed25519 key under an ECDSA signature gives IsKeyEd25519 true,
      IsSigEd25519 false; self-signed Ed25519 both true; Ed25519 signature over an EC key
      IsKeyEd25519 false. Cortex-M4 -Os: ssftlsc -118 B, ssfx509 +40 B (the new function).
- [x] P-384 HRR uses the wrong private key offset. Moot: 2.5 rejects an HRR for a group that
      already has a key share, so only P-256 can be selected by an HRR.
- [x] RTC unavailable: distinct error rather than verifying at time 0. No trusted time (RTC
      read fails, or reads before new `SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC`, default
      2025-01-01) fails VERIFY_CHAIN with its own trace and `internal_error`, instead of
      `bad_certificate` from checking at time 0. The RTC reading is now divided by
      `SSF_TICKS_PER_SEC` (was a literal 1000, wrong on ports with another tick rate). On the
      wire with the RTC at its boot value: alert 80 and the distinct trace (was alert 42,
      "chain verification failed"). Exhaustive run pending.
- [x] `ssfrtc`: `SSFRTCGetUnixNow()` asserts if `SSFRTCInit()` was never called and there is no
      "is initialized" query, so ssftlsc cannot fail gracefully in that case (documented as a
      precondition in `ssftlsc.h`). The simulated RTC (`SSF_RTC_ENABLE_SIM`, the default)
      starts at 0 and reports that as a valid time. Outside the TLS client. Resolved (3B item L) as
      by design, per the user: using ssfrtc before `SSFRTCInit()` (or after `SSFRTCDeInit()`)
      is a programming error and asserts, and there is no "is initialized" query; implementation
      and tests assume `SSFRTCInit()` was called. `ssfrtc.md` corrected to match the code (it
      claimed `false` after DeInit) and now documents initialized vs time valid and that 0 / any
      in-range read counts as valid; ssftlsc's own floor covers the 1970 case. `ssftlsc.h`
      precondition reworded. No code change.
- [x] A record still partly written when `close()` runs is dropped (`close_notify`, or the tail
      of application data). Found during step 1. Fixed with option B (approved, outside the
      client): `ssfnet.h` gains a sixth operation, `shutdown()`: deliver every byte `send()`
      accepted and end this side of the stream; `close()` stays unconditional and never waits.
      `ssfnetsock` returns SUCCESS at once (accepted bytes are in the kernel). `ssftlsc` writes
      out the partly written record, then `close_notify`, then calls the inner `shutdown()`;
      `send()` is ERROR afterwards, `close()` sends no second `close_notify`, and a later failure
      sends no alert. `ssfmqttc` STOPPING polls `shutdown()` once DISCONNECT is accepted and
      closes on SUCCESS; `txPublishTimeout` still bounds the stop, and a `shutdown()` failure
      closes at once. Init of `ssfmqttc` and `ssftlsc` requires the operation. Failure paths
      (keep-alive, protocol errors) still close at once. Unit: `ssfnetsock` (SUCCESS, repeat,
      not connected), `ssfmqttc` (ordering after a byte-at-a-time DISCONNECT, WANT_WRITE x3,
      never completes -> stop limit, ERROR, NULL operation), `ssftlsc` (not connected, NULL inner
      operation). Wire, inner transport throttled to 1000 bytes per call with every other call
      refused: 20 KB via `close()` alone arrives as 16,384 bytes and no `close_notify` (unchanged,
      by design); via `shutdown()` all 20,000 and `close_notify` (5/5). End to end, ssfmqttc over
      TLS to a Python TLS broker, 4 x 5000-byte QoS 0 publishes then `Stop()`: `close_notify`
      now arrives (3/3; before, never). Exhaustive run pending.

## Step 4 — Features

- [x] CertificateRequest and client authentication (mutual TLS: AWS IoT, Azure). Note
      `gnutls-serv` sends an (optional) CertificateRequest by default and the client aborts with
      `unexpected_message`; even without a client certificate, RFC 8446 4.4.2 lets the client
      answer with an empty Certificate. Interop with GnuTLS currently needs
      `--disable-client-cert`.
  - [x] 1a: empty Certificate. `_ParseCertificateRequest()` (RFC 8446 4.3.2, 4.2): empty
        context, extensions filling the message (at least 2 bytes), `signature_algorithms`
        present and well formed (else `missing_extension` / `decode_error`), no duplicate type
        recognized or not, extensions the client sends but CertificateRequest may not carry
        refused with `illegal_parameter`, the rest ignored. Accepted once, between EE and
        Certificate; the empty Certificate (8 bytes) goes into the transcript and the same
        record as the client Finished. `SSF_TLS_ALERT_CERTIFICATE_REQUIRED` (116) added to
        `ssftls.h` (approved); receiving it traces "Server requires a client certificate". 27
        unit vectors (checked against an independent model of 4.3.2). Wire, all
        `unexpected_message` before: `s_server -verify 1` and `gnutls-serv` defaults connect
        and echo (server verified the Finished over the Certificate), also with HRR, SHA-384
        and an RSA leaf; `-Verify 1` / `--require-client-cert` report `certificate_required`
        on the first recv. 11 mutants killed (one survivor first, closed by a new vector);
        ASan / UBSan clean. Cortex-M4 -Os: ssftlsc text +501 B, one session flag. Not
        covered by a test: a second CertificateRequest (no server sends one; it falls through
        to `unexpected_message`). `ssftls.md` alert list completed.
  - [x] 1b: client certificate and CertificateVerify (uses `ssfpkey`). Done (approved:
        stream the Certificate, check leaf against key, empty Certificate when no scheme fits).
        `SSFTLSCSetClientCert(session, chainDer, chainLens, count, key)`: idle only, pointers
        kept (no copy, kept across connections); refused, leaving nothing set, for a malformed
        chain (empty or over-24-bit entry, list over 2^24) or a leaf whose type / public key is
        not the key's (EC point, Ed25519 key, RSA modulus and exponent compared).
        CertificateRequest now also picks the scheme: the server's first listed scheme the key
        can make (PKCS#1 and rsa_pss_pss never). After the server Finished, new states
        SEND_CLIENT_CERT (Certificate generated from the caller's DER into hsBuf, record by
        record, added to the transcript as cut), SIGN_CV (crypto step: content with "TLS 1.3,
        client CertificateVerify", scheme hash, ECDSA RFC 6979 / Ed25519 / RSA-PSS salt =
        hash), SEND_CV_FIN (CertificateVerify + Finished from clientHelloMsg, also streamed).
        Client Finished and the switch to application send keys factored out
        (`_BuildClientFinished`, `_EnterAppSendKeys`) and shared with the no-certificate path.
        Unit: key match / refusals, scheme choice, streamed message byte-exact for six piece
        sizes, CertificateVerify verified with the leaf key over the client context and not the
        server one (all key types, both hashes). Wire, all `certificate_required` before:
        `s_server -Verify` and `gnutls-serv --require-client-cert --verify-client-cert` accept
        P-256, P-384, Ed25519, RSA-2048, RSA-4096 and leaf + intermediate; a server list
        without the key's scheme gets an empty Certificate (`certificate_required`); a server
        trusting another CA answers `unknown_ca`. Same with a 512-byte send build (Certificate
        and CertificateVerify + Finished over several records; RSA-4096 failed before the CV
        was streamed too). That build is no longer allowed (send minimum 768, below); the same
        splitting now comes from the server's record_size_limit: `gnutls-serv
        --recordsize=512` with RSA-4096 (520-byte CV over 511-byte records), RSA-2048, P-256
        and a two-certificate chain all connect, and `_SSFTLSCUTSendFlight()` covers it. 14 mutants: 13 killed, one equivalent (the leaf/key type check is
        implied by the key comparison). ASan / UBSan clean. Cortex-M4 -Os: ssftlsc text
        +2,433 B; session +24 B (Cortex-M4); pollOpen stack peak with an RSA client key ~28.3 KB (RSA-PSS
        signing), unchanged for EC / Ed25519 keys.
        Audit (correctness and security), then fixed TDD: (1) a CertificateRequest refused
        after signature_algorithms left the chosen scheme set (contract said 0); the scheme is
        now chosen into a local and stored only on success (differential fuzz: 2,439 of 200k
        refused requests left one before, 0 after). (2) RFC 8446 4.4.2.3: the chain's own
        signatures must be ones the server lists (signature_algorithms_cert, now validated,
        else signature_algorithms); a self-signed last certificate is exempt (4.4.2.2); if not,
        an empty Certificate with a warning trace. ECDSA certificate signatures count as the
        hash's ECDSA scheme (the issuer's curve is not known), RSA-PSS as rsae or pss. (3)
        `ssftlsc.h`: the key must come from ssfpkey; a hand-built inconsistent key asserts. (4)
        Warning traces, never enforced, for a leaf the server is likely to refuse: Key Usage
        without digitalSignature, EKU without clientAuth, and not valid now (only with trust
        anchors, where the RTC is required, and the trusted-time floor). (5) Stale comments
        updated. Verified: the client certificate is sent only after the server is
        authenticated; parser differential (200k mutated requests vs an RFC model, ASan) 0
        mismatches; GnuTLS record_size_limit 512 / 1024 honored with RSA-4096 and a chain;
        no live secrets after client-auth handshakes. 13 more mutants killed (one survivor
        first, closed by an empty-list vector). Wire: an Ed25519 client whose leaf is
        ECDSA-signed now sends an empty Certificate when the server lists only ed25519, and
        its certificate when ECDSA+SHA256 is also listed; expired / no-clientAuth leaves warn
        and are refused by the server (45 / 43), no-digitalSignature warns and is accepted.
        Cortex-M4 -Os: ssftlsc text +3,671 B over the last commit (+1,238 B for the audit).
- [x] `SSF_TLSC_CONFIG_MAX_SEND_RECORD` accepts 64..16384, but the plaintext ClientHello
      (a few hundred bytes) is sent as one record and is not fragmented, so a build below
      about 512 cannot connect at all (found during 1b: 64 and 256 fail before ServerHello,
      with or without client authentication). Raise the minimum, or fragment the ClientHello.
      ALPN adds up to 6 + `SSF_TLS_CONFIG_MAX_ALPN_LEN` bytes (38 at the default 32, 225 at
      the maximum 219); the largest ClientHello is `SSF_TLSC_CH1_MAX_NO_ALPN` (543) plus that.
      Done, TDD: the minimum is now `SSF_TLSC_CH_SIZE` (768), the most any ClientHello can be
      (ClientHello2 with a cookie included), so it always fits one record; no fragmentation,
      no code. `ssftlsc_opt.h` range check 768..16384 and a tie to `SSF_TLSC_CH_SIZE` in
      `ssftlsc.h`; 64 / 512 / 767 / 16385 are compile errors, 768 builds. The plaintext
      record size check is now unreachable (commented). Unit tests: a cookie making
      ClientHello2 exactly 768 bytes goes out as one record, one byte more is internal_error;
      the largest ClientHello1 is one record. Red at 512 (the unit test built at 512 failed),
      green at 768, and at 768 with `SSF_TLS_CONFIG_MAX_ALPN_LEN` 219 (ClientHello1 = 768).
      Wire at 768: the ALPN set (HRR included) and the trust store set unchanged. RAM: a
      build that wanted a send buffer under 768 bytes gives up at most about 700 B.
      Audit: the client flight's record splitting (`_SendHandshakeOnce`) had no unit test and
      its wire check (a 512-byte send build) is no longer buildable. Fixed, TDD: new
      `_SSFTLSCUTSendFlight()` over the fake transport, which now can write short (at most
      5-7 bytes a call, WANT_WRITE every other call): a 520-byte message at record_size_limit
      64 (9 records of at most 63), 512 (511 + 9) and none, and the client Certificate
      streamed from the chain at 64, each record within the limit and hsBuf, the pieces
      joining to the message and the transcript hashing each byte once. Mutation: 8 mutants,
      all killed (the hsBuf cap only in a receive-512 / send-768 build, where it matters).
      Wire: the 1b set at 768 and `gnutls-serv --recordsize=512` (above) pass.
- [x] A plaintext record of 2^14 + 1 .. 2^14 + 17 bytes gets internal_error instead of
      record_overflow (RFC 8446 5.1) when SSF_TLSC_CONFIG_MAX_RECV_RECORD is below 16384: the
      build-size check runs before the plaintext 2^14 check. Fatal either way; alert code only.
      Found running the unit test at receive 512 (which also trips other tests that assume a
      16 KB receive size). Found during the send-limit audit.
      Done, TDD: the header-time check now also answers record_overflow for a plaintext
      record (outer type not application_data) over 2^14; protected records unchanged
      (record_overflow over 2^14 + 17, or over our record_size_limit once accepted, else
      internal_error). `_SSFTLSCUTPlainOverflow()` drives the handshake over the fake
      transport (its input now 16.5 KB): plaintext 2^14 + 1, + 17 and + 18 are record_overflow;
      2^14 and below parse if they fit hsBuf, else internal_error, beyond hsBuf and beyond the
      record buffer both checked; protected records at the header with and without an
      accepted limit. Red at receive 64 .. 16383 against the old code, green at 64, 512, 4096,
      16366, 16367, 16383 and 16384 (run alone, ASan). Mutation: 6 mutants, all killed (5
      only by the small builds, where the branch is reachable). Text unchanged at the default
      receive size (+10 B at 2048).
- [x] Before keys, a record labelled application_data that is over this build's buffer gets
      internal_error from the header check, where the same record at a normal size gets
      unexpected_message (no keys to decrypt it). Fatal either way; only a broken server sends
      one; alert code only. Found during the plaintext record_overflow audit.
      Done, TDD, more generally: the record type is now judged for the moment at the header,
      before the size, so a record of the wrong type is unexpected_message whatever its
      length (it was record_overflow over the maximum, or internal_error over a small
      build's buffer): change_cipher_spec only during the handshake and of one byte;
      before keys handshake / alert; once keys are active application_data outside. The
      post-read checks this replaces are gone (the 0x01 byte check stays). Bad records are
      also refused without reading them. `_SSFTLSCUTRecordTypeFirst()`: application_data and
      change_cipher_spec before keys, plaintext handshake / alert / change_cipher_spec after,
      at 2, 100, 2^14 + 18 bytes and just over a small build's buffer; a one-byte CCS that is
      not 0x01. Red at every size (the 2^14 + 18 cases), green alone at receive 64 .. 16384
      and in the full unit test (ASan clean). Mutation: 8 mutants; 6 killed, one equivalent
      (CCS after the handshake: recv() refuses it too), one a no-op mutant. Wire: ALPN,
      mutual TLS, trust store and KeyUpdate sets unchanged. Text +6 B.
      Audit: the window between ServerHello and the server Finished (keys active, not yet
      connected), where an on-path party would inject plaintext, had no test; the rule does
      not depend on `connected` (except for change_cipher_spec), but nothing would catch a
      change that made it so. Fixed, TDD: `_SSFTLSCUTMidHandshakeRecords()` puts a session
      over the fake transport mid-handshake (waiting for EncryptedExtensions): a plaintext
      EncryptedExtensions or close_notify is unexpected_message; the compatibility
      change_cipher_spec (one byte 0x01) is dropped and the protected EE that follows is
      processed; a two-byte or non-0x01 change_cipher_spec is unexpected_message. Red shown by
      mutation: the rule keyed on `connected`, or plaintext after keys refused only once
      connected, both pass the committed suite and fail the new test. Test code only.
      Size figures corrected: earlier ones compared against a HEAD copy compiled from a long
      scratch path, whose assertion __FILE__ strings added about 92 B to the old size. Measured
      again with every version compiled from the same relative path: whole .text (string
      constants included), tracing off, less the *ForTest hook functions. ALPN commit f8b84a4
      +554 B (reported +442), trust store commit b14cfc5 +478 B (reported +386; 32 B of it
      the PEM label and marker strings), the send minimum a6deffb 0 and ServerHello 70c1cb3
      +100 B as reported, this change 0.
- [x] Private key loading: PKCS#8 / SEC 1 / PEM. Done (approved: two new codec modules).
      `ssfpem` (RFC 7468): one block per call, multi-block buffers, strict Base64 via
      `SSFBase64Decode`, whitespace anywhere, NULL output to check/measure, all output zeroed on
      failure; meant for trust store loading (item 5) too. `ssfpkey`: PKCS#8 v1/v2 (RSA, P-256,
      P-384, Ed25519), SEC 1, PKCS#1, in PEM (label decides the format) or DER (structure
      decides); validated (EC scalar in [1, n-1], short scalar left-padded, curve agreement,
      `SSFRSAPrivKeyIsValid`, exact framing) and a public key in the file must match the
      derived one; encrypted PKCS#8 refused; exactly one key block, other blocks checked and
      skipped; key and DER buffer wiped on failure. Unit tests from OpenSSL 4.0 fixtures
      (each key also signs and verifies against OpenSSL's public key) plus built negative
      cases; 26 mutants all killed (3 survivors first, each closed by a new test); ASan clean.
      Cortex-M4 -Os: ssfpem 742 B, ssfpkey 1,694 B; stack ~7.2 KB EC, ~19.1 KB RSA (key
      validation, below RSA signing), ~1.5 KB Ed25519. Docs: `ssfpem.md`, `ssfpkey.md`, README
      rows. Using the key for client authentication is item 1b.
      Audit (correctness and security): line-by-line review plus 1.6M-input ASan/UBSan
      mutation fuzz with exact-size buffers (no faults; wipe-on-failure and key-consistency
      invariants held) and an OpenSSL differential (every accepted key accepted by OpenSSL
      with the same private value; every OpenSSL-only accept was key material OpenSSL does
      not check, or a SEC 1 version other than 1). Fixed, TDD: (1) the last Base64 group was
      left in `SSFPEMDecodeNext`'s stack scratch on success; scratch now wiped at a single
      exit, checked by a unit-test hook on every return. (2) `SSF_PKEY_TYPE_NONE` = 0, so a
      wiped or failed key is not an RSA key. (3) BEGIN / END lines must start a line (as
      OpenSSL requires); PEM disagreements with OpenSSL 507 -> 8, all the documented lax
      whitespace. (4) docs: output buffers must not overlap the input. (5) docs: refused
      forms some tools write (RSA-PSS OID keys, compressed EC public key, RSA PKCS#8 without
      NULL parameters). 30 mutants all killed. Not fixed here (belongs to F): secret-derived
      temporaries left on the stack by the EC / Ed25519 public-key derivations and the RSA
      validator's callees; `SSFECDSAPubKeyFromPrivKey` does not wipe `d` when it rejects it.
- [x] KeyUpdate: install new receive keys, answer `update_requested`; send-side KeyUpdate before
      the AEAD record limit. Done (approved: owed reply at the next send(), config threshold
      only, no new API). recv() no longer drops handshake records: `_PostHandshakeFeed()` parses
      them across records (header, type, remaining body); NewSessionTicket checked for its
      minimum length and skipped; KeyUpdate must be one byte, 0 or 1, and end its record (RFC
      8446 4.6.3, 5.1), else decode_error / illegal_parameter / unexpected_message; any other
      type (post-handshake CertificateRequest never offered) unexpected_message. A KeyUpdate
      moves the server application secret on ("traffic upd", 7.2) and installs the new
      receive keys; update_requested sets a flag, answered by one KeyUpdate at the start of the
      next send() (before the data, as 4.6.3 requires), after which the client key moves on.
      send() also rekeys after `SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS` records (new option,
      default 2^24, below AES-GCM's 2^24.5; 1..2^24). Unit: parser cases (tickets split byte by
      byte, ticket + KeyUpdate, header and body in different records, each refusal) and the
      "traffic upd" step against values computed independently (SHA-256 two generations,
      SHA-384). Wire, all `bad_record_mac` (server side) / no client KeyUpdate before:
      `s_server` k / K / k k k with data in both directions after each; client rekeying every
      3 records against `s_server -rev` (6 KeyUpdates seen by the server, 20/20 echoes) and
      `gnutls-serv`. OpenSSL's and GnuTLS's post-handshake NewSessionTickets now go through
      the parser. 13 mutants killed (one survivor first, closed by a case with two sends
      between requests). ASan / UBSan clean. Cortex-M4 -Os: ssftlsc text +854 B, session
      +16 B.
      Audit (correctness and security): verified old secrets and keys are gone after each
      update, one reply answers any number of requests (no amplification), the KeyUpdate is
      the old key's last record and data never precedes it; parser differential (100k streams
      split at random points vs an RFC model, ASan) found only the ticket minimum. Fixed, TDD:
      (1) NewSessionTicket minimum body 13 -> 14 (an empty ticket was accepted). (2) RFC 8446
      5.1: application data between the pieces of a split handshake message is now
      unexpected_message (`_RecordTypeAllowed()`). (3) `ssftlsc.h` notes that tickets are only
      length-checked. New unit test drives recv() / send() over a fake inner transport with
      known secrets: ticket then data, data inside a split ticket, server KeyUpdate then data
      under its next key and the client's KeyUpdate + data under its next key, and the record
      limit; the flow mutants (the recv() call site of (2), and the six that only the wire test
      caught before) are now killed by the unit test. Text +965 B over the last commit.
- [x] ALPN (e.g. `x-amzn-mqtt-ca` for AWS IoT on 443). RFC 7301, TDD.
      `SSFTLSCSetALPN()` keeps pointers to the caller's names (1..255 bytes each, the list
      within `SSF_TLS_CONFIG_MAX_ALPN_LEN`, now used; kept across connections like the client
      certificate); the ClientHello offers them (ClientHello2 identical). EncryptedExtensions:
      exactly one non-empty name, one that was offered (`decode_error` for framing,
      `illegal_parameter` for a name not offered or a second ALPN, `unsupported_extension`
      when none was offered); `SSFTLSCGetALPN()` returns the caller's string, or NULL when the
      server chose none (the caller decides). Alert 120 `no_application_protocol` added to
      `ssftls.h` (approved) and traced. Unit tests: Set validation, 17 EE answers, the
      ClientHello bytes and ClientHello2 after an HRR on the wire, none offered when unset.
      Mutation: 22 mutants; all killed (one, the EE call site, only by the wire test) except
      the 255-byte name cap, equivalent at the default list limit of 32. Wire: `s_server
      -alpn` (match, server preference, no overlap -> alert 120, no ALPN, HRR) and
      `gnutls-serv --alpn` (match, `--alpn-fatal` -> 120, non-fatal mismatch -> none).
      Text +554 B for the commit, tracing off, unit-test hooks excluded (first reported as
      +442 B; corrected, see the plaintext record_overflow item).
      Audit (fuzz: 200k EncryptedExtensions bodies vs an RFC model under ASan / UBSan, no
      mismatch). Fixed, TDD: (1) `SSFTLSCGetALPN()` returns NULL until the handshake is
      complete: the choice arrives before the server is authenticated and stayed set after a
      failed handshake. (2) ALPN in a CertificateRequest is `illegal_parameter` (RFC 8446 4.2,
      as for the other offered extensions). (3) The alert 120 trace is worded for both cases
      ("Server requires an ALPN protocol the client did not offer"). (4)
      `SSF_TLS_CONFIG_MAX_ALPN_LEN` above 219 is a compile error: the largest ClientHello1
      (255-byte host, `SSF_TLSC_CH1_MAX_NO_ALPN`, checked exactly by a unit test) must fit the
      768-byte `SSF_TLSC_CH_SIZE` buffer; the unit test passes at 219. (5) Send-record item
      below updated. (7) `ssftlsc.h`: the names must stay unchanged, not only valid.
- [x] Trust store loading: CA bundles (multiple certificates per file), no silent truncation,
      no filesystem requirement in the core (`ssftls_certs.c` is POSIX-only). TDD.
      `SSFTLSCTrustFromPEM()`: a certificate or bundle in memory (text between blocks allowed,
      RFC 7468), DER into the caller's pool and arrays, the store ready for `SSFTLSCInit()`.
      Fails closed with a distinct result (malformed PEM, non-CERTIFICATE label, not exactly
      one X.509 certificate, over `maxCount` / 255, pool too small, no certificate): the store
      is then empty and the count says which block. NULL pool measures (pool size and count;
      PEM and labels checked, certificates not parsed). `ssftls_certs.c` / `.h` deleted
      (approved; never built). Unit tests: one, a CRLF bundle with text, exact / short pool,
      maxCount, five wrong labels, bad Base64, no END, trailing byte, non-X.509 DER, empty,
      255 / 256 certificates. Mutation: 20 mutants, all killed but an equivalent one (pem
      NULL, also required by ssfpem). Fedora's TLS and email bundles (118 / 87 certificates)
      load identical to OpenSSL's DER, every certificate parsing; its object-signing bundle
      (301) is ERR_COUNT. Wire (`s_server`): bundle of system roots + test CA, CA first or
      last, EC and RSA leaves connect; system roots alone fail with unknown_ca. Cortex-M4
      -Os: stack 1,392 B deepest (SSFX509Parse's certificate); text: see the audit below.
      Audit (fuzz: 200k mutated bundles, exact-size buffers, ASan / UBSan, invariants:
      measure = load, contiguous pool, empty store on error; no failures). Fixed, TDD: (1) a
      block whose BEGIN line was damaged (4 dashes, indent, lower case, no space, missing) was
      text to ssfpem and silently dropped, the load succeeding (1,832 of the 200k): each block
      must now hold exactly one "-----BEGIN" and one "-----END" counting the text before it,
      and the text after the last none, else ERR_PEM (fuzz rerun: 0 drops; both lines damaged
      is still undetectable). (2) The pool overlapping the PEM text asserts (ssfpem's rule). (3)
      `ssftlsc.h`: ders / lens hold maxCount entries; between-block text holds no markers.
      Not changed: a corrupted but parseable root loads and fails at verification; checking
      self-signatures at load would cost a signature per root. Text +152 B for the fixes
      (+478 B for the commit, first reported as +386 B; corrected, see the plaintext
      record_overflow item); stack unchanged (deepest path still through SSFX509Parse).

- [x] ServerHello: extensions the client offers but that are not specified for ServerHello
      (`server_name`, `supported_groups`, `signature_algorithms`, `psk_key_exchange_modes`,
      `record_size_limit`, ALPN) are rejected with `unsupported_extension`; RFC 8446 4.2 asks
      for `illegal_parameter` for a recognized extension in the wrong message, as
      EncryptedExtensions and CertificateRequest already do. Fatal either way; only the alert
      code differs. Found during the ALPN audit.
      Done, TDD: `_ParseServerHello()` answers `server_name`, `supported_groups`,
      `signature_algorithms`, ALPN, `psk_key_exchange_modes`, `record_size_limit`, and a
      cookie outside a HelloRetryRequest, with `illegal_parameter`; `pre_shared_key` and the
      rest stay `unsupported_extension`. A fixed list (extensions this client implements),
      not "sent in this ClientHello": 4.2's recognized-but-not-allowed rule holds either way.
      New test hook `_SSFTLSCParseServerHelloForTest()` builds a real ClientHello1 (fixed
      random, session id and shares) and parses a body against it; `_SSFTLSCUTServerHelloExts()`
      checks 25 ServerHello / HRR cases (red: 7 recognized types got unsupported_extension).
      Mutation: 11 mutants, all killed. Wire: the ALPN set (HRR included) unchanged. Text +48 B.
      Audit: a server unaware of supported_versions answers TLS 1.2 (older OpenSSL / mbedTLS
      brokers); the client reported it as "session id echo mismatch" or "cipher suite"
      (illegal_parameter), and the "missing supported_versions" -> protocol_version check
      at the end of the parser was unreachable. Fixed, TDD: `_ShHasVersions()` walks only
      the framing first; no extension block, or a well-formed one without
      supported_versions, is protocol_version with the trace "the server negotiated TLS 1.2
      or earlier; TLS 1.3 is required", before the session id, suite and extension checks.
      Malformed framing still reaches the full parse (decode_error); supported_versions
      present but not TLS 1.3 stays illegal_parameter; the dead end-of-parser check is
      removed. `_SSFTLSCUTServerHelloVersion()`: TLS 1.2 ServerHellos with session ids of
      0 / 16 / 32 bytes, typical, empty and absent extension blocks; TLS 1.3-shaped ones
      without supported_versions (ServerHello and HRR); four framing errors. Mutation: 9
      mutants killed (one equivalent bounds check removed, its precondition documented).
      Wire: a scripted legacy TLS 1.2 server gets protocol_version with that trace; the
      ALPN set unchanged. Text +52 B (+100 B with the extension fix above).

## Step 5 — Tests and cleanup

- [x] RFC 8448 handshake traces as deterministic vectors (needs injectable random and keys).
      Section 3 (Simple 1-RTT) done, TDD: `_SSFTLSCUTRfc8448Simple()` replays it over the fake
      transport. Test hook `_SSFTLSCInjectClientHelloForTest()` (unit-test builds only) puts
      the RFC's ClientHello and x25519 key in place of fresh randomness and
      `_BuildClientHello()`; unauthenticated mode skips the chain (the RFC's certificate is
      RSA-1024 and names no host) but its CertificateVerify is verified. Checked: the
      ClientHello sent, handshake and application traffic secrets, the client Finished
      record, the NewSessionTicket skipped, the server's application data decrypted, the
      client's application data and close_notify records byte for byte, the server's
      close_notify. Vectors (~1.9 KB, in `ssftlsc_ut.c` to keep the vcxproj unchanged)
      extracted from the RFC text by script and checked twice before use: a pure-Python
      model (x25519, HKDF, AES-128-GCM, self-tested against RFC 7748 / FIPS 197 / SP 800-38D)
      and pyca/cryptography, which also verifies the RSA-PSS CertificateVerify. Red with the
      hook stubbed. Mutation: 5 key schedule mutants (hs labels swapped, ap labels, master
      derivation, client Finished key), all killed; two checked against the committed suite
      passed it, so only the wire tests caught them before. Shipped code unchanged.
      Sections 5, 6 and 7 done, TDD (section 4, PSK / 0-RTT, does not apply). Vectors
      (~4.8 KB) checked with pyca/cryptography first (P-256 ECDH, the message_hash
      transcript, both CertificateVerify signatures of 6).
      7 (Compatibility Mode; AES-128-GCM, not ChaCha20 as first noted here: RFC 8448 has no
      ChaCha20-Poly1305 trace, so ChaCha20 stays covered by interop only): 32-byte session
      id, the server's change_cipher_spec after its ServerHello accepted; secrets, client
      Finished and close_notify records match.
      5 (HelloRetryRequest): new hook `_SSFTLSCInjectClientHello2ForTest()` (unit-test
      builds only) injects ClientHello2 and its P-256 key; ClientHello1 offers x25519 only,
      the HRR selects secp256r1 with a 76-byte cookie; secrets, ClientHello2 sent, client
      Finished and close_notify records match. Red with the hook stubbed.
      6 (Client Authentication): the RFC does not publish the certificates' private keys,
      so the client cannot reproduce the trace's CertificateVerify / Finished (the approved
      ssfport entropy hook for the PSS salt was therefore not added; nothing outside the
      client changed). The client answers with its own RSA-2048 certificate: the
      CertificateRequest, the server's ECDSA P-256 CertificateVerify, the handshake and
      application secrets and the client's close_notify record match the trace; its
      Certificate, rsa_pss_rsae_sha256 CertificateVerify (verified) and Finished
      (recomputed) are checked against the transcript they extend.
      Mutation: message_hash type and length and the HRR left out of the transcript pass the
      committed suite and are killed only by 5; client CV context and Finished transcript
      mutants killed (also by the 1b tests). Shipped code unchanged.
- [x] Deterministic parser unit tests like `_SSFTLSCParseCertificateForTest` for the ServerHello
      parser (2.5 is covered only through `mitm.py` today). Started: the hook
      `_SSFTLSCParseServerHelloForTest()` exists and the extension cases are covered; the
      session id, cipher suite, compression, key share and length checks remain.
      Done, TDD (test code only): `_SSFTLSCParseServerHelloExForTest()` also parses as the
      ServerHello after an HRR (its group and suite) and returns the group, key and cookie;
      `_SSFTLSCUTServerHelloChecks()` covers the rest: accepted ServerHellos (x25519 and
      P-384 keys; each suite's hash and key length, SHA-384 for AES-256-GCM; extension order),
      framing (too short, session id over 32 or cut off, extension block short / long /
      trailing, half a header, an extension or key cut off by the end), session id echo,
      suite not offered (CCM_8, a TLS 1.2 suite), compression, key_share (missing, duplicate,
      0 / 1 / 2 bytes, length field, wrong size, group without a share, x448), HRR
      (selected_group, cookie returned in place, x25519 again, unsupported group, a share
      instead of a group, three bad cookies), after an HRR (the suite and the group must be
      the HRR's). Bodies are parsed from exact-size heap copies. Mutation: every one of the
      27 rejections removed, and its alert changed: 54 mutants, all killed (six only by ASan:
      dropping a length check reads past the message; that is what the exact-size copies
      are for). Differential fuzz against an independent Python model of 4.1.3 / 4.1.4 /
      4.2 (check order and which alert wins included): 2 x 200k ServerHello / HRR /
      after-HRR bodies under ASan / UBSan, no mismatch, no report.
- [x] A HelloRetryRequest without key_share is missing_extension. RFC 8446 4.1.4 allows a
      cookie-only HRR (same shares, cookie added); only one that would change nothing must
      be illegal_parameter. Supporting it needs a ClientHello2 path that keeps the shares.
      Stateless / DoS-protecting servers send them; common MQTT brokers do not. Found
      writing the ServerHello model. Neither installed server sends one (`openssl s_server
      -stateless` answered with a plain ServerHello). Alert fix done, TDD: an HRR with neither
      key_share nor cookie (it would change nothing) is now illegal_parameter (4.1.4); a
      cookie-only HRR stays missing_extension until supported. Unit test rows for both; 3
      mutants of the condition killed; ServerHello differential fuzz (model updated) 200k, no
      mismatch. Full cookie-only support (ClientHello2 keeping both shares plus the cookie;
      the final ServerHello then free to use either), about 120-200 B, will not be done
      (decided 2026-11-24: only the alert fix; that RFC compliance is not required). A
      cookie-only HRR is refused with missing_extension.
- [x] Interop with `openssl s_server` over loopback; test.mosquitto.org:8883 with its CA. Add
      `gnutls-serv` (installed, 3.8.13) as a second independent server in the regression set.
      Done as a scripted regression set (scratch for now; into the repo with the harness item
      below), each row with its expected outcome; not part of the unit tests (needs the
      servers and, for --public, the internet). Matrix: {s_server, gnutls-serv} x 4 suites x
      3 groups (x25519, P-384, P-256 through a real HRR) x 5 server keys (P-256, P-384,
      RSA-2048, RSA-4096, Ed25519): 120 / 120, suite and group as forced, data echoed;
      AES-128-CCM negotiated on the wire for the first time. Red check: a client with a
      wrong CCM key length fails exactly the 30 CCM rows. Features, checked automatically:
      ALPN 10, mutual TLS 13, trust store 5, KeyUpdate 5, server records of at most 512 bytes
      (RSA-4096 chain across records), gnutls record_size_limit 512 with an RSA-4096 client:
      35 / 35. Public: test.mosquitto.org:8886 (Let's Encrypt, 3-certificate chain against
      the 118 system roots loaded with SSFTLSCTrustFromPEM()): TLS 1.3 ChaCha20-Poly1305 /
      x25519 and MQTT CONNACK accepted (ChaCha20's first real-world coverage).
      test.mosquitto.org:8883 fails, see the X.509 v1 item. Whole set about 1 minute.
- [x] test.mosquitto.org:8883 serves an X.509 v1 certificate (no extensions, no
      subjectAltName; the host name only in CN). OpenSSL accepts it; ssfx509 requires v3 and
      matches host names by subjectAltName only, so the client refuses it
      (SSF_X509_VERIFY_ERR_VERSION, alert 43). By design, but self-made broker certificates
      are often v1 (older `openssl x509 -req` without an extension file, as in many
      Mosquitto guides). Options: keep (document), or an opt-in to accept a v1 leaf with a CN
      host name match. Outside the TLS client (ssfx509). Found during the interop set.
      Decided: keep the policy (v3 required, host matched by subjectAltName only), make the
      failure obvious. Done, TDD: the chain-failure trace now explains the two refusals a
      self-made broker certificate most often meets: "an X.509 v1 or v2 certificate: v3 with a
      subjectAltName for the host is required" (code 2) and "no subjectAltName names the host;
      the Common Name is not used" (code 16). ssftlsc.h states the requirement and the
      broker-side fix (-addext / -extfile subjectAltName). Interop: gen-certs.sh makes a v1
      leaf (`req -x509 -x509v1`; OpenSSL 4's `x509 -req` makes v3) and a v3 leaf without
      subjectAltName; new rows expect verify=2 / alert 43 and verify=16 / alert 42 with the
      explanation (red until the trace said it); the public 8883 row expects it too.
      158 local + 6 public pass. Shipped text +0 B (the text exists only with tracing on).
- [x] The interop test CAs (`ssf-test-ca`, `ssf-test-rsa-ca`) expire 2026-12-23: the harness
      should generate its certificates rather than keep these. Done with the harness:
      `gen-certs.sh` generates them per run.
- [x] `ssftls.md` still says `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH` is not referenced; ssftlsc uses
      it. Outside the TLS client.
- [x] Negative tests for every step 2 check.
      Done, TDD (test code only). Already deterministic before: plaintext after encryption,
      the ServerHello and EncryptedExtensions parsers, Certificate bounds, CertificateVerify
      trailing bytes, the empty trust store, close() mid-handshake, the close drain
      (ssfnetsock). New, `_SSFTLSCUTServerFlightNegative()` on the RFC 8448 3 replay: the test
      knows the server's handshake key, changes the flight's plaintext and re-encrypts it.
      Finished bit (decrypt_error) and length (decode_error); CertificateVerify signature bit
      with a Finished recomputed to agree, so only the signature check can catch it
      (decrypt_error); PKCS#1 and ECDSA schemes with the RSA certificate (illegal_parameter);
      certificate DER that does not parse (bad_certificate); an empty certificate list
      (decode_error, 4.4.2.4); an unoffered EncryptedExtensions extension
      (unsupported_extension); CertificateVerify before Certificate and a message after the
      Finished (unexpected_message); a ciphertext bit (bad_record_mac). Each checks the alert
      the client actually sends, decrypted with the trace's client handshake key, and that the
      session's secrets, keys and buffers are wiped at the failure, before close(). The
      control run checks, through `_SSFTLSCScrubTestHook`, that every named stack and session
      secret is reported wiped (zero) on the success path; after close() nothing remains.
      Mutation: 12 failure-site mutants (Finished compare / length / alert, CV signature /
      scheme / alert, empty Certificate, leaf parse, key change ending its record, wipe on
      failure, master secret wipe, bad-record alert), all killed; 9 of them passed the
      committed suite. The first CV-signature case was caught only by the Finished (the
      changed CV changed the transcript); fixed with the recomputed Finished. Compile-time
      switch (script, not a unit test: the unit test needs the opt-in): with
      SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED 0, SSFTLSCSetUnauthenticated() does not compile
      and open() with no trust anchors refuses.
- [x] Mutual TLS against a real endpoint: only local `s_server` / `gnutls-serv` so far.
      test.mosquitto.org port 8884 requires a client certificate (one it issues), a cheap
      real-world check alongside the interop item above. Found reviewing step 4.
      Done, TDD (scripts, part of the interop set's --public run). Client certificates
      issued by test.mosquitto.org/ssl for locally generated P-256 and RSA-2048 keys (CSR
      subject placeholders only: C=XX, O=SSF Test, CN=ssf-tlsc-interop-*; valid until
      2027-02-22, then reissue). Key loaded with SSFPKeyDecodePEM(), chain with
      SSFTLSCSetClientCert(). The server's CertificateRequest lists ML-DSA schemes first; the
      client skips them and chooses ecdsa_secp256r1_sha256 (P-256) / rsa_pss_rsae_sha256
      (RSA). Both connect and get an MQTT CONNACK; no certificate gets certificate_required
      (116) and a certificate from another CA unknown_ca (48), both at the first read after
      the handshake. The server is not authenticated in this run (test opt-in): port 8884
      serves the same X.509 v1 certificate as 8883 (see that item). Red: the expected rows
      failed until the certificates were issued. Now part of `tools/tlsc-interop/run.sh
      --public`, which requests and caches the certificates itself.
- [ ] External signing for the client key: `SSFTLSCSetClientCert()` takes an `SSFPKey_t`
      with the private key in RAM; devices that keep it in a secure element (e.g. ATECC608,
      common with AWS IoT) need a signing callback in its place. Design decision. Found
      reviewing step 4. Skipped for now (2026-11-24): the first target system has no secure
      element. Design notes if revisited: callback given the scheme, the signed content and
      its digest; accept raw r||s for ECDSA and DER-encode in the client; blocking first.
- [x] Bring the loopback `openssl s_server` interop harness into the repo (spot checks for step 2
      currently run from a scratch driver, which sets the unit-test hooks).
      Done, TDD (approved: new directory `tools/tlsc-interop/` and a `.gitignore` line):
      `run.sh` (builds, generates certificates, runs; `--public`, `--self-test`, `--asan`,
      `--only`), `tlsc_interop.c` (one driver replacing the seven scratch ones; trust anchors
      and client chains loaded from PEM with SSFTLSCTrustFromPEM(), keys with
      SSFPKeyDecodePEM()), `interop.py` (every row with its expected outcome; servers found
      listening from /proc/net/tcp, free ports chosen per row), `gen-certs.sh` (every CA and
      leaf fresh per run, 30 days), `public-certs.sh` (Mosquitto CA, and its 8884 client
      certificates requested on demand into the git-ignored `.cache/`, renewed within 7 days
      of expiry), `README.md`. Rows written first (red with no driver); 156 / 156 local in
      about 30 s, 6 / 6 public; self-test: a client with AES-128-CCM broken fails exactly the
      30 CCM rows. The driver links no unit-test objects (no libcrypto needed). Not ported:
      the mitm proxy and step 2 spot-check drivers, replaced by the deterministic negative
      tests.
- [x] The leaf public key is parked in `clientHelloMsg` between handshake steps; give it its own
      field.
      Done, TDD (no RAM or code change: shipped text +0 B, session 43,264 B both). The buffer
      is now `hsScratch`, a union whose members name its three phases (clientHello,
      leafPubKey, clientFlight), with `hsScratchLen`; the session comment says which states
      own it. Compile-time checks for the client's own limits: the largest supported server
      RSA key (SSF_RSA_MAX_PUB_KEY_DER_SIZE) and the largest client flight (an RSA
      CertificateVerify at SSF_RSA_MAX_KEY_BITS plus a SHA-384 Finished, 572 bytes at
      RSA-4096) must fit. Red: a 560-byte scratch with a 1-byte ALPN cap compiled; now an
      #error (572 builds, 571 does not). The run-time check on the server's key stays (the
      key comes from the network). A separate field was not used: about 550 B more RAM. Unit
      tests (both builds) and the interop set (156 / 156) unchanged.
- [ ] SSF conventions: `_SSFTLSC*` static names, 99-column comment boxes, copyright year,
      remove "Phase / M3" milestone comments; documentation `ssftlsc.md`; update `ssftls.md`
      ("no X.509 in SSF" is out of date).
