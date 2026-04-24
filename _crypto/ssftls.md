# ssftls — TLS 1.3 Core Building Blocks

[SSF](../README.md) | [Cryptography](README.md)

TLS 1.3 (RFC 8446) **core building blocks** — not a complete TLS implementation. This
module provides the primitives needed to drive a TLS 1.3 session:

- The **key schedule**: HKDF-Expand-Label, Derive-Secret, traffic-key derivation, and
  the Finished verify-data computation.
- A **transcript-hash** helper that tracks the running hash of handshake messages.
- The **record layer**: AEAD encrypt / decrypt of TLS 1.3 records, with per-suite dispatch
  to AES-GCM, AES-CCM, or ChaCha20-Poly1305.
- A shared namespace of TLS 1.3 wire-format constants (cipher suites, named groups,
  signature schemes, content and handshake types, extensions, alerts).
- A per-connection **trace callback** facility for instrumenting a TLS stack built on top.

What's **not** in this module (and not in SSF at all currently):

- **No handshake state machine.** There is no `SSFTLSConnect()`, `SSFTLSAccept()`, or
  anything that orchestrates ClientHello → ServerHello → EncryptedExtensions →
  Certificate → CertificateVerify → Finished.
- **No certificate chain parsing or trust validation.** The wire-constant namespace
  defines `SSF_TLS_HS_CERTIFICATE`, `SSF_TLS_HS_CERTIFICATE_VERIFY`, and alert codes for
  certificate errors, but no X.509 / PKIX parsing entry points exist.
- **No socket / transport I/O integration.** `SSFTLSIOResult_t` is declared in the header
  (`WANT_READ` / `WANT_WRITE` for non-blocking sockets) but nothing in the current
  implementation consumes or produces it — it's a reserved type for a future I/O layer.
- **No extension parsing or generation.** `SSF_TLS_EXT_*` constants are named for
  callers doing their own extension handling; no encode / decode functions are exposed.
- **No PSK / 0-RTT / session ticket support.** `SSF_TLS_CONFIG_PSK_ENABLE` and
  `SSF_TLS_CONFIG_TICKET_LIFETIME_SEC` are declared in `ssftls_opt.h` but not referenced
  by the current implementation.

Use this module when you are building a TLS 1.3 peer yourself and need the primitives
that would otherwise be tedious to re-implement correctly — particularly the
HKDF-Expand-Label key derivation chain and the record-layer nonce derivation. Pair it
with the other SSF crypto modules for the handshake-side signature / KEM primitives:
[`ssfecdsa`](ssfecdsa.md), [`ssfed25519`](ssfed25519.md), [`ssfrsa`](ssfrsa.md),
[`ssfx25519`](ssfx25519.md), [`ssfhkdf`](ssfhkdf.md), [`ssfsha2`](ssfsha2.md).

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssftls--tls-13-core-building-blocks) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfhmac`](ssfhmac.md) — underlying HKDF extract / expand for the key schedule
- [`ssfsha2`](ssfsha2.md) — SHA-256 / SHA-384 for transcript hash and HKDF
- [`ssfaesgcm`](ssfaesgcm.md) — AEAD backend for the `AES_*_GCM_*` cipher suites
- [`ssfaesccm`](ssfaesccm.md) — AEAD backend for the `AES_*_CCM_*` cipher suites
- [`ssfchacha20poly1305`](ssfchacha20poly1305.md) — AEAD backend for the
  `CHACHA20_POLY1305_SHA256` cipher suite

Callers building a complete TLS stack on top of these primitives will also depend on
the handshake-side crypto modules: one or more of
[`ssfecdsa`](ssfecdsa.md) / [`ssfed25519`](ssfed25519.md) / [`ssfrsa`](ssfrsa.md) for
CertificateVerify; [`ssfx25519`](ssfx25519.md) and / or
[`ssfecdsa`'s ECDH](ssfecdsa.md#ecdh) for the key-share; and
[`ssfhkdf`](ssfhkdf.md) for the master-secret extraction steps of the key schedule (the
Derive-Secret / HKDF-Expand-Label helpers here call HMAC directly rather than going
through the `ssfhkdf` API).

<a id="notes"></a>

## [↑](#ssftls--tls-13-core-building-blocks) Notes

- **Cipher-suite coverage.** Five TLS 1.3 cipher suites are dispatched by
  [`SSFTLSRecordEncrypt`](#ssftlsrecordencrypt) / [`SSFTLSRecordDecrypt`](#ssftlsrecorddecrypt):

  | Value | Suite | AEAD backend | Tag bytes |
  |---|---|---|---|
  | `0x1301` | `TLS_AES_128_GCM_SHA256` | `ssfaesgcm` | 16 |
  | `0x1302` | `TLS_AES_256_GCM_SHA384` | `ssfaesgcm` | 16 |
  | `0x1303` | `TLS_CHACHA20_POLY1305_SHA256` | `ssfchacha20poly1305` | 16 |
  | `0x1304` | `TLS_AES_128_CCM_SHA256` | `ssfaesccm` | 16 |
  | `0x1305` | `TLS_AES_128_CCM_8_SHA256` | `ssfaesccm` | 8 |

  `TLS_AES_128_GCM_SHA256` is the RFC 8446 MTI (mandatory-to-implement). The two CCM
  suites are the IoT-oriented options (fewer transistors / less firmware on
  resource-constrained devices that already have an AES-CCM engine for 802.15.4).
  ChaCha20-Poly1305 is the CPU-constant-time option.
- **Hash pairing to cipher suite is baked in.** All SHA256 suites run the key schedule
  and transcript hash over SHA-256; the SHA384 suite runs them over SHA-384. Callers
  select `SSF_HMAC_HASH_SHA256` or `SSF_HMAC_HASH_SHA384` based on the cipher suite and
  pass that to every key-schedule function.
- **Record-layer nonce construction.** [`SSFTLSRecordEncrypt`](#ssftlsrecordencrypt)
  builds the per-record AEAD nonce by XOR-ing the 64-bit sequence number (big-endian,
  left-padded) into the static IV obtained during
  [`SSFTLSRecordStateInit`](#ssftlsrecordstateinit). The sequence number increments
  internally after every encrypt. This matches RFC 8446 §5.3 exactly; callers must not
  re-use a `SSFTLSRecordState_t` across a re-key or a renegotiation, because the sequence
  counter starts from zero and the IV is re-derived each time. After a KeyUpdate, create
  a new `SSFTLSRecordState_t` rather than mutating the old one.
- **Outer content type is always `application_data`.** TLS 1.3 wraps the inner content
  type (`handshake`, `application_data`, `alert`) inside the AEAD plaintext, then
  advertises `application_data` (`0x17`) in the record header. `SSFTLSRecordEncrypt`
  handles this: the caller passes the *inner* content type; the record header always
  carries `0x17`. `SSFTLSRecordDecrypt` reverses the operation and returns the inner
  content type in its `contentType` out-parameter.
- **Record version in the header is always `0x0303` (TLS 1.2).** Per RFC 8446 §5.1, TLS
  1.3 records on the wire advertise the legacy `0x0303` version for middlebox
  compatibility; the real version is negotiated through the `supported_versions`
  extension (in the ClientHello / ServerHello, not in the record layer).
- **Per-suite AEAD tag length** is derived at runtime via the internal
  `_SSFTLSAeadTagSize()` helper (16 bytes for every suite except
  `TLS_AES_128_CCM_8_SHA256`, which is 8). The value flows into `cipherLen`,
  `totalLen`, the per-suite tag copy, and the decrypt-side `innerLen` arithmetic, so all
  four CCM and non-CCM suites produce correctly-sized records. In particular, a CCM_8
  record for an N-byte plaintext is `5 + (N + 1) + 8` bytes on the wire, not
  `5 + (N + 1) + 16`.
- **Transcript hash spans every handshake message bytewise.** Per RFC 8446 §4.4.1, the
  transcript is the concatenation of all handshake messages (including their 4-byte
  headers) that have been exchanged so far. Feed *every* handshake message to
  [`SSFTLSTranscriptUpdate`](#transcript-hash) as-sent / as-received, in order, before
  computing the `Derive-Secret` or Finished inputs that depend on that transcript. Miss
  one and the handshake breaks in a way that looks like a MAC failure.
- **Finished `verify_data` is HMAC-keyed with a finished_key derived from the handshake
  traffic secret.** [`SSFTLSComputeFinished`](#ssftlscomputefinished) takes the
  *handshake* traffic secret as `baseKey`, internally runs
  `HKDF-Expand-Label(baseKey, "finished", "", hashLen)` to derive the finished_key, then
  computes `HMAC(finished_key, transcriptHash)`. Callers pass the traffic secret
  directly — they do **not** pre-compute the finished_key.
- **Trace callbacks are per-connection and zero-overhead when disabled.** A caller that
  does not install a `SSFTLSTraceCtx_t` — or that installs one with `fn == NULL` — pays
  only a single null-check per would-be trace point (the `SSF_TLS_TRACE_*` macros
  short-circuit). Installing a trace callback formats into a 256-byte stack buffer per
  call; keep this in mind if stack is tight.
- **Configuration options are forward-looking.** `SSF_TLS_CONFIG_MAX_RECORD_SIZE`,
  `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH`, `SSF_TLS_CONFIG_MAX_TRUSTED_CAS`,
  `SSF_TLS_CONFIG_PSK_ENABLE`, `SSF_TLS_CONFIG_TICKET_LIFETIME_SEC`, and
  `SSF_TLS_CONFIG_MAX_ALPN_LEN` are declared in [`_opt/ssftls_opt.h`](../_opt/ssftls_opt.h)
  but not currently referenced by the implementation — they are placeholders for a
  future handshake / chain / PSK layer and have no effect on compiled behavior today.
- **The only "state" in this module is `SSFTLSRecordState_t` and `SSFTLSTranscript_t`.**
  There is no session object, no connection handle — each primitive takes and returns
  its inputs explicitly. Callers are responsible for lifetime management and for wiping
  secret material (traffic secrets, handshake secrets, finished keys) when they go out
  of scope.

<a id="configuration"></a>

## [↑](#ssftls--tls-13-core-building-blocks) Configuration

Options live in [`_opt/ssftls_opt.h`](../_opt/ssftls_opt.h). None of the options currently
affect compiled behaviour of the public API (see the last note above); they are reserved
for a future handshake / transport layer.

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_TLS_CONFIG_MAX_RECORD_SIZE` | `8192` | Reserved for a future record-buffer size. Does **not** currently bound `recordSize` in the public API — the caller supplies the buffer. |
| `SSF_TLS_CONFIG_MAX_CHAIN_DEPTH` | `4` | Reserved for certificate chain validation. Unused today. |
| `SSF_TLS_CONFIG_MAX_TRUSTED_CAS` | `8` | Reserved for trust-store capacity. Unused today. |
| `SSF_TLS_CONFIG_PSK_ENABLE` | `1` | Reserved for PSK handshake support. Unused today. |
| `SSF_TLS_CONFIG_TICKET_LIFETIME_SEC` | `3600` | Reserved for session-ticket lifetime. Unused today. |
| `SSF_TLS_CONFIG_MAX_ALPN_LEN` | `32` | Reserved for ALPN protocol list sizing. Unused today. |

<a id="api-summary"></a>

## [↑](#ssftls--tls-13-core-building-blocks) API Summary

### Definitions

The header declares a large namespace of TLS 1.3 wire-format constants that callers
driving the handshake themselves will need. Grouped logically:

| Category | Constants |
|---|---|
| Protocol versions | `SSF_TLS_VERSION_12` (`0x0303`), `SSF_TLS_VERSION_13` (`0x0304`) |
| Record framing | `SSF_TLS_RECORD_HEADER_SIZE` (`5`), `SSF_TLS_AEAD_TAG_SIZE` (`16`), `SSF_TLS_MAX_HASH_SIZE` (`48`), `SSF_TLS_MAX_KEY_SIZE` (`32`), `SSF_TLS_IV_SIZE` (`12`) |
| Content types | `SSF_TLS_CT_CHANGE_CIPHER` (`20`), `SSF_TLS_CT_ALERT` (`21`), `SSF_TLS_CT_HANDSHAKE` (`22`), `SSF_TLS_CT_APPLICATION` (`23`) |
| Handshake types | `SSF_TLS_HS_CLIENT_HELLO`, `_SERVER_HELLO`, `_NEW_SESSION_TICKET`, `_CERTIFICATE_REQUEST`, `_KEY_UPDATE`, `_ENCRYPTED_EXTENSIONS`, `_CERTIFICATE`, `_CERTIFICATE_VERIFY`, `_FINISHED` |
| Cipher suites | `SSF_TLS_CS_AES_128_GCM_SHA256`, `_AES_256_GCM_SHA384`, `_AES_128_CCM_SHA256`, `_AES_128_CCM_8_SHA256`, `_CHACHA20_POLY1305_SHA256` |
| Named groups | `SSF_TLS_GROUP_SECP256R1`, `_SECP384R1`, `_X25519` |
| Signature schemes | `SSF_TLS_SIG_ECDSA_SECP256R1_SHA256`, `_ECDSA_SECP384R1_SHA384`, `_RSA_PSS_RSAE_SHA256`, `_RSA_PSS_RSAE_SHA384`, `_RSA_PKCS1_SHA256`, `_RSA_PKCS1_SHA384`, `_ED25519` |
| Extension types | `SSF_TLS_EXT_SERVER_NAME`, `_SUPPORTED_GROUPS`, `_SIGNATURE_ALGS`, `_SUPPORTED_VERSIONS`, `_ALPN`, `_PSK_KEY_EXCHANGE`, `_PRE_SHARED_KEY`, `_KEY_SHARE` |
| Alert codes | `SSF_TLS_ALERT_CLOSE_NOTIFY`, `_UNEXPECTED_MSG`, `_BAD_RECORD_MAC`, `_HANDSHAKE_FAILURE`, `_BAD_CERTIFICATE`, `_CERTIFICATE_UNKNOWN`, `_DECODE_ERROR`, `_DECRYPT_ERROR`, `_INTERNAL_ERROR` |
| CertificateVerify | `SSF_TLS_CV_SIGN_CONTENT_MAX_SIZE` (`146`) — max bytes of signed-content buffer (64 filler + 33 context + 1 separator + up-to-48 transcript hash) |

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssftlsrecordstate-t"></a>`SSFTLSRecordState_t` | Struct | Per-direction record state: AEAD key, static IV, 64-bit sequence number, cipher-suite selector. |
| <a id="ssftlstranscript-t"></a>`SSFTLSTranscript_t` | Struct | Running transcript hash (union of `SSFSHA2_32Context_t` / `SSFSHA2_64Context_t`) plus the active hash length and `SSFHMACHash_t` selector. |
| `SSFTLSIOResult_t` | Enum | Reserved I/O result codes (`SUCCESS`, `WANT_READ`, `WANT_WRITE`, `ERROR`) for a future non-blocking transport layer; not used by any currently-exposed function. |
| `SSFTLSTraceLevel_t` / `SSFTLSTraceCategory_t` | Enum | Severity (`ERROR` / `WARN` / `INFO` / `DEBUG`) and category (`HANDSHAKE` / `RECORD` / `CRYPTO` / `CERT` / `ALERT`) for trace callback dispatch. |
| `SSFTLSTraceFn_t` | Typedef | Callback signature: `void (*)(level, category, msg, userCtx)`. |
| `SSFTLSTraceCtx_t` | Struct | `{ fn, userCtx }`; stored per-session, passed to the `SSF_TLS_TRACE_*` macros. |

<a id="functions"></a>

### Functions

**[Key schedule](#key-schedule)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-keyschedule) | [`void SSFTLSHkdfExpandLabel(hash, secret, secretLen, label, context, ctxLen, out, outLen)`](#ssftlshkdfexpandlabel) | RFC 8446 §7.1 `HKDF-Expand-Label` |
| [e.g.](#ex-keyschedule) | [`void SSFTLSDeriveSecret(hash, secret, secretLen, label, transcriptHash, transcriptHashLen, out, outLen)`](#ssftlsderivesecret) | RFC 8446 §7.1 `Derive-Secret` |
| [e.g.](#ex-keyschedule) | [`void SSFTLSDeriveTrafficKeys(hash, trafficSecret, secretLen, key, keyLen, iv, ivLen)`](#ssftlsderivetrafficKeys) | RFC 8446 §7.3 traffic-key + IV derivation |
| [e.g.](#ex-finished) | [`void SSFTLSComputeFinished(hash, baseKey, baseKeyLen, transcriptHash, transcriptHashLen, verifyData, verifyDataLen)`](#ssftlscomputefinished) | Finished `verify_data` = `HMAC(finished_key, transcript_hash)` |

**[Transcript hash](#transcript-hash)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-transcript) | [`void SSFTLSTranscriptInit(t, hash)`](#ssftlstranscriptinit) | Initialise a running transcript hash for the selected `SSFHMACHash_t` |
| [e.g.](#ex-transcript) | [`void SSFTLSTranscriptUpdate(t, data, len)`](#ssftlstranscriptupdate) | Append handshake bytes |
| [e.g.](#ex-transcript) | [`void SSFTLSTranscriptHash(t, out, outSize)`](#ssftlstranscripthash) | Snapshot the current transcript hash without consuming the context |

**[Record layer](#record-layer)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-record) | [`void SSFTLSRecordStateInit(state, cipherSuite, key, keyLen, iv, ivLen)`](#ssftlsrecordstateinit) | Install traffic keys for one direction |
| [e.g.](#ex-record) | [`bool SSFTLSRecordEncrypt(state, contentType, pt, ptLen, record, recordSize, recordLen)`](#ssftlsrecordencrypt) | Build one TLS 1.3 record: header + AEAD ciphertext + tag |
| [e.g.](#ex-record) | [`bool SSFTLSRecordDecrypt(state, record, recordLen, pt, ptSize, ptLen, contentType)`](#ssftlsrecorddecrypt) | Verify + decrypt one record; returns the inner content type |

<a id="function-reference"></a>

## [↑](#ssftls--tls-13-core-building-blocks) Function Reference

<a id="key-schedule"></a>

### [↑](#functions) Key Schedule

<a id="ssftlshkdfexpandlabel"></a>
```c
void SSFTLSHkdfExpandLabel(SSFHMACHash_t hash,
                           const uint8_t *secret, size_t secretLen,
                           const char *label,
                           const uint8_t *context, size_t ctxLen,
                           uint8_t *out, size_t outLen);
```
RFC 8446 §7.1 `HKDF-Expand-Label(Secret, Label, Context, Length)`. Prepends `"tls13 "` to
`label`, frames `(label, context)` into the RFC-specified `HkdfLabel` structure, and
runs `HKDF-Expand` internally. This is the building block for every secret derivation in
TLS 1.3 — traffic secrets, application secrets, resumption secret, exporter secret, etc.
all flow through this function.

<a id="ssftlsderivesecret"></a>
```c
void SSFTLSDeriveSecret(SSFHMACHash_t hash,
                        const uint8_t *secret, size_t secretLen,
                        const char *label,
                        const uint8_t *transcriptHash, size_t transcriptHashLen,
                        uint8_t *out, size_t outLen);
```
RFC 8446 §7.1 `Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
Transcript-Hash(Messages), Hash.length)`. Thin wrapper over
[`SSFTLSHkdfExpandLabel`](#ssftlshkdfexpandlabel) that threads the transcript hash as the
context. Use this at every Derive-Secret site in the key schedule (e.g., deriving
`c_hs_traffic`, `s_hs_traffic`, `c_ap_traffic_0`, `s_ap_traffic_0`, `exp_master`,
`res_master`).

<a id="ssftlsderivetrafficKeys"></a>
```c
void SSFTLSDeriveTrafficKeys(SSFHMACHash_t hash,
                             const uint8_t *trafficSecret, size_t secretLen,
                             uint8_t *key, size_t keyLen,
                             uint8_t *iv, size_t ivLen);
```
RFC 8446 §7.3 traffic-key and IV derivation. Given a traffic secret (handshake or
application), produces the AEAD `key` (length `keyLen` — 16 for AES-128, 32 for AES-256)
and the static `iv` (length `ivLen` — always 12 for TLS 1.3) via
`HKDF-Expand-Label(trafficSecret, "key", "", keyLen)` and
`HKDF-Expand-Label(trafficSecret, "iv", "", ivLen)` respectively.

<a id="ex-keyschedule"></a>

**Example:**

```c
/* Derive the client handshake traffic keys after the key-exchange step. */
uint8_t cHsTraffic[SSF_TLS_MAX_HASH_SIZE];  /* 32 or 48 bytes */
uint8_t cKey[16], cIv[12];

SSFTLSDeriveSecret(SSF_HMAC_HASH_SHA256,
                   handshakeSecret, 32,
                   "c hs traffic",
                   transcriptHashThroughServerHello, 32,
                   cHsTraffic, 32);

SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256,
                        cHsTraffic, 32,
                        cKey, sizeof(cKey),
                        cIv,  sizeof(cIv));
/* cKey + cIv are now ready to install into a SSFTLSRecordState_t. */
```

<a id="ssftlscomputefinished"></a>
```c
void SSFTLSComputeFinished(SSFHMACHash_t hash,
                           const uint8_t *baseKey, size_t baseKeyLen,
                           const uint8_t *transcriptHash, size_t transcriptHashLen,
                           uint8_t *verifyData, size_t verifyDataLen);
```
Produce the `verify_data` field of a Finished message. Internally derives `finished_key =
HKDF-Expand-Label(baseKey, "finished", "", hashLen)` then computes
`verify_data = HMAC(finished_key, transcript_hash)`. Pass the *handshake traffic secret*
(for the regular Finished) or the appropriate application-traffic secret (for resumption
or PSK) as `baseKey`.

<a id="ex-finished"></a>

**Example:**

```c
uint8_t verifyData[SSF_TLS_MAX_HASH_SIZE];

/* Client Finished verify_data over the transcript up through (but not
   including) the client Finished itself. */
SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256,
                      cHsTraffic, 32,
                      transcriptThroughServerFinished, 32,
                      verifyData, 32);
/* Send: Finished { verify_data = verifyData[0..31] }. */
```

---

<a id="transcript-hash"></a>

### [↑](#functions) Transcript Hash

<a id="ssftlstranscriptinit"></a>
```c
void SSFTLSTranscriptInit(SSFTLSTranscript_t *t, SSFHMACHash_t hash);
```
Initialise `t` for the active cipher suite's transcript hash. Pass `SSF_HMAC_HASH_SHA256`
for any `SHA256` suite, `SSF_HMAC_HASH_SHA384` for `AES_256_GCM_SHA384`. Must be called
before the first `Update`.

<a id="ssftlstranscriptupdate"></a>
```c
void SSFTLSTranscriptUpdate(SSFTLSTranscript_t *t, const uint8_t *data, size_t len);
```
Append `len` bytes of handshake-message data to the running transcript. Each full
handshake message (its 4-byte header plus its body) must be fed exactly once, in
wire-order, on both sides. Missing or mis-ordering a message produces a mismatched
transcript hash — detected later as a Finished MAC failure, which looks cryptic unless
you know to check the transcript ordering first.

<a id="ssftlstranscripthash"></a>
```c
void SSFTLSTranscriptHash(const SSFTLSTranscript_t *t, uint8_t *out, size_t outSize);
```
Snapshot the current transcript hash into `out` **without** finalising or invalidating
`t`. Callers can continue updating `t` after this call. That's exactly what the key
schedule needs — e.g., the transcript hash through ServerHello is one input, the
transcript hash through EncryptedExtensions is another, all the way up to the final
Finished, without rebuilding the hash from scratch each time.

<a id="ex-transcript"></a>

**Example:**

```c
SSFTLSTranscript_t t;
uint8_t            thHash[32];

SSFTLSTranscriptInit(&t, SSF_HMAC_HASH_SHA256);

/* Feed every handshake message as it is sent or received. */
SSFTLSTranscriptUpdate(&t, clientHelloBytes, clientHelloLen);
SSFTLSTranscriptUpdate(&t, serverHelloBytes, serverHelloLen);

/* Snapshot the current running hash for a Derive-Secret call — this does
   not disturb `t`, so further Updates produce a consistent transcript. */
SSFTLSTranscriptHash(&t, thHash, sizeof(thHash));

SSFTLSTranscriptUpdate(&t, encExtBytes, encExtLen);
/* ... and so on. */
```

---

<a id="record-layer"></a>

### [↑](#functions) Record Layer

<a id="ssftlsrecordstateinit"></a>
```c
void SSFTLSRecordStateInit(SSFTLSRecordState_t *state, uint16_t cipherSuite,
                           const uint8_t *key, size_t keyLen,
                           const uint8_t *iv, size_t ivLen);
```
Populate `state` with the traffic key (from [`SSFTLSDeriveTrafficKeys`](#ssftlsderivetrafficKeys))
and zero the sequence counter. Create one `SSFTLSRecordState_t` per direction (client→server
and server→client) and re-initialise after each key update — do not reuse a state across
a re-key.

<a id="ssftlsrecordencrypt"></a>
```c
bool SSFTLSRecordEncrypt(SSFTLSRecordState_t *state, uint8_t contentType,
                         const uint8_t *pt, size_t ptLen,
                         uint8_t *record, size_t recordSize, size_t *recordLen);
```
Produce one TLS 1.3 record containing `pt` as the protected payload with inner type
`contentType`. Writes the full wire record to `record`: 5-byte header
(`0x17 0x03 0x03 len_hi len_lo`), then `ptLen + 1` bytes of inner plaintext
(`pt ‖ contentType`) AEAD-encrypted in-place, followed by the AEAD tag (16 bytes for
every suite except `TLS_AES_128_CCM_8_SHA256`, which uses 8 — see the cipher-suite table
in [Notes](#notes)). `recordLen` reports the total wire-record size including header,
ciphertext, and tag.

Returns `false` if `recordSize` is too small or if the record would exceed the RFC 8446
per-record ciphertext limit of `2^14 + 256` bytes. The sequence number is
incremented internally on success.

<a id="ssftlsrecorddecrypt"></a>
```c
bool SSFTLSRecordDecrypt(SSFTLSRecordState_t *state,
                         const uint8_t *record, size_t recordLen,
                         uint8_t *pt, size_t ptSize, size_t *ptLen,
                         uint8_t *contentType);
```
Verify the AEAD tag on `record`, decrypt the payload into `pt`, and extract the inner
content type (writing it to `*contentType`). Returns `false` on any parsing / size /
tag-verification failure — the caller should treat all `false` outcomes identically and
reject the record. On success, `*ptLen` is the length of the actual payload (the inner
content-type byte has already been stripped).

<a id="ex-record"></a>

**Example:**

```c
/* After handshake: install the application traffic keys and send
   application data as encrypted records. */
SSFTLSRecordState_t txState;
SSFTLSRecordStateInit(&txState,
                      SSF_TLS_CS_AES_128_GCM_SHA256,
                      cAppKey, 16,
                      cAppIv,  12);

uint8_t record[5 + 256 + 1 + 16];  /* header + pt + innerType + tag */
size_t  recordLen;

const uint8_t payload[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
if (!SSFTLSRecordEncrypt(&txState,
                         SSF_TLS_CT_APPLICATION,
                         payload, sizeof(payload) - 1,
                         record, sizeof(record), &recordLen))
{
    /* Output buffer too small, or payload exceeds the per-record limit. */
}
/* Write record[0..recordLen-1] to the socket. */

/* On the peer, receive and decrypt: */
SSFTLSRecordState_t rxState;
SSFTLSRecordStateInit(&rxState,
                      SSF_TLS_CS_AES_128_GCM_SHA256,
                      sAppKey, 16,
                      sAppIv,  12);

uint8_t pt[256];
size_t  ptLen;
uint8_t innerCt;
if (!SSFTLSRecordDecrypt(&rxState,
                         record, recordLen,
                         pt, sizeof(pt), &ptLen,
                         &innerCt))
{
    /* Bad MAC, truncated, or malformed. Close the connection with
       SSF_TLS_ALERT_BAD_RECORD_MAC. */
}
if (innerCt == SSF_TLS_CT_APPLICATION)
{
    /* pt[0..ptLen-1] is the recovered application payload. */
}
/* The inner content type might instead be SSF_TLS_CT_HANDSHAKE (for
   post-handshake messages like KeyUpdate) or SSF_TLS_CT_ALERT — handle
   accordingly. */
```
