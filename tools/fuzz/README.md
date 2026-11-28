# Differential Fuzzing — SSF vs OpenSSL

Two libFuzzer harnesses compare SSF cryptographic primitives against
OpenSSL's reference implementations on randomly-mutated inputs, a third
checks the UTF-8 codec against itself (see `fuzz_utf8` below), and a fourth
checks the AWS provisioning module's untrusted-input functions against the
rules it documents (see `fuzz_awsprov` below). Any divergence
(SSF accepts and OpenSSL rejects, or outputs differ on the same input) aborts
immediately and writes the triggering input to disk for triage.

All harnesses run under ASan + UBSan, so any memory bug or undefined
behavior either side hits on adversarial input also surfaces as an abort.

## Targets

- `fuzz_aes_ctr` — compares `SSFAESCTR(key, ...)` against
  `EVP_aes_{128,192,256}_ctr` for random key/IV/plaintext combinations.
  Round-trip property checked (decrypt(encrypt(pt)) == pt).
- `fuzz_ecdsa_verify` — compares `SSFECDSAVerify(P-256, pubkey, hash, sig)`
  against `ECDSA_verify` for random `(pubkey, hash, sig)` triples. Catches
  disagreements on the boundary of valid/invalid.
- `fuzz_utf8` — self-consistency of the [`ssfutf8`](../../_codec/ssfutf8.md)
  codec on arbitrary bytes (no OpenSSL side): `SSFUTF8IsValid` is true exactly
  when `SSFUTF8DecodeNext` walks the whole input, `SSFUTF8Count` agrees with the
  walk, `allowNul` false refuses exactly the inputs holding U+0000, and every
  decoded code point is a scalar value that `SSFUTF8EncodeCP` re-encodes to the
  very bytes it came from (so only shortest forms decode).
- `fuzz_awsprov` — the [`ssfawsprov`](../../_net/ssfawsprov.md) functions that
  take outside input. The first input byte picks the function (`% 5`), the rest
  is its input, in a heap block of exactly its length so ASan sees an over-read:
  0 `SSFAWSProvParseCsrAccepted` (against the unit-test P-256 device key),
  1 `SSFAWSProvParseRegisterAccepted`, 2 `SSFAWSProvParseRejected`,
  3 `SSFAWSProvCredDecode`, 4 `SSFAWSProvBuildRegisterRequest` (the input as the
  ownership token). Each call is checked: a failure leaves every output zero;
  the rx copy is zero after every parse; an accepted certificate response has a
  64-hex id, a terminated token, a certificate that parses again and carries
  the device key; a thing name is 1.. of `[a-zA-Z0-9:_-]` and the device
  configuration valid JSON in braces of the reported length; a rejected
  response has statusCode 100..599 and printable strings; a decoded blob
  encodes back to exactly the same bytes and its key matches its certificate;
  a built request is exactly `{"certificateOwnershipToken":"<input>",
  "parameters":{"k":"v"}}` and valid JSON. Only contract-legal arguments are
  passed, so a failed SSF_REQUIRE is a finding too. Build with
  `-DFUZZ_AWSPROV_TRACE` to print each call's outcome when checking seeds.

## Running

Driver: `tools/fuzz/run.sh [<target>] [<seconds>]`

```sh
./tools/fuzz/run.sh                       # all targets, 60s each (default)
./tools/fuzz/run.sh aes_ctr 300           # AES-CTR for 5 min
./tools/fuzz/run.sh ecdsa_verify 86400    # ECDSA-verify for 24 hr
./tools/fuzz/run.sh utf8 300              # UTF-8 codec for 5 min
./tools/fuzz/run.sh awsprov 1800          # AWS provisioning inputs for 30 min
```

Builds inside a `gcc:latest` Docker container (apt-installs clang +
libssl-dev). podman's `docker` CLI works as well; when SELinux is enforcing
the repository is mounted with the `:z` label. Output goes to `build/fuzz/<target>/`. Crash inputs land at
`build/fuzz/<target>/crash-*` per libFuzzer convention.

The macOS-arm64 host can't run libFuzzer natively (same dyld init race
that affects ASan). Docker is the supported path on Apple Silicon. Linux
hosts can also build directly with clang + libssl-dev installed.

## Smoke results

Initial 30-second runs on first build (clang 19, gcc:latest container,
arm64 Linux under Docker on Apple Silicon):

| Target           | Inputs    | exec/s  | Divergences | Sanitizer aborts |
|------------------|-----------|---------|-------------|------------------|
| `fuzz_aes_ctr`   | 542,956   | 17,514  | 0           | 0                |
| `fuzz_ecdsa_verify` | 1,092,320 | 35,236  | 0           | 0                |

ECDSA-verify is faster per input because most random byte strings fail
pubkey decode early, exiting the verify path before the curve arithmetic.

Runs after `_net` joined the build (2026-11-27; x86-64 Linux, podman's docker
CLI, the same `gcc:latest` image, clang from its apt):

| Target           | Time   | Inputs     | exec/s  | New units | Aborts |
|------------------|--------|------------|---------|-----------|--------|
| `fuzz_aes_ctr`   | 60 s   | 1,757,517  | 28,811  | 123       | 0      |
| `fuzz_ecdsa_verify` | 60 s | 1,960,700 | 32,142  | 26        | 0      |
| `fuzz_utf8`      | 60 s   | 7,992,056  | 131,017 | 816       | 0      |
| `fuzz_awsprov`   | 60 s   | 1,314,314  | 21,546  | 4,384     | 0      |
| `fuzz_awsprov`   | 30 min | 27,515,888 | 15,278  | 4,505     | 0      |

The awsprov campaign continued from the 60 s run's corpus and ended with 3,959
corpus inputs (peak RSS 505 MB). Before it, each of its oracles was shown to
fire: nine deliberate breaks of ssfawsprov.c in a scratch copy (Decode skipping
its CRC or keeping its output on failure, the certificate parser accepting
another key or leaving its rx copy, the RegisterThing parser accepting any name
or keeping it on failure, the rejected parser not sanitizing, the builder
skipping its token check or keeping its output on failure) each abort on a seed
that exercises it, and the unmodified code replays every seed clean.

## Seed corpus

`tools/fuzz/seed_aes_ctr/`, `tools/fuzz/seed_ecdsa_verify/`,
`tools/fuzz/seed_utf8/` and `tools/fuzz/seed_awsprov/` hold seed inputs the
fuzzer mutates from. The awsprov seeds (committed) were built from the
`_net/ssfawsprov_ut_fix.h` fixtures: for each function its valid inputs and a
few near misses (another key's certificate, a curve mismatch, an escaped or
too-deep response, a token with a bare quote or a bad escape), each prefixed
with its selector byte. Real AWS responses (plan task V02) belong there too. The driver
creates a single zero-filled seed (for `utf8`, one sequence of each length and
the edges of the ill-formed ranges) if a directory has none. To accelerate a campaign:

- Copy NIST CAVS / RFC 3686 vectors into `seed_aes_ctr/` (one file per
  test case, raw byte layout matching the harness's input parser).
- Copy Wycheproof ECDSA vectors into `seed_ecdsa_verify/` (raw
  pubkey || hash || sig bytes, no separators).

The fuzzer will mutate around these to find adjacent-but-different
inputs that exercise new code paths.

## Triaging a crash

When libFuzzer aborts, it writes the crashing input to
`build/fuzz/<target>/crash-<sha1>`. Reproduce with:

```sh
./build/fuzz/<target>/fuzz_<target> build/fuzz/<target>/crash-<sha1>
```

The harness prints a `DIVERGENCE: ssf=… ossl=…` line before the abort.
For ASan/UBSan aborts you'll get a stack trace pointing at the offending
line in either SSF or OpenSSL.
