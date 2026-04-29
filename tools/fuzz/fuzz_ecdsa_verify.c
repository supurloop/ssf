/* libFuzzer harness: differential test SSF ECDSA verify against OpenSSL.
 *
 * Input layout (mutated by the fuzzer):
 *   bytes 0..64        — pubkey in SEC1 uncompressed form (0x04 || X || Y); 65 bytes
 *   bytes 65..96       — message hash (SHA-256 output, 32 bytes)
 *   bytes 97..end      — DER-encoded signature (variable length, up to 256 bytes)
 *
 * Run SSF and OpenSSL verify on the same inputs, abort on disagreement.
 *
 * "Disagreement" here means: SSF accepts an input that OpenSSL rejects, OR vice
 * versa. Either direction is a bug — SSF accepting an invalid signature is a
 * security issue; SSF rejecting a valid one is an interop issue.
 *
 * ASan/UBSan instrument both sides: any memory bug or UB that fires on adversarial
 * input shows up as a sanitizer abort regardless of verify result.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "ssfport.h"
#include "ssfassert.h"
#include "ssfecdsa.h"
#include "ssfec.h"

#define PUBKEY_LEN 65u
#define HASH_LEN   32u
#define MAX_SIG_LEN 256u

/* Returns 1 = valid, 0 = invalid, -1 = OpenSSL setup error (treat as "skip"). */
static int ossl_verify(const uint8_t *pub, size_t pubLen,
                       const uint8_t *hash, size_t hashLen,
                       const uint8_t *sig, size_t sigLen)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return -1;
    EC_POINT *pt = EC_POINT_new(group);
    EC_KEY   *key = EC_KEY_new();
    int rc = -1;
    if (pt && key &&
        EC_KEY_set_group(key, group) == 1 &&
        EC_POINT_oct2point(group, pt, pub, pubLen, NULL) == 1 &&
        EC_KEY_set_public_key(key, pt) == 1)
    {
        /* ECDSA_verify returns 1 = valid, 0 = invalid, -1 = error. We treat both 0
           and -1 from OpenSSL as "rejected" — any non-1 means OpenSSL didn't accept. */
        int v = ECDSA_verify(0, hash, (int)hashLen, sig, (int)sigLen, key);
        rc = (v == 1) ? 1 : 0;
    }
    /* If pubkey decode failed, OpenSSL can't even set the key — treat as "rejected"
       since a verifier must reject. */
    if (rc == -1) rc = 0;
    EC_KEY_free(key);
    EC_POINT_free(pt);
    EC_GROUP_free(group);
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < PUBKEY_LEN + HASH_LEN + 2u) return 0;  /* min sig is ~6 bytes for empty */

    const uint8_t *pub  = data;
    const uint8_t *hash = data + PUBKEY_LEN;
    const uint8_t *sig  = data + PUBKEY_LEN + HASH_LEN;
    size_t sigLen = size - PUBKEY_LEN - HASH_LEN;
    if (sigLen > MAX_SIG_LEN) sigLen = MAX_SIG_LEN;

    bool ssf_ok = SSFECDSAVerify(SSF_EC_CURVE_P256,
                                 pub, PUBKEY_LEN,
                                 hash, HASH_LEN,
                                 sig, sigLen);

    int ossl = ossl_verify(pub, PUBKEY_LEN, hash, HASH_LEN, sig, sigLen);
    /* ossl == 1 → accept; ossl == 0 → reject. */

    if ((ssf_ok ? 1 : 0) != ossl) {
        fprintf(stderr, "DIVERGENCE: ssf=%s ossl=%s sigLen=%zu\n",
                ssf_ok ? "accept" : "reject",
                ossl   ? "accept" : "reject",
                sigLen);
        abort();
    }

    return 0;
}
