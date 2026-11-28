/* --------------------------------------------------------------------------------------------- */
/* libFuzzer harness: ssfawsprov's untrusted-input functions (AWSPROV-M10).                      */
/*                                                                                               */
/* The first input byte picks the function, the rest is its input, copied into a heap block of   */
/* exactly its length so ASan sees any read past it:                                             */
/*   0  SSFAWSProvParseCsrAccepted      (an MQTT response; the fixture P-256 device key)         */
/*   1  SSFAWSProvParseRegisterAccepted (an MQTT response)                                       */
/*   2  SSFAWSProvParseRejected         (an MQTT response)                                       */
/*   3  SSFAWSProvCredDecode            (the credentials blob read from flash)                   */
/*   4  SSFAWSProvBuildRegisterRequest  (the input as the ownership token text)                  */
/* Besides memory errors and UB, each call's results are checked (abort on a violation):        */
/* failures leave every output zero, successes meet the rules the module documents, the rx copy  */
/* is zero after every parse, Decode round-trips through Encode byte for byte, and a built       */
/* request is exactly the token and the parameters in place.                                     */
/* Only arguments the API contract allows are passed, so every abort is a real finding.          */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ssfport.h"
#include "ssfassert.h"
#include "ssfjson.h"
#include "ssfx509.h"
#include "ssfecdsa.h"
#include "ssfawsprov.h"
#include "ssfawsprov_ut_fix.h"

/* -DFUZZ_AWSPROV_TRACE prints each call's outcome (for checking seeds; off when fuzzing) */
#ifdef FUZZ_AWSPROV_TRACE
#include <stdio.h>
#define FUZZ_TRACE(fn, ok) printf("%s %s\n", fn, (ok) ? "accepted" : "refused")
#else
#define FUZZ_TRACE(fn, ok)
#endif

#define FUZZ_AWSPROV_TOKEN_PRE  "{\"certificateOwnershipToken\":\""
#define FUZZ_AWSPROV_TOKEN_POST "\",\"parameters\":{\"k\":\"v\"}}"

static uint8_t _pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
static size_t _pubLen;
static char _rx[SSF_AWSPROV_CONFIG_RX_SIZE];
static SSFAWSProvCsrAccepted_t _acc;
static SSFX509Cert_t _cert;
static char _thing[SSF_AWSPROV_CONFIG_THING_NAME_SIZE];
static char _cfg[SSF_AWSPROV_CONFIG_DEVICE_CONFIG_SIZE];
static char _code[SSF_AWSPROV_ERROR_CODE_SIZE];
static char _msg[SSF_AWSPROV_ERROR_MESSAGE_SIZE];
static SSFAWSProvCred_t _cred;
static uint8_t _blob[SSF_AWSPROV_CRED_BLOB_MAX_SIZE];
static char _req[SSF_AWSPROV_CONFIG_REG_REQ_SIZE];
static char _expect[SSF_AWSPROV_CONFIG_REG_REQ_SIZE + 64u];
static const SSFAWSProvParam_t _params[] = { { "k", "v" } };

/* Returns true if buf[0..size) is all zero */
static bool IsZero(const void *buf, size_t size)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t i;

    for (i = 0; i < size; i++) { if (b[i] != 0) return false; }
    return true;
}

/* Returns true if str is terminated within size and every byte before the NUL is 0x20..0x7E */
static bool IsPrintable(const char *str, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
    {
        if (str[i] == 0) return true;
        if (((uint8_t)str[i] < 0x20u) || ((uint8_t)str[i] > 0x7Eu)) return false;
    }
    return false;
}

/* Returns true if str[0..len) is a thing name: 1.. characters of [a-zA-Z0-9:_-] */
static bool IsThingName(const char *str, size_t len)
{
    size_t i;

    if (len == 0) return false;
    for (i = 0; i < len; i++)
    {
        char c = str[i];
        if (!(((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
              ((c >= '0') && (c <= '9')) || (c == ':') || (c == '_') || (c == '-'))) return false;
    }
    return true;
}

static void FuzzCsrAccepted(const uint8_t *in, size_t len)
{
    size_t i;

    bool ok = SSFAWSProvParseCsrAccepted(in, len, _rx, sizeof(_rx), SSF_EC_CURVE_P256, _pub,
                                         _pubLen, &_acc);

    FUZZ_TRACE("csr_accepted", ok);
    if (ok == false)
    {
        if (!IsZero(&_acc, sizeof(_acc))) abort();
    }
    else
    {
        for (i = 0; i < 64u; i++)
        {
            char c = _acc.certificateId[i];
            if (!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')))) abort();
        }
        if (_acc.certificateId[64] != 0) abort();
        if ((_acc.tokenLen == 0) || (_acc.tokenLen >= sizeof(_acc.token)) ||
            (strlen(_acc.token) != _acc.tokenLen)) abort();
        if ((_acc.certDerLen == 0) || (_acc.certDerLen > sizeof(_acc.certDer))) abort();
        if (!SSFX509Parse(_acc.certDer, (uint32_t)_acc.certDerLen, &_cert)) abort();
        if ((_acc.cert.pubKeyLen != _pubLen) || (memcmp(_acc.cert.pubKey, _pub, _pubLen) != 0))
        { abort(); }
        memset(&_acc, 0, sizeof(_acc));
    }
    if (!IsZero(_rx, sizeof(_rx))) abort();
}

static void FuzzRegisterAccepted(const uint8_t *in, size_t len)
{
    size_t cfgLen = 1u;
    size_t n;

    bool ok = SSFAWSProvParseRegisterAccepted(in, len, _rx, sizeof(_rx), _thing, sizeof(_thing),
                                              _cfg, sizeof(_cfg), &cfgLen);

    FUZZ_TRACE("reg_accepted", ok);
    if (ok == false)
    {
        if ((cfgLen != 0) || !IsZero(_thing, sizeof(_thing)) || !IsZero(_cfg, sizeof(_cfg)))
        { abort(); }
    }
    else
    {
        n = strnlen(_thing, sizeof(_thing));
        if ((n >= sizeof(_thing)) || !IsThingName(_thing, n)) abort();
        if ((cfgLen < 2u) || (cfgLen >= sizeof(_cfg)) || (strnlen(_cfg, sizeof(_cfg)) != cfgLen))
        { abort(); }
        if ((_cfg[0] != '{') || (_cfg[cfgLen - 1u] != '}') || !SSFJsonIsValid(_cfg)) abort();
        memset(_thing, 0, sizeof(_thing));
        memset(_cfg, 0, sizeof(_cfg));
    }
    if (!IsZero(_rx, sizeof(_rx))) abort();
}

static void FuzzRejected(const uint8_t *in, size_t len)
{
    uint16_t sc = 1u;

    bool ok = SSFAWSProvParseRejected(in, len, _rx, sizeof(_rx), &sc, _code, sizeof(_code),
                                      _msg, sizeof(_msg));

    FUZZ_TRACE("rejected", ok);
    if (ok == false)
    {
        if ((sc != 0) || !IsZero(_code, sizeof(_code)) || !IsZero(_msg, sizeof(_msg))) abort();
    }
    else
    {
        if ((sc < 100u) || (sc > 599u)) abort();
        if (!IsPrintable(_code, sizeof(_code)) || !IsPrintable(_msg, sizeof(_msg))) abort();
        memset(_code, 0, sizeof(_code));
        memset(_msg, 0, sizeof(_msg));
    }
    if (!IsZero(_rx, sizeof(_rx))) abort();
}

static void FuzzCredDecode(const uint8_t *in, size_t len)
{
    size_t outLen;

    bool ok = SSFAWSProvCredDecode(in, len, &_cred);

    FUZZ_TRACE("cred_decode", ok);
    if (ok == false)
    {
        if (!IsZero(&_cred, sizeof(_cred))) abort();
        return;
    }
    /* Anything accepted encodes back to exactly the same bytes */
    if (!SSFAWSProvCredEncode(&_cred, _blob, sizeof(_blob), &outLen)) abort();
    if ((outLen != len) || (memcmp(_blob, in, len) != 0)) abort();
    if ((_cred.key.pubLen != _cred.cert.pubKeyLen) ||
        (memcmp(_cred.key.pub, _cred.cert.pubKey, _cred.key.pubLen) != 0)) abort();
    if (!IsThingName(_cred.thingName, strlen(_cred.thingName))) abort();
    SSFAWSProvCredWipe(&_cred);
    memset(_blob, 0, sizeof(_blob));
}

static void FuzzRegisterBuild(const uint8_t *in, size_t len)
{
    size_t outLen = 1u;
    size_t n;

    bool ok;

    if (len == 0) return;                                /* tokenLen > 0 is a REQUIRE */
    ok = SSFAWSProvBuildRegisterRequest((const char *)in, len, _params, 1u, _req, sizeof(_req),
                                        &outLen);
    FUZZ_TRACE("build", ok);
    if (ok == false)
    {
        if ((outLen != 0) || !IsZero(_req, sizeof(_req))) abort();
        return;
    }
    /* Exactly the token in place and the parameters after it: nothing the token held could */
    /* have changed the request's structure */
    n = 0;
    memcpy(&_expect[n], FUZZ_AWSPROV_TOKEN_PRE, sizeof(FUZZ_AWSPROV_TOKEN_PRE) - 1u);
    n += sizeof(FUZZ_AWSPROV_TOKEN_PRE) - 1u;
    if ((n + len + sizeof(FUZZ_AWSPROV_TOKEN_POST)) > sizeof(_expect)) abort();
    memcpy(&_expect[n], in, len);
    n += len;
    memcpy(&_expect[n], FUZZ_AWSPROV_TOKEN_POST, sizeof(FUZZ_AWSPROV_TOKEN_POST));
    n += sizeof(FUZZ_AWSPROV_TOKEN_POST) - 1u;
    if ((outLen != n) || (memcmp(_req, _expect, n + 1u) != 0)) abort();
    if (!SSFJsonIsValid(_req)) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *in;
    size_t len;

    /* The fixture device key's public point, once */
    if ((_pubLen == 0) &&
        !SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256, _utAWSProvP256Priv,
                                   sizeof(_utAWSProvP256Priv), _pub, sizeof(_pub), &_pubLen))
    { abort(); }
    if (size < 1u) return 0;

    /* The input in a block of exactly its length (one byte for an empty input, unused) */
    len = size - 1u;
    in = (uint8_t *)malloc((len == 0) ? 1u : len);
    if (in == NULL) return 0;
    if (len > 0) memcpy(in, &data[1], len);

    switch (data[0] % 5u)
    {
    case 0: FuzzCsrAccepted(in, len); break;
    case 1: FuzzRegisterAccepted(in, len); break;
    case 2: FuzzRejected(in, len); break;
    case 3: FuzzCredDecode(in, len); break;
    default: FuzzRegisterBuild(in, len); break;
    }
    free(in);
    return 0;
}
