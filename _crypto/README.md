# Cryptography

[Back to ssf README](../README.md)

Cryptographic interfaces.

## SHA-2 Hash Interface

The SHA-2 hash interface supports SHA256, SHA224, SHA512, SHA384, SHA512/224, and SHA512/256. There are two base functions that provide the ability to compute the six supported hashes. There are macros provided to simplify the calling interface to the base functions.

For example, to compute the SHA256 hash of "abc".

```
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

SSFSHA256("abc", 3, out, sizeof(out));
/* out == "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" */
```

## AES Block Interface

The AES block interface encrypts and decrypts 16 byte blocks of data with the AES cipher. The generic interface supports 128, 192 and 256 bit keys. Macros are supplied for these key sizes. This implementation _SHOULD NOT_ be used in production systems. It _IS_ vulnerable to timing attacks. Instead, processor specific AES instructions should be preferred.

```
    uint8_t pt[16];
    uint8_t dpt[16];
    uint8_t ct[16];
    uint8_t key[16];

    /* Initialize the plaintext and key here */
    memcpy(pt, "1234567890abcdef", sizeof(pt));
    memcpy(key, "secretkey1234567", sizeof(key));

    /* Encrypt the plaintext */
    SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

    /* ct = "\xdc\xc9\x32\xee\xfa\x94\x00\x0d\xfb\x97\x3f\xd4\x3d\x52\x6c\x45" */

    /* Decrypt the ciphertext */
    SSFAES128BlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));

    /* dpt = "1234567890abcdef" */

    /* If the key size is variable use the generic interface */

    /* Encrypt the plaintext */
    SSFAESXXXBlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

    /* ct = "\xdc\xc9\x32\xee\xfa\x94\x00\x0d\xfb\x97\x3f\xd4\x3d\x52\x6c\x45" */

    /* Decrypt the ciphertext */
    SSFAESXXXBlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));

    /* dpt = "1234567890abcdef" */
```

## AES-GCM Interface

The AES-GCM interface provides encryption and authentication for arbitary length data. The generic AES-GCM encrypt/decrypt functions support 128, 196 and 256 bit keys. There are four available modes: authentication, authenticated data, authenticated encryption and authenticated encryption with authenticated data. Examples of these are provided below. See the AES-GCM specification for details on how to generate valid IVs, example below. Note that the AES-GCM implementation relies on the _TIMING ATTACK VULNERABLE_ AES block cipher implementation.

```
    /* This shows a 128-bit IV generation, although a 96-bit IV is recommended and slightly more efficient */
    #define AES_GCM_MAKE_IV(iv, eui, fc) { \
        uint32_t befc = htonl(fc); \
        memcpy(iv, eui, 8); \
        memcpy(&iv[8], &befc, 4); \
        befc = ~befc; \
        memcpy(&iv[12], &befc, 4); \
    }
    size_t ptLen;
    uint8_t pt[100];
    uint8_t dpt[100];
    uint8_t iv[16];
    size_t authLen;
    uint8_t auth[100];
    uint8_t key[16];
    uint8_t tag[16];
    uint8_t ct[100];
    uint8_t eui64[8];
    uint32_t frameCounter;

    /* Initialize pt, iv, auth and key here */
    memcpy(eui64, "\x12\x34\x45\x67\x89\xab\xcd\xef", sizeof(eui64));
    frameCounter = 0;
    memcpy(pt, "1234567890abcdef", 16);
    ptLen = sizeof(pt);
    memcpy(key, "secretkey1234567", sizeof(key));
    memcpy(auth, "unencrypted auth data", 21);
    authLen = 21;

    /* Authentication */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), NULL, 0);

    /* Pass values of iv, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag,
                          sizeof(tag), NULL, 0))
    {
        printf("Authentication failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated data */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag, sizeof(tag),
                     NULL, 0);

    /* Pass values of iv, auth, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag,
                          sizeof(tag), NULL, 0))
    {
        printf("Authentication of unencrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated encryption */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag),
                     ct, sizeof(ct));

    /* Pass values of iv, ct, tag to receiver so they can verify with their copy of private key */
    if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag,
                          sizeof(tag), dpt, sizeof(dpt)))
    {
        printf("Authentication of encrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */


    /* Authenticated encryption and authenticated data */
    AES_GCM_MAKE_IV(iv, eui64, frameCounter);
    frameCounter++;
    SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag,
                     sizeof(tag), ct, sizeof(ct));

    if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), auth, authLen, key,
                          sizeof(key), tag, sizeof(tag), dpt, sizeof(dpt)))
    {
        printf("Authentication of encrypted and unencrypted data failed.\r\n");
        return;
    }
    /* Also verify that frameCounter value used in IV has increased, otherwise message is replayed. */
```

## Cryptographically Secure Capable PRNG Interface

The strength of many cryptographically secure algorithms and protocols is derived from a source of cryptographically secure random numbers. This interface provides a pseudo random number generator (PRNG) that CAN generate a cryptographically secure sequence of random numbers when properly seeded with 128-bits of entropy. The interface is allowed to re-init with new entropy at any time...useful in case the system needs to generate trillions of random numbers and there is a concern that the 64-bit counter might wrap :) After initing, 1-16 bytes of random data can be read on each invocation.

```
uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
uint8_t random[SSF_PRNG_RANDOM_MAX_SIZE];

    ... To be cryptographically secure 128-bits of entropy from a true random source must be
        staged to the entropy buffer;
        Otherwise it is easier to predict the random number sequence which can compromise
        secure algorithms and protocols.

    entropy <----random source
    SSFPRNGInitContext(&context, entropy, sizeof(entropy));

    while (true)
    {
        ...
        SSFPRNGGetRandom(&context, random, sizeof(random));
        /* random now contains 16 bytes of pseudo random data */
        ...

        /* Should we reseed after trillons and trillions of loops? */
        if (reseed)
        {
            /* Yes, reseed */
            entropy <----random source
            SSFPRNGInitContext(&context, entropy, sizeof(entropy));
        }
    }
```
