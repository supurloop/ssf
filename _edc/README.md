# Error Detection Codes (EDC)

[Back to ssf README](../README.md)

Data integrity interfaces.

## 16-bit Fletcher Checksum Interface

Every embedded system needs to use a checksum somewhere, somehow. The 16-bit Fletcher checksum has many of the error detecting properties of a 16-bit CRC, but at the computational cost of an arithmetic checksum. For 88 bytes of program memory how can you go wrong?

The API can compute the checksum of data incrementally.

For example, the first call to SSFFCSum16() results in the same checksum as the following three calls.

```
uint16_t fc;

fc = SSFFCSum16("abcde", 5, SSF_FCSUM_INITIAL);
/* fc == 0xc8f0 */

fc = SSFFCSum16("a", 1, SSF_FCSUM_INITIAL);
fc = SSFFCSum16("bcd", 3, fc);
fc = SSFFCSum16("e", 1, fc);
/* fc == 0xc8f0 */
```

## 16-bit XMODEM/CCITT-16 CRC Interface

This 16-bit CRC uses the 0x1021 polynomial. It uses a table lookup to reduce execution time at the expense of 512 bytes of program memory.
Use if you need compatability with the XMODEM CRC and/or can spare the extra program memory for a little bit better error detection than the 16-bit Fletcher.

The API can compute the CRC of data incrementally.

For example, the first call to SSFCRC16() results in the same CRC as the following three calls.

```
uint16_t crc;

crc = SSFCRC16("abcde", 5, SSF_CRC16_INITIAL);
/* crc == 0x3EE1 */

crc = SSFCRC16("a", 1, SSF_CRC16_INITIAL);
crc = SSFCRC16("bcd", 3, crc);
crc = SSFCRC16("e", 1, crc);
/* crc == 0x3EE1 */
```

## 32-bit CCITT-32 CRC Interface

This 32-bit CRC uses the 0x04C11DB7 polynomial. It uses a table lookup to reduce execution time at the expense of 1024 bytes of program memory.
Use if you need more error detection than provided by CRC16 and/or in conjunction with Reed-Solomon to detect wrong solutions.

The API can compute the CRC of data incrementally.

For example, the first call to SSFCRC32() results in the same CRC as the following three calls.

```
uint32_t crc;

crc = SSFCRC32("abcde", 5, SSF_CRC32_INITIAL);
/* crc == 0x8587D865 */

crc = SSFCRC32("a", 1, SSF_CRC32_INITIAL);
crc = SSFCRC32("bcd", 3, crc);
crc = SSFCRC32("e", 1, crc);
/* crc == 0x8587D865 */
```
