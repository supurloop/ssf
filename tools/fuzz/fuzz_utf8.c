/* libFuzzer harness: self-consistency of the ssfutf8 codec on arbitrary bytes.
 *
 * Input: any bytes. Checks, aborting on the first disagreement:
 *   - SSFUTF8IsValid(allowNul true) is true exactly when SSFUTF8DecodeNext walks the whole
 *     input, and SSFUTF8Count then returns the number of steps;
 *   - with allowNul false it is also false when any decoded code point is U+0000;
 *   - every decoded code point re-encodes with SSFUTF8EncodeCP to the very bytes it came
 *     from (so only shortest forms decode), and is a Unicode scalar value;
 *   - DecodeNext never reports more bytes than it was given, nor more than four.
 * ASan/UBSan instrument the codec, so any out-of-bounds read also aborts.
 *
 * Run:
 *   ./fuzz_utf8 -max_total_time=300 corpus_dir
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ssfport.h"
#include "ssfassert.h"
#include "ssfutf8.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t enc[SSF_UTF8_MAX_SEQ_LEN];
    size_t pos = 0;
    size_t steps = 0;
    size_t n = 0;
    size_t encLen = 0;
    size_t count;
    uint32_t cp;
    bool walked = true;
    bool sawNul = false;
    bool valid;

    /* A non-NULL pointer for the empty input */
    if (data == NULL) data = enc;

    while (pos < size)
    {
        if (!SSFUTF8DecodeNext(&data[pos], size - pos, &cp, &n)) { walked = false; break; }
        if ((n > (size - pos)) || (n > SSF_UTF8_MAX_SEQ_LEN)) abort();
        if ((cp > SSF_UTF8_MAX_CP) || ((cp >= 0xD800ul) && (cp <= 0xDFFFul))) abort();
        if ((!SSFUTF8EncodeCP(cp, enc, sizeof(enc), &encLen)) || (encLen != n)) abort();
        if (memcmp(enc, &data[pos], n) != 0) abort();
        if (cp == 0u) sawNul = true;
        pos += n;
        steps++;
    }
    valid = SSFUTF8IsValid(data, size, true);
    if (valid != walked) abort();
    if (SSFUTF8IsValid(data, size, false) != (walked && !sawNul)) abort();
    count = (size_t)-1;
    if (SSFUTF8Count(data, size, &count) != walked) abort();
    if (walked && (count != steps)) abort();
    return 0;
}
