# Codecs

[Back to ssf README](../README.md)

Encoding and decoding interfaces.

## Base64 Encoder/Decoder Interface

This interface allows you to encode a binary data stream into a Base64 string, or do the reverse.

```
char encodedStr[16];
char decodedBin[16];
uint8_t binOut[2];
size_t binLen;

/* Encode arbitrary binary data */
if (SSFBase64Encode("a", 1, encodedStr, sizeof(encodedStr), NULL))
{
    /* Encode successful */
    printf("%s", encodedStr);
    /* output is "YQ==" */
}

/* Decode Base64 string into binary data */
if (SSFBase64Decode(encodedStr, strlen(encodedStr), decodedBin, sizeof(decodedBin), &binLen))
{
    /* Decode successful */
    /* binLen == 1 */
    /* decodedBin[0] == 'a' */
}
```

## Binary to Hex ASCII Encoder/Decoder Interface

This interface allows you to encode a binary data stream into an ASCII hexadecimal string, or do the reverse.

```
uint8_t binOut[2];
char strOut[5];
size_t binLen;

if (SSFHexBytesToBin("A1F5", 4, binOut, sizeof(binOut), &binLen, false))
{
    /* Encode successful */
    /* binLen == 2 */
    /* binOut[0] = '\xA1' */
    /* binOut[1] = '\xF5' */
}

if (SSFHexBinToBytes(binOut, binLen, strOut, sizeof(strOut), NULL, false, SSF_HEX_CASE_LOWER))
{
  /* Decode in reverse successful */
  printf("%s", strOut);
  /* prints "a1f5" */
}
```

Another convienience feature is the API allows reversal of the byte ordering either for encoding or decoding.

## JSON Parser/Generator Interface

Having searched for and used many JSON parser/generators on small embedded platforms I never found exactly the right mix of attributes. The mjson project came the closest on the parser side, but relied on varargs for the generator, which provides a potential breeding ground for bugs.

Like mjson (a SAX-like parser) this parser operates on the JSON string in place and only consumes modest stack in proportion to the maximum nesting depth. Since the JSON string is parsed from the start each time a data element is accessed it is computationally inefficient; that's ok since most embedded systems are RAM constrained not performance constrained.

On the generator side it does away with varargs and opts for an interface that can be verified at compilation time to be called correctly.

Here are some simple parser examples:

```
char json1Str[] = "{\"name\":\"value\"}";
char json2Str[] = "{\"obj\":{\"name\":\"value\",\"array\":[1,2,3]}}";
char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
char strOut[32];
size_t idx;

/* Must zero out path variable before use */
memset(path, 0, sizeof(path));

/* Get the value of a top level element */
path[0] = "name";
if (SSFJsonGetString(json1Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" excluding double quotes */
}

/* Get the value of a nested element */
path[0] = "obj";
path[1] = "name";
if (SSFJsonGetString(json2Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" excluding double quotes */
}

path[0] = "obj";
path[1] = "array";
path[2] = (char *)&idx;
/* Iterate over a nested array */
for (idx = 0;;idx++)
{
    long si;

    if (SSFJsonGetLong(json2Str, (SSFCStrIn_t *)path, &si))
    {
        if (i != 0) print(", ");
        printf("%ld", si);
    }
    else break;
}
/* Prints "1, 2, 3" */
```

Here is a simple generation example:

```
bool printFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;

    if (!SSFJsonPrintLabel(js, size, start, &start, "label1", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value1", NULL)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "label2", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value2", NULL)) return false;

    *end = start;
    return true;
}
...

char jsonStr[128];
size_t end;

/* JSON is contained within an object {}, so to create a JSON string call SSFJsonPrintObject() */
if (SSFJsonPrintObject(jsonStr, sizeof(jsonStr), 0, &end, printFn, NULL, NULL))
{
    /* jsonStr == "{\"name1\":\"value1\",\"name2\":\"value2\"}" */
}
```

Object and array nesting is achieved by calling SSFJsonPrintObject() or SSFJsonPrintArray() from within a printer function.

There is also an interface, SSFJsonUpdate(), for updating a JSON object with a new value or element.

## TLV Encoder/Decoder Interface

The TLV interface encodes and decodes data into tag, length, value data streams. TLV is a compact alternative to JSON when the size of the data matters, such as when using a metered data connection or sending data over a bandwidth constrained wireless connection.

For small data sets the interface can be compiled in fixed mode that limits the maximum number of tags to 256 and the length of each field to 255 bytes. For larger data sets the variable mode independently uses the 2 most significant bits to encode the byte size of the tag and length fields so they are 1 to 4 bytes in length. This allows many more tags and larger values to be encoded while still maintaining a compact encoding.

For initialization, a user supplied buffer is passed in. If the buffer already has TLV data then the total length of the TLV can be set as well.
When encoding the same tag can be used multiple times. On decode the interface allow simple iteration over all of the duplicate tags.
The decode interface allows a value to be copied to a user supplied buffer, or it can simply pass back the a pointer and length of the value within the TLV data.

```
#define TAG_NAME 1
#define TAG_HOBBY 2

SSFTLV_t tlv;
uint8_t buf[100];

SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_NAME, "Jimmy", 5);
SSFTLVPut(&tlv, TAG_HOBBY, "Coding", 6);
/* tlv.bufLen is the total length of the TLV data encoded */

... Transmit tlv.bufLen bytes of tlv.buf to another system ...

#define TAG_NAME 1
#define TAG_HOBBY 2

SSFTLV_t tlv;
uint8_t rxbuf[100];
uint8_t val[100];
SSFTLVVar_t valLen;
uint8_t *valPtr;

/* rxbuf contains rxlen bytes of received data */
SSFTLVInit(&tlv, rxbuf, sizeof(rxbuf), rxlen);

SSFTLVGet(&tlv, TAG_NAME, 0, val, sizeof(val), &valLen);
/* val == "Jimmy", valLen == 5 */

SSFTLVGet(&tlv, TAG_HOBBY, 0, val, sizeof(val), &valLen);
/* val == "Coding", valLen == 6 */

SSFTLVFind(&tlv, TAG_NAME, 0, &valPtr,  &valLen);
/* valPtr == "Jimmy", valLen == 5 */
```

## INI Parser/Generator Interface

Sad that we still need this, but we still sometimes need to parse and generate INI files. Natively supports string, boolean, and long int types. The parser is forgiving and the main limitation is that it does not support quoted strings, so values cannot have whitespace.

```
    char iniParse[] = "; comment\r\nname=value1\r\n[section]\r\nname=yes\r\nname=0\r\nfoo=bar\r\nX=\r\n";
    char outStr[16];
    bool outBool;
    long int outLong;
    char iniGen[256];
    size_t iniGenLen;

    /* Parse */
    SSFINIIsSectionPresent(iniParse, "section"); /* Returns true */
    SSFINIIsSectionPresent(iniParse, "Section"); /* Returns false */

    SSFIsNameValuePresent(iniParse, NULL, "name", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, NULL, "name", 1); /* Returns false */
    SSFIsNameValuePresent(iniParse, "section", "name", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "name", 1); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "name", 2); /* Returns false */
    SSFIsNameValuePresent(iniParse, "section", "foo", 0); /* Returns true */
    SSFIsNameValuePresent(iniParse, "section", "X", 0); /* Returns true */

    SSFINIGetStrValue(iniParse, "section", name, 1, outStr, sizeof(outStr), NULL); /* Returns true, outStr = "0" */
    SSFINIGetBoolValue(iniParse, "section", name, 1, &outBool); /* Returns true, outBool = false */
    SSFINIGetLongValue(iniParse, "section", name, 1, &outLong); /* Returns true, outLong = 0 */

    /* Generate */
    iniGenLen = 0;
    SSFINIPrintComment(iniGen, sizeof(iniGen), &iniGenLen, " comment", SSF_INI_COMMENT_HASH, SSF_INI_CRLF);
    SSFINIPrintSection(iniGen, sizeof(iniGen), &iniGenLen, "section", SSF_INI_CRLF);
    SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "strName", "value", SSF_INI_CRLF);
    SSFINIPrintNameBoolValue(iniGen, sizeof(iniGen), &iniGenLen, "boolName", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF);
    SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "longName", -1234567890l, SSF_INI_CRLF);

    /* iniGen = "# comment\r\n[section]\r\nstrName=value\r\nboolName=yes\r\nlongName=-1234567890\r\n" */
```

## Universal Binary JSON (UBJSON) Parser/Generator Interface

The UBJSON specification can be found at https://ubjson.org/.

It does appear that work on the specification has stalled, which is unfortunate since a lighter weight JSON encoding that is 1:1 compatible with JSON data types is a great idea.

This parser operates on the UBJSON message in place and only consumes modest stack in proportion to the maximum nesting depth. Since the UBJSON string is parsed from the start each time a data element is accessed it is computationally inefficient; that's ok since most embedded systems are RAM constrained not performance constrained.

Here are some simple parser examples:

```
    uint8_t ubjson1[] = "{i\x04nameSi\x05value}";
    size_t ubjson1Len = 16;
    uint8_t ubjson2[] = "{i\x03obj{i\x04nameSi\x05valuei\x05" "array[$i#i\x03" "123}}";
    size_t ubjson2Len = 39;
    char* path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
    char strOut[32];
    size_t idx;

    /* Must zero out path variable before use */
    memset(path, 0, sizeof(path));

    /* Get the value of a top level element */
    path[0] = "name";
    if (SSFUBJsonGetString(ubjson1, ubjson1Len, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
    {
        printf("%s\r\n", strOut);
        /* Prints "value" excluding double quotes */
    }

    /* Get the value of a nested element */
    path[0] = "obj";
    path[1] = "name";
    if (SSFUBJsonGetString(ubjson2, ubjson2Len, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
    {
        printf("%s\r\n", strOut);
        /* Prints "value" excluding double quotes */
    }

    path[0] = "obj";
    path[1] = "array";
    path[2] = (char*)&idx;
    /* Iterate over a nested array */
    for (idx = 0;; idx++)
    {
        int8_t si;

        if (SSFUBJsonGetInt8(ubjson2, ubjson2Len, (SSFCStrIn_t*)path, &si))
        {
            if (idx != 0) printf(", ");
            printf("%ld", si);
        }
        else break;
    }
    printf("\r\n");
    /* Prints "1, 2, 3" */
```

Here is a simple generation example:

```
bool printFn(uint8_t* js, size_t size, size_t start, size_t* end, void* in)
{
    SSF_ASSERT(in == NULL);

    if (!SSFUBJsonPrintLabel(js, size, start, &start, "label1")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "value1")) return false;
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "label2")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "value2")) return false;

    *end = start;
    return true;
}

...

    uint8_t ubjson[128];
    size_t end;

    /* JSON is contained within an object {}, so to create a JSON string call SSFJsonPrintObject() */
    if (SSFUBJsonPrintObject(ubjson, sizeof(ubjson), 0, &end, printFn, NULL))
    {
        /* ubjson == "{U\x06label1SU\x06value1U\x06label2SU\x06value2}", end == 36 */
        memset(path, 0, sizeof(path));
        path[0] = "label2";
        if (SSFUBJsonGetString(ubjson, end, (SSFCStrIn_t*)path, strOut, sizeof(strOut), NULL))
        {
            printf("%s\r\n", strOut);
            /* Prints "value2" excluding double quotes */
        }
    }
```

Object and array nesting is achieved by calling SSFUBJsonPrintObject() or SSFUBJsonPrintArray() from within a printer function.

Parsing and generation of optimized integer arrays is supported.

## Integer to Decimal String Interface

This interface converts signed or unsigned integers to padded or unpadded decimal strings. It is meant to be faster and have stronger typing than snprintf().

```
    size_t len;
    char str[]

    len = SSFDecIntToStr(-123456789123ull, str, sizeof(str));
    /* len == 13, str = "-123456789123" */

    len = SSFDecIntToStrPadded(-123456789123ull, str, sizeof(str), 15, '0');
    /* len == 15, str = "-00123456789123" */
```

## Safe C String Interface

This interface provides true safe replacements for strcpy(), strcat(), strcpy(), strcmp(), and related "safe" strn() calls that don't always NULL terminate.

```
    size_t len;
    char str[10];

    /* Copy 10 byte string into str var? */
    if (SSFStrCpy(str, sizeof(str), &len, "1234567890", 11)) == false)
    {
        /* No, copy failed because str is not big enough to hold new string plus NULL terminator */
    }

    /* Copy 9 byte string into str var? */
    if (SSFStrCpy(str, sizeof(str), &len, "123456789", 10)) == true)
    {
        /* Yes copy worked, str="123456789", len = 9 */
    }
```

## Generic Object Parser/Generator Interface

Note: This is in BETA and is still under development.

This interface allows a generic hierarchical object structure to be generated and parsed. It is meant to be a representation that can easily translate between other encoding types like JSON and UBJSON, and it is more flexible when modifications to data elements is desired.
