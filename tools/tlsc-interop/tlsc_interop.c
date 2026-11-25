/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* tlsc_interop.c                                                                                */
/* TLS client (ssftlsc) interop driver: one connection to HOST:PORT, then one exchange, and a    */
/* "result key=value ..." line for interop.py to check. Linux; built by run.sh against the unit- */
/* test build's objects (so the unauthenticated test opt-in exists).                            */
/*                                                                                               */
/*   tlsc_interop --host H --port P [--ca PEM]... [--unauth] [--alpn a,b] [--cert PEM --key PEM] */
/*                [--echo | --lines N | --serve-lines | --mqtt]                                  */
/*                                                                                               */
/*   --ca          PEM file(s) of trust anchors, joined and loaded with SSFTLSCTrustFromPEM()    */
/*   --unauth      no trust anchors; the server is NOT authenticated (test opt-in)               */
/*   --cert/--key  client certificate chain (PEM, leaf first) and key (SSFPKeyDecodePEM())      */
/*   --echo        send one 23-byte line, count the bytes echoed back (s_server -rev / --echo)   */
/*   --lines N     send N lines, count the replies (echoed or reversed)                         */
/*   --serve-lines answer each line received with "ack:<line>" until "END"                      */
/*   --mqtt        send an MQTT 3.1.1 CONNECT, expect CONNACK 20 02 00 00                        */
/*                                                                                               */
/* Result fields: tls suite group hrr alpn scheme chain trust echo lines replies mqtt sent rcvd */
/* verify emptycert kusent kurcvd hint (alerts: fatal descriptions; verify: chain error code;  */
/* hint: the client's explanation of a refused certificate, v1 / san / -).                       */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ssfport.h"
#include "ssfnetsock.h"
#include "ssftlsc.h"
#include "ssfpkey.h"
#include "ssfrtc.h"

static SSFNetSock_t _sock;
static SSFTLSCSession_t _tls;

/* What the client's trace reported */
static int _innerOpenFailed;
static unsigned _group, _hrr, _sent, _rcvd, _verify, _emptyCert, _kuSent, _kuRcvd;
static const char *_hint = "-";

static void _Trace(SSFTLSTraceLevel_t lv, SSFTLSTraceCategory_t c, const char *m, void *u)
{
    unsigned a, b;

    (void)c; (void)u;
    if (strstr(m, "Inner transport open failed") != NULL) _innerOpenFailed = 1;
    if (strstr(m, "HelloRetryRequest received") != NULL) _hrr = 1;
    if ((sscanf(m, "ServerHello: suite=0x%x group=0x%x", &a, &b) == 2) ||
        (sscanf(m, "ServerHello after HRR: suite=0x%x group=0x%x", &a, &b) == 2)) _group = b;
    if (sscanf(m, "Sending alert level=2 desc=%u", &a) == 1) _sent = a;
    if (sscanf(m, "RecvRecord: ALERT level=2 desc=%u", &a) == 1) _rcvd = a;
    if (sscanf(m, "Certificate chain verification failed: code %u", &a) == 1) _verify = a;
    if (strstr(m, "empty Certificate") != NULL) _emptyCert = 1;
    if (strstr(m, "X.509 v1") != NULL) _hint = "v1";                 /* The trace's explanation */
    if (strstr(m, "no subjectAltName names the host") != NULL) _hint = "san";
    if (strncmp(m, "KeyUpdate sent", 14) == 0) _kuSent++;
    if (strncmp(m, "KeyUpdate received", 18) == 0) _kuRcvd++;
    if ((getenv("TLSC_INTEROP_TRACE") != NULL) && (lv <= SSF_TLS_TRACE_WARN)) printf("  trace: %s\n", m);
}

/* Appends file path's contents to *buf (grown with realloc). */
static int _Append(char **buf, size_t *len, const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;

    if (f == NULL) return 0;
    fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
    *buf = realloc(*buf, *len + (size_t)n + 1u);
    *len += fread(&(*buf)[*len], 1, (size_t)n, f);
    fclose(f);
    return 1;
}

/* Sends all of data within 10 s. */
static int _SendAll(SSFNetTransport_t *t, const void *data, size_t len)
{
    size_t off = 0, n;
    SSFPortTick_t end = SSFPortGetTick64() + 10000u;

    while (off < len)
    {
        SSFNetIOResult_t r = t->send(t, (const uint8_t *)data + off, len - off, &n);
        if (r == SSF_NET_IO_SUCCESS) off += n; else if (r != SSF_NET_IO_WANT_WRITE) return 0;
        if (SSFPortGetTick64() > end) return 0;
    }
    return 1;
}

/* Receives one '\n'-terminated line (1), or nothing before ms (0), or the end (-1). */
static int _RecvLine(SSFNetTransport_t *t, char *line, size_t size, unsigned ms)
{
    size_t n = 0;
    SSFPortTick_t end = SSFPortGetTick64() + ms;

    while (SSFPortGetTick64() < end)
    {
        size_t g = 0;
        SSFNetIOResult_t r = t->recv(t, (uint8_t *)&line[n], 1, &g);
        if (r == SSF_NET_IO_SUCCESS)
        {
            n += g;
            if ((line[n - 1u] == '\n') || ((n + 1u) >= size)) { line[n] = 0; return 1; }
        }
        else if (r != SSF_NET_IO_WANT_READ) return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *host = "localhost", *alpn = NULL, *certPath = NULL, *keyPath = NULL;
    const char *mode = "none";
    uint16_t port = 0;
    int unauth = 0, i, tries, nLines = 0, lines = 0, replies = 0, mqtt = 0;
    char *caPem = NULL;
    size_t caLen = 0, echo = 0;
    static const char *protos[8];
    static char alpnBuf[256];
    uint8_t nProtos = 0;
    static uint8_t caPool[256 * 1024];
    static const uint8_t *caDers[255];
    static uint32_t caLens[255];
    static SSFTLSCTrustStore_t trust;
    static uint8_t certPool[16384];
    static const uint8_t *chainDers[4];
    static uint32_t chainLens[4];
    static SSFTLSCTrustStore_t chain;
    static uint8_t keyDer[4096];
    static SSFPKey_t key;
    size_t used;
    uint8_t trustCount = 0, chainCount = 0;
    SSFNetTransport_t *t = &_tls.transport;
    SSFNetIOResult_t r = SSF_NET_IO_ERROR;
    SSFPortTick_t end;
    const char *chosen;

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "--host") == 0) && (i + 1 < argc)) host = argv[++i];
        else if ((strcmp(argv[i], "--port") == 0) && (i + 1 < argc)) port = (uint16_t)atoi(argv[++i]);
        else if ((strcmp(argv[i], "--ca") == 0) && (i + 1 < argc))
        { if (!_Append(&caPem, &caLen, argv[++i])) { printf("result error=ca-unreadable\n"); return 3; } }
        else if (strcmp(argv[i], "--unauth") == 0) unauth = 1;
        else if ((strcmp(argv[i], "--alpn") == 0) && (i + 1 < argc)) alpn = argv[++i];
        else if ((strcmp(argv[i], "--cert") == 0) && (i + 1 < argc)) certPath = argv[++i];
        else if ((strcmp(argv[i], "--key") == 0) && (i + 1 < argc)) keyPath = argv[++i];
        else if ((strcmp(argv[i], "--lines") == 0) && (i + 1 < argc)) { mode = "lines"; nLines = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--echo") == 0) mode = "echo";
        else if (strcmp(argv[i], "--serve-lines") == 0) mode = "serve";
        else if (strcmp(argv[i], "--mqtt") == 0) mode = "mqtt";
        else { printf("result error=usage:%s\n", argv[i]); return 3; }
    }

    SSFRTCInit();
    SSFRTCSet((uint64_t)time(NULL));
    SSFNetSockInit(&_sock);
    if (caPem != NULL)
    {
        if (SSFTLSCTrustFromPEM(caPem, caLen, caPool, sizeof(caPool), caDers, caLens,
                                (uint8_t)(sizeof(caDers) / sizeof(caDers[0])), &trust, &used,
                                &trustCount) != SSF_TLSC_TRUST_OK)
        { printf("result error=trust-load\n"); return 3; }
    }
    SSFTLSCInit(&_tls, &_sock.transport, (caPem != NULL) ? &trust : NULL);
    SSFTLSCSetTrace(&_tls, _Trace, NULL);
    if (unauth) SSFTLSCSetUnauthenticated(&_tls, true);
    if (alpn != NULL)
    {
        char *p;

        snprintf(alpnBuf, sizeof(alpnBuf), "%s", alpn);
        for (p = strtok(alpnBuf, ","); (p != NULL) && (nProtos < 8u); p = strtok(NULL, ",")) protos[nProtos++] = p;
        if (!SSFTLSCSetALPN(&_tls, protos, nProtos)) { printf("result error=alpn\n"); return 3; }
    }
    if (certPath != NULL)
    {
        char *cp = NULL, *kp = NULL;
        size_t cl = 0, kl = 0;

        if (!_Append(&cp, &cl, certPath) || !_Append(&kp, &kl, keyPath))
        { printf("result error=cert-unreadable\n"); return 3; }
        /* The client chain's DER, decoded with the PEM bundle loader */
        if (SSFTLSCTrustFromPEM(cp, cl, certPool, sizeof(certPool), chainDers, chainLens, 4u, &chain,
                                &used, &chainCount) != SSF_TLSC_TRUST_OK)
        { printf("result error=cert-pem\n"); return 3; }
        if (!SSFPKeyDecodePEM(kp, kl, keyDer, sizeof(keyDer), &key)) { printf("result error=key-pem\n"); return 3; }
        if (!SSFTLSCSetClientCert(&_tls, (const uint8_t *const *)chainDers, chainLens, chainCount, &key))
        { printf("result error=setclientcert\n"); return 3; }
    }

    /* Connect; the server may still be starting: retry while the inner open is refused */
    for (tries = 0; tries < 30; tries++)
    {
        if (!t->open(t, host, strlen(host) + 1u, port)) { printf("result error=open\n"); return 1; }
        end = SSFPortGetTick64() + 20000u;
        do r = t->pollOpen(t);
        while (((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) && (SSFPortGetTick64() < end));
        if (!_innerOpenFailed) break;
        _innerOpenFailed = 0; _hrr = 0; _group = 0;
        t->close(t);
        { struct timespec ts = { 0, 100000000 }; nanosleep(&ts, NULL); }
    }

    if (r == SSF_NET_IO_SUCCESS)
    {
        char line[512];

        if (strcmp(mode, "echo") == 0)
        {
            static const char msg[] = "matrix-ping-0123456789\n";
            uint8_t buf[64];

            if (_SendAll(t, msg, sizeof(msg) - 1u))
            {
                end = SSFPortGetTick64() + 5000u;
                while ((echo < (sizeof(msg) - 1u)) && (SSFPortGetTick64() < end))
                {
                    size_t g = 0;
                    SSFNetIOResult_t rr = t->recv(t, buf, sizeof(buf), &g);
                    if (rr == SSF_NET_IO_SUCCESS) echo += g; else if (rr != SSF_NET_IO_WANT_READ) break;
                }
            }
        }
        else if (strcmp(mode, "lines") == 0)
        {
            for (i = 0; i < nLines; i++)
            {
                char msg[64], want[64];
                size_t n, j;

                snprintf(msg, sizeof(msg), "message-%03d\n", i);
                if (!_SendAll(t, msg, strlen(msg)) || (_RecvLine(t, line, sizeof(line), 5000u) <= 0)) break;
                n = strlen(msg) - 1u;
                for (j = 0; j < n; j++) want[j] = msg[n - 1u - j];
                want[n] = '\n'; want[n + 1u] = 0;
                if ((strcmp(line, msg) == 0) || (strcmp(line, want) == 0)) replies++; else break;
            }
        }
        else if (strcmp(mode, "serve") == 0)
        {
            while (_RecvLine(t, line, sizeof(line), 15000u) > 0)
            {
                char ack[600];

                lines++;
                if (strncmp(line, "END", 3) == 0) break;
                snprintf(ack, sizeof(ack), "ack:%s", line);
                if (!_SendAll(t, ack, strlen(ack))) break;
            }
        }
        else if (strcmp(mode, "mqtt") == 0)
        {
            static const uint8_t connect[] = { 0x10, 0x1c, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00,
                                               0x3c, 0x00, 0x10, 's', 's', 'f', '-', 't', 'l', 's', 'c', '-',
                                               'i', 'n', 't', 'e', 'r', 'o', 'p' };
            uint8_t buf[64];
            size_t got = 0;

            if (_SendAll(t, connect, sizeof(connect)))
            {
                end = SSFPortGetTick64() + 10000u;
                while ((got < 4u) && (SSFPortGetTick64() < end))
                {
                    size_t g = 0;
                    SSFNetIOResult_t rr = t->recv(t, &buf[got], sizeof(buf) - got, &g);
                    if (rr == SSF_NET_IO_SUCCESS) got += g; else if (rr != SSF_NET_IO_WANT_READ) break;
                }
            }
            mqtt = (got >= 4u) && (buf[0] == 0x20) && (buf[1] == 0x02) && (buf[3] == 0x00);
        }
    }

    chosen = (r == SSF_NET_IO_SUCCESS) ? SSFTLSCGetALPN(&_tls) : NULL;
    printf("result tls=%d suite=0x%04x group=0x%04x hrr=%u alpn=%s scheme=0x%04x chain=%u trust=%u echo=%zu "
           "lines=%d replies=%d mqtt=%d sent=%u rcvd=%u verify=%u emptycert=%u kusent=%u kurcvd=%u hint=%s\n",
           r == SSF_NET_IO_SUCCESS, (r == SSF_NET_IO_SUCCESS) ? _tls.cipherSuite : 0u, _group, _hrr,
           (chosen != NULL) ? chosen : "-", _tls.clientScheme, chainCount, trustCount, echo, lines, replies,
           mqtt, _sent, _rcvd, _verify, _emptyCert, _kuSent, _kuRcvd, _hint);
    if (r == SSF_NET_IO_SUCCESS) (void)t->shutdown(t);
    t->close(t);
    SSFTLSCDeInit(&_tls);
    SSFNetSockDeInit(&_sock);
    free(caPem);
    return 0;
}
