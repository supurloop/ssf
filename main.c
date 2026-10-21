/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* main.c                                                                                        */
/* Entry point for unit testing SSF components.                                                  */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#if defined(_WIN32)
#include <crtdbg.h>
#else /* _WIN32 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif /* _WIN32 */
#include "ssfassert.h"
#include "ssfversion.h"
#include "ssfbfifo.h"
#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfsll.h"
#include "ssfport.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"
#include "ssffcsum.h"
#include "ssfrs.h"
#include "ssfcrc16.h"
#include "ssfcrc32.h"
#include "ssfsha1.h"
#include "ssfsha2.h"
#include "ssfbn.h"
#include "ssfchacha20.h"
#include "ssfpoly1305.h"
#include "ssfx25519.h"
#include "ssfed25519.h"
#include "ssfaesccm.h"
#include "ssfaesctr.h"
#include "ssfcrypt.h"
#include "ssfhmac.h"
#include "ssfchacha20poly1305.h"
#include "ssfec.h"
#include "ssfhkdf.h"
#include "ssfecdsa.h"
#include "ssfrsa.h"
#include "ssftls.h"
#include "ssftlv.h"
#include "ssfaes.h"
#include "ssfaesgcm.h"
#include "ssfcfg.h"
#include "ssfprng.h"
#include "ssfini.h"
#include "ssfubjson.h"
#include "ssfasn1.h"
#include "ssfdtime.h"
#include "ssfrtc.h"
#include "ssfiso8601.h"
#include "ssfdec.h"
#include "ssfstr.h"
#include "ssfheap.h"
#include "ssfgobj.h"
#include "ssftrace.h"
#include "ssfargv.h"
#include "ssfvted.h"
#include "ssfcli.h"
#include "ssflptask.h"

typedef struct
{
    char *module;
    char *description;
    void (*utf)(void);
} SSFUnitTest_t;

SSFUnitTest_t unitTests[] =
{
    /* _crypto */
#if SSF_CONFIG_BN_UNIT_TEST == 1
    { "ssfbn", "Big Number Arithmetic", SSFBNUnitTest },
#endif /* SSF_CONFIG_BN_UNIT_TEST */
#if SSF_CONFIG_AES_UNIT_TEST == 1
    { "ssfaes", "AES128-256 Block", SSFAESUnitTest },
#endif /* SSF_CONFIG_AES_UNIT_TEST */
#if SSF_CONFIG_AESGCM_UNIT_TEST == 1
    { "ssfaesgcm", "AES-GCM Authenticated Cipher", SSFAESGCMUnitTest },
#endif /* SSF_CONFIG_AESGCM_UNIT_TEST */
#if SSF_CONFIG_PRNG_UNIT_TEST == 1
    { "ssfprng", "Crypto Secure Capable PRNG", SSFPRNGUnitTest },
#endif /* SSF_CONFIG_PRNG_UNIT_TEST */
#if SSF_CONFIG_SHA1_UNIT_TEST == 1
    { "ssfsha1", "SHA1 160-bit", SSFSHA1UnitTest },
#endif /* SSF_CONFIG_SHA1_UNIT_TEST */
#if SSF_CONFIG_SHA2_UNIT_TEST == 1
    { "ssfsha2", "SHA2 256-512-bits", SSFSHA2UnitTest },
#endif /* SSF_CONFIG_SHA2_UNIT_TEST */
#if SSF_CONFIG_CHACHA20_UNIT_TEST == 1
    { "ssfchacha20", "ChaCha20 Stream Cipher", SSFChaCha20UnitTest },
#endif /* SSF_CONFIG_CHACHA20_UNIT_TEST */
#if SSF_CONFIG_POLY1305_UNIT_TEST == 1
    { "ssfpoly1305", "Poly1305 MAC", SSFPoly1305UnitTest },
#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */
#if SSF_CONFIG_X25519_UNIT_TEST == 1
    { "ssfx25519", "X25519 Key Exchange", SSFX25519UnitTest },
#endif /* SSF_CONFIG_X25519_UNIT_TEST */
#if SSF_CONFIG_ED25519_UNIT_TEST == 1
    { "ssfed25519", "Ed25519 Sign/Verify", SSFEd25519UnitTest },
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */
#if SSF_CONFIG_AESCCM_UNIT_TEST == 1
    { "ssfaesccm", "AES-CCM Authenticated Cipher", SSFAESCCMUnitTest },
#endif /* SSF_CONFIG_AESCCM_UNIT_TEST */
#if SSF_CONFIG_AESCTR_UNIT_TEST == 1
    { "ssfaesctr", "AES-CTR Stream Cipher", SSFAESCTRUnitTest },
#endif /* SSF_CONFIG_AESCTR_UNIT_TEST */
#if SSF_CONFIG_CRYPT_UNIT_TEST == 1
    { "ssfcrypt", "Cryptographic Helpers", SSFCryptUnitTest },
#endif /* SSF_CONFIG_CRYPT_UNIT_TEST */
#if SSF_CONFIG_HMAC_UNIT_TEST == 1
    { "ssfhmac", "HMAC Authentication Code", SSFHMACUnitTest },
#endif /* SSF_CONFIG_HMAC_UNIT_TEST */
#if SSF_CONFIG_CCP_UNIT_TEST == 1
    { "ssfchacha20poly1305", "ChaCha20-Poly1305 AEAD", SSFChaCha20Poly1305UnitTest },
#endif /* SSF_CONFIG_CCP_UNIT_TEST */
#if SSF_CONFIG_EC_UNIT_TEST == 1
    { "ssfec", "Elliptic Curve Points", SSFECUnitTest },
#endif /* SSF_CONFIG_EC_UNIT_TEST */
#if SSF_CONFIG_HKDF_UNIT_TEST == 1
    { "ssfhkdf", "HKDF Key Derivation", SSFHKDFUnitTest },
#endif /* SSF_CONFIG_HKDF_UNIT_TEST */
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    { "ssfecdsa", "ECDSA/ECDH", SSFECDSAUnitTest },
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */
#if SSF_CONFIG_RSA_UNIT_TEST == 1
    { "ssfrsa", "RSA Sign/Verify", SSFRSAUnitTest },
#endif /* SSF_CONFIG_RSA_UNIT_TEST */
#if SSF_CONFIG_TLS_UNIT_TEST == 1
    { "ssftls", "TLS 1.3 Core", SSFTLSUnitTest },
#endif /* SSF_CONFIG_TLS_UNIT_TEST */

    /* _ui */
#if SSF_CONFIG_ARGV_UNIT_TEST == 1
    { "ssfargv", "Command Line Argv Parser", SSFArgvUnitTest },
#endif /* SSF_CONFIG_ARGV_UNIT_TEST */
#if SSF_CONFIG_CLI_UNIT_TEST == 1
    { "ssfcli", "CLI Framework", SSFCLIUnitTest },
#endif /* SSF_CONFIG_CLI_UNIT_TEST */
#if SSF_CONFIG_VTED_UNIT_TEST == 1
    { "ssfvted", "VT100 Terminal Line Editor", SSFVTEdUnitTest },
#endif /* SSF_CONFIG_VTED_UNIT_TEST */

    /* _debug */
#if SSF_CONFIG_TRACE_UNIT_TEST == 1
    { "ssftrace", "Debug Trace", SSFTraceUnitTest },
#endif /* SSF_CONFIG_TRACE_UNIT_TEST */

    /* _codec */
#if SSF_CONFIG_BASE64_UNIT_TEST == 1
    { "ssfbase64", "Base64 Codec", SSFBase64UnitTest },
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */
#if SSF_CONFIG_DEC_UNIT_TEST == 1
    { "ssfdec", "Decimal String Codec", SSFDecUnitTest },
#endif /* SSF_CONFIG_DEC_UNIT_TEST */
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
    { "ssfgobj", "Generic Object Codec", SSFGObjUnitTest },
#endif /* SSF_CONFIG_GOBJ_UNIT_TEST */
#if SSF_CONFIG_HEX_UNIT_TEST == 1
    { "ssfhex", "Hex String Codec", SSFHexUnitTest },
#endif /* SSF_CONFIG_HEX_UNIT_TEST */
#if SSF_CONFIG_INI_UNIT_TEST == 1
    { "ssfini", "INI Codec", SSFINIUnitTest },
#endif /* SSF_CONFIG_INI_UNIT_TEST */
#if SSF_CONFIG_JSON_UNIT_TEST == 1
    { "ssfjson", "JSON Codec", SSFJsonUnitTest },
#endif /* SSF_CONFIG_JSON_UNIT_TEST */
#if SSF_CONFIG_STR_UNIT_TEST == 1
    { "ssfstr", "Safe C Strings", SSFStrUnitTest },
#endif /* SSF_CONFIG_STR_UNIT_TEST */
#if SSF_CONFIG_TLV_UNIT_TEST == 1
    { "ssftlv", "Tag/Length/Value Codec", SSFTLVUnitTest },
#endif /* SSF_CONFIG_TLV_UNIT_TEST */
#if SSF_CONFIG_UBJSON_UNIT_TEST == 1
    { "ssfubjson", "Universal Binary JSON Codec", SSFUBJsonUnitTest },
#endif /* SSF_CONFIG_UBJSON_UNIT_TEST */
#if SSF_CONFIG_ASN1_UNIT_TEST == 1
    { "ssfasn1", "ASN.1 DER Codec", SSFASN1UnitTest },
#endif /* SSF_CONFIG_ASN1_UNIT_TEST */

    /* _ecc */
#if SSF_CONFIG_RS_UNIT_TEST == 1
    { "ssfrs", "Reed Solomon ECC", SSFRSUnitTest },
#endif /* SSF_CONFIG_RS_UNIT_TEST */

    /* _edc */
#if SSF_CONFIG_CRC16_UNIT_TEST == 1
    { "ssfcrc16", "16-bit XMODEM/CCITT-16", SSFCRC16UnitTest },
#endif /* SSF_CONFIG_CRC16_UNIT_TEST */
#if SSF_CONFIG_CRC32_UNIT_TEST == 1
    { "ssfcrc32", "32-bit CCITT-32", SSFCRC32UnitTest },
#endif /* SSF_CONFIG_CRC32_UNIT_TEST */
#if SSF_CONFIG_FCSUM_UNIT_TEST == 1
    { "ssffcsum", "Fletcher's Checksum", SSFFCSumUnitTest },
#endif /* SSF_CONFIG_FCSUM_UNIT_TEST */

    /* _fsm */
#if SSF_CONFIG_SM_UNIT_TEST == 1
    { "ssfsm", "Finite State Machine", SSFSMUnitTest },
#endif /* SSF_CONFIG_SM_UNIT_TEST */

    /* _storage */
#if SSF_CONFIG_CFG_UNIT_TEST == 1
    { "ssfcfg", "Read/Write NV Config", SSFCfgUnitTest },
#endif /* SSF_CONFIG_CFG_UNIT_TEST */

    /* _struct */
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
    { "ssfbfifo", "Byte FIFO", SSFBFifoUnitTest },
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */
#if SSF_CONFIG_HEAP_UNIT_TEST == 1
    { "ssfheap", "Integrity Checked Heap", SSFHeapUnitTest },
#endif /* SSF_CONFIG_HEAP_UNIT_TEST */
#if SSF_CONFIG_LL_UNIT_TEST == 1
    { "ssfll", "Linked List", SSFLLUnitTest },
#endif /* SSF_CONFIG_LL_UNIT_TEST */
#if SSF_CONFIG_MPOOL_UNIT_TEST == 1
    { "ssfmpool", "Memory Pool", SSFMPoolUnitTest },
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */
#if SSF_CONFIG_SLL_UNIT_TEST == 1
    { "ssfsll", "Sorted Linked List", SSFSLLUnitTest },
#endif /* SSF_CONFIG_SLL_UNIT_TEST */

    /* _time */
#if SSF_CONFIG_DTIME_UNIT_TEST == 1
    { "ssfdtime", "Date Time", SSFDTimeUnitTest },
#endif /* SSF_CONFIG_DTIME_UNIT_TEST */
#if SSF_CONFIG_ISO8601_UNIT_TEST == 1
    { "ssfiso8601", "ISO8601 Time", SSFISO8601UnitTest },
#endif /* SSF_CONFIG_ISO8601_UNIT_TEST */
#if SSF_CONFIG_RTC_UNIT_TEST == 1
    { "ssfrtc", "RTC", SSFRTCUnitTest },
#endif /* SSF_CONFIG_RTC_UNIT_TEST */

    /* _osal */
#if SSF_CONFIG_LPTASK_UNIT_TEST == 1
    { "ssflptask", "Low-Priority Task Queue", SSFLPTaskUnitTest },
#endif /* SSF_CONFIG_LPTASK_UNIT_TEST */
};

#if !defined(_WIN32)
/* Cap on concurrent worker processes regardless of host core count. */
#define SSF_PARALLEL_MAX_WORKERS 64

typedef struct
{
    pid_t pid;
    int fd;
    size_t idx;
    SSFPortTick_t start;
    char *buf;
    size_t bufLen;
    size_t bufCap;
    bool inUse;
    bool eof;
} SSFTestRun_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns count of online CPUs clamped to [1, SSF_PARALLEL_MAX_WORKERS].                        */
/* --------------------------------------------------------------------------------------------- */
static int SSFCoreCount(void)
{
    long n;

    n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > SSF_PARALLEL_MAX_WORKERS) n = SSF_PARALLEL_MAX_WORKERS;
    return (int)n;
}

/* --------------------------------------------------------------------------------------------- */
/* Forks a child to run unitTests[idx] with stdout/stderr captured. Returns true if started.     */
/* --------------------------------------------------------------------------------------------- */
static bool SSFStartRun(SSFTestRun_t *run, size_t idx)
{
    int pipeFd[2];
    pid_t pid;
    int flags;

    SSF_REQUIRE(run != NULL);
    SSF_REQUIRE(idx < sizeof(unitTests) / sizeof(SSFUnitTest_t));

    /* Drain parent stdio buffers so the forked child does not replay them. */
    (void)fflush(stdout);
    (void)fflush(stderr);

    if (pipe(pipeFd) != 0) return false;
    pid = fork();
    if (pid < 0) { (void)close(pipeFd[0]); (void)close(pipeFd[1]); return false; }
    if (pid == 0)
    {
        (void)close(pipeFd[0]);
        (void)dup2(pipeFd[1], STDOUT_FILENO);
        (void)dup2(pipeFd[1], STDERR_FILENO);
        (void)close(pipeFd[1]);
        unitTests[idx].utf();
        (void)fflush(stdout);
        (void)fflush(stderr);
#if defined(SSF_COVERAGE)
        /* Run atexit handlers so libgcov flushes counters to .gcda; the worker  */
        /* registers no other atexit hooks, so exit() and _exit() differ only in */
        /* this flush.                                                           */
        exit(0);
#else
        _exit(0);
#endif
    }
    (void)close(pipeFd[1]);
    flags = fcntl(pipeFd[0], F_GETFL, 0);
    if (flags >= 0) (void)fcntl(pipeFd[0], F_SETFL, flags | O_NONBLOCK);

    run->pid = pid;
    run->fd = pipeFd[0];
    run->idx = idx;
    run->start = SSFPortGetTick64();
    run->buf = NULL;
    run->bufLen = 0;
    run->bufCap = 0;
    run->inUse = true;
    run->eof = false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Drains all available bytes from run->fd into run->buf, sets run->eof on remote close.         */
/* --------------------------------------------------------------------------------------------- */
static void SSFDrainRun(SSFTestRun_t *run)
{
    char tmp[4096];
    ssize_t n;
    size_t newCap;
    char *p;

    SSF_REQUIRE(run != NULL);

    for (;;)
    {
        n = read(run->fd, tmp, sizeof(tmp));
        if (n > 0)
        {
            if (run->bufLen + (size_t)n + 1 > run->bufCap)
            {
                newCap = run->bufCap == 0 ? 8192 : run->bufCap * 2;
                while (newCap < run->bufLen + (size_t)n + 1) { newCap *= 2; }
                p = (char *)realloc(run->buf, newCap);
                SSF_ASSERT(p != NULL);
                run->buf = p;
                run->bufCap = newCap;
            }
            memcpy(run->buf + run->bufLen, tmp, (size_t)n);
            run->bufLen += (size_t)n;
            run->buf[run->bufLen] = '\0';
            continue;
        }
        if (n == 0) { run->eof = true; return; }
        if (errno == EINTR) continue;
        return;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Reaps the finished child, prints its result line and captured output. Returns true if passed.*/
/* --------------------------------------------------------------------------------------------- */
static bool SSFFinishRun(SSFTestRun_t *run)
{
    int status;
    SSFPortTick_t elapsed;
    bool passed;

    SSF_REQUIRE(run != NULL);
    SSF_REQUIRE(run->inUse);

    status = 0;
    (void)waitpid(run->pid, &status, 0);
    (void)close(run->fd);
    elapsed = (SSFPortGetTick64() - run->start) / SSF_TICKS_PER_SEC;
    passed = WIFEXITED(status) && (WEXITSTATUS(status) == 0);

    printf("Running %20s (%30s) unit test...%s in %llus\r\n",
           unitTests[run->idx].module, unitTests[run->idx].description,
           passed ? "PASSED" : "FAILED", (unsigned long long)elapsed);
    if (run->bufLen > 0) { (void)fwrite(run->buf, 1, run->bufLen, stdout); }
    (void)fflush(stdout);
    free(run->buf);
    memset(run, 0, sizeof(*run));
    return passed;
}

/* --------------------------------------------------------------------------------------------- */
/* SSF unit test entry point. Runs tests in parallel up to host core count.                      */
/* --------------------------------------------------------------------------------------------- */
int main(void)
{
    size_t total;
    size_t next;
    size_t done;
    int cores;
    bool allPassed;
    SSFTestRun_t *runs;
    struct pollfd *pfds;
    int i;
    int nPoll;
    int pr;
    int hdrLen;

    total = sizeof(unitTests) / sizeof(SSFUnitTest_t);
    next = 0;
    done = 0;
    cores = SSFCoreCount();
    if (total > 0 && (size_t)cores > total) cores = (int)total;
    if (cores < 1) cores = 1;
    allPassed = true;

    printf("\r\n");
    hdrLen = printf("Testing SSF Version %s (parallel x%d)", SSF_VERSION_STR, cores);
    SSF_ASSERT(hdrLen > 0);
    printf("\r\n");
    while (hdrLen--) { printf("-"); }
    printf("\r\n");

    if (total == 0) { printf("\r\n"); return 0; }

    runs = (SSFTestRun_t *)calloc((size_t)cores, sizeof(SSFTestRun_t));
    SSF_ASSERT(runs != NULL);
    pfds = (struct pollfd *)calloc((size_t)cores, sizeof(struct pollfd));
    SSF_ASSERT(pfds != NULL);

    while (done < total)
    {
        for (i = 0; i < cores && next < total; i++)
        {
            if (!runs[i].inUse)
            {
                if (!SSFStartRun(&runs[i], next)) SSF_ERROR();
                next++;
            }
        }
        nPoll = 0;
        for (i = 0; i < cores; i++)
        {
            if (runs[i].inUse && !runs[i].eof)
            {
                pfds[nPoll].fd = runs[i].fd;
                pfds[nPoll].events = POLLIN;
                pfds[nPoll].revents = 0;
                nPoll++;
            }
        }
        if (nPoll > 0)
        {
            do { pr = poll(pfds, (nfds_t)nPoll, 1000); } while (pr < 0 && errno == EINTR);
        }
        for (i = 0; i < cores; i++)
        {
            if (!runs[i].inUse) continue;
            SSFDrainRun(&runs[i]);
            if (runs[i].eof) { if (!SSFFinishRun(&runs[i])) allPassed = false; done++; }
        }
    }

    free(runs);
    free(pfds);
    printf("\r\n");
    return allPassed ? 0 : 1;
}

#else /* _WIN32 */

/* Cap on concurrent worker processes; WaitForMultipleObjects() cannot wait on more than this. */
#define SSF_PARALLEL_MAX_WORKERS MAXIMUM_WAIT_OBJECTS

/* Hidden command line switch that re-launches this executable as a single-test worker. */
#define SSF_WORKER_ARG "--ssf-worker"

typedef struct
{
    HANDLE process;
    HANDLE reader;
    HANDLE pipe;
    size_t idx;
    SSFPortTick_t start;
    char *buf;
    size_t bufLen;
    size_t bufCap;
    bool inUse;
} SSFTestRun_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns count of logical processors clamped to [1, SSF_PARALLEL_MAX_WORKERS].                 */
/* --------------------------------------------------------------------------------------------- */
static int SSFCoreCount(void)
{
    SYSTEM_INFO si;
    DWORD n;

    GetSystemInfo(&si);
    n = si.dwNumberOfProcessors;
    if (n < 1) n = 1;
    if (n > SSF_PARALLEL_MAX_WORKERS) n = SSF_PARALLEL_MAX_WORKERS;
    return (int)n;
}

/* --------------------------------------------------------------------------------------------- */
/* Reader thread: drains run->pipe into run->buf until the worker closes its end of the pipe.    */
/* --------------------------------------------------------------------------------------------- */
static DWORD WINAPI SSFReaderThread(LPVOID param)
{
    SSFTestRun_t *run = (SSFTestRun_t *)param;
    char tmp[4096];
    DWORD n;
    size_t newCap;
    char *p;

    SSF_REQUIRE(run != NULL);

    for (;;)
    {
        n = 0;
        if (!ReadFile(run->pipe, tmp, sizeof(tmp), &n, NULL) || (n == 0)) break;
        if (run->bufLen + (size_t)n + 1 > run->bufCap)
        {
            newCap = run->bufCap == 0 ? 8192 : run->bufCap * 2;
            while (newCap < run->bufLen + (size_t)n + 1) { newCap *= 2; }
            p = (char *)realloc(run->buf, newCap);
            SSF_ASSERT(p != NULL);
            run->buf = p;
            run->bufCap = newCap;
        }
        memcpy(run->buf + run->bufLen, tmp, (size_t)n);
        run->bufLen += (size_t)n;
        run->buf[run->bufLen] = '\0';
    }
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Spawns a worker process to run unitTests[idx] with stdout/stderr captured. Returns true if    */
/* started.                                                                                      */
/* --------------------------------------------------------------------------------------------- */
static bool SSFStartRun(SSFTestRun_t *run, size_t idx)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE readEnd;
    HANDLE writeEnd;
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH + sizeof(SSF_WORKER_ARG) + 32];
    DWORD len;
    int n;
    BOOL ok;

    SSF_REQUIRE(run != NULL);
    SSF_REQUIRE(idx < sizeof(unitTests) / sizeof(SSFUnitTest_t));

    len = GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));
    if ((len == 0) || (len >= sizeof(exePath))) return false;
    n = snprintf(cmdLine, sizeof(cmdLine), "\"%s\" %s %u", exePath, SSF_WORKER_ARG,
                 (unsigned int)idx);
    if ((n < 0) || ((size_t)n >= sizeof(cmdLine))) return false;

    /* The worker inherits the write end only; keep the read end out of every worker process. */
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) return false;
    (void)SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;
    memset(&pi, 0, sizeof(pi));

    /* Workers are started one at a time and the write end is closed immediately, so a pipe is */
    /* never inherited by any worker other than its own.                                        */
    ok = CreateProcessA(exePath, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    (void)CloseHandle(writeEnd);
    if (!ok) { (void)CloseHandle(readEnd); return false; }
    (void)CloseHandle(pi.hThread);

    run->process = pi.hProcess;
    run->pipe = readEnd;
    run->idx = idx;
    run->start = SSFPortGetTick64();
    run->buf = NULL;
    run->bufLen = 0;
    run->bufCap = 0;
    run->inUse = true;
    run->reader = CreateThread(NULL, 0, SSFReaderThread, run, 0, NULL);
    if (run->reader == NULL)
    {
        (void)TerminateProcess(run->process, 1);
        (void)CloseHandle(run->process);
        (void)CloseHandle(run->pipe);
        memset(run, 0, sizeof(*run));
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Reaps the finished worker, prints its result line and captured output. Returns true if passed.*/
/* --------------------------------------------------------------------------------------------- */
static bool SSFFinishRun(SSFTestRun_t *run)
{
    DWORD exitCode;
    SSFPortTick_t elapsed;
    bool passed;

    SSF_REQUIRE(run != NULL);
    SSF_REQUIRE(run->inUse);

    (void)WaitForSingleObject(run->process, INFINITE);
    /* The reader thread exits once the worker's end of the pipe closes. */
    (void)WaitForSingleObject(run->reader, INFINITE);
    exitCode = 1;
    passed = GetExitCodeProcess(run->process, &exitCode) && (exitCode == 0);
    (void)CloseHandle(run->reader);
    (void)CloseHandle(run->process);
    (void)CloseHandle(run->pipe);
    elapsed = (SSFPortGetTick64() - run->start) / SSF_TICKS_PER_SEC;

    printf("Running %20s (%30s) unit test...%s in %llus\r\n",
           unitTests[run->idx].module, unitTests[run->idx].description,
           passed ? "PASSED" : "FAILED", (unsigned long long)elapsed);
    if (run->bufLen > 0) { (void)fwrite(run->buf, 1, run->bufLen, stdout); }
    (void)fflush(stdout);
    free(run->buf);
    memset(run, 0, sizeof(*run));
    return passed;
}

/* --------------------------------------------------------------------------------------------- */
/* Worker entry point: runs the single test selected by idxStr. Returns 0 on pass, else non-zero.*/
/* --------------------------------------------------------------------------------------------- */
static int SSFWorkerMain(const char *idxStr)
{
    char *end;
    unsigned long idx;

    SSF_REQUIRE(idxStr != NULL);

    /* Never stall a parallel run on a modal dialog: route crashes, abort() and CRT asserts to */
    /* the exit code and stderr instead.                                                       */
    (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    (void)_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#if defined(_DEBUG)
    (void)_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    (void)_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
#endif /* _DEBUG */

    end = NULL;
    idx = strtoul(idxStr, &end, 10);
    if ((end == idxStr) || (*end != '\0') || (idx >= sizeof(unitTests) / sizeof(SSFUnitTest_t)))
    {
        printf("SSF worker: invalid test index '%s'\r\n", idxStr);
        return 2;
    }
    unitTests[idx].utf();
    (void)fflush(stdout);
    (void)fflush(stderr);
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* SSF unit test entry point. Runs tests in parallel up to host core count.                      */
/* --------------------------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    size_t total;
    size_t next;
    size_t done;
    int cores;
    bool allPassed;
    SSFTestRun_t *runs;
    HANDLE *handles;
    int *slots;
    int i;
    int nWait;
    DWORD wr;
    int hdrLen;

    if ((argc == 3) && (strcmp(argv[1], SSF_WORKER_ARG) == 0)) { return SSFWorkerMain(argv[2]); }

    total = sizeof(unitTests) / sizeof(SSFUnitTest_t);
    next = 0;
    done = 0;
    cores = SSFCoreCount();
    if (total > 0 && (size_t)cores > total) cores = (int)total;
    if (cores < 1) cores = 1;
    allPassed = true;

    printf("\r\n");
    hdrLen = printf("Testing SSF Version %s (parallel x%d)", SSF_VERSION_STR, cores);
    SSF_ASSERT(hdrLen > 0);
    printf("\r\n");
    while (hdrLen--) { printf("-"); }
    printf("\r\n");

    if (total == 0) { printf("\r\n"); return 0; }

    runs = (SSFTestRun_t *)calloc((size_t)cores, sizeof(SSFTestRun_t));
    SSF_ASSERT(runs != NULL);
    handles = (HANDLE *)calloc((size_t)cores, sizeof(HANDLE));
    SSF_ASSERT(handles != NULL);
    slots = (int *)calloc((size_t)cores, sizeof(int));
    SSF_ASSERT(slots != NULL);

    while (done < total)
    {
        for (i = 0; i < cores && next < total; i++)
        {
            if (!runs[i].inUse)
            {
                if (!SSFStartRun(&runs[i], next)) SSF_ERROR();
                next++;
            }
        }
        nWait = 0;
        for (i = 0; i < cores; i++)
        {
            if (runs[i].inUse)
            {
                handles[nWait] = runs[i].process;
                slots[nWait] = i;
                nWait++;
            }
        }
        SSF_ASSERT(nWait > 0);
        wr = WaitForMultipleObjects((DWORD)nWait, handles, FALSE, INFINITE);
        SSF_ASSERT((wr >= WAIT_OBJECT_0) && (wr < WAIT_OBJECT_0 + (DWORD)nWait));
        i = slots[wr - WAIT_OBJECT_0];
        if (!SSFFinishRun(&runs[i])) allPassed = false;
        done++;
    }

    free(runs);
    free(handles);
    free(slots);
    printf("\r\n");
    return allPassed ? 0 : 1;
}

#endif /* _WIN32 */
