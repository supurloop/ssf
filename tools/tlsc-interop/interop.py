#!/usr/bin/env python3
"""TLS client (ssftlsc) interop regression set: runs tlsc_interop against openssl s_server and
gnutls-serv over loopback (and test.mosquitto.org with --public) and checks every row against its
expected outcome. Normally started by run.sh, which builds the driver and the certificates.

  interop.py BIN_DIR CERT_DIR [--public] [--only NAME] [--expect-fail SUBSTR]

BIN_DIR holds tlsc_interop (and tlsc_interop_ku3, the client rekeying every 3 records); CERT_DIR
the output of gen-certs.sh. --expect-fail is the self-test: rows whose name contains SUBSTR must
fail and all others pass.
"""
import os, re, socket, subprocess, sys, time

BIN, CERTS = sys.argv[1], sys.argv[2]
OPTS = sys.argv[3:]
PUBLIC = '--public' in OPTS
ONLY = OPTS[OPTS.index('--only') + 1] if '--only' in OPTS else None
EXPECT_FAIL = OPTS[OPTS.index('--expect-fail') + 1] if '--expect-fail' in OPTS else None
HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, '.cache')
SYSTEM_BUNDLES = ['/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', '/etc/ssl/certs/ca-certificates.crt',
                  '/etc/ssl/cert.pem']
SYSTEM = next((b for b in SYSTEM_BUNDLES if os.path.exists(b)), None)
C = lambda n: os.path.join(CERTS, n)


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def listening(port):
    """True if something listens on 127.0.0.1:port (from /proc/net/tcp; no connection made, since
    a connection would use up s_server's single accept)."""
    try:
        with open('/proc/net/tcp') as f:
            for line in f.readlines()[1:]:
                x = line.split()
                if x[3] == '0A' and int(x[1].split(':')[1], 16) == port: return True
    except OSError:
        pass
    return False


def server(kind, port, cert, key, extra=(), stdin=False):
    if kind == 'openssl':
        cmd = ['openssl', 's_server', '-accept', '127.0.0.1:%d' % port, '-cert', cert, '-key', key, '-tls1_3',
               '-naccept', '1'] + list(extra)
        if not stdin: cmd.append('-rev')
    else:
        cmd = ['gnutls-serv', '-p', str(port), '--echo', '--x509certfile', cert, '--x509keyfile', key] + list(extra)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                         stdout=subprocess.PIPE if stdin else subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        if listening(port): return p
        time.sleep(0.05)
    p.kill(); raise RuntimeError('server did not start: ' + ' '.join(cmd))


def driver(args, binary='tlsc_interop', timeout=60):
    out = subprocess.run([os.path.join(BIN, binary)] + args, capture_output=True, text=True, timeout=timeout,
                         env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0')).stdout
    m = re.search(r'^result (.*)$', out, re.M)
    return dict(kv.split('=', 1) for kv in m.group(1).split()) if m else {'error': out.strip()[-200:]}


def check(got, want):
    """want: {field: value or compiled regex or callable}."""
    for k, v in want.items():
        g = got.get(k)
        if callable(v) and not isinstance(v, re.Pattern):
            if g is None or not v(g): return False
        elif isinstance(v, re.Pattern):
            if g is None or not v.fullmatch(g): return False
        elif g != str(v):
            return False
    return True


ROWS = []   # (name, function returning the driver's result, expected fields)
LOCAL = ['--host', 'localhost', '--echo']
OK = {'tls': 1}

# ---- Matrix: {s_server, gnutls-serv} x 4 suites x 3 groups x 5 server keys ----
SUITES = [('0x1301', 'TLS_AES_128_GCM_SHA256', 'AES-128-GCM'), ('0x1302', 'TLS_AES_256_GCM_SHA384', 'AES-256-GCM'),
          ('0x1303', 'TLS_CHACHA20_POLY1305_SHA256', 'CHACHA20-POLY1305'), ('0x1304', 'TLS_AES_128_CCM_SHA256', 'AES-128-CCM')]
GROUPS = [('0x001d', 'X25519', 'X25519', 0), ('0x0018', 'P-384', 'SECP384R1', 0), ('0x0017', 'P-256', 'SECP256R1', 1)]
KEYS = [('leaf', 'ca'), ('p384leaf', 'ca'), ('rsaleaf', 'rsaca'), ('rsa4kleaf', 'rsaca'), ('edleaf', 'ca')]
for kind in ('openssl', 'gnutls'):
    for sid, so, sg in SUITES:
        for gid, go, gg, hrr in GROUPS:
            for k, ca in KEYS:
                if kind == 'openssl':
                    extra = ['-ciphersuites', so, '-groups', go]
                else:
                    extra = ['--priority', 'NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+%s:-GROUP-ALL:+GROUP-%s' % (sg, gg)]
                def run(kind=kind, k=k, ca=ca, extra=extra):
                    p = free_port(); s = server(kind, p, C(k + '.pem'), C(k + '.key'), extra)
                    try: return driver(LOCAL + ['--port', str(p), '--ca', C(ca + '.pem')])
                    finally: s.kill()
                ROWS.append(('matrix %s %s %s %s' % (kind, sid, go, k), run,
                             dict(tls=1, suite=sid, group=gid, hrr=hrr, echo=23)))

# ---- ALPN ----
def alpn_row(name, kind, sextra, protos, want):
    def run():
        p = free_port(); s = server(kind, p, C('leaf.pem'), C('leaf.key'), sextra)
        try: return driver(LOCAL + ['--port', str(p), '--ca', C('ca.pem')] + (['--alpn', protos] if protos else []))
        finally: s.kill()
    ROWS.append(('alpn ' + name, run, want))
GN = ['--priority', 'NORMAL:-VERS-ALL:+VERS-TLS1.3']
alpn_row('s_server picks mqtt', 'openssl', ['-alpn', 'mqtt'], 'x-amzn-mqtt-ca,mqtt', dict(tls=1, alpn='mqtt', echo=23))
alpn_row('s_server picks x-amzn-mqtt-ca', 'openssl', ['-alpn', 'x-amzn-mqtt-ca'], 'x-amzn-mqtt-ca,mqtt', dict(tls=1, alpn='x-amzn-mqtt-ca'))
alpn_row('s_server no overlap', 'openssl', ['-alpn', 'h2'], 'mqtt', dict(tls=0, rcvd=120))
alpn_row('s_server no ALPN', 'openssl', [], 'mqtt', dict(tls=1, alpn='-'))
alpn_row('client offers none', 'openssl', ['-alpn', 'mqtt'], None, dict(tls=1, alpn='-'))
alpn_row('s_server HRR then mqtt', 'openssl', ['-alpn', 'mqtt', '-groups', 'P-256'], 'mqtt', dict(tls=1, alpn='mqtt', hrr=1))
alpn_row('gnutls picks mqtt', 'gnutls', GN + ['--alpn=mqtt'], 'x-amzn-mqtt-ca,mqtt', dict(tls=1, alpn='mqtt', echo=23))
alpn_row('gnutls fatal no overlap', 'gnutls', GN + ['--alpn=h2', '--alpn-fatal'], 'mqtt', dict(tls=0, rcvd=120))
alpn_row('gnutls non-fatal no overlap', 'gnutls', GN + ['--alpn=h2'], 'mqtt', dict(tls=1, alpn='-'))
alpn_row('gnutls no ALPN', 'gnutls', GN, 'mqtt', dict(tls=1, alpn='-'))

# ---- Mutual TLS ----
def mtls_row(name, kind, sextra, client, want, scas='cca'):
    def run():
        p = free_port()
        if kind == 'openssl': extra = ['-Verify', '2', '-verify_return_error', '-CAfile', C(scas + '.pem')] + sextra
        else: extra = ['--x509cafile', C(scas + '.pem'), '--require-client-cert', '--verify-client-cert'] + GN + sextra
        s = server(kind, p, C('leaf.pem'), C('leaf.key'), extra)
        try:
            args = LOCAL + ['--port', str(p), '--ca', C('ca.pem')]
            if client: args += ['--cert', C(client + '.pem'), '--key', C(client + '.key')]
            return driver(args)
        finally: s.kill()
    ROWS.append(('mtls ' + name, run, want))
for c, sch in (('p256', '0x0403'), ('p384', '0x0503'), ('ed', '0x0807'), ('rsa2k', '0x0804'), ('rsa4k', '0x0804')):
    mtls_row('s_server %s client' % c, 'openssl', [], c, dict(tls=1, scheme=sch, echo=23))
mtls_row('s_server leaf + intermediate', 'openssl', [], 'p256chain', dict(tls=1, scheme='0x0403', chain=2, echo=23))
for c, sch in (('p256', '0x0403'), ('rsa2k', '0x0804'), ('ed', '0x0807')):
    mtls_row('gnutls %s client' % c, 'gnutls', [], c, dict(tls=1, scheme=sch, echo=23))
mtls_row('server accepts only ECDSA+SHA384, P-256 client', 'openssl', ['-client_sigalgs', 'ECDSA+SHA384'], 'p256',
         dict(tls=1, scheme='0x0000', echo=0, rcvd=116))
mtls_row('server trusts another CA', 'openssl', [], 'p256', dict(tls=1, echo=0, rcvd=48), scas='ca')
mtls_row('server lists only ed25519, ECDSA-signed Ed25519 leaf', 'openssl', ['-client_sigalgs', 'ed25519'], 'ed',
         dict(tls=1, scheme='0x0000', emptycert=1, echo=0, rcvd=116))
mtls_row('server lists ed25519:ECDSA+SHA256', 'openssl', ['-client_sigalgs', 'ed25519:ECDSA+SHA256'], 'ed',
         dict(tls=1, scheme='0x0807', echo=23))
mtls_row('no client certificate, s_server requires one', 'openssl', [], None, dict(tls=1, emptycert=1, echo=0, rcvd=116))

# ---- Trust store loaded from PEM bundles ----
if SYSTEM:
    def trust_row(name, leaf, cas, want):
        def run():
            p = free_port(); s = server('openssl', p, C(leaf + '.pem'), C(leaf + '.key'))
            try: return driver(LOCAL + ['--port', str(p)] + sum((['--ca', x] for x in cas), []))
            finally: s.kill()
        ROWS.append(('trust ' + name, run, want))
    trust_row('system roots + test CAs, EC leaf', 'leaf', [SYSTEM, C('ca.pem'), C('rsaca.pem')],
              dict(tls=1, trust=lambda v: int(v) > 2, echo=23))
    trust_row('test CA first, then system roots', 'leaf', [C('ca.pem'), SYSTEM], dict(tls=1, echo=23))
    trust_row('system roots only, EC leaf', 'leaf', [SYSTEM], dict(tls=0, verify=8, sent=48))
    trust_row('system roots + test CAs, RSA leaf', 'rsaleaf', [SYSTEM, C('ca.pem'), C('rsaca.pem')], dict(tls=1, echo=23))
    trust_row('system roots only, RSA leaf', 'rsaleaf', [SYSTEM], dict(tls=0, verify=8, sent=48))

# ---- Server certificates refused by policy, with the trace saying why ----
def cert_row(name, leaf, want):
    def run():
        p = free_port(); s = server('openssl', p, C(leaf + '.pem'), C(leaf + '.key'))
        try: return driver(LOCAL + ['--port', str(p), '--ca', C('ca.pem')])
        finally: s.kill()
    ROWS.append(('cert ' + name, run, want))
cert_row('X.509 v1 server certificate', 'v1leaf', dict(tls=0, verify=2, sent=43, hint='v1'))
cert_row('v3 without subjectAltName', 'nosanleaf', dict(tls=0, verify=16, sent=42, hint='san'))

# ---- KeyUpdate ----
def ku_server_row(name, script, want):
    """s_server sends lines and k / K commands typed on its stdin; the client acks each line."""
    def run():
        p = free_port(); s = server('openssl', p, C('leaf.pem'), C('leaf.key'), ['-ign_eof', '-msg'], stdin=True)
        d = subprocess.Popen([os.path.join(BIN, 'tlsc_interop')] + LOCAL[:2] + ['--port', str(p), '--ca', C('ca.pem'),
                             '--serve-lines'], stdout=subprocess.PIPE, text=True,
                             env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
        try:
            time.sleep(1.0)
            for x in script:
                s.stdin.write(x + '\n'); s.stdin.flush(); time.sleep(0.4)
            out, _ = d.communicate(timeout=30)
        finally:
            s.kill(); d.kill()
        m = re.search(r'^result (.*)$', out, re.M)
        return dict(kv.split('=', 1) for kv in m.group(1).split()) if m else {'error': out[-200:]}
    ROWS.append(('keyupdate ' + name, run, want))
ku_server_row('server KeyUpdate, not requested', ['hello-a', 'k', 'hello-b', 'END'], dict(lines=3, kurcvd=1, kusent=0))
ku_server_row('server KeyUpdate requested, twice', ['hello-a', 'K', 'hello-b', 'hello-c', 'K', 'hello-d', 'END'],
              dict(lines=5, kurcvd=2, kusent=2))
ku_server_row('three server KeyUpdates in a row', ['hello-a', 'k', 'k', 'k', 'hello-b', 'END'], dict(lines=3, kurcvd=3))
def ku_client_row(name, kind):
    def run():
        p = free_port(); s = server(kind, p, C('leaf.pem'), C('leaf.key'), GN if kind == 'gnutls' else [])
        try: return driver(LOCAL[:2] + ['--port', str(p), '--ca', C('ca.pem'), '--lines', '20'], binary='tlsc_interop_ku3')
        finally: s.kill()
    ROWS.append(('keyupdate ' + name, run, dict(replies=20, kusent=lambda v: int(v) >= 6)))
ku_client_row('client rekeys every 3 records, s_server', 'openssl')
ku_client_row('client rekeys every 3 records, gnutls', 'gnutls')

# ---- Record sizes ----
def rs_server_frag():
    p = free_port(); s = server('openssl', p, C('rsa4kleaf.pem'), C('rsa4kleaf.key'), ['-max_send_frag', '512'])
    try: return driver(LOCAL + ['--port', str(p), '--ca', C('rsaca.pem')])
    finally: s.kill()
ROWS.append(('record size: server records of at most 512 bytes', rs_server_frag, dict(tls=1, echo=23)))
mtls_row('gnutls record_size_limit 512, RSA-4096 client flight split', 'gnutls', ['--recordsize=512'], 'rsa4k',
         dict(tls=1, scheme='0x0804', echo=23))

# ---- Public: test.mosquitto.org ----
if PUBLIC:
    MCA = os.path.join(CACHE, 'mosquitto.org.crt')
    def pub(port, args):
        return lambda: driver(['--host', 'test.mosquitto.org', '--port', str(port), '--mqtt'] + args, timeout=90)
    if SYSTEM:
        ROWS.append(('public 8886 Let\'s Encrypt, system roots, MQTT', pub(8886, ['--ca', SYSTEM]), dict(tls=1, mqtt=1)))
    ROWS.append(('public 8883 X.509 v1 server certificate refused (punch list)', pub(8883, ['--ca', MCA]),
                 dict(tls=0, verify=2, sent=43, hint='v1')))
    for k, sch in (('p256', '0x0403'), ('rsa2k', '0x0804')):
        ROWS.append(('public 8884 mutual TLS, %s client (server unauthenticated: v1 certificate)' % k,
                     pub(8884, ['--unauth', '--cert', os.path.join(CACHE, k + '.crt'), '--key', os.path.join(CACHE, k + '.key')]),
                     dict(tls=1, scheme=sch, mqtt=1)))
    ROWS.append(('public 8884 no client certificate', pub(8884, ['--unauth']), dict(tls=1, mqtt=0, rcvd=116)))
    ROWS.append(('public 8884 client certificate from another CA',
                 pub(8884, ['--unauth', '--cert', C('p256.pem'), '--key', C('p256.key')]), dict(tls=1, mqtt=0, rcvd=48)))


def main():
    passed = failed = 0
    unexpected = []
    for name, run, want in ROWS:
        if ONLY and ONLY not in name: continue
        try: got = run()
        except Exception as e: got = {'error': str(e)}
        ok = check(got, want)
        if EXPECT_FAIL:
            should = EXPECT_FAIL not in name
            if ok != should: unexpected.append(name); print('UNEXPECTED %s: %s' % ('pass' if ok else 'failure', name))
            passed += ok; failed += not ok
            continue
        if ok: passed += 1
        else:
            failed += 1
            print('FAIL %s\n     got  %s\n     want %s' % (name, ' '.join('%s=%s' % x for x in sorted(got.items())),
                                                         ' '.join('%s=%s' % (k, getattr(v, 'pattern', v)) for k, v in want.items())))
    if EXPECT_FAIL:
        print('self-test: %d rows failed, %d passed; %s' % (failed, passed, 'OK' if not unexpected else 'NOT OK'))
        return 0 if (not unexpected and failed > 0) else 1
    print('interop: %d passed, %d failed of %d%s' % (passed, failed, passed + failed, '' if SYSTEM else ' (no system CA bundle: trust rows skipped)'))
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
