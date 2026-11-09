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

// LDAP signing bypass probe (CVE-2026-70229). Fixed messages, no credentials are sent:
//   messageID 1: BindRequest, v3, empty DN, empty simple password (anonymous bind)
//   messageID 2: ExtendedRequest "Who am I?" (1.3.6.1.4.1.4203.1.11.3)
static const unsigned char BP_MSGS[] = {
    0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00,
    0x30,0x1e,0x02,0x01,0x02,0x77,0x19,0x80,0x17,
    '1','.','3','.','6','.','1','.','4','.','1','.','4','2','0','3','.','1','.','1','1','.','3'
};
#define BP_BIND_LEN 14

#define BP_UNPATCHED  0
#define BP_PATCHED    1
#define BP_ERROR      2  // couldn't connect to port 389
#define BP_NO_BIND    3  // inconclusive: no bind response
#define BP_NO_CONTROL 4  // inconclusive: whoami unanswered even when not stacked

// Returns 1 if a complete reply to messageID 2 is in buf; sets *bind_rc to the
//   resultCode of the messageID 1 BindResponse, or -1 if there isn't one yet.
static int bp_parse(const unsigned char *buf, int len, int *bind_rc) {
    int saw2 = 0, i = 0;
    *bind_rc = -1;
    while (i + 2 <= len && buf[i] == 0x30) {
        unsigned int mlen = buf[i + 1];  // unsigned: AD sends 4-byte lengths, which must not go negative
        i += 2;
        if (mlen & 0x80) {
            int nb = mlen & 0x7F;
            if (nb > 4 || i + nb > len) break;
            for (mlen = 0; nb > 0; nb--) mlen = (mlen << 8) | buf[i++];
        }
        if (mlen > (unsigned int)(len - i)) break;
        const unsigned char *m = buf + i;  // 02 01 <messageID> <protocolOp>...
        if (mlen >= 3 && m[0] == 0x02 && m[1] == 0x01) {
            if (m[2] == 2) saw2 = 1;
            if (m[2] == 1 && mlen >= 5 && m[3] == 0x61) {  // BindResponse; resultCode follows its length
                int p = 5 + ((m[4] & 0x80) ? (m[4] & 0x7F) : 0);
                if (p + 3 <= mlen && m[p] == 0x0A) *bind_rc = m[p + 2];
            }
        }
        i += mlen;
    }
    return saw2;
}

static SOCKET bp_connect(const char *host) {
    struct addrinfo hints, *res = NULL;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (WS2_32$getaddrinfo(host, "389", &hints, &res) != 0 || !res) return INVALID_SOCKET;

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET && WS2_32$connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        WS2_32$closesocket(s);
        s = INVALID_SOCKET;
    }
    WS2_32$freeaddrinfo(res);
    if (s != INVALID_SOCKET) {
        DWORD tv = 5000;
        WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    }
    return s;
}

// Send data, then read until the bind (want == 1) or whoami (want == 2) is answered,
//   the server closes, the buffer fills, or a read times out. Returns 1 if whoami was answered.
static int bp_exchange(SOCKET s, const unsigned char *data, int len, int want, int *bind_rc) {
    unsigned char buf[2048];  // keep the frame under 4KB, or the compiler emits a __chkstk call BOF loaders can't resolve
    int got = 0, r, saw2 = 0;
    *bind_rc = -1;
    if (WS2_32$send(s, (const char*)data, len, 0) != len) return 0;
    while (got < (int)sizeof(buf) && (r = WS2_32$recv(s, (char*)buf + got, (int)sizeof(buf) - got, 0)) > 0) {
        got += r;
        saw2 = bp_parse(buf, got, bind_rc);
        if (want == 2 ? saw2 : *bind_rc >= 0) break;
    }
    return saw2;
}

// Bind and whoami are sent stacked in one write: an unpatched DC answers both, a patched DC
//   drops the whoami. If whoami goes unanswered, a control run sends them one at a time to
//   confirm the DC does answer whoami normally.
static int bp_probe(const char *host) {
    WSADATA wsa;
    int bind_rc, result = BP_ERROR;
    if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) return BP_ERROR;

    SOCKET s = bp_connect(host);
    if (s != INVALID_SOCKET) {
        if (bp_exchange(s, BP_MSGS, sizeof(BP_MSGS), 2, &bind_rc)) result = BP_UNPATCHED;
        else result = bind_rc < 0 ? BP_NO_BIND : BP_NO_CONTROL;
        WS2_32$closesocket(s);
    }

    if (result == BP_NO_CONTROL && (s = bp_connect(host)) != INVALID_SOCKET) {
        bp_exchange(s, BP_MSGS, BP_BIND_LEN, 1, &bind_rc);
        if (bp_exchange(s, BP_MSGS + BP_BIND_LEN, sizeof(BP_MSGS) - BP_BIND_LEN, 2, &bind_rc)) result = BP_PATCHED;
        WS2_32$closesocket(s);
    }

    WS2_32$WSACleanup();
    return result;
}

// ─── Protection check ────────────────────────────────────────────────────────

void CheckProtection(char* host) {
    // No need to arm AcquireCredentialsHandleW since we can control the auth mechanism in WLDAP32$ldap_bind_s()
    PVOID vehIscW = NULL; void* addrIscW = NULL;
    if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextW", 1, ISC_VEH, &vehIscW, &addrIscW, FALSE)) {
		internal_printf("Failed to set HWBP on sspicli!InitializeSecurityContextW (DR1).\n");
		return;
	}

    // ── 1. LDAP signing ──────────────────────────────────────────
    g_stripProtFlags = 1;
    ULONG noSigning = trigger_ldap_auth(host, FALSE);

    if (noSigning == LDAP_STRONG_AUTH_REQUIRED) {
        internal_printf("[%s] (LDAP) server ALWAYS REQUIRES signing\n", host);
    } else if (noSigning == LDAP_SUCCESS) {
        internal_printf("[%s] (LDAP) server signing requirement is OFF\n", host);
    } else {
        internal_printf("[%s] (LDAP) signing requirement unknown - result code:%lu\n", host, noSigning);
    }

    // The signing bypass only matters when signing is enforced
    if (noSigning == LDAP_STRONG_AUTH_REQUIRED) {
        int bypass = bp_probe(host);
        if (bypass == BP_UNPATCHED) {
            internal_printf("[%s] (LDAP) SIGNING BYPASS UNPATCHED (CVE-2026-70229)\n", host);
        } else if (bypass == BP_PATCHED) {
            internal_printf("[%s] (LDAP) signing bypass patched (CVE-2026-70229)\n", host);
        } else if (bypass == BP_NO_BIND) {
            internal_printf("[%s] (LDAP) signing bypass inconclusive - no bind response\n", host);
        } else if (bypass == BP_NO_CONTROL) {
            internal_printf("[%s] (LDAP) signing bypass inconclusive - whoami unanswered even when not stacked\n", host);
        } else {
            internal_printf("[%s] (LDAP) signing bypass probe failed - could not connect to port 389\n", host);
        }
    }

    // ── 3. LDAPS channel binding ──────────────────────────────────
    g_stripProtFlags = 0;
    g_cbtMode = 1; g_cbtModified = 0;
    ULONG zeroCBT = trigger_ldap_auth(host, TRUE);

    if (zeroCBT == LDAP_INVALID_CREDENTIALS) {
        internal_printf("[%s] (LDAPS) channel binding token requirement is set to ALWAYS or WHEN SUPPORTED\n", host);
    } else if (zeroCBT == LDAP_SUCCESS) {
        internal_printf("[%s] (LDAPS) channel binding token requirement is set to NEVER\n", host);
    } else {
        internal_printf("[%s] (LDAPS) channel binding token requirement unknown - result code:%lu\n", host, zeroCBT);
    }

    // Cleanup
    HWBP_Clear(1);  // DR1 (ISC-W)
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



