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

void CheckProtection(char* host) {
    // No need to arm AcquireCredentialsHandleW since we can control the auth mechanism in WLDAP32$ldap_bind_s()
    PVOID vehIscW = NULL; void* addrIscW = NULL;
    if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextW", 1, ISC_VEH, &vehIscW, &addrIscW, FALSE)) {
		internal_printf("Failed to set HWBP on sspicli!InitializeSecurityContextW (DR1).\n");
		return;
	}

    g_stripProtFlags = 1;
    ULONG noSigning = trigger_ldap_auth(host, FALSE);

    if (noSigning == LDAP_STRONG_AUTH_REQUIRED) {
        internal_printf("[%s] (LDAP) server ALWAYS REQUIRES signing\n", host);
    } else if (noSigning == LDAP_SUCCESS) {
        internal_printf("[%s] (LDAP) server signing requirement is OFF\n", host);
    } else {
        internal_printf("[%s] (LDAP) signing requirement unknown - result code:%lu\n", host, noSigning);
    }

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



