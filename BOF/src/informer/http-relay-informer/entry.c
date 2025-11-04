#include "bofdefs.h"
#include "base.c"

static wchar_t g_fakeSpnW[64] = L"HTTP/relay.informer";
#include "hwbp.c"

// Global variables for hardware breakpoints
PVOID vehAchW = NULL;
void* addrAchW = NULL;
PVOID vehIscW = NULL;
void* addrIscW = NULL;

//
// HTTPS case has to handle thread switch, so this func will be called multiple times
// instead of just once at the start of CheckProtection()
//
static BOOL ArmBps(){
    // ACH-W: register VEH once; re-arm only thereafter
    if (!vehAchW) {
        if (!HWBP_SetOnApiEx("sspicli.dll", "AcquireCredentialsHandleW", 0, ACH_VEH, &vehAchW, &addrAchW, TRUE)) {
            internal_printf("Failed to set HWBP on sspicli!AcquireCredentialsHandleW (DR0).\n");
            return FALSE;
        }
    } else {
        // Re-arm across threads without re-registering VEH
        if (!HWBP_SetOnApiEx("sspicli.dll", "AcquireCredentialsHandleW", 0, NULL, NULL, &addrAchW, TRUE)) {
            internal_printf("Failed to re-arm HWBP on AcquireCredentialsHandleW (DR0).\n");
            return FALSE;
        }
    }

    // ISC-W: register VEH once; re-arm only thereafter
    if (!vehIscW) {
        if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextW", 1, ISC_VEH, &vehIscW, &addrIscW, TRUE)) {
            internal_printf("Failed to set HWBP on sspicli!InitializeSecurityContextW (DR1).\n");
            return FALSE;
        }
    } else {
        if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextW", 1, NULL, NULL, &addrIscW, TRUE)) {
            internal_printf("Failed to re-arm HWBP on InitializeSecurityContextW (DR1).\n");
            return FALSE;
        }
    }
    return TRUE;
}


//
// Trigger NTLM auth over HTTP/S
//
static DWORD trigger_winhttp_ntlm(wchar_t* kHost, wchar_t* kPath, INTERNET_PORT kPort, BOOL ssl) {
	// Session
	HINTERNET hSes = WINHTTP$WinHttpOpen(L"Relay-Informer/1.0",
									  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
									  WINHTTP_NO_PROXY_NAME,
									  WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSes) { return 0; }

	DWORD pol = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
	WINHTTP$WinHttpSetOption(hSes, WINHTTP_OPTION_AUTOLOGON_POLICY, &pol, sizeof(pol));

	// Connect + Request (single handle for whole handshake)
	HINTERNET hConn = WINHTTP$WinHttpConnect(hSes, kHost, kPort, 0);
	if (!hConn) { WINHTTP$WinHttpCloseHandle(hSes); return 0; }

	HINTERNET hReq = WINHTTP$WinHttpOpenRequest(hConn, L"GET", kPath, NULL,
											  WINHTTP_NO_REFERER,
											  WINHTTP_DEFAULT_ACCEPT_TYPES,
											  ssl ? WINHTTP_FLAG_SECURE : 0);
	if (!hReq) { WINHTTP$WinHttpCloseHandle(hConn); WINHTTP$WinHttpCloseHandle(hSes); return 0; }

	// Rearm hardware breakpoints to handle potential thread switch
	ArmBps();

	if (ssl) {
		// Hardcode: ignore TLS cert errors (CN/date/CA)
		DWORD secFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
					   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
					   | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		
		WINHTTP$WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
	}

	WINHTTP$WinHttpAddRequestHeaders(hReq, L"Connection: keep-alive", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

	// 1) First unauthenticated request → expect 401
	if (!WINHTTP$WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
						WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		WINHTTP$WinHttpCloseHandle(hReq); WINHTTP$WinHttpCloseHandle(hConn); WINHTTP$WinHttpCloseHandle(hSes); return 0;
	}

	// Rearm hardware breakpoints to handle potential thread switch
	ArmBps();

	if (!WINHTTP$WinHttpReceiveResponse(hReq, NULL)) {
		WINHTTP$WinHttpCloseHandle(hReq); WINHTTP$WinHttpCloseHandle(hConn); WINHTTP$WinHttpCloseHandle(hSes); return 0;
	}

	DWORD status=0, cb=sizeof(status);
	WINHTTP$WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
						NULL, &status, &cb, NULL);

	// with LOW SSO, winhttp should complete the ntlm handshake by now
	// so we should get a 200 here, if all EPA/service binding requirements are met

	WINHTTP$WinHttpCloseHandle(hReq); WINHTTP$WinHttpCloseHandle(hConn); WINHTTP$WinHttpCloseHandle(hSes);
	return status;
}

//
// Main test loginc
//
void CheckProtection(wchar_t* URL) {
    wchar_t* kHost = NULL;
    wchar_t* kPath = NULL;
    INTERNET_PORT kPort = 0;
    BOOL ssl = FALSE;

    // Parse URL into components
    URL_COMPONENTSW urlComp = {0};
    urlComp.dwStructSize = sizeof(URL_COMPONENTSW);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwSchemeLength = (DWORD)-1;

    if (!WINHTTP$WinHttpCrackUrl(URL, 0, 0, &urlComp)) {
        internal_printf("Failed to parse URL\n");
        return;
    }

    // Store hostname and path separately (ensure null-terminated copies)
    if (urlComp.lpszHostName && urlComp.dwHostNameLength > 0) {
        kHost = (wchar_t*)intAlloc((urlComp.dwHostNameLength + 1) * sizeof(wchar_t));
        if (!kHost) {
            internal_printf("Failed to allocate host buffer\n");
            return;
        }
        MSVCRT$memcpy(kHost, urlComp.lpszHostName, urlComp.dwHostNameLength * sizeof(wchar_t));
        kHost[urlComp.dwHostNameLength] = L'\0';
    }

    if (urlComp.lpszUrlPath && urlComp.dwUrlPathLength > 0) {
        kPath = (wchar_t*)intAlloc((urlComp.dwUrlPathLength + 1) * sizeof(wchar_t));
        if (!kPath) {
            intFree(kHost);
            internal_printf("Failed to allocate path buffer\n");
            return;
        }
        MSVCRT$memcpy(kPath, urlComp.lpszUrlPath, urlComp.dwUrlPathLength * sizeof(wchar_t));
        kPath[urlComp.dwUrlPathLength] = L'\0';
    } else {
        // Default to root path
        kPath = (wchar_t*)intAlloc(2 * sizeof(wchar_t));
        if (!kPath) {
            intFree(kHost);
            internal_printf("Failed to allocate default path buffer\n");
            return;
        }
        kPath[0] = L'/';
        kPath[1] = L'\0';
    }

    kPort = urlComp.nPort;
    ssl = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

	#ifndef BOF
    internal_printf("[DBG] Host: %ls, Path: %ls, Port: %lu, SSL: %d\n", kHost, kPath, kPort, ssl);
	#endif

	// Arm hardware breakpoints
	if (!ArmBps()){
		internal_printf("Failed to arm hardware breakpoints.\n");
		return;
	}


	g_forceNtlm = 1;

    // 1) Observe only
    g_cbtMode = 0; g_cbtModified = 0;
    DWORD baseline = trigger_winhttp_ntlm(kHost, kPath, kPort, ssl);
	if (baseline != 200) {
		// print the response
		internal_printf("[ERR] Baseline response: %lu\n", baseline);
		internal_printf("[ERR] Baseline request did not receive HTTP 200! Exiting...\n");

		if (baseline == 401) {
			internal_printf("[ERR] If using IP address, you may need to try hostname instead\n");
		}

		goto cleanup;
	}

	// 2) Zero CBT, and only for HTTPS
	DWORD zeroCBT;
	if (ssl) {
		g_cbtMode = 1; g_cbtModified = 0;
		zeroCBT = trigger_winhttp_ntlm(kHost, kPath, kPort, ssl);
	} else {
		zeroCBT = 200;
	}

    // 3) SPN override (service binding test)
    g_cbtMode = 0; g_cbtModified = 0;
    g_spnMode = 1; g_spnModified = 0;
    DWORD spnOverride = trigger_winhttp_ntlm(kHost, kPath, kPort, ssl);

	if (zeroCBT == 200 && spnOverride == 200) {
		internal_printf("[*] EPA is OFF\n");
	} else if (zeroCBT == 200 && spnOverride == 401) {
		internal_printf("[*] Invalid TargetName rejected!\n");
		internal_printf("[*] EPA is ACCEPT or REQUIRED (Service Binding)\n");
	} else if (zeroCBT == 401 && spnOverride == 200) {
		internal_printf("[*] Zeroed out channel binding token rejected!\n");
		internal_printf("[*] EPA is ACCEPT or REQUIRED (Channel Binding)\n");
	} else if (zeroCBT == 401 && spnOverride == 401) {
		internal_printf("[*] Invalid TargetName and zeroed out channel binding token rejected!\n");
		internal_printf("[!] This should not happen - EPA is UNKNOWN\n");
	} else {
		internal_printf("[*] EPA is UNKNOWN\n");
		internal_printf("[DBG] Invalid TargetName response: %lu\n", spnOverride);
		internal_printf("[DBG] Zeroed CBT response: %lu\n", zeroCBT);
	}

cleanup:
	//
    // Cleanup
	//
	if (kHost) { intFree(kHost); }
	if (kPath) { intFree(kPath); }
	HWBP_Clear(0);
	HWBP_ClearOnAllThreads(0);
	HWBP_Clear(1);
	HWBP_ClearOnAllThreads(1);
	HWBP_RemoveVeh(vehAchW);
	HWBP_RemoveVeh(vehIscW);

    return;
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    if(!bofstart()) { return; }

	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	wchar_t* kURL = (wchar_t*)BeaconDataExtract(&parser, NULL);	
	
	internal_printf("[*] Targeting URL: %ls\n", kURL);
	CheckProtection(kURL);

    printoutput(TRUE);
}
#else
int main() {
	CheckProtection(L"https://braavos.essos.local:443/certsrv/");
	//CheckProtection(L"http://braavos.essos.local:80/certsrv/");
	//CheckProtection(L"https://10.5.10.23/certsrv/");
    return 0;
}
#endif



