#pragma once
#pragma intrinsic(memcmp, memcpy,strcpy,strcmp,_stricmp,strlen)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <windns.h>
#include <winldap.h>
#include <wtsapi32.h>
#include <sql.h>
#include <sqlext.h>
#include <stdio.h>
#include <winhttp.h>
#define SECURITY_WIN32
#include <sspi.h>


#ifdef _WIN32
#define STDCALL __stdcall
#else
#define STDCALL
#endif

#ifdef BOF

// KERNEL32
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI Kernel32$MultiByteToWideChar (UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI PVOID WINAPI KERNEL32$AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
WINBASEAPI ULONG WINAPI KERNEL32$RemoveVectoredExceptionHandler(PVOID Handle);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread();
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId();
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId();
WINBASEAPI BOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI BOOL WINAPI KERNEL32$SetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI BOOL WINAPI KERNEL32$GetComputerNameExA(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI SIZE_T WINAPI KERNEL32$VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);


#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

// MSVCRT
WINBASEAPI int __cdecl MSVCRT$atoi(const char *_Str);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *buf1, const void *buf2, size_t count);
WINBASEAPI int __cdecl MSVCRT$rand(void);
WINBASEAPI int __cdecl MSVCRT$srand(unsigned int _Seed);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char *_Str1,const char *_Str2,size_t _MaxCount);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strchr(const char *_Str,int _Ch);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncat(char * __restrict__ _Dest,const char * __restrict__ _Source,size_t _Count);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncpy(char * __restrict__ _Dest,const char * __restrict__ __src,size_t _Count);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strstr(const char * _Str,const char * _StrSearch);
WINBASEAPI time_t __cdecl MSVCRT$time(time_t *_Time);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
WINBASEAPI int __cdecl MSVCRT$_strnicmp(const char *_Str1,const char *_Str2, size_t count);
WINBASEAPI void * __cdecl MSVCRT$memmove(void * _Dst, const void * _Src, size_t _MaxCount);

// Provide BOF-local forwarders so compiler-emitted libcalls resolve
//  Cobalt Strike's coffloader whines about unresolved sysmbols without these
void * __cdecl memmove(void *dst, const void *src, size_t n) { return MSVCRT$memmove(dst, src, n); }
size_t __cdecl strlen(const char *s) { return MSVCRT$strlen(s); }

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// ODBC32
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle, SQLHANDLE* OutputHandlePtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLCloseCursor(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDescribeCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLCHAR* ColumnName, SQLSMALLINT BufferLength, SQLSMALLINT* NameLengthPtr, SQLSMALLINT* DataTypePtr, SQLULEN* ColumnSizePtr, SQLSMALLINT* DecimalDigitsPtr, SQLSMALLINT* NullablePtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDisconnect(SQLHDBC ConnectionHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLDriverConnect(SQLHDBC ConnectionHandle, SQLHWND WindowHandle, SQLCHAR* InConnectionString, SQLSMALLINT StringLength1, SQLCHAR* OutConnectionString, SQLSMALLINT BufferLength, SQLSMALLINT* StringLength2Ptr, SQLUSMALLINT DriverCompletion);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR* StatementText, SQLINTEGER TextLength);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLFetch(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLGetData(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength, SQLLEN* StrLen_or_IndPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLGetDiagRec(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber, SQLCHAR* Sqlstate, SQLINTEGER* NativeErrorPtr, SQLCHAR* MessageText, SQLSMALLINT BufferLength, SQLSMALLINT* TextLengthPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLNumResultCols(SQLHSTMT StatementHandle, SQLSMALLINT* ColumnCountPtr);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLMoreResults(SQLHSTMT StatementHandle);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLSetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
WINBASEAPI SQL_API SQLRETURN ODBC32$SQLSetStmtAttr(SQLHSTMT StatementHandle, SQLINTEGER Attribute, SQLPOINTER Value, SQLINTEGER StringLength);

//WS2_32
WINBASEAPI int STDCALL WS2_32$closesocket(SOCKET s);
WINBASEAPI u_short STDCALL WS2_32$htons(u_short hostshort);
WINBASEAPI int STDCALL WS2_32$inet_pton(int af, const char *src, void *dst);
WINBASEAPI int STDCALL WS2_32$recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
WINBASEAPI int STDCALL WS2_32$sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
WINBASEAPI int STDCALL WS2_32$setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen);
WINBASEAPI SOCKET STDCALL WS2_32$socket(int af, int type, int protocol);
WINBASEAPI int STDCALL WS2_32$WSACleanup();
WINBASEAPI int STDCALL WS2_32$WSAGetLastError();
WINBASEAPI int STDCALL WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
WINBASEAPI int STDCALL WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
WINBASEAPI int STDCALL WS2_32$send(SOCKET s, const char *buf, int len, int flags);
WINBASEAPI int STDCALL WS2_32$recv(SOCKET s, char *buf, int len, int flags);
WINBASEAPI int WSAAPI WS2_32$getaddrinfo(const char *nodename,const char *servname,const struct addrinfo *hints,struct addrinfo **res);
WINBASEAPI void WSAAPI WS2_32$freeaddrinfo(struct addrinfo *res);

// WLDAP32
WINBASEAPI ULONG WINAPI WLDAP32$ldap_connect(LDAP *ld, const struct l_timeval *timeout);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_unbind(LDAP *ld);
WINBASEAPI LDAP* WINAPI WLDAP32$ldap_initW(PWSTR HostName, ULONG PortNumber);
WINBASEAPI LDAP* WINAPI WLDAP32$ldap_sslinitW(PWSTR HostName, ULONG PortNumber, ULONG secure);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP *ld, int option, const void *invalue);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_sasl_bind_sW(LDAP *ld, const PWSTR dn, const PWSTR authmechanism, const BERVAL *cred, const PLDAPControlW *serverctrls, const PLDAPControlW *clientctrls, PBERVAL *serverdata);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP *ld, int option, const void *invalue);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_bind_s(LDAP *ld, const PSTR dn, const PWSTR cred, ULONG method);
WINBASEAPI LDAP* WINAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_bind(LDAP *ld, const PWSTR dn, const PWSTR cred, ULONG method);
WINBASEAPI ULONG WINAPI WLDAP32$ldap_get_optionW(LDAP *ld, int option, void *outvalue);

// DNSAPI
WINBASEAPI DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR lpstrName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORDA* ppQueryResults, PVOID* pReserved);
WINBASEAPI VOID WINAPI DNSAPI$DnsRecordListFree(PDNS_RECORDA pRecordList, DNS_FREE_TYPE FreeType);

// WINHTTP
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
WINBASEAPI HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET hInternet);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryAuthSchemes(HINTERNET hRequest, LPDWORD lpdwSupportedSchemes, LPDWORD lpdwFirstScheme, LPDWORD pdwAuthTarget);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpSetCredentials(HINTERNET hRequest, DWORD dwAuthTargets, DWORD dwAuthScheme, LPCWSTR pwszUserName, LPCWSTR pwszPassword, LPVOID pAuthParams);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpAddRequestHeaders(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
WINBASEAPI BOOL WINAPI WINHTTP$WinHttpCrackUrl(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);

#else

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// KERNEL32
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$CreateThread CreateThread
#define Kernel32$WideCharToMultiByte  WideCharToMultiByte 
#define Kernel32$MultiByteToWideChar MultiByteToWideChar
#define KERNEL32$HeapFree  HeapFree 
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$WaitForSingleObject WaitForSingleObject
#define KERNEL32$AddVectoredExceptionHandler AddVectoredExceptionHandler
#define KERNEL32$RemoveVectoredExceptionHandler RemoveVectoredExceptionHandler
#define KERNEL32$GetCurrentThread GetCurrentThread
#define KERNEL32$GetCurrentThreadId GetCurrentThreadId
#define KERNEL32$GetCurrentProcessId GetCurrentProcessId
#define KERNEL32$GetThreadContext GetThreadContext
#define KERNEL32$SetThreadContext SetThreadContext
#define KERNEL32$GetModuleHandleA GetModuleHandleA
#define KERNEL32$GetProcAddress GetProcAddress
#define KERNEL32$GetComputerNameExA GetComputerNameExA
#define KERNEL32$VirtualProtect VirtualProtect
#define KERNEL32$GetSystemInfo GetSystemInfo
#define KERNEL32$VirtualQuery VirtualQuery
#define KERNEL32$LoadLibraryA LoadLibraryA
#define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define KERNEL32$Thread32First Thread32First
#define KERNEL32$Thread32Next Thread32Next
#define KERNEL32$OpenThread OpenThread
#define KERNEL32$SuspendThread SuspendThread
#define KERNEL32$ResumeThread ResumeThread

// MSVCRT
#define MSVCRT$atoi atoi
#define MSVCRT$calloc calloc
#define MSVCRT$free free
#define MSVCRT$malloc malloc
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$memcmp memcmp
#define MSVCRT$rand rand
#define MSVCRT$srand srand
#define MSVCRT$sprintf sprintf
#define MSVCRT$strcat strcat
#define MSVCRT$strcmp strcmp
#define MSVCRT$strncmp strncmp
#define MSVCRT$strchr strchr
#define MSVCRT$strlen strlen
#define MSVCRT$strncat strncat
#define MSVCRT$strncpy strncpy
#define MSVCRT$strstr strstr
#define MSVCRT$time time
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$strcpy strcpy
#define MSVCRT$_strnicmp _strnicmp

// ODBC32
#define ODBC32$SQLAllocHandle SQLAllocHandle
#define ODBC32$SQLCloseCursor SQLCloseCursor
#define ODBC32$SQLDescribeCol SQLDescribeCol
#define ODBC32$SQLDisconnect SQLDisconnect
#define ODBC32$SQLDriverConnect SQLDriverConnect
#define ODBC32$SQLExecDirect SQLExecDirect
#define ODBC32$SQLFetch SQLFetch
#define ODBC32$SQLFreeHandle SQLFreeHandle
#define ODBC32$SQLGetData SQLGetData
#define ODBC32$SQLGetDiagRec SQLGetDiagRec
#define ODBC32$SQLNumResultCols SQLNumResultCols
#define ODBC32$SQLMoreResults SQLMoreResults
#define ODBC32$SQLSetEnvAttr SQLSetEnvAttr
#define ODBC32$SQLSetStmtAttr SQLSetStmtAttr

//WS2_32
#define WS2_32$closesocket closesocket
#define WS2_32$htons htons
#define WS2_32$inet_pton inet_pton
#define WS2_32$recvfrom recvfrom
#define WS2_32$sendto sendto
#define WS2_32$setsockopt setsockopt
#define WS2_32$socket socket
#define WS2_32$WSACleanup WSACleanup
#define WS2_32$WSAGetLastError WSAGetLastError
#define WS2_32$WSAStartup WSAStartup
#define WS2_32$connect connect
#define WS2_32$send send
#define WS2_32$recv recv
#define WS2_32$getaddrinfo getaddrinfo
#define WS2_32$freeaddrinfo freeaddrinfo

// WLDAP32
#define WLDAP32$ldap_initA ldap_initA
#define WLDAP32$ldap_sslinitA ldap_sslinitA
#define WLDAP32$ldap_set_optionA ldap_set_optionA
#define WLDAP32$ldap_connect ldap_connect
#define WLDAP32$ldap_bind_sA ldap_bind_sA
#define WLDAP32$ldap_unbind ldap_unbind
#define WLDAP32$ldap_initW ldap_initW
#define WLDAP32$ldap_sslinitW ldap_sslinitW
#define WLDAP32$ldap_set_optionW ldap_set_optionW
#define WLDAP32$ldap_sasl_bind_sW ldap_sasl_bind_sW
#define WLDAP32$ldap_get_optionW ldap_get_optionW

// DNSAPI
#define DNSAPI$DnsQuery_A DnsQuery_A
#define DNSAPI$DnsRecordListFree DnsRecordListFree
#define WLDAP32$ldap_bind_s ldap_bind_s
#define WLDAP32$ldap_init ldap_init
#define WLDAP32$ldap_bind ldap_bind
#define WLDAP32$ldap_get_optionW ldap_get_optionW

// WINHTTP
#define WINHTTP$WinHttpOpen WinHttpOpen
#define WINHTTP$WinHttpConnect WinHttpConnect
#define WINHTTP$WinHttpOpenRequest WinHttpOpenRequest
#define WINHTTP$WinHttpSendRequest WinHttpSendRequest
#define WINHTTP$WinHttpReceiveResponse WinHttpReceiveResponse
#define WINHTTP$WinHttpQueryHeaders WinHttpQueryHeaders
#define WINHTTP$WinHttpReadData WinHttpReadData
#define WINHTTP$WinHttpCloseHandle WinHttpCloseHandle
#define WINHTTP$WinHttpSetOption WinHttpSetOption
#define WINHTTP$WinHttpQueryAuthSchemes WinHttpQueryAuthSchemes
#define WINHTTP$WinHttpSetCredentials WinHttpSetCredentials
#define WINHTTP$WinHttpAddRequestHeaders WinHttpAddRequestHeaders
#define WINHTTP$WinHttpQueryDataAvailable WinHttpQueryDataAvailable
#define WINHTTP$WinHttpQueryOption WinHttpQueryOption
#define WINHTTP$WinHttpCrackUrl WinHttpCrackUrl

#endif
