#include <windows.h>
#include <sql.h>
#include <odbcss.h>


//
// prints a SQL error message
//
SQLINTEGER ShowError(unsigned int handletype, const SQLHANDLE* handle)
{
    SQLCHAR sqlstate[1024];
    SQLCHAR message[1024];
    SQLINTEGER nativeError = 0;
    ODBC32$SQLGetDiagRec(handletype, (SQLHANDLE)handle, 1, sqlstate, &nativeError, message, 1024, NULL);
    return nativeError;
}

// Return codes for TDS PreLogin encryption policy
// 0: ENCRYPT_OFF, 1: ENCRYPT_ON, 2: ENCRYPT_NOT_SUP, 3: ENCRYPT_REQ

// Minimal TDS PreLogin over TCP to query server encryption policy
// Returns: -1 error; otherwise ENCRYPT_* value read from server ENCRYPTION option
int TdsPreloginCheckEncryption(const char* host, unsigned short port) {
    
    WSADATA wsa; if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) return -1;
    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WS2_32$WSACleanup(); return -1; }

    struct sockaddr_in sin; intZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = WS2_32$htons(port);
    if (WS2_32$inet_pton(AF_INET, host, &sin.sin_addr) != 1) {
        // Fallback DNS resolution
        struct addrinfo hints; intZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
        struct addrinfo* res = NULL;
        if (WS2_32$getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
            struct sockaddr_in* ain = (struct sockaddr_in*)res->ai_addr;
            sin.sin_addr = ain->sin_addr;
            WS2_32$freeaddrinfo(res);
        } else { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }
    }

    if (WS2_32$connect(s, (struct sockaddr*)&sin, sizeof(sin)) != 0) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }

    // Build PreLogin request with VERSION and ENCRYPTION options
    // Option table: [Token(1) Offset(2) Length(2)] ... 0xFF terminator ... data blobs
    unsigned char payload[64]; int p = 0;
    const unsigned char TOKEN_VERSION    = 0x00;
    const unsigned char TOKEN_ENCRYPTION = 0x01;

    // VERSION entry
    payload[p++] = TOKEN_VERSION;
    int verOffPos = p; payload[p++] = 0; payload[p++] = 0; // offset placeholder
    payload[p++] = 0x00; payload[p++] = 0x06; // length = 6

    // ENCRYPTION entry
    payload[p++] = TOKEN_ENCRYPTION;
    int encOffPos = p; payload[p++] = 0; payload[p++] = 0; // offset placeholder
    payload[p++] = 0x00; payload[p++] = 0x01; // length = 1

    // Terminator
    payload[p++] = 0xFF;

    // Data blobs start here
    int dataStart = p;
    // VERSION 6 bytes: major, minor, buildHi, buildLo, subBuildHi, subBuildLo
    // Use requested version 8.0.341 => major=8, minor=0, build=341 (0x0155), subBuild=0
    payload[p++] = 0x08; // major
    payload[p++] = 0x00; // minor
    payload[p++] = 0x01; // build hi (0x0155)
    payload[p++] = 0x55; // build lo
    payload[p++] = 0x00; // subBuild hi
    payload[p++] = 0x00; // subBuild lo

    // ENCRYPTION value (client value is ignored; server replies with its policy)
    payload[p++] = 0x00; // send 0x00 here; server will still return its policy

    // Patch offsets (big-endian) relative to start of payload
    int verDataOff = dataStart;
    int encDataOff = dataStart + 6;
    payload[verOffPos]   = (unsigned char)((verDataOff >> 8) & 0xFF);
    payload[verOffPos+1] = (unsigned char)(verDataOff & 0xFF);
    payload[encOffPos]   = (unsigned char)((encDataOff >> 8) & 0xFF);
    payload[encOffPos+1] = (unsigned char)(encDataOff & 0xFF);

    // Build TDS header + payload
    unsigned char pkt[96]; int idx = 0;
    pkt[idx++] = 0x12; // PRELOGIN
    pkt[idx++] = 0x01; // EOM
    int lenPos = idx; pkt[idx++] = 0; pkt[idx++] = 0; // Length (to patch)
    pkt[idx++] = 0x00; pkt[idx++] = 0x00; // SPID
    pkt[idx++] = 0x01; // PacketID
    pkt[idx++] = 0x00; // Window

    int payloadLen = p;
    for (int i = 0; i < payloadLen; i++) pkt[idx++] = payload[i];

    int totalLen = idx;
    pkt[lenPos]   = (unsigned char)((totalLen >> 8) & 0xFF);
    pkt[lenPos+1] = (unsigned char)(totalLen & 0xFF);

    if (WS2_32$send(s, (const char*)pkt, totalLen, 0) != totalLen) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }

    // Read full response based on TDS header length
    unsigned char resp[1024]; int received = 0;
    // First read header
    while (received < 8) {
        int r = WS2_32$recv(s, (char*)resp + received, 8 - received, 0);
        if (r <= 0) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }
        received += r;
    }
    int respLen = ((int)resp[2] << 8) | resp[3];
    if (respLen < 8 || respLen > (int)sizeof(resp)) respLen = (int)sizeof(resp);
    while (received < respLen) {
        int r = WS2_32$recv(s, (char*)resp + received, respLen - received, 0);
        if (r <= 0) break;
        received += r;
    }
    if (received < 9) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }

    // Parse response option table
    const unsigned char* rp = resp + 8; int rem = received - 8; int i = 0;
    int encOffset = -1, encLen = 0;
    while (i < rem) {
        unsigned char tok = rp[i++];
        if (tok == 0xFF) break; // terminator
        if (i + 4 > rem) break;
        int off = ((int)rp[i] << 8) | rp[i+1]; i += 2;
        int len = ((int)rp[i] << 8) | rp[i+1]; i += 2;
        if (tok == TOKEN_ENCRYPTION) { encOffset = off; encLen = len; }
    }
    int result = -1;
    if (encOffset >= 0 && encLen >= 1 && encOffset + encLen <= rem) {
        result = (int)rp[encOffset];
    }

    WS2_32$closesocket(s);
    WS2_32$WSACleanup();
    return result;
}

//
// Clear the cursor so it can be closed without a 24000 Invalid Cursor State error
//
void ClearCursor(SQLHSTMT stmt)
{
    SQLRETURN ret = SQL_SUCCESS;
    
    //
    // Fetch all results to clear the cursor
    //
    while(ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
        ODBC32$SQLFetch(stmt);
        ret = ODBC32$SQLMoreResults(stmt);
    }
}

//
// Connect to a SQL server
//
SQLHDBC ConnectToSqlServer(SQLHENV* env, char* server, int port, char* dbName, SQLINTEGER* nativeError)
{
    SQLRETURN ret;
    SQLCHAR connstr[1024];
    SQLHDBC dbc = NULL;

    // Allocate an environment handle and set ODBC version
    ret = ODBC32$SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, env);
    if (!SQL_SUCCEEDED(ret)) { ShowError(SQL_HANDLE_ENV, *env); return NULL; }
    ret = ODBC32$SQLSetEnvAttr(*env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
    if (!SQL_SUCCEEDED(ret)) { ShowError(SQL_HANDLE_ENV, *env); return NULL; }

    // Allocate a connection handle
    ret = ODBC32$SQLAllocHandle(SQL_HANDLE_DBC, *env, &dbc);
    if (!SQL_SUCCEEDED(ret)) { ShowError(SQL_HANDLE_ENV, *env); return NULL; }

    if (dbName == NULL)
    {
        MSVCRT$sprintf((char*)connstr, "DRIVER={SQL Server};SERVER=%s,%d;Trusted_Connection=Yes;TrustServerCertificate=yes;", server, port);
    } else
    {
        MSVCRT$sprintf((char*)connstr, "DRIVER={SQL Server};SERVER=%s,%d;DATABASE=%s;Trusted_Connection=Yes;TrustServerCertificate=yes;", server, port, dbName);
    }
    
    ret = ODBC32$SQLDriverConnect(dbc, NULL, connstr, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    
    if (!SQL_SUCCEEDED(ret))
    {
        *nativeError = ShowError(SQL_HANDLE_DBC, dbc);
        return NULL;
    }
    
    return dbc;
}

//
// Close the connection to a SQL server
//
void DisconnectSqlServer(SQLHENV env, SQLHDBC dbc, SQLHSTMT stmt)
{
    SQLRETURN ret;

    if (stmt != NULL) { ret = ODBC32$SQLFreeHandle(SQL_HANDLE_STMT, stmt); }
    if (dbc != NULL) {
        ret = ODBC32$SQLDisconnect(dbc);
        ret = ODBC32$SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    }
    if (env != NULL) { ret = ODBC32$SQLFreeHandle(SQL_HANDLE_ENV, env); }
}

