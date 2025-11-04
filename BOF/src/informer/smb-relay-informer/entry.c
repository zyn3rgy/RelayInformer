//
// Claude to the rescue
//

#include "bofdefs.h"
#include "base.c"

// Minimal SMB2 NEGOTIATE probe to read server SecurityMode
// Returns: -1 on error; otherwise SecurityMode bits from NEGOTIATE Response
//  bit0 (0x01): SIGNING_ENABLED; bit1 (0x02): SIGNING_REQUIRED
static int Smb2ProbeSecurityMode(const char* host)
{
    WSADATA wsa; if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) return -1;
    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WS2_32$WSACleanup(); return -1; }

    struct sockaddr_in sin; intZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = WS2_32$htons(445);
    if (WS2_32$inet_pton(AF_INET, host, &sin.sin_addr) != 1) {
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

    // SMB2 NEGOTIATE request over TCP (no NetBIOS session service header needed on modern stacks)
    // Structure sizes and fields follow MS-SMB2; this is a minimal dialect list (0x0202, 0x0311)
    unsigned char req[200]; int p = 0;
    // Framing: NetBIOS Session Service header (RFC 1002) is still used: 1 byte type (0x00), 3-byte length
    // We'll fill length later. Type=0x00 Session Message.
    int nbLenPos = p; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;

    // SMB2 Header (64 bytes)
    // ProtocolId: 0xFE,'S','M','B'
    req[p++] = 0xFE; req[p++] = 'S'; req[p++] = 'M'; req[p++] = 'B';
    // StructureSize (2)
    req[p++] = 0x40; req[p++] = 0x00;
    // CreditCharge (2)
    req[p++] = 0x00; req[p++] = 0x00;
    // ChannelSequence (2) + Reserved (2)
    req[p++] = 0x00; req[p++] = 0x00; // ChannelSequence
    req[p++] = 0x00; req[p++] = 0x00; // Reserved
    // Command (2) = NEGOTIATE(0)
    req[p++] = 0x00; req[p++] = 0x00;
    // CreditRequest (2)
    req[p++] = 0x00; req[p++] = 0x00;
    // Flags (4)
    req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;
    // NextCommand (4)
    req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;
    // MessageId (8)
    for (int i = 0; i < 8; i++) req[p++] = 0x00;
    // Reserved (4)
    for (int i = 0; i < 4; i++) req[p++] = 0x00;
    // TreeId (4)
    for (int i = 0; i < 4; i++) req[p++] = 0x00;
    // SessionId (8)
    for (int i = 0; i < 8; i++) req[p++] = 0x00;
    // Signature (16)
    for (int i = 0; i < 16; i++) req[p++] = 0x00;

    // SMB2 NEGOTIATE Request body
    int bodyStart = p;
    req[p++] = 0x24; req[p++] = 0x00; // StructureSize = 36
    req[p++] = 0x01; req[p++] = 0x00; // DialectCount = 1
    req[p++] = 0x00; req[p++] = 0x00; // SecurityMode (client caps) - leave 0
    req[p++] = 0x00; req[p++] = 0x00; // Reserved
    // Capabilities (4)
    req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;
    // ClientGUID (16)
    for (int i = 0; i < 16; i++) req[p++] = (unsigned char)MSVCRT$rand();
    // For SMB2.1 and earlier: ClientStartTime (8)
    req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;
    req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00; req[p++] = 0x00;
    // Dialects (2 each)
    req[p++] = 0x10; req[p++] = 0x02; // 0x0210 (SMB 2.1)

    // Patch NetBIOS length (big-endian 3 bytes) excluding the first header byte
    int smbLen = p - 4; // after 4-byte NBSS header
    req[nbLenPos + 1] = (unsigned char)((smbLen >> 16) & 0xFF);
    req[nbLenPos + 2] = (unsigned char)((smbLen >> 8) & 0xFF);
    req[nbLenPos + 3] = (unsigned char)(smbLen & 0xFF);

    if (WS2_32$send(s, (const char*)req, p, 0) != p) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }

    // Read NBSS header then rest
    unsigned char hdr[4]; int rcv = 0;
    while (rcv < 4) {
        int r = WS2_32$recv(s, (char*)hdr + rcv, 4 - rcv, 0);
        if (r <= 0) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }
        rcv += r;
    }
    if (hdr[0] != 0x00) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }
    int payloadLen = ((int)hdr[1] << 16) | ((int)hdr[2] << 8) | hdr[3];
    if (payloadLen <= 0 || payloadLen > 0xFFFF) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }

    unsigned char* buf = (unsigned char*)intAlloc((size_t)payloadLen);
    if (!buf) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return -1; }
    int got = 0;
    while (got < payloadLen) {
        int r = WS2_32$recv(s, (char*)buf + got, payloadLen - got, 0);
        if (r <= 0) break; got += r;
    }

    WS2_32$closesocket(s);
    WS2_32$WSACleanup();

    int result = -1;
    if (got >= 64 + 2) { // need SMB2 header + at least start of body
        // Validate SMB2 header
        if (buf[0] == 0xFE && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B') {
            // Command should be NEGOTIATE (0)
            if (buf[12] == 0x00 && buf[13] == 0x00) {
                // NEGOTIATE Response body follows header
                const unsigned char* body = buf + 64;
                // StructureSize (2) should be 65 for response; SecurityMode (2) at offset 2
                int respStruct = body[0] | (body[1] << 8);
                if (respStruct >= 65) {
                    int securityMode = body[2] | (body[3] << 8);
                    result = securityMode & 0x03; // enabled/required bits
                }
            }
        }
    }
    intFree(buf);
    return result;
}

void CheckProtection(const char* host) {
    internal_printf("[*] Target: smb://%s\n", host);
    int sm = Smb2ProbeSecurityMode(host);
    if (sm < 0) {
        internal_printf("[ERR] Probe failed or no response\n");
    } else {
        BOOL enabled = (sm & 0x01) != 0;
        BOOL required = (sm & 0x02) != 0;
        
        if (enabled && required) {
            internal_printf("[*] SMB2 SecurityMode: Signing is ENABLED and REQUIRED\n");
        } else if (enabled) {
            internal_printf("[*] SMB2 SecurityMode: Signing is ENABLED but NOT REQUIRED\n");
        } else {
            internal_printf("[*] SMB2 SecurityMode: Signing is DISABLED\n");
        }
    }
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if(!bofstart()) { return; }

    datap parser; BeaconDataParse(&parser, Buffer, Length);
    char* host = (char*)BeaconDataExtract(&parser, NULL);
    
    if (!host) {
        internal_printf("[ERR] host is required\n");
        return;
    }

    CheckProtection(host);

    printoutput(TRUE);
}
#else
int main()
{
    const char* host = "castelblack.north.sevenkingdoms.local";
    CheckProtection(host);
    return 0;
}
#endif


