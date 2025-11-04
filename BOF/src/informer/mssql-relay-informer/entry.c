#include "bofdefs.h"
#include "base.c"
#include "sql.c"

static const wchar_t g_fakeSpnW[] = L"MSSQLSvc/relay.informer";

#include "hwbp.c"

static SQLINTEGER trigger_sql_auth(char* host, int port, char* database) {
    SQLHENV env		= NULL;
    SQLHSTMT stmt 	= NULL;
	SQLHDBC dbc 	= NULL;
	SQLRETURN ret;

    // native error code is our indicator of EPA enforcement
    SQLINTEGER nativeError = 0;

	dbc = ConnectToSqlServer(&env, host, port, database, &nativeError);

    DisconnectSqlServer(env, dbc, stmt);
       
    return nativeError;
}

void CheckProtection(char* host, int port, char* database) {
    // Quick TDS PreLogin probe for encryption policy
    int enc = TdsPreloginCheckEncryption(host, (unsigned short)port);

    #ifndef BOF
    internal_printf("[DBG] TDS PreLogin ENCRYPTION=%d (0=OFF,1=ON,2=NOT_SUP,3=REQUIRE)\n", enc);
    #endif

    if (enc == -1) {
        internal_printf("[ERR] Failed to connect to SQL Server\n");
        return;
    }
    
    // Arm DR-based hardware breakpoints using sspicli exports and existing VEH handlers
    PVOID vehAchA = NULL; void* addrAchA = NULL;
    if (!HWBP_SetOnApiEx("sspicli.dll", "AcquireCredentialsHandleA", 0, ACH_A_VEH, &vehAchA, &addrAchA, FALSE)) {
		internal_printf("Failed to set HWBP on sspicli!AcquireCredentialsHandleW (DR0).\n");
		return;
	}
    
    PVOID vehIscA = NULL; void* addrIscA = NULL;
    if (!HWBP_SetOnApiEx("sspicli.dll", "InitializeSecurityContextA", 1, ISC_A_VEH, &vehIscA, &addrIscA, FALSE)) {
		internal_printf("Failed to set HWBP on sspicli!InitializeSecurityContextW (DR1).\n");
		return;
	}

    g_forceNtlm = 1;
    g_cbtMode = 0; g_cbtModified = 0;

    // will hold the native error code from ODBC32$SQLGetDiagRec
    // and will be used to determine EPA enforcement
    SQLINTEGER result = 0;

    switch (enc) {
        case 0:
            // SPN override (service binding test)
            internal_printf("[*] Force Encryption is OFF, checking service binding...\n");
            g_spnMode = 1; g_spnModified = 0;
            result = trigger_sql_auth(host, port, database);
            g_spnMode = 0; g_spnModified = 0;
            break;

        case 1:
            break;
        case 2:
            break;
        case 3:
            // SQL Driver used sends an all 0x00 CBT
            // this will fail if EPA is allowed/required
            internal_printf("[*] ForceEncryption is ON, checking channel binding...\n");
            result = trigger_sql_auth(host, port, database);
            break;
    }

    // if result is 18456 (login failed) then EPA is off 
    // and our user does not have access to the database
    if (result == 18456) {    
        internal_printf("[*] EPA is OFF\n");
    }
    // if result is 18452 (login is from an untrusted domain/integrated auth)
    // then EPA is allowed or required
    else if (result == 18452) {
        internal_printf("[*] EPA is ALLOWED or REQUIRED\n");
    }
    // if result is 0 (login succeeded) then EPA is off
    else {
        internal_printf("[*] EPA is OFF\n");
        internal_printf("[+] Database login successful, we have access to the database\n");
    }

    //
    // Cleanup
    //
    HWBP_Clear(0);
    HWBP_Clear(1);
    HWBP_RemoveVeh(vehAchA);
    HWBP_RemoveVeh(vehIscA);
    return;
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    if(!bofstart()) { return; }

	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	
	char* host = (char*)BeaconDataExtract(&parser, NULL);
	int port = BeaconDataInt(&parser);
    char* database = (char*)BeaconDataExtract(&parser, NULL);

    if (!database) {
        database = "master";
    }

    //ensure not null
	if (!host || !port) {
		internal_printf("[ERR] Host or port is null\n");
		return;
	}

    internal_printf("[*] Target: mssql://%s:%d\n", host, port);
	CheckProtection(host, port, database);

    printoutput(TRUE);
}
#else
int main() {
	//
	// Constants for testing
	//
	//char* host = "10.5.10.22";
    char* host = "castelblack.north.sevenkingdoms.local";
	int port = 1433;
    char* database = "master";

	CheckProtection(host, port, database);

    return 0;
}
#endif



