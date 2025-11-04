# Relay Informer BOFs
Beacon object files that allow an operator to determine EPA enforcement from a beacon's logon session, without supplying explicit credentials. Due to reliance on [`sspicli!InitializeSecurityContext`](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw) API calls, channel binding and target name AV pairs cannot be completely stripped from NTLM messages, meaning EPA enforcement level (required vs allowed/accepted/when supported) cannot be fully inferred. Each BOF is capable of determining if EPA is off or if a greater enforcement level is set. If the distinction between required and allowed/accepted/when supported is important for your use case, the Python `relay-informer` implementation can make this distinction, but requires knowledge of a cleartext credential or NTLM hash.

Only x64 builds are currently supported.

## Usage
Load the Cobalt Strike aggressor script from `informer/informer.cna`

## Available commands
|Commands|Usage|Notes|
|--------|-----|-----|
|http-relay-informer | [url]| Inform on HTTP(S) service binding enforcement and HTTPS channel binding enforcement|
|ldap-relay-informer | [host\|all]| Inform on LDAP signing enforcement and LDAPS channel binding enforcement|
|mssql-relay-informer | [host] [opt: port] [opt: database]| Inform on MSSQL service binding and channel binding enforcement|
|smb-relay-informer | [host]| Inform on SMB2 signing enforcement|

## How do the BOFs work?
Each BOF (except `smb-relay-informer`) sets hardware breakpoints targeting `sspicli!AcquireCredentialsHandleA/W` and/or `sspicli!InitializeSecurityContextA/W` in debug registers 0 and 1. A vectored exception handler is added to handle each API call. The handler inspects the parameters being passed to each API call and modifies parameters that aid us in determining EPA settings. Both of these APIs get called under the hood by various ODBC32, WINHTTP, and WLDAP32 APIs when it's time to authenticate to a serivce using the credentials of the calling user.

> [!NOTE]
> The `smb-relay-informer` BOF does not set any hardware breakpoints or initiaite authentication to the targeted SMB2 server. It only checks the server's response to a `SMB_COM_NEGOTIATE` request.

### AcquireCredentialsHandle
We care about the [pszPackage](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlea#parameters) parameter because we need to force NTLM authentication. The exception handler for `AcquireCredentialsHandle` monitors the incoming `pszPackage` parameter and flips any `Kerberos` or `Negotiate` references to `NTLM`.

### InitializeSecurityContext
Multiple [parameters](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw#parameters) are of interest depending on the test (service binding, channel binding, LDAP signing) being performed.

#### HTTP(S) and MSSQL Service Binding
The `pTargetName` parameter influences the `Target Name` AV pair sent to the server in the NTLM type 3 message. To determine if service binding is being enforced, valid target names (e.g., `HTTP/certserver.domain.local`) being passed into the ISC call are invalidated (e.g., `HTTP/relay.informer`).

#### HTTPS, LDAPS and MSSQL Channel Binding
The `pInput` parameter contains a pointer to a [SecBufferDesc](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc) structure, which will contain the valid channel binding token (CBT) passed into the NTLM type 3 channel bindings AV pair. By locating the valid [SEC_CHANNEL_BINDINGS](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings) structure, we can strip the channel binding application data. Windows will still send a channel bindings AV pair regardless, but when stripped the CBT will be `00000000000000000000000000000000`. If the server rejects this NTLM message, we can infer that EPA is required or accepted/allowed/when supported.

#### LDAP Signing
We can determine if LDAP signing is required by stripping specific flags from the `fContextReq` parameter. By removing the `ISC_REQ_INTEGRITY`, `ISC_REQ_SEQUENCE_DETECT` and `ISC_REQ_CONFIDENTIALITY` flags, we can elicit a [LDAP_STRONG_AUTH_REQUIRED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/return-values) error if LDAP signing is required.

## References and Credits
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
- [cube0x0](https://x.com/cube0x0) for [LdapSignCheck](https://github.com/cube0x0/LdapSignCheck)
- [VoldeSec](https://x.com/VoldeSec) for [PatchlessInlineExecute-Assembly](https://github.com/VoldeSec/PatchlessInlineExecute-Assembly)