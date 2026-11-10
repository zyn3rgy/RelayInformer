# RelayInformer - Python
Python tool that enables an operator to determine EPA enforcement levels from a Linux host. Since NTLM messages are constructed without the Windows SSP, channel binding and target name AV pairs can stripped from NTLM messages, meaning EPA enforcement level (required vs allowed/accepted/when supported) *can* be fully inferred. A cleartext password or NTLM hash for a domain account is required for each module except the LDAPS channel binding and LDAP signing bypass checks of the LDAP module

## Installation
Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
Install `relayinformer`
```
git clone https://github.com/zyn3rgy/RelayInformer
cd RelayInformer/Python
uv sync
uv run relayinformer -h
```

## Usage Examples

#### LDAP/LDAPS
Determine the exact level of EPA enforcement and server signing enforced on Domain Controllers. This module has options for LDAPS (checks EPA enforcement) or both LDAPS and LDAP (checks server signing requirements and the [LDAP signing bypass](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/), CVE-2026-70229).

> [!NOTE]
> LDAPS (EPA) and the signing bypass can be determined **unauthenticated**. LDAP server signing requires a **valid domain user credential**. Without one, `--method BOTH` skips the signing check and still runs the bypass check.

```bash
# Check LDAPS only (channel binding) - unauthenticated
uv run relayinformer ldap --method LDAPS --dc-ip 192.168.1.10

# Check LDAPS and the LDAP signing bypass - unauthenticated (signing enforcement not checked)
uv run relayinformer ldap --method BOTH --target dc01.domain.local

# Lookup SRV records to check all DCs
uv run relayinformer ldap --method BOTH --dc-ip 192.168.1.10 --dns 192.168.1.53 -u username -p mypass -d domain.local

# Check one known DC directly without SRV discovery
uv run relayinformer ldap --method LDAPS --target dc01.domain.local -d domain.local

# Check known DCs from a file without SRV discovery
uv run relayinformer ldap --method BOTH --target dc-targets.txt -u username -p mypass -d domain.local
```

#### HTTP/HTTPS

Determine exact level of EPA enforcement for standard HTTP and HTTPS services.

> [!NOTE]
> Requires a password or ntlm hash for a user that can authenticate (recieve a 200 response code) to the target service. 

```bash
# Test HTTPS server with password
uv run relayinformer http --url https://pki.domain.local/certsrv --user domain/username --password mypass

# Test HTTP server with NTLM hash
uv run relayinformer http --url http://pki.domain.local/certsrv --user domain\\username --hashes LM:NT
```

#### MSSQL

Determine the exact level of EPA enforcement for MSSQL services, regardless of encryption requirements. 

> [!NOTE]
> Requires a valid domain user credential, and that user does not need access to the database.

```bash
# Test with password
uv run relayinformer mssql --target sql.domain.local --user domain/username --password mypass

# Specify custom port
uv run relayinformer mssql -t sql.domain.local -u domain/admin -p mypass --port 1434
```
