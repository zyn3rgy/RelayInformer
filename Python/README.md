# Relay Informer
Python tool that enables an operator to determine EPA enforcement levels from a Linux host. Since NTLM messages are constructed without the Windows SSP, channel binding and target name AV pairs can stripped from NTLM messages, meaning EPA enforcement level (required vs allowed/accepted/when supported) *can* be fully inferred. A cleartext password or NTLM hash for a domain account is required for each module except the LDAPS method (`--method LDAPS`) of the LDAP module

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

### HTTP/HTTPS
```bash
# Test HTTPS server with password
uv run relayinformer http --url https://pki.domain.local/certsrv --user domain/username --password mypass

# Test HTTP server with NTLM hash
uv run relayinformer http --url http://pki.domain.local/certsrv --user domain\\username --hashes LM:NT
```

### LDAP/LDAPS
Check Domain Controllers for LDAP authentication protections. LDAPS checks can be done unauthenticated, while checking both LDAP and LDAPS requires authentication.

```bash
# Check LDAPS only (channel binding) on a single DC - unauthenticated
uv run relayinformer ldap --method LDAPS --dc-ip 192.168.1.10

# Lookup SRV records to check all DCs
uv run relayinformer ldap --method BOTH --dns -u username -p mypass -d domain.local
```

### MSSQL
```bash
# Test with password
uv run relayinformer mssql --target sql.domain.local --user domain/username --password mypass

# Specify custom port
uv run relayinformer mssql -t sql.domain.local -u admin -p mypass --port 1434
```

