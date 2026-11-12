import urllib.parse
import dns.resolver
import ldap3
import ssl
import socket
import time
import asyncio
import typer
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory

from relayinformer.logger import logger


# Fixed LDAP messages for the signing bypass probe. No credentials are ever sent.
# messageID 1: BindRequest, version 3, empty DN, empty simple password (anonymous bind)
LDAP_ANON_BIND = bytes.fromhex("300c020101600702010304008000")
# messageID 2: ExtendedRequest "Who am I?" (1.3.6.1.4.1.4203.1.11.3)
LDAP_WHOAMI = bytes.fromhex("301e02010277198017312e332e362e312e342e312e343230332e312e31312e33")

ERROR_CODES = {
    "data 525": "account does not exist",
    "data 52e": "wrong user name or password",
    "data 530": "not allowed to log on at this time",
    "data 531": "not allowed to log on from this computer",
    "data 532": "password has expired",
    "data 533": "account is disabled",
    "data 701": "account has expired",
    "data 773": "password must be changed",
    "data 775": "account is locked out",
}


class LdapInformer:

    def __init__(self, fqdn, user, password):
        self.fqdn = fqdn
        self.user = user
        self.password = password

    #
    # Conduct and LDAP bind and determine if server signing requirements
    #   are enforced based on potential errors during the bind attempt 
    #
    def RunLdap(self, target):
        ldapServer = ldap3.Server(
            target, use_ssl=False, port=389, get_info=ldap3.ALL)
        ldapConn = ldap3.Connection(
            ldapServer, user=f"{self.fqdn}\\{self.user}", password=self.password, authentication=ldap3.NTLM)
        if not ldapConn.bind():
            ldapConn_result_str = str(ldapConn.result)
            if "stronger" in ldapConn_result_str:
                return True #because LDAP server signing requirements ARE enforced
            else:
                for code, meaning in ERROR_CODES.items():
                    if code in ldapConn_result_str:
                        logger.error("Error " + code + " - " + meaning)
                        raise typer.Exit(1)
                logger.error("UNEXPECTED ERROR: " + ldapConn_result_str)
                raise typer.Exit(1)
        else:
            #LDAPS bind successful
            return False #because LDAP server signing requirements are not enforced
        

    #
    # Check for the LDAP signing bypass (CVE-2026-70229). An anonymous bind and a
    #   whoami are sent stacked in a single write. An unpatched DC answers both; a
    #   patched DC discards the stacked whoami. If the whoami goes unanswered, a control
    #   run sends the same two messages one at a time to confirm the DC does answer
    #   whoami normally, so the silence can be attributed to the patch.
    #   Returns (verdict, bind_rc): verdict is "UNPATCHED", "PATCHED" or "INCONCLUSIVE".
    #
    @staticmethod
    def RunLdapSigningBypass(target, timeout):
        with socket.create_connection((target, 389), timeout=timeout) as sock:
            msgs = LdapInformer._LdapExchange(sock, LDAP_ANON_BIND + LDAP_WHOAMI, 2, timeout)

        bind_rc = next((rc for msgid, rc in msgs if msgid == 1), None)
        logger.debug(f"{target} - bypass probe bind rc={bind_rc}, responses={msgs}")
        if any(msgid == 2 for msgid, _ in msgs):
            return "UNPATCHED", bind_rc
        if bind_rc is None:
            return "INCONCLUSIVE", None

        with socket.create_connection((target, 389), timeout=timeout) as sock:
            LdapInformer._LdapExchange(sock, LDAP_ANON_BIND, 1, timeout)
            control = LdapInformer._LdapExchange(sock, LDAP_WHOAMI, 2, timeout)
        logger.debug(f"{target} - bypass control responses={control}")
        if any(msgid == 2 for msgid, _ in control):
            return "PATCHED", bind_rc
        return "INCONCLUSIVE", bind_rc

    #
    # Send data, then read until a response with messageID want_msgid arrives, the
    #   server closes the connection, or timeout seconds pass in total.
    #
    @staticmethod
    def _LdapExchange(sock, data, want_msgid, timeout):
        sock.sendall(data)
        deadline = time.monotonic() + timeout
        buf = b""
        while True:
            msgs = LdapInformer._ParseLdapMessages(buf)
            remaining = deadline - time.monotonic()
            if any(msgid == want_msgid for msgid, _ in msgs) or remaining <= 0:
                return msgs
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(8192)
            except OSError:
                return msgs
            if not chunk:
                return msgs
            buf += chunk

    #
    # Minimal BER parsing: returns [(messageID, bind_rc)] for each complete LDAPMessage
    #   in buf. bind_rc is the resultCode of a BindResponse, None for anything else.
    #
    @staticmethod
    def _ParseLdapMessages(buf):
        def read_tlv(i):
            # (tag, value_start, value_end) of the TLV at buf[i], or None if incomplete
            if i + 2 > len(buf):
                return None
            tag, length, j = buf[i], buf[i + 1], i + 2
            if length & 0x80:
                n = length & 0x7F
                if j + n > len(buf):
                    return None
                length = int.from_bytes(buf[j:j + n], "big")
                j += n
            if j + length > len(buf):
                return None
            return tag, j, j + length

        msgs = []
        i = 0
        while (msg := read_tlv(i)) and msg[0] == 0x30:
            msgid_tlv = read_tlv(msg[1])
            if not msgid_tlv or msgid_tlv[0] != 0x02:
                break
            msgid = int.from_bytes(buf[msgid_tlv[1]:msgid_tlv[2]], "big")
            bind_rc = None
            op = read_tlv(msgid_tlv[2])
            if op and op[0] == 0x61:  # BindResponse
                rc = read_tlv(op[1])
                if rc and rc[0] == 0x0A:
                    bind_rc = int.from_bytes(buf[rc[1]:rc[2]], "big")
            msgs.append((msgid, bind_rc))
            i = msg[2]
        return msgs

    #
    # Domain Controllers do not have a certificate setup for LDAPS on port 636 by default.
    #   If this has not been setup, the TLS handshake will hang and you will not be able to 
    #   interact with LDAPS. The condition for the certificate existing as it should is either 
    #    an error regarding the fact that the certificate is self-signed, or no error at all. 
    #    Any other "successful" edge cases not yet accounted for.
    #
    @staticmethod
    def DoesLdapsCompleteHandshake(target):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)

        # Use SSLContext-based wrapping (wrap_socket is removed in Python 3.12)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL

        ssl_sock = context.wrap_socket(
            s,
            server_hostname=target,
            do_handshake_on_connect=False
        )
        try:
            ssl_sock.connect((target, 636))
            try:
                ssl_sock.do_handshake()
                return True
            except Exception as e:
                # Treat cert verification errors as a sign that TLS is enabled
                if isinstance(e, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(e):
                    return True
                # Timeouts indicate LDAPS is likely not configured
                if isinstance(e, (TimeoutError, socket.timeout)) or "handshake operation timed out" in str(e):
                    return False
                else:
                    raise
        finally:
            ssl_sock.close()

    #
    # Conduct a bind to LDAPS and determine if channel binding is enforced based 
    #   on the contents of potential errors returned. This can be determined 
    #   unauthenticated, because the error indicating channel binding enforcement
    #   will be returned regardless of a successful LDAPS bind.
    #
    def RunLdapsNoEpa(self, target):
        try:
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            ldapServer = ldap3.Server(
                target, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
            ldapConn = ldap3.Connection(
                ldapServer, user=f"{self.fqdn}\\{self.user}", password=self.password, authentication=ldap3.NTLM)
            if not ldapConn.bind():
                if "data 80090346" in str(ldapConn.result):
                    return True #channel binding IS enforced
                elif "data 52e" in str(ldapConn.result):
                    return False #channel binding not enforced
                else:
                    ldapConn_result_str = str(ldapConn.result)
                    for code, meaning in ERROR_CODES.items():
                        if code in ldapConn_result_str:
                            logger.error("Error " + code + " - " + meaning)
                            raise typer.Exit(1)
                    logger.error("UNEXPECTED ERROR: " + ldapConn_result_str)
                    raise typer.Exit(1)
            else:
                #LDAPS bind successful
                return False #because channel binding is not enforced
        except typer.Exit:
            raise
        except Exception as e:
            logger.error(f"{target} - {str(e)}")
            logger.warning("Ensure DNS is resolving properly, and that you can reach LDAPS on this host")


    #
    # Conduct a bind to LDAPS with channel binding supported but intentionally
    #   miscalculated. In the case that and LDAPS bind has without channel binding
    #   supported has occured, you can determine whether the policy is set to "never"
    #   or if it's set to "when supported" based on the potential error recieved
    #   from the bind attempt.
    #
    async def RunLdapsWithEpa(self, target, timeout):
        try:
            password = urllib.parse.quote(self.password)
            url = f'ldaps+ntlm-password://{self.fqdn}\\{self.user}:{password}@{target}'
            conn_url = LDAPConnectionFactory.from_url(url)
            ldaps_client = conn_url.get_client()
            ldaps_client.target.timeout = timeout
            ldapsClientConn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
            _, err = await ldapsClientConn.connect()
            if err is not None:
                raise err
            #forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
            ldapsClientConn.cb_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            _, err = await ldapsClientConn.bind()
            if "data 80090346" in str(err):
                return True
            elif "data 52e" in str(err):
                return False
            elif err is not None:
                logger.error(f"Error while connecting to {target}: {err}")
            elif err is None:
                return False
        except Exception as e:
            logger.error(f"Something went wrong during LdapsWithEpa bind: {str(e)}")


    #
    # DNS query of an SRV record that should return
    #   a list of domain controllers.
    #
    def ResolveDCs(nameserverIp, fqdn):
        dcList = set()
        DnsResolver = dns.resolver.Resolver()
        DnsResolver.timeout = 20
        DnsResolver.nameservers = [nameserverIp]
        dcQuery = DnsResolver.resolve(
            f"_ldap._tcp.dc._msdcs.{fqdn}", 
            'SRV',
            tcp=True
        )

        testout = str(dcQuery.response).split("\n")
        for line in testout:
            if "IN A" in line:
                dcList.add(line.split(" ")[0].rstrip(line.split(" ")[0][-1]))
        
        return dcList

    #
    # Conduct an anonymous bind to the provided "nameserver" arg during execution. This should work 
    #   even if LDAP server integrity checks are enforced. The FQDN of the internal domain will be 
    #   parsed from the basic server info gathered from that anonymous bind.
    #
    @staticmethod
    def InternalDomainFromAnonymousLdap(nameserverIp, timeout):
        logger.debug(f"Performing anonymous LDAP bind to {nameserverIp}")

        tls = ldap3.Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLSv1_2
        )

        #ldapServer = ldap3.Server(dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        ldapServer = ldap3.Server(
            nameserverIp,
            use_ssl=False,
            port=389,
            get_info=ldap3.ALL,
            connect_timeout=timeout
        )

        ldapConn = ldap3.Connection(
            ldapServer,
            authentication=ldap3.ANONYMOUS
        )

        try:
            ldapConn.bind()
            parsedServerInfo = str(ldapServer.info).split("\n")
        except Exception as e:
            logger.error("Failed to bind to LDAP server")
            logger.error(e)
            raise typer.Exit(1)
        
        fqdn = ""
        for line in parsedServerInfo:
            if "$" in line:
                fqdn = line.strip().split("@")[1]

        logger.debug(f"Parsed FQDN - {fqdn}")
        return fqdn