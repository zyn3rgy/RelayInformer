import urllib.parse
import dns.resolver
import ldap3
import ssl
import socket
import asyncio
import typer
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory

from relayinformer.logger import logger


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
            elif "data 52e" in ldapConn_result_str or "data 532" in ldapConn_result_str:
                logger.warning(ldapConn_result_str)
                raise typer.Exit("Invalid credentials - aborting to prevent unnecessary authentication")

            else:
                logger.error("UNEXPECTED ERROR: " + ldapConn_result_str)
        else:
            #LDAPS bind successful
            return False #because LDAP server signing requirements are not enforced
        

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
        ssl_sock.connect((target, 636))
        try:
            ssl_sock.do_handshake()
            ssl_sock.close()
            return True
        except Exception as e:
            # Treat cert verification errors as a sign that TLS is enabled
            if isinstance(e, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(e):
                ssl_sock.close()
                return True
            # Timeouts indicate LDAPS is likely not configured
            if isinstance(e, (TimeoutError, socket.timeout)) or "handshake operation timed out" in str(e):
                ssl_sock.close()
                return False
            else:
                logger.error("Unexpected error during LDAPS handshake: " + str(e))
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
                    logger.error("UNEXPECTED ERROR: " + str(ldapConn.result))
            else:
                #LDAPS bind successful
                return False #because channel binding is not enforced
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