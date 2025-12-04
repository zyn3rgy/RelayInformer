import sys
import typer
import getpass
import asyncio
from enum import Enum

from relayinformer import console
from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers import LdapInformer


class Method(str, Enum):
    LDAPS = "LDAPS"
    BOTH = "BOTH"


app = typer.Typer()
COMMAND_NAME = "ldap"
HELP = "Checks Domain Controllers for LDAP authentication protection."  \
        " You can check for only LDAPS protections (channel binding), this is done unauthenticated." \
        " Alternatively you can check for both LDAPS and LDAP (server signing) protections. This requires a successful LDAP bind."


DEFAULTPASS = "defaultpass"
DEFAULTUSER = "guestuser"


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main(
        ctx: typer.Context,

        method      : Method    = typer.Option(Method.LDAPS, '--method', help="LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP channel binding [authentication required]", case_sensitive=False),
        dc_ip       : str       = typer.Option(..., '--dc-ip', help='Any DC\'s IPv4 address should work (used for LDAP/LDAPS connections)'),
        dns         : str       = typer.Option(None, '--dns', help='DNS nameserver to use for SRV lookups (optional, overrides --dc-ip for DNS queries)'),
        user        : str       = typer.Option(DEFAULTUSER, '-u', '--user', help='Domain username value'),
        password    : str       = typer.Option(DEFAULTPASS, '-p', '--password', help='Domain password value'),
        fqdn        : str       = typer.Option(None, '-d', '--domain', help='Fully qualified domain name'),
        nthash      : str       = typer.Option(None, '-nh', '--nthash', help='NT hash of password'),
        timeout     : int       = typer.Option(10, '--timeout', help='The timeout for MSLDAP client connection')
    ):

    if method == Method.BOTH and user == DEFAULTUSER:
        logger.warning("Using BOTH method requires a username parameter")
        raise typer.Exit(1)
    
    if method == Method.BOTH:
        if nthash is not None:
            nthash = f"aad3b435b51404eeaad3b435b51404ee:{nthash}" 
        
        elif password is not DEFAULTPASS:
            pass

        else:
            logger.warning("Using BOTH method requires a password or NT hash")
        
    if method == Method.BOTH and password == DEFAULTPASS and nthash is None:
        password = getpass.getpass(prompt="Password: ")
    
    if fqdn is None:
        fqdn = LdapInformer.InternalDomainFromAnonymousLdap(dns if dns else dc_ip, timeout)
    
    dc_list = LdapInformer.ResolveDCs(dns if dns else dc_ip, fqdn)
    logger.info("Identified Domain Controllers")
    
    print()
    for dc in dc_list:
        print("   -> " + dc)
    print()

    logger.info("Checking DCs for LDAP NTLM relay protections")
    
    informer = LdapInformer(fqdn, user, password)
    logger.debug(f"Authing with values:\nUser: {user}\nPass: {password} \nDomain:  {fqdn}")

    for dc in dc_list:
        with console.status(f"[bold]Checking {dc}...\n", spinner="flip"):
            try:
                if method == Method.BOTH:
                    if informer.RunLdap(dc):
                        logger.info(f"\\[{dc}] (LDAP) server [red]enforcing[/] signing requirements", extra=OBJ_EXTRA_FMT)
                    else:
                        logger.info(f"\\[{dc}] (LDAP) SERVER SIGNING REQUIREMENTS [green]NOT ENFORCED[/]!", extra=OBJ_EXTRA_FMT)
                    
                if LdapInformer.DoesLdapsCompleteHandshake(dc):
                    ldapsChannelBindingAlwaysCheck = informer.RunLdapsNoEpa(dc)
                    ldapsChannelBindingWhenSupportedCheck = asyncio.run(
                        informer.RunLdapsWithEpa(dc, timeout)
                    )
                    if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                        logger.info(f"\\[{dc}] (LDAPS) channel binding is set to [yellow]when supported[/] - " \
                                    "this may prevent an NTLM relay depending on the client's support for channel binding", extra=OBJ_EXTRA_FMT)
                    elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                            logger.info(f"\\[{dc}] (LDAPS) CHANNEL BINDING SET TO [green]NEVER[/]! PARTY TIME!", extra=OBJ_EXTRA_FMT)
                    elif ldapsChannelBindingAlwaysCheck == True:
                        logger.info(f"\\[{dc}] (LDAPS) channel binding set to [red]required[/], no fun allowed", extra=OBJ_EXTRA_FMT)
                    else:
                        logger.error(f"\\[{dc}] Something went wrong...")
                        logger.debug("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(ldapsChannelBindingWhenSupportedCheck))
                        #exit()        
                else:
                    logger.warning(f"{dc} cannot complete TLS handshake, cert likely not configured")
            except Exception as e:
                logger.error(f"[{dc}] {str(e)}")
    