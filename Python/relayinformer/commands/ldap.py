import sys
import typer
import getpass
import asyncio
from enum import Enum

from relayinformer import console
from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers import LdapInformer
from relayinformer.targets import parse_targets, TARGET_HELP


class Method(str, Enum):
    LDAPS = "LDAPS"
    BOTH = "BOTH"


app = typer.Typer()
COMMAND_NAME = "ldap"
HELP = "Checks Domain Controllers for LDAP authentication protection."  \
        " You can check for only LDAPS protections (channel binding), this is done unauthenticated." \
        " Alternatively you can check for both LDAPS and LDAP protections: the LDAP signing bypass (unauthenticated)" \
        " and, when credentials are supplied, LDAP server signing enforcement (requires a successful LDAP bind)."


DEFAULTPASS = "defaultpass"
DEFAULTUSER = "guestuser"
DIRECT_TARGET_PANEL = "Direct Targeting"
DISCOVERY_TARGET_PANEL = "DNS Discovery Targeting"
AUTH_PANEL = "Authentication"
RUNTIME_PANEL = "Runtime"


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main(
        ctx: typer.Context,

        method      : Method     = typer.Option(Method.LDAPS, '--method', help="LDAPS checks for channel binding, BOTH also checks LDAP for the signing bypass and, with credentials, signing enforcement", case_sensitive=False, rich_help_panel=RUNTIME_PANEL),
        target      : str | None = typer.Option(None, '--target', '-t', help=TARGET_HELP, rich_help_panel=DIRECT_TARGET_PANEL),
        dc_ip       : str | None = typer.Option(None, '--dc-ip', help='Bootstrap DC IPv4 address used for LDAP/LDAPS connections and DNS discovery', rich_help_panel=DISCOVERY_TARGET_PANEL),
        dns         : str | None = typer.Option(None, '--dns', help='DNS nameserver to use for SRV lookups (optional, overrides --dc-ip for DNS queries)', rich_help_panel=DISCOVERY_TARGET_PANEL),
        user        : str        = typer.Option(DEFAULTUSER, '-u', '--user', help='Domain username value', rich_help_panel=AUTH_PANEL),
        password    : str        = typer.Option(DEFAULTPASS, '-p', '--password', help='Domain password value', rich_help_panel=AUTH_PANEL),
        fqdn        : str | None = typer.Option(None, '-d', '--domain', help='Fully qualified domain name', rich_help_panel=AUTH_PANEL),
        nthash      : str | None = typer.Option(None, '-nh', '--nthash', help='NT hash of password', rich_help_panel=AUTH_PANEL),
        timeout     : int        = typer.Option(10, '--timeout', help='The timeout for MSLDAP client connection', rich_help_panel=RUNTIME_PANEL
        )
    ):

    if target is not None and (dc_ip is not None or dns is not None):
        logger.warning("--target cannot be combined with --dc-ip or --dns")
        raise typer.Exit(1)

    if target is None and dc_ip is None:
        logger.warning("Either --target or --dc-ip must be provided")
        raise typer.Exit(1)

    # Signing enforcement needs an authenticated bind; without a username, BOTH only runs
    #   the (unauthenticated) signing bypass probe on LDAP.
    check_signing = method == Method.BOTH and user != DEFAULTUSER

    if check_signing:
        if nthash is not None:
            nthash = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
        elif password == DEFAULTPASS:
            password = getpass.getpass(prompt="Password: ")
    
    if target is not None:
        dc_list = parse_targets(target)
        if fqdn is None:
            fqdn = LdapInformer.InternalDomainFromAnonymousLdap(dc_list[0], timeout)
        logger.info("Using supplied Domain Controller targets")
    else:
        discovery_target = dns if dns else dc_ip
        if fqdn is None:
            fqdn = LdapInformer.InternalDomainFromAnonymousLdap(discovery_target, timeout)
        dc_list = LdapInformer.ResolveDCs(discovery_target, fqdn)
        logger.info("Identified Domain Controllers")
    
    print()
    for dc in dc_list:
        print("   -> " + dc)
    print()

    logger.info("Checking DCs for LDAP NTLM relay protections")

    informer = LdapInformer(fqdn, user, password)
    if user == DEFAULTUSER:
        logger.debug(f"No credentials supplied - LDAPS channel binding checks will bind as placeholder {DEFAULTUSER}/{DEFAULTPASS} (the resulting error reveals the setting); the LDAP signing bypass probe uses an anonymous bind")
    else:
        logger.debug(f"Authing with values:\nUser: {user}\nPass: {password} \nDomain:  {fqdn}")

    for dc in dc_list:
        with console.status(f"[bold]Checking {dc}...\n", spinner="flip"):
            try:
                if method == Method.BOTH:
                    signing_enforced = None
                    if check_signing:
                        signing_enforced = informer.RunLdap(dc)
                        if signing_enforced:
                            logger.info(f"\\[{dc}] (LDAP) server [red]enforcing[/] signing requirements", extra=OBJ_EXTRA_FMT)
                        else:
                            logger.info(f"\\[{dc}] (LDAP) SERVER SIGNING REQUIREMENTS [green]NOT ENFORCED[/]!", extra=OBJ_EXTRA_FMT)
                    else:
                        logger.info(f"\\[{dc}] (LDAP) signing enforcement [yellow]not checked[/] - run with credentials to evaluate", extra=OBJ_EXTRA_FMT)

                    # The bypass only matters when signing is enforced, or when that is unknown
                    if signing_enforced is True or not check_signing:
                        try:
                            verdict, bind_rc = LdapInformer.RunLdapSigningBypass(dc, timeout)
                            if verdict == "UNPATCHED":
                                logger.info(f"\\[{dc}] (LDAP) [green]SIGNING BYPASS UNPATCHED[/] (CVE-2026-70229)", extra=OBJ_EXTRA_FMT)
                            elif verdict == "PATCHED":
                                logger.info(f"\\[{dc}] (LDAP) signing bypass [red]patched[/] (CVE-2026-70229)", extra=OBJ_EXTRA_FMT)
                            elif bind_rc is None:
                                logger.warning(f"\\[{dc}] (LDAP) signing bypass inconclusive - no bind response", extra=OBJ_EXTRA_FMT)
                            else:
                                logger.warning(f"\\[{dc}] (LDAP) signing bypass inconclusive - whoami unanswered even when not stacked", extra=OBJ_EXTRA_FMT)
                        except Exception as bp_e:
                            logger.warning(f"\\[{dc}] (LDAP) signing bypass probe exception: {bp_e}", extra=OBJ_EXTRA_FMT)

                if LdapInformer.DoesLdapsCompleteHandshake(dc):
                    ldapsChannelBindingAlwaysCheck = informer.RunLdapsNoEpa(dc)
                    ldapsChannelBindingWhenSupportedCheck = asyncio.run(
                        informer.RunLdapsWithEpa(dc, timeout)
                    )
                    if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                        logger.info(f"\\[{dc}] (LDAPS) channel binding is set to [yellow]when supported[/] - this may prevent an NTLM relay depending on the client's support for channel binding", extra=OBJ_EXTRA_FMT)
                    elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                            logger.info(f"\\[{dc}] (LDAPS) CHANNEL BINDING SET TO [green]NEVER[/]! PARTY TIME!", extra=OBJ_EXTRA_FMT)
                    elif ldapsChannelBindingAlwaysCheck == True:
                        logger.info(f"\\[{dc}] (LDAPS) channel binding set to [red]required[/], no fun allowed", extra=OBJ_EXTRA_FMT)
                    else:
                        logger.error(f"\\[{dc}] Something went wrong...")
                        logger.debug("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(ldapsChannelBindingWhenSupportedCheck))
                else:
                    logger.warning(f"{dc} cannot complete TLS handshake, cert likely not configured")
            except Exception as e:
                logger.error(f"[{dc}] {str(e)}")
