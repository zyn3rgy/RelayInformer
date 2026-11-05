import sys
import typer
import getpass
import asyncio
from enum import Enum
from pathlib import Path

from relayinformer import console
from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers import LdapInformer
from relayinformer.informers.LdapBypassInformer import LdapBypassInformer


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
DIRECT_TARGET_PANEL = "Direct Targeting"
DISCOVERY_TARGET_PANEL = "DNS Discovery Targeting"
AUTH_PANEL = "Authentication"
RUNTIME_PANEL = "Runtime"


def _targets_from_target_option(target: str) -> list[str]:
    target_path = Path(target).expanduser()

    if not target_path.exists():
        return [target]

    if not target_path.is_file():
        logger.error(f"--target points to an existing path that is not a file: {target_path}")
        raise typer.Exit(1)

    try:
        targets = [
            line.strip()
            for line in target_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read targets from {target_path}: {e}")
        raise typer.Exit(1)

    if not targets:
        logger.error(f"No targets found in {target_path}")
        raise typer.Exit(1)

    return targets


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main(
        ctx: typer.Context,

        method      : Method     = typer.Option(Method.LDAPS, '--method', help="LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP channel binding [authentication required]", case_sensitive=False, rich_help_panel=RUNTIME_PANEL),
        target      : str | None = typer.Option(None, '--target', '-t', help='Single DC hostname/IP or a file containing one DC hostname/IP per line', rich_help_panel=DIRECT_TARGET_PANEL),
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
    
    if target is not None:
        dc_list = _targets_from_target_option(target)
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
    bypass_informer = LdapBypassInformer("", "")
    logger.debug(f"Authing with values:\nUser: {user}\nPass: {password} \nDomain:  {fqdn}")

    for dc in dc_list:
        with console.status(f"[bold]Checking {dc}...\n", spinner="flip"):
            try:
                signing_enforced = None

                if method == Method.BOTH:
                    signing_enforced = informer.RunLdap(dc)
                    if signing_enforced:
                        logger.info(f"\\[{dc}] (LDAP) server [red]enforcing[/] signing requirements", extra=OBJ_EXTRA_FMT)
                    else:
                        logger.info(f"\\[{dc}] (LDAP) SERVER SIGNING REQUIREMENTS [green]NOT ENFORCED[/]!", extra=OBJ_EXTRA_FMT)

                if signing_enforced is True:
                    try:
                        bp = bypass_informer.run(dc, 389, "whoami", False, float(timeout))
                        if bp.get("error"):
                            logger.warning(f"\\[{dc}] (LDAP) signing bypass probe error: {bp['error']}", extra=OBJ_EXTRA_FMT)
                        else:
                            bv = bp["verdict"]
                            if bv == "UNPATCHED":
                                logger.info(f"\\[{dc}] (LDAP) [green]SIGNING BYPASS UNPATCHED[/] - relay [green]VIABLE[/]! (signing enforced, CVE-2026-70229 unpatched)", extra=OBJ_EXTRA_FMT)
                            elif bv == "PATCHED":
                                logger.info(f"\\[{dc}] (LDAP) signing bypass [red]patched[/] - relay blocked (signing enforced, CVE-2026-70229 patched)", extra=OBJ_EXTRA_FMT)
                            else:
                                logger.warning(f"\\[{dc}] (LDAP) signing bypass inconclusive - no bind response", extra=OBJ_EXTRA_FMT)
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
