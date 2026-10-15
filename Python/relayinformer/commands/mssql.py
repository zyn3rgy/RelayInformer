import typer
from getpass import getpass

from relayinformer.logger import logger
from relayinformer.informers.MssqlInformer import MssqlInformer
from impacket import tds
from relayinformer.targets import parse_targets, TARGET_HELP

app = typer.Typer()
COMMAND_NAME = "mssql"
HELP = "Check MSSQL servers"

class LoginFailed(Exception):
    pass

def check_target(target: str, user: str, password: str, hashes: str, port: int):
    """Check one MSSQL server. Raises typer.Exit with the same codes as a single-target run."""
    logger.info(f"Testing EPA enforcement level for MSSQL service at {target} on port {port} as {user}")
    
    try:
        with MssqlInformer(target, user, port) as informer:
            # Determine encryption requirements
            encryption_setting = informer.check_encryption_requirements()

            # Run prerequisite check: ensure normal login flow works with valid/default parameters
            if not informer.prereq_check(password, hashes, None, encryption_setting):
                logger.error("Prereq check failed, check credentials and try again")
                raise LoginFailed()
            
            if encryption_setting == tds.TDS_ENCRYPT_REQ:
                logger.info("Conducting logins while manipulating channel binding av pair over encrypted connection")
                
                # Test with bogus channel binding
                bogus_cb_result = informer.test_epa_with_bogus_channel_binding(password, hashes, None)
                if bogus_cb_result == "untrusted_domain":
                    
                    # Test with missing channel binding
                    missing_cb_result = informer.test_epa_with_missing_channel_binding(password, hashes, None)
                    if missing_cb_result == "untrusted_domain":
                        logger.info("--------------------------------")                     
                        logger.info("     EPA setting - Required")
                        logger.info("--------------------------------")     
                    else:
                        logger.info("--------------------------------")
                        logger.info("     EPA setting - Allowed")
                        logger.info("--------------------------------")
                        raise typer.Exit(1)
                else:
                    logger.info("--------------------------------")
                    logger.info("     EPA setting - Off")
                    logger.info("--------------------------------")
                    
            elif encryption_setting == tds.TDS_ENCRYPT_OFF:
                logger.info("Conducting logins while manipulating target service av pair over unencrypted connection")
                
                # Test with bogus target service
                bogus_ts_result = informer.test_epa_with_bogus_target_service(password, hashes, None)
                if bogus_ts_result == "untrusted_domain":
                    logger.debug("Failed due to EPA (service binding) while supplying bogus target service")
                    
                    # Test with missing target service
                    missing_ts_result = informer.test_epa_with_missing_target_service(password, hashes, None)
                    if missing_ts_result == "untrusted_domain":
                        logger.debug("Failed due to EPA (service binding) while excluding target service av pair")
                        logger.info("--------------------------------")
                        logger.info("     EPA setting - Required")
                        logger.info("--------------------------------")
                    else:
                        logger.info("--------------------------------")
                        logger.info("     EPA setting - Allowed")
                        logger.info("--------------------------------")
                        raise typer.Exit(1)
                else:
                    logger.info("--------------------------------")
                    logger.info("     EPA setting - Off")
                    logger.info("--------------------------------")
                    
            else:
                logger.error(f"Previously untested encryption setting: {encryption_setting}, please report this to the authors")
                logger.error("EPA setting - Unknown")
                            
    except typer.Exit:
        # Handle typer.Exit to not mistakenly error on "Allowed" results
        raise
    except LoginFailed:
        raise
    except Exception as e:
        logger.error(f"Exception during MSSQL EPA testing: {str(e)}")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
        
        target:     str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
        user:       str = typer.Option(..., "--user", "-u", help="Username in format [domain/]username"),
        password:   str = typer.Option(None,"--password", "-p", help="Password for authentication"),
        hashes:     str = typer.Option(None, "--hashes", help="NTLM hashes in format LMHASH:NTHASH"),
        port:       int = typer.Option(1433, "--port", help="Target MSSQL port"),
        
    ):
    """
    Test EPA enforcement level for MSSQL servers using Windows authentication.
    
    Examples:
        relayinformer mssql --target server.com --user domain/username --password mypass
        relayinformer mssql --target 192.168.1.10 --user domain/username --hashes LM:NT
        relayinformer mssql -t server.com -u admin -p mypass --port 1434
        relayinformer mssql -t sql-targets.txt -u domain/username -p mypass
    """
    
    
    # Validate user format
    try:
        MssqlInformer.parse_domain_user(user)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    targets = parse_targets(target)

    # Prompt for password if neither password nor hashes provided
    if password is None and hashes is None:
        password = getpass("Password:")

    exit_code = 0
    try:
        for t in targets:
            try:
                check_target(t, user, password, hashes, port)
            except typer.Exit as e:
                exit_code = max(exit_code, e.exit_code)
            except LoginFailed:
                logger.error("Login failed, stopping so the account is not locked out")
                raise typer.Exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        raise typer.Exit(0)

    if exit_code:
        raise typer.Exit(exit_code)
