import typer
from getpass import getpass

from relayinformer.logger import logger
from relayinformer.informers.MssqlInformer import MssqlInformer
from impacket import tds

app = typer.Typer()
COMMAND_NAME = "mssql"
HELP = "Check MSSQL servers"


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
        
        target:     str = typer.Option(..., "--target", "-t", help="Target hostname or IP address"),
        user:       str = typer.Option(..., "--user", "-u", help="Username in format domain/username"),
        password:   str = typer.Option(None,"--password", "-p", help="Password for authentication"),
        hashes:     str = typer.Option(None, "--hashes", help="NTLM hashes in format LMHASH:NTHASH"),
        port:       int = typer.Option(1433, "--port", help="Target MSSQL port"),
        
    ):
    """
    Test EPA enforcement level for MSSQL servers using Windows authentication.
    
    Examples:
        relayinformer mssql --target server.com --user domain/username --password mypass
        relayinformer mssql --target 192.168.1.10 --user domain/username --hashes LM:NT
        relayinformer mssql -t server.com -u domain/admin -p mypass --port 1434
    """
    
    
    # Validate user format
    try:
        MssqlInformer.parse_domain_user(user)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    logger.info(f"Testing EPA enforcement level for MSSQL service at {target} on port {port} as {user}")
    
    try:
        with MssqlInformer(target, user, port) as informer:
            # Prompt for password if neither password nor hashes provided
            if password is None and hashes is None:
                password = getpass("Password:")
            
            # Determine encryption requirements
            encryption_setting = informer.check_encryption_requirements()

            # Run prerequisite check: ensure normal login flow works with valid/default parameters
            if not informer.prereq_check(password, hashes, None, encryption_setting):
                logger.error("Prereq check failed, check credentials and try again")
                raise typer.Exit(1)
            
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
                            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        raise typer.Exit(0)
    except typer.Exit:
        # Handle typer.Exit to not mistakenly error on "Allowed" results
        raise
    except Exception as e:
        logger.error(f"Exception during MSSQL EPA testing: {str(e)}")
        raise typer.Exit(1)