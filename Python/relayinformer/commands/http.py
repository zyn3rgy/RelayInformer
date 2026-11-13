import typer
from typing import Optional, Annotated
from getpass import getpass
from urllib.parse import urlparse
import time

from relayinformer.logger import logger
from relayinformer.informers.HttpInformer import HttpInformer

app = typer.Typer()
COMMAND_NAME = "http"
HELP = "Check HTTP/HTTPS servers for EPA settings"


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
        
        url:        str = typer.Option(..., "--url", "-u", help="Target HTTP/HTTPS URL that requires NTLM authentication"),
        user:       str = typer.Option(..., "--user", help="Username in format [domain/]username or domain\\username"),
        password:   str = typer.Option(None, "--password", "-p", help="Password for authentication"),
        hashes:     str = typer.Option(None, "--hashes", help="NTLM hashes in format LMHASH:NTHASH"),
        


    ):
    """
    Test EPA enforcement level for HTTP/HTTPS servers using NTLM authentication.
    
    This command tests Extended Protection for Authentication (EPA) settings by manipulating 
    Channel Binding Tokens (CBT) for HTTPS connections and target name AV pairs for both 
    HTTP and HTTPS connections.
    
    Examples:
        relayinformer http --url https://intranet.example.com --user domain/username --password mypass
        relayinformer http --url http://server.local --user domain\\\\username --hashes LM:NT  
        relayinformer http -u https://server.com --user domain/user --password mypass
    """
    
    # Validate URL format
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            logger.error("URL must include protocol (http:// or https://) and hostname")
            raise typer.Exit(1)
        if parsed_url.scheme not in ['http', 'https']:
            logger.error("URL must use http:// or https:// protocol")
            raise typer.Exit(1)
    except Exception:
        logger.error("Invalid URL format")
        raise typer.Exit(1)
    
    # Validate user format
    try:
        HttpInformer.parse_domain_user(user)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)
    


    # Warn about credentials requirement

    is_https = url.lower().startswith('https://')
    protocol = "HTTPS" if is_https else "HTTP"
    
    logger.info(f"Testing EPA enforcement level for {protocol} service at {url} as {user}")
    

    
    try:
        with HttpInformer(url, user) as informer:

            # Prompt for password if neither password nor hashes provided
            if password is None and hashes is None:
                password = getpass("Password:")

            def check_status_code(code: str) -> None:
                if code not in ("200", "401"):
                    logger.error(f"Step returned {code} instead of 200 or 401. Cannot determine EPA status. Run with -v for details.")
                    raise typer.Exit(1)

            def to_status_code(result: str) -> str:
                if result == "success":
                    return "200"
                if result == "unauthorized":
                    return "401"
                # If result already a numeric string from informer, return as-is
                return result

            # Step 1: Prerequisite check - ensure basic authentication works
            logger.debug("Running prerequisite check with correct parameters")
            result, cbt_bytes, target_name = informer.test_epa_connection(
                password, hashes,
                send_cbt=is_https,  # Use CBT for HTTPS, don't use for HTTP
                custom_cert_hash=None,
                fake_target_name=False,
                strip_target_name=False,
            )
            code = to_status_code(result)
            if code != "200":
                logger.error(f"Prereq check failed - expected 200 OK with correct parameters, got {code}")
                raise typer.Exit(1)
            else:
                logger.info("Prereq check passed with correct av pair values")

            if is_https:
                # HTTPS multi-step flow
                logger.debug("EPA checks will manipulate channel binding AV pair over encrypted (HTTPS) connection")
                # Step 2: No CBT, correct target name
                logger.debug("Checking with NO CBT and correct target name")
                result, _, _ = informer.test_epa_connection(
                        password, hashes,
                        send_cbt=False,
                        custom_cert_hash=None,
                        fake_target_name=False,
                        strip_target_name=False,
                )
                code = to_status_code(result)
                check_status_code(code)
                if code == "200":
                    # Step 3: Fake CBT, correct target name
                    logger.debug("NO CBT allowed (200). Checking with FAKE CBT and correct target name")
                    fake_cbt = b"\x00" * 69
                    result, _, _ = informer.test_epa_connection(
                            password, hashes,
                            send_cbt=True,
                            custom_cert_hash=fake_cbt,
                            fake_target_name=False,
                            strip_target_name=False,
                    )
                    code = to_status_code(result)
                    check_status_code(code)
                    if code == "200":
                        logger.info("EPA (channel binding) is DISABLED")
                    else:
                        logger.info("EPA (channel binding) is ALLOWED")
                    # proceed to next step either way
                else:
                    logger.info(f"EPA (channel binding) is REQUIRED")
                    # Skip fake CBT check; proceed directly to service binding check

                # Step 4: Correct CBT, stripped target name
                logger.debug("Checking with CORRECT CBT and STRIPPED target name (service binding)")
                result, _, _ = informer.test_epa_connection(
                    password, hashes,
                    send_cbt=True,
                    custom_cert_hash=None,
                    fake_target_name=False,
                    strip_target_name=True,
                )
                code = to_status_code(result)
                check_status_code(code)
                if code != "200":
                    logger.info("EPA (service binding) is REQUIRED")
                    raise typer.Exit(0)
                else:
                    logger.debug("Service binding not required when target name stripped (200). Proceeding to fake target service check")

                # Step 5: Correct CBT, fake target service name
                logger.debug("Checking with CORRECT CBT and FAKE target service name")
                result, _, _ = informer.test_epa_connection(
                    password, hashes,
                    send_cbt=True,
                    custom_cert_hash=None,
                    fake_target_name=True,
                    strip_target_name=False,
                )
                code = to_status_code(result)
                check_status_code(code)
                if code == "200":
                    logger.info("EPA (service binding) is DISABLED")
                else:
                    logger.info("EPA (service binding) is ALLOWED")
                raise typer.Exit(0)
            else:
                # HTTP: service binding only (CBT is irrelevant)
                logger.debug('EPA checks will manipulate "target service" AV pair over unencrypted (HTTP) connection')
                # Step 2: Stripped target name
                logger.debug("HTTP check: STRIPPED target name")
                result, _, _ = informer.test_epa_connection(
                        password, hashes,
                        send_cbt=False,
                        custom_cert_hash=None,
                        fake_target_name=False,
                        strip_target_name=True,
                )
                code = to_status_code(result)
                check_status_code(code)
                if code != "200":
                    logger.info("EPA (service binding) is REQUIRED")
                    raise typer.Exit(0)

                # Step 3: Fake target service name
                logger.debug("HTTP check: FAKE target service name")
                result, _, _ = informer.test_epa_connection(
                        password, hashes,
                        send_cbt=False,
                        custom_cert_hash=None,
                        fake_target_name=True,
                        strip_target_name=False,
                )
                code = to_status_code(result)
                check_status_code(code)
                if code == "200":
                    logger.info("EPA (service binding) is DISABLED")
                else:
                    logger.info("EPA (service binding) is ALLOWED")
                raise typer.Exit(0)
                            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        raise typer.Exit(0)
    except typer.Exit:
        # Handle typer.Exit to not mistakenly error on specific results
        raise
    except Exception as e:
        logger.error(f"Exception during HTTP EPA testing: {str(e)}")
        raise typer.Exit(1)
    