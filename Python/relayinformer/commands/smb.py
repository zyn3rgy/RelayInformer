import typer

from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers import SmbInformer
from relayinformer.targets import parse_targets, TARGET_HELP


app = typer.Typer()
COMMAND_NAME = "smb"
HELP = "Check SMB servers for message signing enforcement (unauthenticated)."


def check_target(target: str, port: int, timeout: int) -> bool:
    """Check one SMB server. Returns False if the check errored."""
    logger.info(f"Checking SMB signing enforcement on {target}:{port}")

    informer = SmbInformer(target, port, timeout)
    try:
        result = informer.Run()
    except Exception as e:
        logger.error(f"[{target}] {str(e)}")
        return False

    dialect = result["dialect"]
    if result["required"] is None:
        logger.warning(f"\\[{target}] (SMB) server negotiated SMB1 - signing policy is not checked for SMB1.", extra=OBJ_EXTRA_FMT)
    elif result["required"]:
        logger.info(f"\\[{target}] (SMB) server [red]enforcing[/] signing requirements (dialect {dialect})", extra=OBJ_EXTRA_FMT)
    elif result["enabled"] is None:
        logger.info(f"\\[{target}] (SMB) server [yellow]not requiring[/] signing (dialect {dialect}) - NTLM relay is possible", extra=OBJ_EXTRA_FMT)
    elif result["enabled"]:
        logger.info(f"\\[{target}] (SMB) signing [yellow]enabled but not required[/] (dialect {dialect}) - NTLM relay is possible", extra=OBJ_EXTRA_FMT)
    else:
        logger.info(f"\\[{target}] (SMB) SIGNING [green]DISABLED[/] (dialect {dialect}) - NTLM relay is possible!", extra=OBJ_EXTRA_FMT)
    return True


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,

        target:  str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
        port:    int = typer.Option(445, "--port", help="Target SMB port"),
        timeout: int = typer.Option(10, "--timeout", help="Connection timeout in seconds")
    ):
    """
    Determine SMB message signing enforcement on the target. This is done
    unauthenticated by parsing the server's SecurityMode from an SMB
    NEGOTIATE response. No session is established.

    Examples:
        relayinformer smb --target 192.168.1.10
        relayinformer smb -t file.domain.local --port 445 --timeout 5
        relayinformer smb -t 192.168.1.10,192.168.1.11
        relayinformer smb -t smb-targets.txt
    """

    targets = parse_targets(target)

    failed = 0
    for t in targets:
        if not check_target(t, port, timeout):
            failed += 1

    if failed:
        raise typer.Exit(1)
