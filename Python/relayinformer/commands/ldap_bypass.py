import sys
import typer
import getpass
from enum import Enum
from pathlib import Path

from relayinformer import console
from relayinformer.logger import logger, OBJ_EXTRA_FMT
from relayinformer.informers.LdapBypassInformer import LdapBypassInformer


class Trailing(str, Enum):
    WHOAMI  = "whoami"
    ROOTDSE = "rootdse"


app          = typer.Typer()
COMMAND_NAME = "ldap-bypass"
HELP         = (
    "Checks Domain Controllers for the LDAP signing-bypass vulnerability (Oct-2026 fix). "
    "Sends a BindRequest and a trailing op stacked in a single write; an unpatched DC "
    "answers both, a patched DC silently discards the trailing op. "
    "Requires valid low-privilege domain credentials."
)

DEFAULTPASS         = "defaultpass"
DEFAULTUSER         = "guestuser"
DIRECT_TARGET_PANEL = "Direct Targeting"
AUTH_PANEL          = "Authentication"
RUNTIME_PANEL       = "Runtime"


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

        target   : str | None = typer.Option(None,        '--target',   '-t',  help='Single DC hostname/IP or a file containing one DC hostname/IP per line', rich_help_panel=DIRECT_TARGET_PANEL),

        user     : str        = typer.Option(DEFAULTUSER, '-u', '--user',       help='Domain username',                                                        rich_help_panel=AUTH_PANEL),
        password : str        = typer.Option(DEFAULTPASS, '-p', '--password',   help='Domain password',                                                        rich_help_panel=AUTH_PANEL),
        fqdn     : str | None = typer.Option(None,        '-d', '--domain',     help='Fully qualified domain name (constructs user@domain bind DN)',            rich_help_panel=AUTH_PANEL),

        port     : int        = typer.Option(389,         '--port',             help='LDAP port (default: 389)',                                                                                                              rich_help_panel=RUNTIME_PANEL),
        trailing : Trailing   = typer.Option(Trailing.WHOAMI, '--trailing',     help='Trailing op stacked behind the bind (whoami or rootdse)',                 rich_help_panel=RUNTIME_PANEL),
        control  : bool       = typer.Option(False,       '--control',          help='Also run a no-stack control probe to confirm the signal is stacking-specific', rich_help_panel=RUNTIME_PANEL),
        timeout  : float      = typer.Option(5.0,         '--timeout',          help='Socket/read timeout in seconds',                                          rich_help_panel=RUNTIME_PANEL),
    ):

    if target is None:
        logger.warning("--target must be provided")
        raise typer.Exit(1)

    if user == DEFAULTUSER:
        logger.warning("--user is required")
        raise typer.Exit(1)

    if password == DEFAULTPASS:
        password = getpass.getpass(prompt="Password: ")

    # Construct bind DN: user@domain or bare user
    dn = f"{user}@{fqdn}" if fqdn else user

    effective_port = port

    dc_list = _targets_from_target_option(target)

    print()
    for dc in dc_list:
        print("   -> " + dc)
    print()

    logger.info("Checking DCs for LDAP signing bypass (switcheroo) vulnerability")

    informer = LdapBypassInformer(dn, password)

    for dc in dc_list:
        with console.status(f"[bold]Checking {dc}...\n", spinner="flip"):
            try:
                result = informer.run(dc, effective_port, trailing.value, control, timeout)
            except Exception as e:
                logger.error(f"[{dc}] Unexpected error: {e}")
                continue

        if result.get("error"):
            logger.error(f"\\[{dc}] connection/probe error: {result['error']}", extra=OBJ_EXTRA_FMT)
            continue

        verdict  = result["verdict"]
        bind_rc  = result["bind_rc"]
        rc_name  = result["bind_rc_name"]
        n_pdus   = result["response_pdus"]
        trailing_ans = result["trailing_answered"]

        logger.info(
            f"\\[{dc}] bind result: {rc_name} (rc={bind_rc})  |  "
            f"response PDUs: {n_pdus}  |  trailing msgID-2 answered: {trailing_ans}",
            extra=OBJ_EXTRA_FMT,
        )

        if control:
            ctrl = result.get("control_answered")
            ctrl_err = result.get("control_error")
            if ctrl_err:
                logger.warning(f"\\[{dc}] control probe error: {ctrl_err}", extra=OBJ_EXTRA_FMT)
            elif ctrl is not None:
                ok = "  OK" if ctrl else "  <-- unexpected; verdict may be unreliable"
                logger.info(f"\\[{dc}] control (no-stack trailing answered): {ctrl}{ok}", extra=OBJ_EXTRA_FMT)

        if verdict == "UNPATCHED":
            logger.info(
                f"\\[{dc}] VERDICT: [green]UNPATCHED[/] -> stacked op was processed "
                f"-> LDAP signing bypass (switcheroo) [green]WILL WORK[/]",
                extra=OBJ_EXTRA_FMT,
            )
        elif verdict == "PATCHED":
            logger.info(
                f"\\[{dc}] VERDICT: [red]PATCHED[/] -> stacked op discarded "
                f"-> bypass [red]fixed[/] (Oct-2026)",
                extra=OBJ_EXTRA_FMT,
            )
        else:
            logger.warning(
                f"\\[{dc}] VERDICT: [yellow]INCONCLUSIVE[/] "
                f"-> no bindResponse seen; check creds/port/reachability",
                extra=OBJ_EXTRA_FMT,
            )
