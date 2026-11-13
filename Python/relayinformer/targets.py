import typer
from pathlib import Path

from relayinformer.logger import logger


TARGET_HELP = "Hostname/IP, comma-separated list of hostnames/IPs, or a file containing one hostname/IP per line"


def parse_targets(target: str) -> list[str]:
    """
    Expand a --target value into a list of targets. An existing file is read
    one target per line (blank lines and # comments skipped), anything else
    is split on commas.
    """
    target_path = Path(target).expanduser()

    if not target_path.exists():
        targets = [t.strip() for t in target.split(",") if t.strip()]
        if not targets:
            logger.error("--target is empty")
            raise typer.Exit(1)
        return targets

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
