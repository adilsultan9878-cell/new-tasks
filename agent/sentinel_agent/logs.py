from __future__ import annotations

import logging
import logging.handlers
import sys

from sentinel_agent.state import agent_home


def setup_logging(verbose: bool = False) -> None:
    """Console + rotating local log file (1 MB x 3) in the agent's data directory."""
    root = logging.getLogger("sentinel_agent")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    root.addHandler(console)
    log_dir = agent_home() / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "agent.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError:
        root.warning("cannot write log file in %s; logging to console only", log_dir)
