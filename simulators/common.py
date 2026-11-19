"""
Command-line plumbing shared by the protocol simulators: the --host / --port
/ --denied options and running the server until Ctrl+C.
"""

import argparse
import asyncio
import logging
from typing import Coroutine, List, Optional, Tuple

DEFAULT_HOST_HELP = "Host to bind to (default 127.0.0.1; 0.0.0.0 = all interfaces)"


def parse_denied_ranges(text: Optional[str]) -> List[Tuple[int, int]]:
    """'5000-5100,7000-7050' -> [(5000, 5100), (7000, 7050)]; items without '-' are ignored"""
    ranges = []
    for range_str in (text or "").split(","):
        if "-" in range_str:
            start, end = range_str.split("-")
            ranges.append((int(start), int(end)))
    return ranges


def simulator_parser(description: str, default_port: int, default_denied: Optional[str] = None
                     ) -> argparse.ArgumentParser:
    """Parser with --host and --port (and --denied when a default is given)"""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default="127.0.0.1", help=DEFAULT_HOST_HELP)
    parser.add_argument("--port", type=int, default=default_port,
                        help=f"Port to listen on (default: {default_port})")
    if default_denied is not None:
        parser.add_argument("--denied", default=default_denied,
                            help=f"Denied address ranges (default: '{default_denied}')")
    return parser


def run_simulator(server: Coroutine, logger: logging.Logger) -> None:
    """Run the server until Ctrl+C"""
    try:
        asyncio.run(server)
    except KeyboardInterrupt:
        logger.info("Simulator stopped")
