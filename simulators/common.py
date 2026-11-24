"""
Command-line plumbing shared by the protocol simulators: the --host / --port
/ --denied options and running the server until Ctrl+C.
"""

import argparse
import asyncio
import logging
from typing import Any, Coroutine, List, Optional, Tuple

DEFAULT_HOST_HELP = "Host to bind to (default 127.0.0.1; 0.0.0.0 = all interfaces)"


def parse_denied_ranges(text: Optional[str]) -> List[Tuple[int, int]]:
    """'5000-5100,7000-7050' -> [(5000, 5100), (7000, 7050)]; items without '-' are ignored"""
    ranges = []
    for range_str in (text or "").split(","):
        if "-" in range_str:
            start, end = range_str.split("-")
            ranges.append((int(start), int(end)))
    return ranges


def peer_text(transport: Any) -> str:
    """'192.168.1.14:50408' for a connection's remote end ('?' when unknown)"""
    peer = transport.get_extra_info("peername") if transport is not None else None
    if isinstance(peer, (tuple, list)) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer) if peer else "?"


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


async def serve_until_stopped(server: Any, logger: logging.Logger) -> None:
    """
    Keep a server (already listening: create_server starts it) running until
    the task is cancelled (Ctrl+C), then close it.

    Not ``async with server: await server.serve_forever()``: since Python
    3.12 both wait for every connected client to leave, so Ctrl+C did not
    stop a simulator while a scanner was still connected. The wait for the
    clients is bounded here.
    """
    try:
        await asyncio.Event().wait()
    finally:
        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=2)
        except asyncio.TimeoutError:
            logger.info("Simulator stopped with clients still connected")


def run_simulator(server: Coroutine, logger: logging.Logger) -> None:
    """Run the server until Ctrl+C"""
    try:
        asyncio.run(server)
    except KeyboardInterrupt:
        logger.info("Simulator stopped")
    except OSError as e:
        # Port below 1024 without administrator rights (the standard
        # Modbus 502 / S7 102), or a port already in use: say what to do
        # instead of ending in a traceback
        logger.error(f"Cannot start the simulator: {e}")
        logger.error("Choose another port with --port (e.g. --port 1502), or stop the program using it")
        raise SystemExit(1) from None
