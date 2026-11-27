#!/usr/bin/env python3
"""
Silent device: listens on TCP ports and never answers.

Stands for equipment on the factory network that accepts connections on a
PLC port but speaks none of the scanner's protocols: a PLC whose SLMP port
is set to UDP or to another code, or another vendor's PLC (Yokogawa FA-M3,
JTEKT TOYOPUC, Panasonic MEWTOCOL ...) that a gateway such as DeviceGateway
reads with its own driver. Discovery must list it as 未対応・要確認 with its
open ports instead of leaving it out.

Usage:
    python silent_device.py [--host 127.0.0.1] [--ports 5001,44818]
"""

import argparse
import asyncio
import logging
from typing import List

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Silent-Device")

try:
    from .common import DEFAULT_HOST_HELP, peer_text, run_simulator
except ImportError:
    from common import DEFAULT_HOST_HELP, peer_text, run_simulator  # type: ignore[no-redef]

DEFAULT_PORTS = "5001"


class SilentProtocol(asyncio.Protocol):
    """Accepts the connection, reads and discards everything, answers nothing"""

    def connection_made(self, transport):
        self.peer = peer_text(transport)
        logger.info(f"Connection from {self.peer} (not answered)")

    def data_received(self, data: bytes) -> None:
        logger.debug(f"{len(data)} byte(s) from {self.peer} ignored")

    def connection_lost(self, exc):
        logger.info(f"Connection closed: {getattr(self, 'peer', '?')}")


def parse_ports(text: str) -> List[int]:
    """'5001,44818' -> [5001, 44818]"""
    ports = [int(part) for part in text.split(",") if part.strip()]
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError(f"ports must be 1-65535, got '{text}'")
    return ports


async def run_server(host: str, ports: List[int]) -> None:
    loop = asyncio.get_running_loop()
    servers = [await loop.create_server(SilentProtocol, host, port) for port in ports]
    logger.info(f"Silent device listening on {host} port(s) {', '.join(map(str, ports))}; no request is answered")
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()


def main():
    parser = argparse.ArgumentParser(description="Device that accepts TCP connections and never answers")
    parser.add_argument("--host", default="127.0.0.1", help=DEFAULT_HOST_HELP)
    parser.add_argument("--ports", default=DEFAULT_PORTS, help=f"Comma-separated TCP ports (default: {DEFAULT_PORTS})")
    args = parser.parse_args()
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))
    run_simulator(run_server(args.host, ports), logger)


if __name__ == "__main__":
    main()
