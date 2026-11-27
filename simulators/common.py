"""
Command-line plumbing shared by the protocol simulators: the --host / --port
/ --denied options, running the server until Ctrl+C, and the fault options
(--delay, --drop-denied, --max-connections) that make a simulator behave
like a slow, picky or busy PLC.
"""

import argparse
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, List, Optional, Tuple

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


def simulator_parser(
    description: str, default_port: int, default_denied: Optional[str] = None
) -> argparse.ArgumentParser:
    """Parser with --host and --port (and --denied when a default is given)"""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default="127.0.0.1", help=DEFAULT_HOST_HELP)
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to listen on (default: {default_port})")
    if default_denied is not None:
        parser.add_argument(
            "--denied", default=default_denied, help=f"Denied address ranges (default: '{default_denied}')"
        )
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


@dataclass
class Faults:
    """
    Behaviours of real PLCs that the scanner must cope with:

    delay_ms: every answer is sent this much later (a busy CPU, a slow
        network); longer than the scanner's timeout, every request times out
    drop_denied: a request that touches a denied address is not answered
        at all (some devices drop such requests instead of answering an
        error): the scanner's unanswered-range search
    max_connections: connections beyond this many are closed at once (a
        PLC port with its connections in use, e.g. by a DeviceGateway); 0 =
        no limit
    """

    delay_ms: int = 0
    drop_denied: bool = False
    max_connections: int = 0

    @property
    def active(self) -> bool:
        return bool(self.delay_ms or self.drop_denied or self.max_connections)


def add_fault_options(parser: argparse.ArgumentParser) -> None:
    """--delay, --drop-denied and --max-connections"""
    parser.add_argument("--delay", type=int, default=0, metavar="MS", help="Send every answer MS milliseconds late")
    parser.add_argument(
        "--drop-denied",
        action="store_true",
        help="Do not answer requests that touch a denied address (instead of an error answer)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=0,
        metavar="N",
        help="Close connections beyond N at once, like a PLC port in use (default: no limit)",
    )


def faults_from_args(args: argparse.Namespace) -> Faults:
    return Faults(
        delay_ms=max(0, getattr(args, "delay", 0) or 0),
        drop_denied=bool(getattr(args, "drop_denied", False)),
        max_connections=max(0, getattr(args, "max_connections", 0) or 0),
    )


def log_faults(faults: Optional[Faults], logger: logging.Logger) -> None:
    if faults and faults.active:
        parts = []
        if faults.delay_ms:
            parts.append(f"answers {faults.delay_ms} ms late")
        if faults.drop_denied:
            parts.append("requests touching a denied address are not answered")
        if faults.max_connections:
            parts.append(f"at most {faults.max_connections} connection(s)")
        logger.info("Faults: " + "; ".join(parts))


class _FaultyTransport:
    """A connection's transport whose writes are delayed or dropped"""

    def __init__(self, transport: Any, faults: Faults, device: Any) -> None:
        self._transport = transport
        self._faults = faults
        self._device = device

    def __getattr__(self, name: str) -> Any:
        return getattr(self._transport, name)

    def write(self, data: bytes) -> None:
        if self._device is not None and getattr(self._device, "_fault_denied_seen", False):
            # The request touched a denied address: no answer at all
            self._device._fault_denied_seen = False
            return
        if not self._faults.delay_ms:
            self._transport.write(data)
            return

        def late_write() -> None:
            if not self._transport.is_closing():
                self._transport.write(data)

        asyncio.get_running_loop().call_later(self._faults.delay_ms / 1000, late_write)


class _FaultyProtocol(asyncio.Protocol):
    """Wraps a simulator's protocol: connection limit, late / dropped answers"""

    def __init__(self, inner: asyncio.Protocol, faults: Faults, device: Any, counter: List[int]) -> None:
        self._inner = inner
        self._faults = faults
        self._device = device
        self._counter = counter
        self._refused = False

    def connection_made(self, transport: Any) -> None:
        if self._faults.max_connections and self._counter[0] >= self._faults.max_connections:
            self._refused = True
            logging.getLogger("Simulator").info(
                f"Connection from {peer_text(transport)} closed: "
                f"{self._faults.max_connections} connection(s) already in use"
            )
            transport.close()
            return
        self._counter[0] += 1
        # Duck-typed: forwards everything to the real transport but write()
        self._inner.connection_made(_FaultyTransport(transport, self._faults, self._device))  # type: ignore[arg-type]

    def data_received(self, data: bytes) -> None:
        if self._refused:
            return
        if self._device is not None:
            self._device._fault_denied_seen = False
        self._inner.data_received(data)

    def eof_received(self) -> Optional[bool]:
        return None if self._refused else self._inner.eof_received()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._refused:
            return
        self._counter[0] -= 1
        self._inner.connection_lost(exc)


def _watch_denied(device: Any) -> None:
    """Make device.is_address_denied() remember a hit, for drop_denied"""
    original = getattr(device, "is_address_denied", None)
    if original is None or getattr(device, "_fault_watching", False):
        return

    def is_address_denied(*args: Any, **kwargs: Any) -> bool:
        denied = bool(original(*args, **kwargs))
        if denied:
            device._fault_denied_seen = True
        return denied

    device.is_address_denied = is_address_denied
    device._fault_watching = True
    device._fault_denied_seen = False


def with_faults(
    factory: Callable[[], asyncio.Protocol], faults: Optional[Faults], device: Any = None
) -> Callable[[], asyncio.Protocol]:
    """
    Protocol factory for create_server() with the faults applied (the
    factory itself when there are none). ``device`` is the simulated
    device whose is_address_denied() decides drop_denied.
    """
    if faults is None or not faults.active:
        return factory
    if faults.drop_denied and device is not None:
        _watch_denied(device)
    counter = [0]
    watched = device if faults.drop_denied else None
    return lambda: _FaultyProtocol(factory(), faults, watched, counter)
