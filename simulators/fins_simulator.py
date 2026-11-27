#!/usr/bin/env python3
"""
FINS Protocol Simulator

Simulates an Omron PLC with FINS/UDP and FINS/TCP protocol support.
Used for testing without actual PLC hardware.

FINS/TCP framing (Omron W342):
    Header (16 bytes): "FINS" | length (4) | command (4) | error code (4)
    length counts the bytes after the length field (command + error + data).
    Commands: 0 = node address data send (client -> server)
              1 = node address data send (server -> client)
              2 = FINS frame send
              3 = FINS frame send error notification

Usage:
    python fins_simulator.py [--port 9600] [--host 127.0.0.1] [--transport both|udp|tcp]
"""

import asyncio
import logging
import random
import struct
from typing import Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Shared CLI helpers (support both direct execution and package import)
try:
    from .common import (
        Faults,
        add_fault_options,
        faults_from_args,
        log_faults,
        run_simulator,
        simulator_parser,
        with_datagram_faults,
        with_faults,
    )
except ImportError:
    from common import (  # type: ignore[no-redef]
        Faults,
        add_fault_options,
        faults_from_args,
        log_faults,
        run_simulator,
        simulator_parser,
        with_datagram_faults,
        with_faults,
    )

# FINS Constants
FINS_ICF_RESPONSE = 0xC0  # Response frame
FINS_CMD_MEMORY_READ = (0x01, 0x01)
FINS_CMD_CONTROLLER_DATA_READ = (0x05, 0x01)  # CPU model / version

# FINS/TCP constants
FINS_TCP_MAGIC = b"FINS"
FINS_TCP_HEADER_SIZE = 16
FINS_TCP_CMD_NODE_REQUEST = 0x00000000  # client -> server
FINS_TCP_CMD_NODE_RESPONSE = 0x00000001  # server -> client
FINS_TCP_CMD_FRAME = 0x00000002  # FINS frame send
FINS_TCP_CMD_ERROR = 0x00000003  # FINS frame send error notification
FINS_TCP_ERR_NOT_FINS = 0x00000001  # header is not "FINS"
FINS_TCP_ERR_TOO_LONG = 0x00000002  # data length too long
FINS_TCP_ERR_UNSUPPORTED = 0x00000003  # command not supported
FINS_TCP_MAX_LENGTH = 2048  # sanity limit for the length field
FINS_TCP_SERVER_NODE = 1  # simulated PLC node address

# Memory area codes
FINS_AREA_DM = 0x82
FINS_AREA_HR = 0xB2
FINS_AREA_W = 0xB1
FINS_AREA_CIO = 0xB0
FINS_AREA_AR = 0xB3
FINS_AREA_EM0 = 0xA0  # EM bank 0
FINS_AREA_TC = 0x89  # timer present values 0000-, counter present values 8000-

# Timers / counters per kind (CJ2): TIM0000-4095 at 0000-0FFF, CNT0000-4095 at 8000-8FFF
FINS_TC_POINTS = 4096
FINS_COUNTER_BASE = 0x8000

# Words per memory area (CS/CJ series) and per Memory Area Read
FINS_AREA_SIZES = {
    FINS_AREA_DM: 32768,
    FINS_AREA_HR: 512,
    FINS_AREA_W: 512,
    FINS_AREA_CIO: 6144,
    FINS_AREA_AR: 960,
    FINS_AREA_EM0: 32768,
    FINS_AREA_TC: FINS_COUNTER_BASE + FINS_TC_POINTS,
}
FINS_MAX_READ_WORDS = 999

# Simulated inaccessible ranges
INACCESSIBLE_RANGES = [
    (FINS_AREA_DM, 5000, 5100),  # DM5000-5100
    (FINS_AREA_HR, 300, 350),  # HR300-350 (inside the 512-word HR area)
]


class FINSSimulator:
    """Simulates an Omron PLC with FINS protocol"""

    def __init__(self, host: str = "127.0.0.1", port: int = 9600):
        self.host = host
        self.port = port
        self._running = False

        # Simulated memory areas
        self._dm_area: Dict[int, int] = {}  # DM area (0x82)
        self._hr_area: Dict[int, int] = {}  # HR area (0xB2)
        self._w_area: Dict[int, int] = {}  # W area (0xB1)
        self._ar_area: Dict[int, int] = {}  # AR area (0xB3)
        self._em_area: Dict[int, int] = {}  # EM bank 0 (0xA0)
        self._tc_area: Dict[int, int] = {}  # timer / counter present values (0x89)

        # Answer to Controller Data Read (05 01)
        self.cpu_model = "CJ2M-CPU33 Sim"
        self.cpu_version = "02.01"

        # Initialize with sample data
        self._initialize_sample_data()

    def _initialize_sample_data(self):
        """Initialize memory areas with sample data"""
        # DM Area: Various data patterns
        for i in range(1000):
            if i < 100:
                # Temperature values (scaled by 10)
                self._dm_area[i] = 200 + random.randint(-20, 50)
            elif i < 200:
                # Counter values
                self._dm_area[i] = i * 10
            elif i < 300:
                # Random production data
                self._dm_area[i] = random.randint(0, 65535)
            else:
                # Sequential pattern
                self._dm_area[i] = i

        # HR Area: Holding registers
        for i in range(500):
            self._hr_area[i] = i * 2

        # W Area: Work registers
        for i in range(200):
            self._w_area[i] = random.randint(0, 255)

        # AR, EM, timers (TIM0-99) and counters (CNT0-99)
        for i in range(100):
            self._ar_area[i] = i
            self._em_area[i] = 1000 + i
            self._tc_area[i] = 50 + i
            self._tc_area[FINS_COUNTER_BASE + i] = i * 3

        logger.info(f"Initialized DM: {len(self._dm_area)} words")
        logger.info(f"Initialized HR: {len(self._hr_area)} words")
        logger.info(f"Initialized W: {len(self._w_area)} words")

    def _get_memory_area(self, area_code: int) -> Dict[int, int]:
        """Get memory area dictionary by code"""
        if area_code == FINS_AREA_DM:
            return self._dm_area
        elif area_code == FINS_AREA_HR:
            return self._hr_area
        elif area_code == FINS_AREA_W:
            return self._w_area
        elif area_code == FINS_AREA_AR:
            return self._ar_area
        elif area_code == FINS_AREA_EM0:
            return self._em_area
        elif area_code == FINS_AREA_TC:
            return self._tc_area
        else:
            return {}

    def _is_accessible(self, area_code: int, address: int) -> bool:
        """Check if address is accessible"""
        return not self.is_address_denied(area_code, address)

    def is_address_denied(self, area_code: int, address: int) -> bool:
        """An address of INACCESSIBLE_RANGES (answered 1103, or not at all with --drop-denied)"""
        return any(area == area_code and start <= address <= end for area, start, end in INACCESSIBLE_RANGES)

    def handle_frame(self, data: bytes, client_addr: Tuple[str, int]) -> Optional[bytes]:
        """
        Process one FINS frame (shared by UDP and TCP) and return the
        response frame, or None if the frame is too short to answer.
        """
        if len(data) < 12:
            logger.warning("Invalid FINS frame (too short)")
            return None

        cmd_main = data[10]
        cmd_sub = data[11]

        if (cmd_main, cmd_sub) == FINS_CMD_MEMORY_READ:
            return self._handle_read_command(data, client_addr)
        if (cmd_main, cmd_sub) == FINS_CMD_CONTROLLER_DATA_READ:
            # CPU unit model (20) + version (20) + system use (40) + area data (12)
            reply = (
                self.cpu_model.encode().ljust(20, b" ")
                + self.cpu_version.encode().ljust(20, b" ")
                + bytes(40)
                + bytes(12)
            )
            return self._build_success_response(data, reply)

        logger.warning(f"Unknown command: {cmd_main:02X} {cmd_sub:02X}")
        return self._build_error_response(data, 0x0401)

    def _handle_read_command(self, request: bytes, client_addr: Tuple[str, int]) -> bytes:
        """Handle memory area read command"""
        # Parse request
        # Format: Header(10) + Cmd(2) + AreaCode(1) + AddrHigh(1) + AddrLow(1) + Bit(1) + CountHigh(1) + CountLow(1)
        if len(request) < 18:
            return self._build_error_response(request, 0x0401)

        area_code = request[12]
        addr_high = request[13]
        addr_low = request[14]
        start_address = (addr_high << 8) | addr_low
        count_high = request[16]
        count_low = request[17]
        count = (count_high << 8) | count_low

        logger.debug(f"Read request: area=0x{area_code:02X}, " f"addr={start_address}, count={count}")

        # Answer as a CPU does, not with zeros: these are the end codes the
        # scanner's error handling and request-size limit depend on
        size = FINS_AREA_SIZES.get(area_code)
        if size is None:
            return self._build_error_response(request, 0x1101)  # area classification missing
        if count == 0:
            return self._build_error_response(request, 0x110C)  # parameter error
        if count > FINS_MAX_READ_WORDS:
            return self._build_error_response(request, 0x110B)  # response too long
        if start_address + count > size:
            return self._build_error_response(request, 0x1104)  # address range exceeded
        if area_code == FINS_AREA_TC and not (
            start_address + count <= FINS_TC_POINTS
            or FINS_COUNTER_BASE <= start_address <= start_address + count <= FINS_COUNTER_BASE + FINS_TC_POINTS
        ):
            return self._build_error_response(request, 0x1104)  # beyond TIM4095 / CNT4095

        # Check accessibility
        for addr in range(start_address, start_address + count):
            if not self._is_accessible(area_code, addr):
                logger.warning(f"Inaccessible address: area=0x{area_code:02X}, addr={addr}")
                return self._build_error_response(request, 0x1103)  # address range error

        # Get memory area
        memory = self._get_memory_area(area_code)

        # Build response data
        data = []
        for addr in range(start_address, start_address + count):
            value = memory.get(addr, 0)
            data.append((value >> 8) & 0xFF)  # High byte
            data.append(value & 0xFF)  # Low byte

        return self._build_success_response(request, bytes(data))

    def _build_success_response(self, request: bytes, data: bytes) -> bytes:
        """Build successful response frame"""
        # Response header
        header = bytes(
            [
                FINS_ICF_RESPONSE,  # ICF (response)
                request[1],  # RSV
                request[2],  # GCT
                request[6],  # DNA (swap with source)
                request[7],  # DA1
                request[8],  # DA2
                request[3],  # SNA
                request[4],  # SA1
                request[5],  # SA2
                request[9],  # SID
            ]
        )

        # Command code
        cmd = bytes([request[10], request[11]])

        # End code (success)
        end_code = bytes([0x00, 0x00])

        return header + cmd + end_code + data

    def _build_error_response(self, request: bytes, error_code: int) -> bytes:
        """Build error response frame"""
        # Response header
        header = bytes(
            [
                FINS_ICF_RESPONSE,
                request[1],
                request[2],
                request[6],
                request[7],
                request[8],
                request[3],
                request[4],
                request[5],
                request[9],
            ]
        )

        # Command code
        cmd = bytes([request[10], request[11]])

        # End code (error)
        end_code = bytes([(error_code >> 8) & 0xFF, error_code & 0xFF])

        return header + cmd + end_code


class FINSUDPServerProtocol(asyncio.DatagramProtocol):
    """UDP Protocol handler for FINS simulator"""

    def __init__(self, simulator: FINSSimulator):
        self.simulator = simulator
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("FINS UDP server ready")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        logger.debug(f"Received {len(data)} bytes from {addr}")
        response = self.simulator.handle_frame(data, addr)
        if response is not None and self.transport is not None:
            self.transport.sendto(response, addr)


def build_fins_tcp_frame(command: int, payload: bytes = b"", error_code: int = 0) -> bytes:
    """Build a FINS/TCP frame: header + payload"""
    length = 8 + len(payload)  # command + error code + payload
    return FINS_TCP_MAGIC + struct.pack(">III", length, command, error_code) + payload


class FINSTCPServerProtocol(asyncio.Protocol):
    """
    FINS/TCP connection handler for the simulator.

    The client must first send a node address request (command 0); the
    server answers with the client and server node addresses (command 1).
    After that, FINS frames are exchanged with command 2.
    """

    # Node addresses handed out to clients that request automatic allocation
    _next_client_node = 10

    def __init__(self, simulator: FINSSimulator):
        self.simulator = simulator
        # Set by connection_made, before any data arrives
        self.transport: asyncio.Transport
        self.peer: Tuple[str, int] = ("?", 0)
        self.client_node: Optional[int] = None
        self._buffer = bytearray()

    @classmethod
    def _allocate_node(cls) -> int:
        node = cls._next_client_node
        cls._next_client_node = 10 + (cls._next_client_node - 9) % 240  # stay within 10-249
        return node

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.info(f"FINS/TCP client connected: {self.peer}")

    def connection_lost(self, exc):
        logger.info(f"FINS/TCP client disconnected: {self.peer} (node {self.client_node})")

    def data_received(self, data: bytes) -> None:
        self._buffer.extend(data)
        while len(self._buffer) >= FINS_TCP_HEADER_SIZE:
            if bytes(self._buffer[:4]) != FINS_TCP_MAGIC:
                logger.warning("FINS/TCP: header is not 'FINS'")
                self._send_error(FINS_TCP_ERR_NOT_FINS)
                self.transport.close()
                return

            length = struct.unpack(">I", self._buffer[4:8])[0]
            if length < 8 or length > FINS_TCP_MAX_LENGTH:
                logger.warning(f"FINS/TCP: invalid length {length}")
                self._send_error(FINS_TCP_ERR_TOO_LONG)
                self.transport.close()
                return

            frame_size = 8 + length  # magic + length field + (command + error + data)
            if len(self._buffer) < frame_size:
                return  # wait for the rest of the frame

            frame = bytes(self._buffer[:frame_size])
            del self._buffer[:frame_size]
            self._handle_tcp_frame(frame)

    def _send_error(self, error_code: int) -> None:
        self.transport.write(build_fins_tcp_frame(FINS_TCP_CMD_ERROR, error_code=error_code))

    def _handle_tcp_frame(self, frame: bytes) -> None:
        command = struct.unpack(">I", frame[8:12])[0]
        payload = frame[FINS_TCP_HEADER_SIZE:]

        if command == FINS_TCP_CMD_NODE_REQUEST:
            requested = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else 0
            self.client_node = requested if 0 < requested < 255 else self._allocate_node()
            logger.debug(f"FINS/TCP node allocation: client={self.client_node}, server={FINS_TCP_SERVER_NODE}")
            self.transport.write(
                build_fins_tcp_frame(
                    FINS_TCP_CMD_NODE_RESPONSE,
                    struct.pack(">II", self.client_node, FINS_TCP_SERVER_NODE),
                )
            )
            return

        if command == FINS_TCP_CMD_FRAME:
            if self.client_node is None:
                logger.warning("FINS/TCP: FINS frame before node address exchange")
                self._send_error(FINS_TCP_ERR_UNSUPPORTED)
                return
            response = self.simulator.handle_frame(payload, self.peer)
            if response is not None:
                self.transport.write(build_fins_tcp_frame(FINS_TCP_CMD_FRAME, response))
            return

        logger.warning(f"FINS/TCP: unsupported command 0x{command:08X}")
        self._send_error(FINS_TCP_ERR_UNSUPPORTED)


async def run_fins_simulator(host: str, port: int, transport: str = "both", faults: Optional[Faults] = None) -> None:
    """
    Run FINS simulator server.

    Args:
        host: Address to bind
        port: Port for both UDP and TCP (Omron default 9600)
        transport: "udp", "tcp" or "both"
        faults: late / dropped answers (UDP and TCP) and the connection limit (TCP)
    """
    simulator = FINSSimulator(host, port)

    loop = asyncio.get_running_loop()
    udp_transport = None
    tcp_server = None

    if transport in ("udp", "both"):
        udp_transport, _ = await loop.create_datagram_endpoint(
            with_datagram_faults(lambda: FINSUDPServerProtocol(simulator), faults, simulator), local_addr=(host, port)
        )

    if transport in ("tcp", "both"):
        tcp_server = await loop.create_server(
            with_faults(lambda: FINSTCPServerProtocol(simulator), faults, simulator), host, port
        )

    logger.info(f"FINS Simulator started on {host}:{port} ({transport.upper()})")
    logger.info("Memory areas:")
    logger.info("  DM Area (0x82): 0-999 (accessible)")
    logger.info("  DM Area (0x82): 5000-5100 (INACCESSIBLE)")
    logger.info("  HR Area (0xB2): 0-499 (accessible)")
    logger.info("  HR Area (0xB2): 300-350 (INACCESSIBLE)")
    logger.info("  W Area (0xB1): 0-199 (accessible)")
    logger.info("  AR (0xB3) 0-959, EM bank 0 (0xA0) 0-32767, TIM / CNT (0x89) 0-4095")
    log_faults(faults, logger)

    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info("FINS Simulator shutting down...")
    finally:
        if udp_transport:
            udp_transport.close()
        if tcp_server:
            tcp_server.close()
            # wait_closed() waits for connected clients (Python 3.12+): with
            # a scanner still connected, Ctrl+C would never end the simulator
            try:
                await asyncio.wait_for(tcp_server.wait_closed(), timeout=2)
            except asyncio.TimeoutError:
                logger.info("FINS Simulator stopped with clients still connected")


def main():
    parser = simulator_parser("FINS Protocol Simulator for Omron PLCs", 9600)
    parser.add_argument(
        "--transport", choices=["both", "udp", "tcp"], default="both", help="Transport(s) to serve (default: both)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    add_fault_options(parser)
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    run_simulator(run_fins_simulator(args.host, args.port, args.transport, faults_from_args(args)), logger)


if __name__ == "__main__":
    main()
