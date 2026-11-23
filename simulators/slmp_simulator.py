#!/usr/bin/env python3
"""
SLMP (Seamless Message Protocol) Simulator

Simulates a Mitsubishi/Keyence PLC that responds to the SLMP / MC protocol
(binary code, 3E and 4E frames): batch, random and block reads, CPU model
name and loopback test. Used for testing PLC Discovery tool, or another
SLMP client (e.g. a device gateway), without physical hardware.

Usage:
    python slmp_simulator.py [--host 127.0.0.1] [--port 5001]
"""

import asyncio
import struct
import logging
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SLMP-Simulator")

# Shared CLI helpers (support both direct execution and package import)
try:
    from .common import parse_denied_ranges, run_simulator, simulator_parser
except ImportError:
    from common import parse_denied_ranges, run_simulator, simulator_parser  # type: ignore[no-redef]

# SLMP frame constants (binary code)
SLMP_SUBHEADER = 0x00D0  # 3E response subheader 'D0 00'
SUBHEADER_3E_REQUEST = 0x0050  # '50 00'
SUBHEADER_4E_REQUEST = 0x0054  # '54 00'
SUBHEADER_4E_RESPONSE = 0x00D4  # 'D4 00'
SLMP_NETWORK = 0x00
SLMP_PC_NO = 0xFF
SLMP_IO_NO = 0x03FF
SLMP_STATION = 0x00
# Longest request accepted (a 960-point block read is far shorter)
MAX_REQUEST_LENGTH = 8192

# Device codes (binary, Q/L series; the iQ-R format uses the same codes in 2 bytes)
DEVICE_CODES = {
    "D": 0xA8,    # Data register
    "W": 0xB4,    # Link register
    "R": 0xAF,    # File register
    "ZR": 0xB0,   # File register (serial number access)
    "SD": 0xA9,   # Special register
    "SW": 0xB5,   # Link special register
    "TN": 0xC2,   # Timer current value
    "CN": 0xC5,   # Counter current value
    "M": 0x90,    # Internal relay
    "X": 0x9C,    # Input
    "Y": 0x9D,    # Output
    "L": 0x92,    # Latch relay
    "F": 0x93,    # Annunciator
    "V": 0x94,    # Edge relay
    "B": 0xA0,    # Link relay
    "SM": 0x91,   # Special relay
    "SB": 0xA1,   # Link special relay
    "DX": 0xA2,   # Direct input
    "DY": 0xA3,   # Direct output
    "TS": 0xC1,   # Timer contact
    "TC": 0xC0,   # Timer coil
    "CS": 0xC4,   # Counter contact
    "CC": 0xC3,   # Counter coil
}
DEVICE_NAMES = {code: name for name, code in DEVICE_CODES.items()}
# Devices holding one bit per number (a word read packs 16 of them)
BIT_DEVICES = {"M", "X", "Y", "L", "F", "V", "B", "SM", "SB", "DX", "DY", "TS", "TC", "CS", "CC"}

# End codes
ERR_ILLEGAL_DEVICE = 0xC055       # used for denied / unknown devices (as before)
ERR_POINTS = 0xC051               # number of points out of range
ERR_UNSUPPORTED = 0xC059          # command / subcommand not supported
ERR_REQUEST_LENGTH = 0xC061       # request data length does not match

# Point limits of the Q series CPUs (3E/4E binary)
MAX_BATCH_WORDS = 960
MAX_BATCH_BITS = 7168
MAX_RANDOM_POINTS = 192           # word points + double word points
MAX_BLOCK_POINTS = 960
MAX_BLOCKS = 120


class SLMPError(Exception):
    """A request answered with an end code other than 0"""

    def __init__(self, code: int, message: str = ""):
        super().__init__(message or f"end code {code:04X}")
        self.code = code


class SLMPDevice:
    """Simulated SLMP device memory"""

    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None):
        """
        Initialize device memory.

        Args:
            denied_ranges: List of (start, end) tuples for addresses that should return errors
        """
        # Every device starts empty (reads as 0); bit devices hold 0 / 1
        self.memory: Dict[str, Dict[int, int]] = {name: {} for name in DEVICE_CODES}
        self.denied_ranges = denied_ranges or []
        # Answer to Read CPU Model Name (0101)
        self.cpu_model = "Q03UDVCPU"
        self.cpu_code = 0x0366
        self._initialize_sample_data()

    def _initialize_sample_data(self):
        """Initialize memory with sample data for testing"""
        # D registers with various test patterns
        for i in range(0, 1000):
            self.memory["D"][i] = i * 10  # D0=0, D1=10, D2=20...

        # Some specific test values
        self.memory["D"][100] = 0x1234
        self.memory["D"][101] = 0xABCD
        self.memory["D"][200] = 0xFFFF

        # M relays (bit devices)
        for i in range(0, 100):
            self.memory["M"][i] = i % 2  # Alternating 0 and 1

        # W link registers
        for i in range(0, 500):
            self.memory["W"][i] = 0x5500 + i

        logger.info("Sample data initialized")

    def is_address_denied(self, device: str, address: int) -> bool:
        """Check if address is in denied range"""
        for start, end in self.denied_ranges:
            if start <= address <= end:
                return True
        return False

    def _check(self, device: str, address: int, count: int) -> None:
        if device not in self.memory:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"unknown device {device}")
        for addr in range(address, address + count):
            if self.is_address_denied(device, addr):
                raise SLMPError(ERR_ILLEGAL_DEVICE, f"access denied: {device}{addr}")

    def words(self, device: str, address: int, count: int) -> List[int]:
        """``count`` words from ``address``; a bit device gives 16 bits per word (LSB first)"""
        if device in BIT_DEVICES:
            self._check(device, address, count * 16)
            bits = self.memory[device]
            return [
                sum((bits.get(address + i * 16 + k, 0) & 1) << k for k in range(16))
                for i in range(count)
            ]
        self._check(device, address, count)
        return [self.memory[device].get(addr, 0) & 0xFFFF for addr in range(address, address + count)]

    def bits(self, device: str, address: int, count: int) -> List[int]:
        """``count`` bits of a bit device"""
        if device not in BIT_DEVICES:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"{device} is not a bit device")
        self._check(device, address, count)
        return [self.memory[device].get(addr, 0) & 1 for addr in range(address, address + count)]

    def read_word(self, device: str, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read word data: (values or None, end code)"""
        try:
            return self.words(device, address, count), 0
        except SLMPError as e:
            logger.debug(str(e))
            return None, e.code

    def read_bit(self, device: str, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read bit data: (values or None, end code)"""
        try:
            return self.bits(device, address, count), 0
        except SLMPError as e:
            logger.debug(str(e))
            return None, e.code


def _pack_words(values: List[int]) -> bytes:
    return b"".join(struct.pack("<H", v & 0xFFFF) for v in values)


def _pack_bits(values: List[int]) -> bytes:
    """Two points per byte, the first in the upper 4 bits"""
    data = bytearray()
    for i in range(0, len(values), 2):
        high = values[i] & 1
        low = values[i + 1] & 1 if i + 1 < len(values) else 0
        data.append((high << 4) | low)
    return bytes(data)


class SLMPProtocol(asyncio.Protocol):
    """
    SLMP / MC protocol server, binary code, 3E and 4E frames.

    Supported commands (Q/L series format, and the iQ-R format with 4-byte
    device numbers where noted): batch read in word / bit units (0401,
    subcommand 0000 / 0001, iQ-R 0002 / 0003), random read (0403, 0000 /
    0002), block read (0406, 0000 / 0002), read CPU model name (0101) and
    loopback test (0619). The simulator is read-only: writes are answered
    as unsupported.
    """

    def __init__(self, device: SLMPDevice):
        self.device = device
        self.transport = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        logger.info(f"Connection from {peername}")

    def connection_lost(self, exc):
        logger.info("Connection closed")

    def data_received(self, data: bytes):
        """Answer every complete frame; a frame may arrive in pieces or several at once"""
        self.buffer += data
        while self.buffer:
            frame = self._next_frame()
            if frame is None:
                return
            try:
                response = self._process_frame(frame)
            except Exception as e:  # never let one bad request kill the connection
                logger.error(f"Error processing frame: {e}")
                continue
            if response and self.transport is not None:
                self.transport.write(response)

    def _next_frame(self) -> Optional[bytes]:
        """Take one complete frame off the buffer (None until it has fully arrived)"""
        if len(self.buffer) < 2:
            return None
        subheader = struct.unpack("<H", self.buffer[0:2])[0]
        if subheader == SUBHEADER_3E_REQUEST:
            length_at = 7
        elif subheader == SUBHEADER_4E_REQUEST:
            length_at = 11
        else:
            # No way to find the next frame boundary: drop what was received
            logger.warning(f"Invalid subheader: {subheader:04X} (binary 3E/4E frames only)")
            self.buffer = b""
            return None
        if len(self.buffer) < length_at + 2:
            return None
        length = struct.unpack("<H", self.buffer[length_at:length_at + 2])[0]
        if length > MAX_REQUEST_LENGTH:
            logger.warning(f"Request data length {length} too large; dropping the received data")
            self.buffer = b""
            return None
        end = length_at + 2 + length
        if len(self.buffer) < end:
            return None
        frame, self.buffer = self.buffer[:end], self.buffer[end:]
        return frame

    def _process_frame(self, frame: bytes) -> bytes:
        """Process one SLMP request frame and return the response"""
        subheader = struct.unpack("<H", frame[0:2])[0]
        if subheader == SUBHEADER_4E_REQUEST:
            # Subheader, serial number, 00 00, then the 3E header
            prefix = struct.pack("<H", SUBHEADER_4E_RESPONSE) + frame[2:6]
            route, body = frame[6:11], frame[13:]
        else:
            prefix = struct.pack("<H", SLMP_SUBHEADER)
            route, body = frame[2:7], frame[9:]
        # body: monitoring timer (2), command (2), subcommand (2), data
        if len(body) < 6:
            return self._response(prefix, route, ERR_REQUEST_LENGTH, error_info=route + body[2:6])
        command, subcommand = struct.unpack("<HH", body[2:6])
        logger.debug(f"Command: {command:04X}, Subcommand: {subcommand:04X}")
        try:
            data = self._handle(command, subcommand, body[6:])
        except SLMPError as e:
            if e.code == ERR_UNSUPPORTED:
                logger.warning(f"Unsupported command: {command:04X} subcommand {subcommand:04X}")
            else:
                logger.info(f"Command {command:04X}: {e}")
            return self._response(prefix, route, e.code, error_info=route + body[2:6])
        return self._response(prefix, route, 0, data)

    @staticmethod
    def _response(prefix: bytes, route: bytes, end_code: int, data: bytes = b"", error_info: bytes = b"") -> bytes:
        """Response with the request's route (network, PC, I/O, station) echoed"""
        payload = struct.pack("<H", end_code) + (data if end_code == 0 else error_info)
        return prefix + route + struct.pack("<H", len(payload)) + payload

    # -- commands --

    def _handle(self, command: int, subcommand: int, data: bytes) -> bytes:
        iqr = subcommand in (0x0002, 0x0003)
        if command == 0x0401 and subcommand in (0x0000, 0x0002):
            return self._batch_read(data, iqr, bit_units=False)
        if command == 0x0401 and subcommand in (0x0001, 0x0003):
            return self._batch_read(data, iqr, bit_units=True)
        if command == 0x0403 and subcommand in (0x0000, 0x0002):
            return self._random_read(data, iqr)
        if command == 0x0406 and subcommand in (0x0000, 0x0002):
            return self._block_read(data, iqr)
        if command == 0x0101 and subcommand == 0x0000:
            name = self.device.cpu_model.encode("ascii")[:16].ljust(16, b" ")
            return name + struct.pack("<H", self.device.cpu_code)
        if command == 0x0619 and subcommand == 0x0000:
            if len(data) < 2:
                raise SLMPError(ERR_REQUEST_LENGTH)
            size = struct.unpack("<H", data[0:2])[0]
            if len(data) != 2 + size:
                raise SLMPError(ERR_REQUEST_LENGTH)
            return data
        raise SLMPError(ERR_UNSUPPORTED)

    @staticmethod
    def _device_spec(data: bytes, offset: int, iqr: bool) -> Tuple[str, int, int]:
        """(device name, number, next offset); 3+1 bytes, or 4+2 bytes in the iQ-R format"""
        size = 6 if iqr else 4
        if len(data) < offset + size:
            raise SLMPError(ERR_REQUEST_LENGTH)
        if iqr:
            number = struct.unpack("<I", data[offset:offset + 4])[0]
            code = struct.unpack("<H", data[offset + 4:offset + 6])[0]
        else:
            number = struct.unpack("<I", data[offset:offset + 3] + b"\x00")[0]
            code = data[offset + 3]
        name = DEVICE_NAMES.get(code)
        if name is None:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"unknown device code {code:02X}")
        return name, number, offset + size

    @staticmethod
    def _points(data: bytes, offset: int) -> Tuple[int, int]:
        if len(data) < offset + 2:
            raise SLMPError(ERR_REQUEST_LENGTH)
        return struct.unpack("<H", data[offset:offset + 2])[0], offset + 2

    def _batch_read(self, data: bytes, iqr: bool, bit_units: bool) -> bytes:
        device, number, offset = self._device_spec(data, 0, iqr)
        points, offset = self._points(data, offset)
        if offset != len(data):
            raise SLMPError(ERR_REQUEST_LENGTH)
        limit = MAX_BATCH_BITS if bit_units else MAX_BATCH_WORDS
        if not 1 <= points <= limit:
            raise SLMPError(ERR_POINTS, f"{points} points (1-{limit})")
        if bit_units:
            logger.debug(f"Read bits: {device}{number} x {points} points")
            return _pack_bits(self.device.bits(device, number, points))
        logger.debug(f"Read: {device}{number} x {points} words")
        return _pack_words(self.device.words(device, number, points))

    def _random_read(self, data: bytes, iqr: bool) -> bytes:
        if len(data) < 2:
            raise SLMPError(ERR_REQUEST_LENGTH)
        word_count, dword_count = data[0], data[1]
        if not 1 <= word_count + dword_count <= MAX_RANDOM_POINTS:
            raise SLMPError(ERR_POINTS, f"{word_count + dword_count} points (1-{MAX_RANDOM_POINTS})")
        offset = 2
        specs = []
        for _ in range(word_count + dword_count):
            device, number, offset = self._device_spec(data, offset, iqr)
            specs.append((device, number))
        if offset != len(data):
            raise SLMPError(ERR_REQUEST_LENGTH)
        values: List[int] = []
        for device, number in specs[:word_count]:
            values += self.device.words(device, number, 1)
        for device, number in specs[word_count:]:
            values += self.device.words(device, number, 2)  # low word first
        logger.debug(f"Random read: {word_count} word(s), {dword_count} double word(s)")
        return _pack_words(values)

    def _block_read(self, data: bytes, iqr: bool) -> bytes:
        if len(data) < 2:
            raise SLMPError(ERR_REQUEST_LENGTH)
        word_blocks, bit_blocks = data[0], data[1]
        if not 1 <= word_blocks + bit_blocks <= MAX_BLOCKS:
            raise SLMPError(ERR_POINTS, f"{word_blocks + bit_blocks} blocks (1-{MAX_BLOCKS})")
        offset = 2
        blocks = []
        for index in range(word_blocks + bit_blocks):
            device, number, offset = self._device_spec(data, offset, iqr)
            points, offset = self._points(data, offset)
            if index >= word_blocks and device not in BIT_DEVICES:
                raise SLMPError(ERR_ILLEGAL_DEVICE, f"bit block on word device {device}")
            blocks.append((device, number, points))
        if offset != len(data):
            raise SLMPError(ERR_REQUEST_LENGTH)
        total = sum(points for _, _, points in blocks)
        if not 1 <= total <= MAX_BLOCK_POINTS or any(points == 0 for _, _, points in blocks):
            raise SLMPError(ERR_POINTS, f"{total} points (1-{MAX_BLOCK_POINTS})")
        values: List[int] = []
        # Word blocks and bit blocks alike are read in words (16 bits each)
        for device, number, points in blocks:
            values += self.device.words(device, number, points)
        logger.debug(f"Block read: {word_blocks} word block(s), {bit_blocks} bit block(s)")
        return _pack_words(values)


async def run_server(host: str, port: int, denied_ranges: List[Tuple[int, int]]):
    """Run SLMP simulator server"""
    device = SLMPDevice(denied_ranges)

    loop = asyncio.get_event_loop()
    server = await loop.create_server(
        lambda: SLMPProtocol(device),
        host, port
    )

    addr = server.sockets[0].getsockname()
    logger.info(f"SLMP Simulator running on {addr[0]}:{addr[1]}")
    logger.info(f"Denied address ranges: {denied_ranges}")

    async with server:
        await server.serve_forever()


def main():
    parser = simulator_parser("SLMP PLC Simulator", 5001, "5000-5100,7000-7050")
    args = parser.parse_args()
    denied_ranges = parse_denied_ranges(args.denied)
    run_simulator(run_server(args.host, args.port, denied_ranges), logger)


if __name__ == "__main__":
    main()
