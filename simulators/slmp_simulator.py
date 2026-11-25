#!/usr/bin/env python3
"""
SLMP (Seamless Message Protocol) Simulator

Simulates a Mitsubishi/Keyence PLC that responds to the SLMP / MC protocol
(binary code, 3E and 4E frames): batch, random and block reads, CPU model
name and loopback test, and with --writable batch / random writes. Used for
testing PLC Discovery tool, or another SLMP client (e.g. a device gateway),
without physical hardware.

The simulated CPU is a Q03UDVCPU or an R04CPU (--cpu, see CPU_MODELS): its
model name answers "read CPU model" and device numbers end where its do -
reading past them is answered with C056, like the real CPU.

Usage:
    python slmp_simulator.py [--host 127.0.0.1] [--port 5001] [--writable] [--cpu R04CPU]
"""

import asyncio
import logging
import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SLMP-Simulator")

# Shared CLI helpers (support both direct execution and package import)
try:
    from .common import parse_denied_ranges, peer_text, run_simulator, serve_until_stopped, simulator_parser
except ImportError:
    from common import (  # type: ignore[no-redef]
        parse_denied_ranges,
        peer_text,
        run_simulator,
        serve_until_stopped,
        simulator_parser,
    )

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
# Distinct error lines remembered per connection (see SLMPProtocol._log_once)
MAX_LOGGED_ERRORS = 1000

# Device codes (binary, Q/L series; the iQ-R format uses the same codes in 2 bytes)
DEVICE_CODES = {
    "D": 0xA8,  # Data register
    "W": 0xB4,  # Link register
    "R": 0xAF,  # File register
    "ZR": 0xB0,  # File register (serial number access)
    "SD": 0xA9,  # Special register
    "SW": 0xB5,  # Link special register
    "TN": 0xC2,  # Timer current value
    "CN": 0xC5,  # Counter current value
    "M": 0x90,  # Internal relay
    "X": 0x9C,  # Input
    "Y": 0x9D,  # Output
    "L": 0x92,  # Latch relay
    "F": 0x93,  # Annunciator
    "V": 0x94,  # Edge relay
    "B": 0xA0,  # Link relay
    "SM": 0x91,  # Special relay
    "SB": 0xA1,  # Link special relay
    "DX": 0xA2,  # Direct input
    "DY": 0xA3,  # Direct output
    "TS": 0xC1,  # Timer contact
    "TC": 0xC0,  # Timer coil
    "CS": 0xC4,  # Counter contact
    "CC": 0xC3,  # Counter coil
}
DEVICE_NAMES = {code: name for name, code in DEVICE_CODES.items()}
# Points of each device (numbers 0 to points - 1): the default parameters of
# a Q03UDVCPU (file registers R / ZR: 32K / 96K points of the standard RAM)
DEVICE_LIMITS = {
    "D": 12288,
    "W": 8192,
    "R": 32768,
    "ZR": 98304,
    "SD": 2048,
    "SW": 2048,
    "TN": 2048,
    "CN": 1024,
    "M": 8192,
    "X": 8192,
    "Y": 8192,
    "L": 8192,
    "F": 2048,
    "V": 2048,
    "B": 8192,
    "SM": 2048,
    "SB": 2048,
    "DX": 8192,
    "DY": 8192,
    "TS": 2048,
    "TC": 2048,
    "CS": 1024,
    "CC": 1024,
}
# An iQ-R R04CPU with its default device settings (file registers assumed
# like the Q03UDVCPU's: they depend on the memory configured)
R04_DEVICE_LIMITS = {
    **DEVICE_LIMITS,
    "D": 18432,
    "M": 12288,
    "X": 12288,
    "Y": 12288,
    "DX": 12288,
    "DY": 12288,
    "SM": 4096,
    "SD": 4096,
    "TN": 1024,
    "TS": 1024,
    "TC": 1024,
    "CN": 512,
    "CS": 512,
    "CC": 512,
}


class CPUModel(NamedTuple):
    code: int  # model code answered with the name (Read CPU Model Name, 0101)
    limits: Dict[str, int]


CPU_MODELS = {
    "Q03UDVCPU": CPUModel(0x0366, DEVICE_LIMITS),
    "R04CPU": CPUModel(0x4800, R04_DEVICE_LIMITS),
}
DEFAULT_CPU = "Q03UDVCPU"
# Devices holding one bit per number (a word read packs 16 of them)
BIT_DEVICES = {"M", "X", "Y", "L", "F", "V", "B", "SM", "SB", "DX", "DY", "TS", "TC", "CS", "CC"}

# End codes
ERR_ILLEGAL_DEVICE = 0xC055  # used for denied / unknown devices (as before)
ERR_POINTS = 0xC051  # number of points out of range
ERR_ADDRESS_RANGE = 0xC056  # beyond the device's last number
ERR_UNSUPPORTED = 0xC059  # command / subcommand not supported
ERR_REQUEST_LENGTH = 0xC061  # request data length does not match

# Point limits of the Q series CPUs (3E/4E binary)
MAX_BATCH_WORDS = 960
MAX_BATCH_BITS = 7168
MAX_RANDOM_POINTS = 192  # word points + double word points
MAX_BLOCK_POINTS = 960
MAX_BLOCKS = 120
MAX_RANDOM_WRITE_SIZE = 1920  # word points x 12 + double word points x 14
MAX_RANDOM_WRITE_BITS = 188


class SLMPError(Exception):
    """A request answered with an end code other than 0"""

    def __init__(self, code: int, message: str = ""):
        super().__init__(message or f"end code {code:04X}")
        self.code = code


class SLMPDevice:
    """Simulated SLMP device memory"""

    def __init__(
        self,
        denied_ranges: Optional[List[Tuple[int, int]]] = None,
        writable: bool = False,
        limits: Optional[Dict[str, int]] = None,
        cpu: str = DEFAULT_CPU,
    ):
        """
        Initialize device memory.

        Args:
            denied_ranges: List of (start, end) tuples for addresses that should return errors
            writable: Accept write commands (1401 / 1402); otherwise they are unsupported (C059)
            limits: Points per device, overriding those of the CPU
            cpu: Simulated CPU model (a key of CPU_MODELS)
        """
        # Every device starts empty (reads as 0); bit devices hold 0 / 1
        self.memory: Dict[str, Dict[int, int]] = {name: {} for name in DEVICE_CODES}
        self.denied_ranges = denied_ranges or []
        self.writable = writable
        if cpu not in CPU_MODELS:
            raise ValueError(f"unknown CPU model {cpu!r} (known: {', '.join(CPU_MODELS)})")
        self.limits = {**CPU_MODELS[cpu].limits, **(limits or {})}
        # Answer to Read CPU Model Name (0101)
        self.cpu_model = cpu
        self.cpu_code = CPU_MODELS[cpu].code
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

    def check_range(self, device: str, address: int, count: int = 1) -> None:
        """C056 unless numbers ``address`` .. ``address + count - 1`` exist on this CPU"""
        if device not in self.memory:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"unknown device {device}")
        limit = self.limits[device]
        if address < 0 or address + count > limit:
            raise SLMPError(ERR_ADDRESS_RANGE, f"{device}{address} x {count} beyond {device}0-{device}{limit - 1}")

    def _check(self, device: str, address: int, count: int) -> None:
        self.check_range(device, address, count)
        for addr in range(address, address + count):
            if self.is_address_denied(device, addr):
                raise SLMPError(ERR_ILLEGAL_DEVICE, f"access denied: {device}{addr}")

    def words(self, device: str, address: int, count: int) -> List[int]:
        """``count`` words from ``address``; a bit device gives 16 bits per word (LSB first)"""
        if device in BIT_DEVICES:
            self._check(device, address, count * 16)
            bits = self.memory[device]
            return [sum((bits.get(address + i * 16 + k, 0) & 1) << k for k in range(16)) for i in range(count)]
        self._check(device, address, count)
        return [self.memory[device].get(addr, 0) & 0xFFFF for addr in range(address, address + count)]

    def bits(self, device: str, address: int, count: int) -> List[int]:
        """``count`` bits of a bit device"""
        if device not in BIT_DEVICES:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"{device} is not a bit device")
        self._check(device, address, count)
        return [self.memory[device].get(addr, 0) & 1 for addr in range(address, address + count)]

    def write_words(self, device: str, address: int, values: List[int]) -> None:
        """Write words from ``address``; a bit device takes 16 bits per word (LSB first)"""
        if device in BIT_DEVICES:
            self._check(device, address, len(values) * 16)
            for i, word in enumerate(values):
                for k in range(16):
                    self.memory[device][address + i * 16 + k] = (word >> k) & 1
            return
        self._check(device, address, len(values))
        for i, word in enumerate(values):
            self.memory[device][address + i] = word & 0xFFFF

    def write_bits(self, device: str, address: int, values: List[int]) -> None:
        """Write bits of a bit device"""
        if device not in BIT_DEVICES:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"{device} is not a bit device")
        self._check(device, address, len(values))
        for i, bit in enumerate(values):
            self.memory[device][address + i] = bit & 1

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


def _unpack_bits(data: bytes, count: int) -> List[int]:
    """``count`` points packed two per byte, the first in the upper 4 bits"""
    return [(data[i // 2] >> (0 if i % 2 else 4)) & 1 for i in range(count)]


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
    loopback test (0619). Batch / random writes (1401 / 1402) only when the
    device is writable; otherwise they are answered as unsupported (C059).
    """

    def __init__(self, device: SLMPDevice):
        self.device = device
        self.transport = None
        self.buffer = b""
        # Error lines already logged on this connection: a client polling
        # every few ms repeats the same failing request, logged once here
        self._logged: set = set()

    def _log_once(self, level: int, message: str) -> None:
        """Log ``message`` at ``level`` the first time on this connection, then at DEBUG"""
        if message in self._logged:
            logger.debug(message)
            return
        if len(self._logged) < MAX_LOGGED_ERRORS:
            self._logged.add(message)
        logger.log(level, message)

    def connection_made(self, transport):
        self.transport = transport
        self.peer = peer_text(transport)
        logger.info(f"Connection from {self.peer}")

    def connection_lost(self, exc):
        logger.info(f"Connection closed: {getattr(self, 'peer', '?')}")

    def data_received(self, data: bytes) -> None:
        """Answer every complete frame; a frame may arrive in pieces or several at once"""
        self.buffer += data
        while self.buffer:
            frame = self._next_frame()
            if frame is None:
                return
            try:
                response = self._process_frame(frame)
            except Exception as e:  # never let one bad request kill the connection
                self._log_once(logging.ERROR, f"Error processing frame: {e}")
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
        length = struct.unpack("<H", self.buffer[length_at : length_at + 2])[0]
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
                self._log_once(logging.WARNING, f"Unsupported command: {command:04X} subcommand {subcommand:04X}")
            else:
                self._log_once(logging.INFO, f"Command {command:04X}: {e}")
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
        if command in (0x1401, 0x1402) and subcommand in (0x0000, 0x0001, 0x0002, 0x0003):
            if not self.device.writable:
                raise SLMPError(ERR_UNSUPPORTED)  # read-only unless started with --writable
            bit_units = subcommand in (0x0001, 0x0003)
            if command == 0x1401:
                return self._batch_write(data, iqr, bit_units)
            return self._random_write(data, iqr, bit_units)
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
            number = struct.unpack("<I", data[offset : offset + 4])[0]
            code = struct.unpack("<H", data[offset + 4 : offset + 6])[0]
        else:
            number = struct.unpack("<I", data[offset : offset + 3] + b"\x00")[0]
            code = data[offset + 3]
        name = DEVICE_NAMES.get(code)
        if name is None:
            raise SLMPError(ERR_ILLEGAL_DEVICE, f"unknown device code {code:02X}")
        return name, number, offset + size

    @staticmethod
    def _points(data: bytes, offset: int) -> Tuple[int, int]:
        if len(data) < offset + 2:
            raise SLMPError(ERR_REQUEST_LENGTH)
        return struct.unpack("<H", data[offset : offset + 2])[0], offset + 2

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

    def _batch_write(self, data: bytes, iqr: bool, bit_units: bool) -> bytes:
        device, number, offset = self._device_spec(data, 0, iqr)
        points, offset = self._points(data, offset)
        limit = MAX_BATCH_BITS if bit_units else MAX_BATCH_WORDS
        if not 1 <= points <= limit:
            raise SLMPError(ERR_POINTS, f"{points} points (1-{limit})")
        size = (points + 1) // 2 if bit_units else points * 2
        if len(data) != offset + size:
            raise SLMPError(ERR_REQUEST_LENGTH)
        values = data[offset:]
        if bit_units:
            self.device.write_bits(device, number, _unpack_bits(values, points))
        else:
            self.device.write_words(device, number, list(struct.unpack(f"<{points}H", values)))
        unit = "points" if bit_units else "words"
        self._log_once(logging.INFO, f"Write: {device}{number} x {points} {unit}")
        return b""

    def _random_write(self, data: bytes, iqr: bool, bit_units: bool) -> bytes:
        spec_size = 6 if iqr else 4
        if bit_units:
            if len(data) < 1:
                raise SLMPError(ERR_REQUEST_LENGTH)
            count = data[0]
            if not 1 <= count <= MAX_RANDOM_WRITE_BITS:
                raise SLMPError(ERR_POINTS, f"{count} points (1-{MAX_RANDOM_WRITE_BITS})")
            value_size = 2 if iqr else 1  # the iQ-R format sets / resets in 2 bytes
            if len(data) != 1 + count * (spec_size + value_size):
                raise SLMPError(ERR_REQUEST_LENGTH)
            writes = []
            offset = 1
            for _ in range(count):
                device, number, offset = self._device_spec(data, offset, iqr)
                writes.append((device, number, data[offset]))
                offset += value_size
            for device, number, _ in writes:  # all checked before any is written
                self.device._check(device, number, 1)
                if device not in BIT_DEVICES:
                    raise SLMPError(ERR_ILLEGAL_DEVICE, f"{device} is not a bit device")
            for device, number, value in writes:
                self.device.write_bits(device, number, [value])
            self._log_once(logging.INFO, f"Random write: {count} bit(s)")
            return b""
        if len(data) < 2:
            raise SLMPError(ERR_REQUEST_LENGTH)
        word_count, dword_count = data[0], data[1]
        if word_count + dword_count == 0 or word_count * 12 + dword_count * 14 > MAX_RANDOM_WRITE_SIZE:
            raise SLMPError(ERR_POINTS, f"{word_count} word(s), {dword_count} double word(s)")
        if len(data) != 2 + word_count * (spec_size + 2) + dword_count * (spec_size + 4):
            raise SLMPError(ERR_REQUEST_LENGTH)
        words = []
        offset = 2
        for index in range(word_count + dword_count):
            device, number, offset = self._device_spec(data, offset, iqr)
            if index < word_count:
                words.append((device, number, [struct.unpack("<H", data[offset : offset + 2])[0]]))
                offset += 2
            else:
                value = struct.unpack("<I", data[offset : offset + 4])[0]
                words.append((device, number, [value & 0xFFFF, value >> 16]))  # low word first
                offset += 4
        for device, number, values in words:  # all checked before any is written
            self.device._check(device, number, len(values) * (16 if device in BIT_DEVICES else 1))
        for device, number, values in words:
            self.device.write_words(device, number, values)
        self._log_once(logging.INFO, f"Random write: {word_count} word(s), {dword_count} double word(s)")
        return b""


async def run_server(
    host: str, port: int, denied_ranges: List[Tuple[int, int]], writable: bool = False, cpu: str = DEFAULT_CPU
) -> None:
    """Run SLMP simulator server"""
    device = SLMPDevice(denied_ranges, writable=writable, cpu=cpu)

    loop = asyncio.get_event_loop()
    server = await loop.create_server(lambda: SLMPProtocol(device), host, port)

    addr = server.sockets[0].getsockname()
    logger.info(f"SLMP Simulator running on {addr[0]}:{addr[1]}")
    logger.info(f"CPU: {cpu} (D0-D{device.limits['D'] - 1}, M0-M{device.limits['M'] - 1})")
    logger.info(f"Denied address ranges: {denied_ranges}")
    logger.info("Writes: " + ("accepted (--writable)" if writable else "refused (read-only; --writable to accept)"))

    await serve_until_stopped(server, logger)


def main():
    parser = simulator_parser("SLMP PLC Simulator", 5001, "5000-5100,7000-7050")
    parser.add_argument(
        "--writable", action="store_true", help="Accept batch / random writes (1401 / 1402); read-only by default"
    )
    parser.add_argument(
        "--cpu",
        choices=list(CPU_MODELS),
        default=DEFAULT_CPU,
        help=f"Simulated CPU: model name and device ranges (default: {DEFAULT_CPU})",
    )
    args = parser.parse_args()
    denied_ranges = parse_denied_ranges(args.denied)
    run_simulator(run_server(args.host, args.port, denied_ranges, args.writable, args.cpu), logger)


if __name__ == "__main__":
    main()
