#!/usr/bin/env python3
"""
SLMP (Seamless Message Protocol) Simulator

Simulates a Mitsubishi/Keyence PLC that responds to SLMP 3E frame protocol.
Used for testing PLC Discovery tool without physical hardware.

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

# SLMP 3E Frame constants
SLMP_SUBHEADER = 0x00D0  # Response subheader 'D0 00'
SLMP_NETWORK = 0x00
SLMP_PC_NO = 0xFF
SLMP_IO_NO = 0x03FF
SLMP_STATION = 0x00

# Device codes for SLMP
DEVICE_CODES = {
    "D": 0xA8,    # Data register
    "M": 0x90,    # Internal relay
    "X": 0x9C,    # Input
    "Y": 0x9D,    # Output
    "W": 0xB4,    # Link register
    "R": 0xAF,    # File register
    "B": 0xA0,    # Link relay
    "SM": 0x91,   # Special relay
}

# Error codes
ERR_ILLEGAL_DEVICE = 0xC055


class SLMPDevice:
    """Simulated SLMP device memory"""

    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None):
        """
        Initialize device memory.

        Args:
            denied_ranges: List of (start, end) tuples for addresses that should return errors
        """
        self.memory: Dict[str, Dict[int, int]] = {
            "D": {},   # Data registers (0-8191)
            "M": {},   # Internal relays (0-8191)
            "W": {},   # Link registers (0-2047)
            "R": {},   # File registers (0-32767)
            "X": {},   # Inputs (0-1023)
            "Y": {},   # Outputs (0-1023)
        }
        self.denied_ranges = denied_ranges or []
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

    def read_word(self, device: str, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """
        Read word data from device.

        Returns:
            Tuple of (data list or None, error code)
        """
        if device not in self.memory:
            return None, ERR_ILLEGAL_DEVICE

        # Check for denied addresses
        for addr in range(address, address + count):
            if self.is_address_denied(device, addr):
                logger.debug(f"Access denied: {device}{addr}")
                return None, ERR_ILLEGAL_DEVICE

        # Read data
        data = []
        for addr in range(address, address + count):
            value = self.memory[device].get(addr, 0)
            data.append(value)

        return data, 0

    def read_bit(self, device: str, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read bit data from device"""
        if device not in self.memory:
            return None, ERR_ILLEGAL_DEVICE

        # Check for denied addresses
        for addr in range(address, address + count):
            if self.is_address_denied(device, addr):
                return None, ERR_ILLEGAL_DEVICE

        # Read data
        data = []
        for addr in range(address, address + count):
            value = self.memory[device].get(addr, 0) & 0x01
            data.append(value)

        return data, 0


class SLMPProtocol(asyncio.Protocol):
    """SLMP 3E Frame Protocol Handler"""

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
        """Process received SLMP frame"""
        self.buffer += data

        # Minimum frame size check
        if len(self.buffer) < 11:
            return

        try:
            response = self._process_frame(self.buffer)
            if response:
                self.transport.write(response)
            self.buffer = b""
        except Exception as e:
            logger.error(f"Error processing frame: {e}")
            self.buffer = b""

    def _process_frame(self, frame: bytes) -> bytes:
        """Process SLMP 3E frame and return response"""
        # Parse 3E frame header
        # Subheader (2) + Network (1) + PC (1) + IO (2) + Station (1) + Data length (2) + ...
        if len(frame) < 11:
            return self._make_error_response(0x4000)

        subheader = struct.unpack("<H", frame[0:2])[0]
        # bytes 7-9: request data length

        # Check subheader (should be 0x0050 for request '50 00')
        if subheader != 0x0050:
            logger.warning(f"Invalid subheader: {subheader:04X}")
            return self._make_error_response(0x4000)

        # Get command
        if len(frame) < 15:
            return self._make_error_response(0x4000)

        # bytes 9-11: monitoring timer
        command = struct.unpack("<H", frame[11:13])[0]
        subcommand = struct.unpack("<H", frame[13:15])[0]

        logger.debug(f"Command: {command:04X}, Subcommand: {subcommand:04X}")

        # Handle commands
        if command == 0x0401:  # Batch read (word)
            return self._handle_batch_read_word(frame[15:])
        elif command == 0x0401 and subcommand == 0x0001:  # Batch read (bit)
            return self._handle_batch_read_bit(frame[15:])
        else:
            logger.warning(f"Unsupported command: {command:04X}")
            return self._make_error_response(0xC059)

    def _handle_batch_read_word(self, data: bytes) -> bytes:
        """Handle batch read word units command"""
        if len(data) < 6:
            return self._make_error_response(0x4000)

        # Parse device specification
        head_device = struct.unpack("<I", data[0:3] + b'\x00')[0]
        device_code = data[3]
        device_points = struct.unpack("<H", data[4:6])[0]

        # Get device name
        device_name = None
        for name, code in DEVICE_CODES.items():
            if code == device_code:
                device_name = name
                break

        if not device_name:
            logger.warning(f"Unknown device code: {device_code:02X}")
            return self._make_error_response(ERR_ILLEGAL_DEVICE)

        # Calculate address (device code in 3 bytes + 1 byte for device code)
        address = head_device & 0xFFFFFF

        logger.info(f"Read: {device_name}{address} x {device_points} words")

        # Read from device
        values, error = self.device.read_word(device_name, address, device_points)

        if error != 0:
            return self._make_error_response(error)

        # Build response
        return self._make_success_response(values)

    def _handle_batch_read_bit(self, data: bytes) -> bytes:
        """Handle batch read bit units command"""
        if len(data) < 6:
            return self._make_error_response(0x4000)

        head_device = struct.unpack("<I", data[0:3] + b'\x00')[0]
        device_code = data[3]
        device_points = struct.unpack("<H", data[4:6])[0]

        device_name = None
        for name, code in DEVICE_CODES.items():
            if code == device_code:
                device_name = name
                break

        if not device_name:
            return self._make_error_response(ERR_ILLEGAL_DEVICE)

        address = head_device & 0xFFFFFF

        logger.info(f"Read bits: {device_name}{address} x {device_points} points")

        values, error = self.device.read_bit(device_name, address, device_points)

        if error != 0:
            return self._make_error_response(error)

        # Pack bits into bytes
        return self._make_success_response_bits(values)

    def _make_success_response(self, values: List[int]) -> bytes:
        """Create success response with word data"""
        # Response subheader
        response = struct.pack("<H", SLMP_SUBHEADER)
        # Network, PC, IO, Station
        response += struct.pack("<B", SLMP_NETWORK)
        response += struct.pack("<B", SLMP_PC_NO)
        response += struct.pack("<H", SLMP_IO_NO)
        response += struct.pack("<B", SLMP_STATION)

        # Data length (end code + data)
        data_length = 2 + len(values) * 2
        response += struct.pack("<H", data_length)

        # End code (0 = success)
        response += struct.pack("<H", 0)

        # Data
        for value in values:
            response += struct.pack("<H", value & 0xFFFF)

        return response

    def _make_success_response_bits(self, values: List[int]) -> bytes:
        """Create success response with bit data"""
        response = struct.pack("<H", SLMP_SUBHEADER)
        response += struct.pack("<B", SLMP_NETWORK)
        response += struct.pack("<B", SLMP_PC_NO)
        response += struct.pack("<H", SLMP_IO_NO)
        response += struct.pack("<B", SLMP_STATION)

        # Pack bits (4 bits per byte in SLMP)
        packed_data = []
        for i in range(0, len(values), 2):
            byte_val = (values[i] & 0x0F)
            if i + 1 < len(values):
                byte_val |= (values[i + 1] & 0x0F) << 4
            packed_data.append(byte_val)

        data_length = 2 + len(packed_data)
        response += struct.pack("<H", data_length)
        response += struct.pack("<H", 0)  # End code

        for b in packed_data:
            response += struct.pack("<B", b)

        return response

    def _make_error_response(self, error_code: int) -> bytes:
        """Create error response"""
        response = struct.pack("<H", SLMP_SUBHEADER)
        response += struct.pack("<B", SLMP_NETWORK)
        response += struct.pack("<B", SLMP_PC_NO)
        response += struct.pack("<H", SLMP_IO_NO)
        response += struct.pack("<B", SLMP_STATION)
        response += struct.pack("<H", 2)  # Data length (just end code)
        response += struct.pack("<H", error_code)

        logger.debug(f"Error response: {error_code:04X}")
        return response


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
