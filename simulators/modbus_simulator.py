#!/usr/bin/env python3
"""
Modbus/TCP Simulator

Simulates a Modbus/TCP device for testing PLC Discovery tool.
Supports Function Codes: 01 (Read Coils), 02 (Read Discrete Inputs),
03 (Read Holding Registers), 04 (Read Input Registers)

Usage:
    python modbus_simulator.py [--host 127.0.0.1] [--port 502]
"""

import asyncio
import struct
import logging
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Modbus-Simulator")

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

# Modbus Function Codes
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_READ_DEVICE_ID = 0x2B  # MEI

# Modbus Exception Codes
EX_ILLEGAL_FUNCTION = 0x01
EX_ILLEGAL_DATA_ADDRESS = 0x02
EX_ILLEGAL_DATA_VALUE = 0x03
EX_SERVER_DEVICE_FAILURE = 0x04


class ModbusDevice:
    """Simulated Modbus device memory"""

    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None):
        """
        Initialize device memory.

        Args:
            denied_ranges: List of (start, end) tuples for addresses that should return errors
        """
        # Modbus memory areas
        self.coils: Dict[int, bool] = {}           # 0x - Coils
        self.discrete_inputs: Dict[int, bool] = {}  # 1x - Discrete Inputs
        self.holding_registers: Dict[int, int] = {}  # 4x - Holding Registers
        self.input_registers: Dict[int, int] = {}   # 3x - Input Registers

        self.denied_ranges = denied_ranges or []

        # Device identification
        self.device_info = {
            0x00: b"PLC Simulator",      # Vendor Name
            0x01: b"ModbusSim v1.0",     # Product Code
            0x02: b"1.0.0",              # Major Minor Revision
        }

        self._initialize_sample_data()

    def _initialize_sample_data(self):
        """Initialize memory with sample data"""
        # Holding registers (40001-49999 in Modbus addressing)
        for i in range(0, 1000):
            self.holding_registers[i] = i * 5  # 0, 5, 10, 15...

        # Some specific values
        self.holding_registers[100] = 0x1234
        self.holding_registers[101] = 0xABCD
        self.holding_registers[200] = 0xFFFF
        self.holding_registers[500] = 12345

        # Input registers (30001-39999)
        for i in range(0, 500):
            self.input_registers[i] = 1000 + i

        # Coils
        for i in range(0, 100):
            self.coils[i] = (i % 2) == 0  # Alternating True/False

        # Discrete inputs
        for i in range(0, 100):
            self.discrete_inputs[i] = (i % 3) == 0

        logger.info("Sample data initialized")

    def is_address_denied(self, address: int) -> bool:
        """Check if address is in denied range"""
        for start, end in self.denied_ranges:
            if start <= address <= end:
                return True
        return False

    def read_holding_registers(self, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read holding registers"""
        # Check for denied addresses
        for addr in range(address, address + count):
            if self.is_address_denied(addr):
                logger.debug(f"Access denied: HR{addr}")
                return None, EX_ILLEGAL_DATA_ADDRESS

        # Check address bounds
        if address + count > 10000:
            return None, EX_ILLEGAL_DATA_ADDRESS

        data = []
        for addr in range(address, address + count):
            data.append(self.holding_registers.get(addr, 0))

        return data, 0

    def read_input_registers(self, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read input registers"""
        for addr in range(address, address + count):
            if self.is_address_denied(addr):
                return None, EX_ILLEGAL_DATA_ADDRESS

        if address + count > 10000:
            return None, EX_ILLEGAL_DATA_ADDRESS

        data = []
        for addr in range(address, address + count):
            data.append(self.input_registers.get(addr, 0))

        return data, 0

    def read_coils(self, address: int, count: int) -> Tuple[Optional[List[bool]], int]:
        """Read coils"""
        for addr in range(address, address + count):
            if self.is_address_denied(addr):
                return None, EX_ILLEGAL_DATA_ADDRESS

        if address + count > 10000:
            return None, EX_ILLEGAL_DATA_ADDRESS

        data = []
        for addr in range(address, address + count):
            data.append(self.coils.get(addr, False))

        return data, 0

    def read_discrete_inputs(self, address: int, count: int) -> Tuple[Optional[List[bool]], int]:
        """Read discrete inputs"""
        for addr in range(address, address + count):
            if self.is_address_denied(addr):
                return None, EX_ILLEGAL_DATA_ADDRESS

        if address + count > 10000:
            return None, EX_ILLEGAL_DATA_ADDRESS

        data = []
        for addr in range(address, address + count):
            data.append(self.discrete_inputs.get(addr, False))

        return data, 0


class ModbusProtocol(asyncio.Protocol):
    """Modbus/TCP Protocol Handler"""

    def __init__(self, device: ModbusDevice, unit_id: int = 1):
        self.device = device
        self.unit_id = unit_id
        self.transport = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = peer_text(transport)
        logger.info(f"Connection from {self.peer}")

    def connection_lost(self, exc):
        logger.info(f"Connection closed: {getattr(self, 'peer', '?')}")

    def data_received(self, data: bytes):
        """Process received Modbus/TCP frame"""
        self.buffer += data

        # Modbus/TCP MBAP header is 7 bytes
        while len(self.buffer) >= 7:
            # Parse MBAP header
            transaction_id = struct.unpack(">H", self.buffer[0:2])[0]
            protocol_id = struct.unpack(">H", self.buffer[2:4])[0]
            length = struct.unpack(">H", self.buffer[4:6])[0]
            unit_id = self.buffer[6]

            # Check protocol ID (should be 0 for Modbus)
            if protocol_id != 0:
                self.buffer = b""
                continue

            # Check if we have complete PDU
            total_length = 6 + length
            if len(self.buffer) < total_length:
                break

            # Extract PDU
            pdu = self.buffer[7:total_length]
            self.buffer = self.buffer[total_length:]

            # Process and respond
            try:
                response_pdu = self._process_pdu(pdu)
                response = self._make_response(transaction_id, unit_id, response_pdu)
                self.transport.write(response)
            except Exception as e:
                logger.error(f"Error processing PDU: {e}")

    def _process_pdu(self, pdu: bytes) -> bytes:
        """Process Modbus PDU and return response PDU"""
        if len(pdu) < 1:
            return self._make_exception(0, EX_ILLEGAL_FUNCTION)

        function_code = pdu[0]

        logger.debug(f"Function code: {function_code:02X}")

        if function_code == FC_READ_COILS:
            return self._handle_read_coils(pdu)
        elif function_code == FC_READ_DISCRETE_INPUTS:
            return self._handle_read_discrete_inputs(pdu)
        elif function_code == FC_READ_HOLDING_REGISTERS:
            return self._handle_read_holding_registers(pdu)
        elif function_code == FC_READ_INPUT_REGISTERS:
            return self._handle_read_input_registers(pdu)
        elif function_code == FC_READ_DEVICE_ID:
            return self._handle_read_device_id(pdu)
        else:
            return self._make_exception(function_code, EX_ILLEGAL_FUNCTION)

    def _handle_read_holding_registers(self, pdu: bytes) -> bytes:
        """Handle Read Holding Registers (FC 03)"""
        if len(pdu) < 5:
            return self._make_exception(FC_READ_HOLDING_REGISTERS, EX_ILLEGAL_DATA_VALUE)

        address = struct.unpack(">H", pdu[1:3])[0]
        count = struct.unpack(">H", pdu[3:5])[0]

        logger.info(f"Read Holding Registers: addr={address}, count={count}")

        if count < 1 or count > 125:
            return self._make_exception(FC_READ_HOLDING_REGISTERS, EX_ILLEGAL_DATA_VALUE)

        data, error = self.device.read_holding_registers(address, count)

        if error != 0:
            return self._make_exception(FC_READ_HOLDING_REGISTERS, error)

        # Build response
        response = bytes([FC_READ_HOLDING_REGISTERS, count * 2])
        for value in data:
            response += struct.pack(">H", value & 0xFFFF)

        return response

    def _handle_read_input_registers(self, pdu: bytes) -> bytes:
        """Handle Read Input Registers (FC 04)"""
        if len(pdu) < 5:
            return self._make_exception(FC_READ_INPUT_REGISTERS, EX_ILLEGAL_DATA_VALUE)

        address = struct.unpack(">H", pdu[1:3])[0]
        count = struct.unpack(">H", pdu[3:5])[0]

        logger.info(f"Read Input Registers: addr={address}, count={count}")

        if count < 1 or count > 125:
            return self._make_exception(FC_READ_INPUT_REGISTERS, EX_ILLEGAL_DATA_VALUE)

        data, error = self.device.read_input_registers(address, count)

        if error != 0:
            return self._make_exception(FC_READ_INPUT_REGISTERS, error)

        response = bytes([FC_READ_INPUT_REGISTERS, count * 2])
        for value in data:
            response += struct.pack(">H", value & 0xFFFF)

        return response

    def _handle_read_coils(self, pdu: bytes) -> bytes:
        """Handle Read Coils (FC 01)"""
        if len(pdu) < 5:
            return self._make_exception(FC_READ_COILS, EX_ILLEGAL_DATA_VALUE)

        address = struct.unpack(">H", pdu[1:3])[0]
        count = struct.unpack(">H", pdu[3:5])[0]

        logger.info(f"Read Coils: addr={address}, count={count}")

        if count < 1 or count > 2000:
            return self._make_exception(FC_READ_COILS, EX_ILLEGAL_DATA_VALUE)

        data, error = self.device.read_coils(address, count)

        if error != 0:
            return self._make_exception(FC_READ_COILS, error)

        # Pack bits into bytes
        byte_count = (count + 7) // 8
        packed = []
        for i in range(0, count, 8):
            byte_val = 0
            for j in range(8):
                if i + j < count and data[i + j]:
                    byte_val |= (1 << j)
            packed.append(byte_val)

        response = bytes([FC_READ_COILS, byte_count]) + bytes(packed)
        return response

    def _handle_read_discrete_inputs(self, pdu: bytes) -> bytes:
        """Handle Read Discrete Inputs (FC 02)"""
        if len(pdu) < 5:
            return self._make_exception(FC_READ_DISCRETE_INPUTS, EX_ILLEGAL_DATA_VALUE)

        address = struct.unpack(">H", pdu[1:3])[0]
        count = struct.unpack(">H", pdu[3:5])[0]

        logger.info(f"Read Discrete Inputs: addr={address}, count={count}")

        if count < 1 or count > 2000:
            return self._make_exception(FC_READ_DISCRETE_INPUTS, EX_ILLEGAL_DATA_VALUE)

        data, error = self.device.read_discrete_inputs(address, count)

        if error != 0:
            return self._make_exception(FC_READ_DISCRETE_INPUTS, error)

        byte_count = (count + 7) // 8
        packed = []
        for i in range(0, count, 8):
            byte_val = 0
            for j in range(8):
                if i + j < count and data[i + j]:
                    byte_val |= (1 << j)
            packed.append(byte_val)

        response = bytes([FC_READ_DISCRETE_INPUTS, byte_count]) + bytes(packed)
        return response

    def _handle_read_device_id(self, pdu: bytes) -> bytes:
        """Handle Read Device Identification (FC 2B/0E)"""
        if len(pdu) < 3:
            return self._make_exception(FC_READ_DEVICE_ID, EX_ILLEGAL_DATA_VALUE)

        mei_type = pdu[1]
        read_device_id = pdu[2]

        if mei_type != 0x0E:
            return self._make_exception(FC_READ_DEVICE_ID, EX_ILLEGAL_FUNCTION)

        logger.info(f"Read Device ID: type={read_device_id}")

        # Build response with device info
        response = bytes([FC_READ_DEVICE_ID, 0x0E, read_device_id, 0x01, 0x00, 0x00])

        # Number of objects
        objects_count = len(self.device.device_info)
        response += bytes([objects_count])

        for obj_id, value in self.device.device_info.items():
            response += bytes([obj_id, len(value)]) + value

        return response

    def _make_exception(self, function_code: int, exception_code: int) -> bytes:
        """Create exception response"""
        return bytes([function_code | 0x80, exception_code])

    def _make_response(self, transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
        """Create Modbus/TCP response with MBAP header"""
        response = struct.pack(">H", transaction_id)  # Transaction ID
        response += struct.pack(">H", 0)               # Protocol ID
        response += struct.pack(">H", len(pdu) + 1)   # Length
        response += bytes([unit_id])                   # Unit ID
        response += pdu                                # PDU
        return response


async def run_server(host: str, port: int, denied_ranges: List[Tuple[int, int]]):
    """Run Modbus/TCP simulator server"""
    device = ModbusDevice(denied_ranges)

    loop = asyncio.get_event_loop()
    server = await loop.create_server(
        lambda: ModbusProtocol(device),
        host, port
    )

    addr = server.sockets[0].getsockname()
    logger.info(f"Modbus/TCP Simulator running on {addr[0]}:{addr[1]}")
    logger.info(f"Denied address ranges: {denied_ranges}")

    await serve_until_stopped(server, logger)


def main():
    parser = simulator_parser("Modbus/TCP PLC Simulator", 502, "5000-5100,8000-8050")
    args = parser.parse_args()
    denied_ranges = parse_denied_ranges(args.denied)
    run_simulator(run_server(args.host, args.port, denied_ranges), logger)


if __name__ == "__main__":
    main()
