#!/usr/bin/env python3
"""
Siemens S7 Communication Simulator

Simulates a Siemens S7 PLC for testing PLC Discovery tool.
Implements basic S7comm protocol for data block and memory access.

Usage:
    python s7_simulator.py [--host 127.0.0.1] [--port 102]
"""

import asyncio
import logging
import struct
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("S7-Simulator")

# Shared CLI helpers (support both direct execution and package import)
try:
    from .common import (
        Faults,
        add_fault_options,
        faults_from_args,
        log_faults,
        parse_denied_ranges,
        peer_text,
        run_simulator,
        serve_until_stopped,
        simulator_parser,
        with_faults,
    )
except ImportError:
    from common import (  # type: ignore[no-redef]
        Faults,
        add_fault_options,
        faults_from_args,
        log_faults,
        parse_denied_ranges,
        peer_text,
        run_simulator,
        serve_until_stopped,
        simulator_parser,
        with_faults,
    )

# S7comm constants
S7_PROTOCOL_ID = 0x32
S7_PDU_TYPE_JOB = 0x01
S7_PDU_TYPE_ACK = 0x02
S7_PDU_TYPE_ACK_DATA = 0x03
S7_PDU_TYPE_USERDATA = 0x07

# S7 Function codes
S7_FUNC_READ_VAR = 0x04
S7_FUNC_WRITE_VAR = 0x05
S7_FUNC_SETUP_COMM = 0xF0

# S7 Area IDs
S7_AREA_PE = 0x81  # Process inputs
S7_AREA_PA = 0x82  # Process outputs
S7_AREA_MK = 0x83  # Merkers (flags)
S7_AREA_DB = 0x84  # Data blocks
S7_AREA_CT = 0x1C  # Counters
S7_AREA_TM = 0x1D  # Timers

# Return codes
S7_RET_OK = 0xFF
S7_RET_ITEM_NOT_AVAILABLE = 0x0A
S7_RET_ADDRESS_OUT_OF_RANGE = 0x05

# Smallest length of a simulated data block in bytes (values written
# beyond the sample data, e.g. by the simulator GUI, extend it)
DB_MIN_LENGTH = 2000

# USER_DATA: read SZL (system status list), as used by snap7's get_cpu_info
S7_USERDATA_GROUP_SZL = 0x04
S7_USERDATA_READ_SZL = 0x01
SZL_COMPONENT_ID = 0x001C  # component identification
SZL_RECORD_LENGTH = 34  # 2-byte index + 32 bytes of text
SZL_MODULE_ID = 0x0011  # module identification (order number, versions)
SZL_MODULE_RECORD_LENGTH = 28  # index, MlfB (20), BGTyp, Ausbg, Ausbe

# SZL 0x0011 records: index -> (order number, Ausbg, Ausbe). Index 1 is the
# module, 6 the hardware, 7 the firmware ("V" + major, minor, patch).
DEFAULT_MODULE_IDS = {
    0x0001: ("6ES7 515-2AM02-0AB0", 0x0000, 0x0003),
    0x0006: ("6ES7 515-2AM02-0AB0", 0x0000, 0x0003),
    0x0007: ("", 0x5602, 0x0904),  # firmware V2.9.4
}

# SZL 0x001C records (index -> text) as an S7-1500 reports them
DEFAULT_COMPONENT_IDS = {
    0x0001: "S7-1500 Sim",  # name of the automation system
    0x0002: "PLC_1",  # name of the module
    0x0004: "Original Siemens Equipment",  # copyright
    0x0005: "S C-SIM000001",  # serial number
    0x0007: "CPU 1515-2 PN Sim",  # module type name
}


class S7Device:
    """Simulated S7 device memory"""

    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None):
        self.denied_ranges = denied_ranges or []

        # CPU identification returned for SZL 0x001C (snap7 get_cpu_info)
        self.component_ids = dict(DEFAULT_COMPONENT_IDS)
        # Order number and firmware version for SZL 0x0011
        self.module_ids = dict(DEFAULT_MODULE_IDS)

        # Memory areas
        self.data_blocks: Dict[int, Dict[int, int]] = {}  # DB -> {offset: byte}
        self.merkers: Dict[int, int] = {}  # Offset -> byte
        self.inputs: Dict[int, int] = {}  # Offset -> byte
        self.outputs: Dict[int, int] = {}  # Offset -> byte

        self._initialize_data()

    def _initialize_data(self):
        """Initialize sample data"""
        # DB1 - Sample data
        self.data_blocks[1] = {}
        for i in range(1000):
            # Fill with test pattern (big-endian words)
            self.data_blocks[1][i * 2] = (i >> 8) & 0xFF
            self.data_blocks[1][i * 2 + 1] = i & 0xFF

        # Some specific values
        self.data_blocks[1][0] = 0x12
        self.data_blocks[1][1] = 0x34
        self.data_blocks[1][2] = 0xAB
        self.data_blocks[1][3] = 0xCD

        # DB2 - More sample data
        self.data_blocks[2] = {}
        for i in range(500):
            self.data_blocks[2][i] = i & 0xFF

        # Merkers
        for i in range(100):
            self.merkers[i] = i & 0xFF

        logger.info("Sample data initialized")

    def is_address_denied(self, address: int) -> bool:
        """Check if address is in denied range"""
        for start, end in self.denied_ranges:
            if start <= address <= end:
                return True
        return False

    def read_db(self, db_number: int, start: int, size: int) -> Tuple[Optional[bytes], int]:
        """Read from data block"""
        if db_number not in self.data_blocks:
            logger.debug(f"DB{db_number} not found")
            return None, S7_RET_ITEM_NOT_AVAILABLE

        # Check denied addresses
        for offset in range(start, start + size):
            if self.is_address_denied(offset):
                logger.debug(f"Access denied: DB{db_number}.{offset}")
                return None, S7_RET_ITEM_NOT_AVAILABLE

        db = self.data_blocks[db_number]
        # A data block has a length: a read past its end is refused by the
        # CPU (address out of range), not answered with zeros
        if start < 0 or start + size > self.db_length(db_number):
            logger.debug(f"Read past the end of DB{db_number}: {start}+{size}")
            return None, S7_RET_ADDRESS_OUT_OF_RANGE

        data = bytearray()
        for offset in range(start, start + size):
            data.append(db.get(offset, 0))

        return bytes(data), S7_RET_OK

    def db_length(self, db_number: int) -> int:
        """Length of a data block in bytes (its highest initialised byte + 1, at least DB_MIN_LENGTH)"""
        db = self.data_blocks.get(db_number) or {}
        return max(DB_MIN_LENGTH, max(db, default=-1) + 1)

    def read_merkers(self, start: int, size: int) -> Tuple[Optional[bytes], int]:
        """Read from merker memory"""
        for offset in range(start, start + size):
            if self.is_address_denied(offset):
                return None, S7_RET_ITEM_NOT_AVAILABLE

        data = bytearray()
        for offset in range(start, start + size):
            data.append(self.merkers.get(offset, 0))

        return bytes(data), S7_RET_OK


class COTPProtocol(asyncio.Protocol):
    """COTP (Connection-Oriented Transport Protocol) for S7"""

    def __init__(self, device: S7Device):
        self.device = device
        self.transport = None
        self.buffer = b""
        self.connected = False

    def connection_made(self, transport):
        self.transport = transport
        self.peer = peer_text(transport)
        logger.info(f"Connection from {self.peer}")

    def connection_lost(self, exc):
        logger.info(f"Connection closed: {getattr(self, 'peer', '?')}")

    def data_received(self, data: bytes) -> None:
        """Process received TPKT/COTP/S7comm data"""
        self.buffer += data

        # TPKT header is 4 bytes
        while len(self.buffer) >= 4:
            # Parse TPKT header
            version = self.buffer[0]
            # byte 1: reserved
            length = struct.unpack(">H", self.buffer[2:4])[0]

            if version != 0x03:
                logger.warning(f"Invalid TPKT version: {version}")
                self.buffer = b""
                continue

            if length < 4:
                # The length includes the 4-byte header: a smaller one would
                # consume nothing and loop forever, blocking every simulator
                # sharing this event loop
                logger.warning(f"Invalid TPKT length: {length}")
                self.buffer = b""
                break

            if len(self.buffer) < length:
                break

            # Extract TPKT payload
            payload = self.buffer[4:length]
            self.buffer = self.buffer[length:]

            try:
                response = self._process_cotp(payload)
                if response and self.transport is not None:
                    self.transport.write(response)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")

    def _process_cotp(self, data: bytes) -> Optional[bytes]:
        """Process COTP packet"""
        if len(data) < 2:
            return None

        # byte 0: COTP length
        cotp_type = data[1]

        logger.debug(f"COTP type: {cotp_type:02X}")

        if cotp_type == 0xE0:  # Connection Request
            return self._handle_connect_request(data)
        elif cotp_type == 0xF0:  # Data Transfer
            return self._handle_data_transfer(data)
        else:
            logger.warning(f"Unsupported COTP type: {cotp_type:02X}")
            return None

    def _handle_connect_request(self, data: bytes) -> bytes:
        """Handle COTP connection request"""
        logger.info("COTP Connection Request received")
        self.connected = True

        # COTP Connection Confirm (CC)
        cotp = bytes(
            [
                0x11,  # Length
                0xD0,  # CC PDU type
                0x00,
                0x01,  # DST-REF
                0x00,
                0x01,  # SRC-REF
                0x00,  # Class/options
                # Parameters
                0xC0,
                0x01,
                0x0A,  # TPDU size
                0xC1,
                0x02,
                0x01,
                0x00,  # Source TSAP
                0xC2,
                0x02,
                0x01,
                0x02,  # Destination TSAP
            ]
        )

        return self._make_tpkt(cotp)

    def _handle_data_transfer(self, data: bytes) -> Optional[bytes]:
        """Handle COTP data transfer (contains S7comm)"""
        if len(data) < 3:
            return None

        # COTP DT header
        # bytes 0-3: COTP DT header
        s7_data = data[3:]

        if len(s7_data) < 10:
            return None

        # Parse S7comm header
        if s7_data[0] != S7_PROTOCOL_ID:
            logger.warning("Invalid S7 protocol ID")
            return None

        pdu_type = s7_data[1]

        if pdu_type == S7_PDU_TYPE_JOB:
            return self._handle_s7_job(s7_data)
        elif pdu_type == S7_PDU_TYPE_USERDATA:
            return self._handle_userdata(s7_data)
        else:
            logger.warning(f"Unsupported PDU type: {pdu_type:02X}")
            return None

    def _handle_s7_job(self, data: bytes) -> Optional[bytes]:
        """Handle S7comm Job request"""
        if len(data) < 12:
            return None

        # Parse S7 header
        # bytes 2-4: reserved
        pdu_ref = struct.unpack(">H", data[4:6])[0]
        param_len = struct.unpack(">H", data[6:8])[0]
        # bytes 8-10: data length

        params = data[10 : 10 + param_len]

        if len(params) < 1:
            return None

        function = params[0]
        logger.debug(f"S7 Function: {function:02X}")

        if function == S7_FUNC_SETUP_COMM:
            return self._handle_setup_comm(pdu_ref, params)
        elif function == S7_FUNC_READ_VAR:
            return self._handle_read_var(pdu_ref, params)
        else:
            logger.warning(f"Unsupported S7 function: {function:02X}")
            return None

    def _handle_setup_comm(self, pdu_ref: int, params: bytes) -> bytes:
        """Handle Setup Communication request"""
        logger.info("S7 Setup Communication")

        # PDU size: what the client asked for, at most 960 (a real CPU never
        # grants more than requested; an S7-300 grants 240)
        requested = struct.unpack(">H", params[6:8])[0] if len(params) >= 8 else 960
        pdu_size = min(requested, 960) if requested else 960

        # Response parameters
        resp_params = bytes(
            [
                S7_FUNC_SETUP_COMM,
                0x00,  # Reserved
                0x00,
                0x03,  # Max calling
                0x00,
                0x03,  # Max called
            ]
        ) + struct.pack(">H", pdu_size)

        return self._make_s7_response(pdu_ref, resp_params, b"")

    def _handle_read_var(self, pdu_ref: int, params: bytes) -> bytes:
        """Handle Read Var request"""
        if len(params) < 2:
            return self._make_s7_error_response(pdu_ref)

        item_count = params[1]
        logger.info(f"S7 Read Var: {item_count} items")

        # Parse items and read data
        offset = 2
        responses = []

        for i in range(item_count):
            if offset + 12 > len(params):
                break

            # Parse item specification
            # bytes 0-4: variable specification, address length, syntax id, transport size
            length = struct.unpack(">H", params[offset + 4 : offset + 6])[0]
            db_number = struct.unpack(">H", params[offset + 6 : offset + 8])[0]
            area = params[offset + 8]
            address_bytes = params[offset + 9 : offset + 12]
            address = (address_bytes[0] << 16) | (address_bytes[1] << 8) | address_bytes[2]
            byte_offset = address >> 3

            logger.debug(f"  Item {i}: Area={area:02X}, DB={db_number}, Offset={byte_offset}, Len={length}")

            # Read data based on area
            if area == S7_AREA_DB:
                data, ret_code = self.device.read_db(db_number, byte_offset, length)
            elif area == S7_AREA_MK:
                data, ret_code = self.device.read_merkers(byte_offset, length)
            else:
                data, ret_code = None, S7_RET_ITEM_NOT_AVAILABLE

            if ret_code == S7_RET_OK:
                responses.append((ret_code, data))
            else:
                responses.append((ret_code, None))

            offset += 12

        return self._make_read_response(pdu_ref, responses)

    def _make_read_response(self, pdu_ref: int, responses: List[Tuple[int, Optional[bytes]]]) -> bytes:
        """Create Read Var response"""
        # Response parameters
        resp_params = bytes([S7_FUNC_READ_VAR, len(responses)])

        # Response data
        resp_data = b""
        for ret_code, data in responses:
            if ret_code == S7_RET_OK and data:
                resp_data += bytes([ret_code, 0x04])  # Return code + Transport size (byte)
                resp_data += struct.pack(">H", len(data) * 8)  # Length in bits
                resp_data += data
                # Padding to even length
                if len(data) % 2 == 1:
                    resp_data += b"\x00"
            else:
                # A failed item is 4 bytes too: return code, transport size 0
                # (null), length 0 - or the items after it are misaligned
                resp_data += bytes([ret_code, 0x00, 0x00, 0x00])

        return self._make_s7_response(pdu_ref, resp_params, resp_data)

    def _szl_payload(self, szl_id: Optional[int]) -> Optional[bytes]:
        """SZL list (header + records) for 0x001C / 0x0011, None for others"""
        if szl_id == SZL_COMPONENT_ID:
            length = SZL_RECORD_LENGTH
            records = [
                struct.pack(">H", index) + text.encode("ascii").ljust(length - 2, b"\x00")
                for index, text in self.device.component_ids.items()
            ]
        elif szl_id == SZL_MODULE_ID:
            length = SZL_MODULE_RECORD_LENGTH
            records = [
                struct.pack(">H", index) + order.encode("ascii").ljust(20, b" ") + struct.pack(">HHH", 0, ausbg, ausbe)
                for index, (order, ausbg, ausbe) in self.device.module_ids.items()
            ]
        else:
            return None
        return struct.pack(">HHHH", szl_id, 0, length, len(records)) + b"".join(records)

    def _handle_userdata(self, data: bytes) -> bytes:
        """USER_DATA: read SZL 0x001C / 0x0011 (CPU identification); other requests get an error"""
        pdu_ref = struct.unpack(">H", data[4:6])[0]
        param_len = struct.unpack(">H", data[6:8])[0]
        params = data[10 : 10 + param_len]
        body = data[10 + param_len :]
        group = params[5] & 0x0F if len(params) >= 7 else None
        subfunction = params[6] if len(params) >= 7 else None
        szl_id = struct.unpack(">H", body[4:6])[0] if len(body) >= 8 else None
        payload = None
        if (group, subfunction) == (S7_USERDATA_GROUP_SZL, S7_USERDATA_READ_SZL):
            payload = self._szl_payload(szl_id)
        if payload is not None:
            return_code, error = S7_RET_OK, 0
        else:
            logger.warning(f"Unsupported USER_DATA request: group={group} subfunction={subfunction} szl={szl_id}")
            payload, return_code, error = b"", S7_RET_ITEM_NOT_AVAILABLE, 0xD401  # SZL not available
        group_byte = 0x80 | (group or 0)
        reply_params = struct.pack(
            ">BBBBBBBBBBH", 0x00, 0x01, 0x12, 0x08, 0x12, group_byte, subfunction or 0, 0x00, 0x00, 0x00, error
        )
        reply_data = struct.pack(">BBH", return_code, 0x09 if payload else 0x00, len(payload)) + payload
        header = struct.pack(
            ">BBHHHH", S7_PROTOCOL_ID, S7_PDU_TYPE_USERDATA, 0, pdu_ref, len(reply_params), len(reply_data)
        )
        return self._make_tpkt(bytes([0x02, 0xF0, 0x80]) + header + reply_params + reply_data)

    def _make_s7_response(self, pdu_ref: int, params: bytes, data: bytes) -> bytes:
        """Create S7comm response"""
        # S7 header
        s7_header = bytes([S7_PROTOCOL_ID, S7_PDU_TYPE_ACK_DATA])
        s7_header += struct.pack(">H", 0)  # Reserved
        s7_header += struct.pack(">H", pdu_ref)
        s7_header += struct.pack(">H", len(params))
        s7_header += struct.pack(">H", len(data))
        s7_header += bytes([0x00, 0x00])  # Error class/code

        s7_packet = s7_header + params + data

        # COTP DT header
        cotp = bytes([0x02, 0xF0, 0x80]) + s7_packet

        return self._make_tpkt(cotp)

    def _make_s7_error_response(self, pdu_ref: int) -> bytes:
        """Create S7 error response"""
        return self._make_s7_response(pdu_ref, b"", b"")

    def _make_tpkt(self, data: bytes) -> bytes:
        """Wrap data in TPKT"""
        length = len(data) + 4
        return bytes([0x03, 0x00]) + struct.pack(">H", length) + data


async def run_server(
    host: str, port: int, denied_ranges: List[Tuple[int, int]], faults: Optional[Faults] = None
) -> None:
    """Run S7 simulator server"""
    device = S7Device(denied_ranges)

    loop = asyncio.get_event_loop()
    server = await loop.create_server(with_faults(lambda: COTPProtocol(device), faults, device), host, port)

    addr = server.sockets[0].getsockname()
    logger.info(f"S7 Simulator running on {addr[0]}:{addr[1]}")
    logger.info(f"Denied address ranges: {denied_ranges}")
    log_faults(faults, logger)

    await serve_until_stopped(server, logger)


def main():
    parser = simulator_parser("Siemens S7 PLC Simulator", 102, "500-550")
    add_fault_options(parser)
    args = parser.parse_args()
    denied_ranges = parse_denied_ranges(args.denied)
    run_simulator(run_server(args.host, args.port, denied_ranges, faults_from_args(args)), logger)


if __name__ == "__main__":
    main()
