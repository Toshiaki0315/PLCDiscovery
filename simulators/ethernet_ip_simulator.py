#!/usr/bin/env python3
"""
EtherNet/IP (CIP) Simulator

Simulates an EtherNet/IP device for testing PLC Discovery tool.
Implements basic CIP Identity Object and simple data access.

Usage:
    python ethernet_ip_simulator.py [--host 127.0.0.1] [--port 44818]
"""

import asyncio
import struct
import logging
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EtherNetIP-Simulator")

# Shared CLI helpers (support both direct execution and package import)
try:
    from .common import parse_denied_ranges, peer_text, run_simulator, simulator_parser
except ImportError:
    from common import parse_denied_ranges, peer_text, run_simulator, simulator_parser  # type: ignore[no-redef]

# EtherNet/IP Commands
EIP_CMD_NOP = 0x0000
EIP_CMD_LIST_SERVICES = 0x0004
EIP_CMD_LIST_IDENTITY = 0x0063
EIP_CMD_LIST_INTERFACES = 0x0064
EIP_CMD_REGISTER_SESSION = 0x0065
EIP_CMD_UNREGISTER_SESSION = 0x0066
EIP_CMD_SEND_RR_DATA = 0x006F
EIP_CMD_SEND_UNIT_DATA = 0x0070

# CIP Services
CIP_GET_ATTRIBUTE_ALL = 0x01
CIP_GET_ATTRIBUTE_SINGLE = 0x0E
CIP_READ_TAG = 0x4C
CIP_WRITE_TAG = 0x4D

# Connection manager services (connected messaging, used by pycomm3's SLCDriver)
CIP_FORWARD_OPEN = 0x54
CIP_LARGE_FORWARD_OPEN = 0x5B
CIP_FORWARD_CLOSE = 0x4E

# PCCC (PLC-5/SLC/MicroLogix data files) over CIP
CIP_EXECUTE_PCCC = 0x4B
PCCC_CMD_TYPED = 0x0F           # request command code
PCCC_FNC_TYPED_READ = 0xA2      # protected typed logical read, 3 address fields
PCCC_FILE_TYPES = {0x89: "N", 0x85: "B"}   # integer file N7, bit file B3
PCCC_STS_ADDRESS_ERROR = 0x50   # "address problem or memory protect"

# CIP Class Codes
CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_ASSEMBLY = 0x04
CIP_CLASS_CONNECTION_MANAGER = 0x06
CIP_CLASS_PROGRAM_NAME = 0x64
CIP_CLASS_SYMBOL = 0x6B
CIP_CLASS_TEMPLATE = 0x6C
CIP_GET_ATTRIBUTE_LIST = 0x03

# Logix services (used by pycomm3's LogixDriver)
CIP_UNCONNECTED_SEND = 0x52          # to the connection manager (unconnected)
CIP_READ_TAG_FRAGMENTED = 0x52       # to a tag (connected)
CIP_MULTIPLE_SERVICE = 0x0A
CIP_GET_INSTANCE_ATTRIBUTE_LIST = 0x55

# CIP general status codes
CIP_OK = 0x00
CIP_PATH_DESTINATION_UNKNOWN = 0x05
CIP_PARTIAL_TRANSFER = 0x06
CIP_SERVICE_NOT_SUPPORTED = 0x08
CIP_EMBEDDED_SERVICE_ERROR = 0x1E

# Atomic data types: code -> (name, struct format, size). Logix uses the
# signed / REAL types; Omron NJ/NX also the unsigned, LREAL and bit-string types.
CIP_TYPES = {
    0xC1: ("BOOL", "<B", 1),
    0xC2: ("SINT", "<b", 1),
    0xC3: ("INT", "<h", 2),
    0xC4: ("DINT", "<i", 4),
    0xC5: ("LINT", "<q", 8),
    0xC6: ("USINT", "<B", 1),
    0xC7: ("UINT", "<H", 2),
    0xC8: ("UDINT", "<I", 4),
    0xC9: ("ULINT", "<Q", 8),
    0xCA: ("REAL", "<f", 4),
    0xCB: ("LREAL", "<d", 8),
    0xD1: ("BYTE", "<B", 1),
    0xD2: ("WORD", "<H", 2),
    0xD3: ("DWORD", "<I", 4),
    0xD4: ("LWORD", "<Q", 8),
}
CIP_TYPE_CODES = {name: code for code, (name, _, _) in CIP_TYPES.items()}

# Omron NJ/NX STRING: type code, then a 2-byte length and the characters
OMRON_STRING_TYPE = 0xD0

# Structure read reply type (followed by the 2-byte structure handle)
STRUCTURE_REPLY_TYPE = b"\xa0\x02"

# Bytes of tag data per reply before a fragmented read continues
LOGIX_FRAGMENT_BYTES = 400

# User-defined types (UDT): name -> (template instance id, [(member, atomic type)])
DEFAULT_UDTS = {
    "MotorData": (0x0100, [("Speed", "DINT"), ("Current", "REAL"), ("Count", "INT")]),
}

# Controller tags of the Logix mode: name -> (type, value). An array is a
# list; a UDT value is a dict of member values.
DEFAULT_LOGIX_TAGS = {
    "Speed": ("DINT", 1500),
    "Temp": ("REAL", 23.5),
    "Running": ("BOOL", 1),
    "Counter": ("INT", 42),
    "Recipe": ("DINT", [i * 10 for i in range(10)]),
    "Trend": ("INT", list(range(600))),          # larger than one reply: fragmented read
    "Motor": ("MotorData", {"Speed": 1200, "Current": 3.5, "Count": 7}),
}

# Program-scope tags of the Logix mode: program -> {name: (type, value)}
DEFAULT_PROGRAM_TAGS = {
    "MainProgram": {
        "Step": ("DINT", 3),
        "Setpoint": ("REAL", 50.0),
    },
}

# Variables of the Omron NJ/NX mode (published variables, read by name only:
# the controller has no Logix tag list / program name object)
DEFAULT_OMRON_TAGS = {
    "Temperature": ("REAL", 25.5),
    "Pressure": ("LREAL", 0.101325),
    "TotalCount": ("UDINT", 123456),
    "StatusWord": ("WORD", 0x00FF),
    "Values": ("INT", [i * 2 for i in range(20)]),
    "History": ("DINT", list(range(300))),       # larger than one reply: fragmented read
    "Message": ("STRING", "Hello NJ"),
    "Motor": ("MotorData", {"Speed": 900, "Current": 2.5, "Count": 4}),
}


class EtherNetIPDevice:
    """Simulated EtherNet/IP device"""

    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None, mode: str = "slc"):
        """
        Args:
            mode: "slc" - a PLC-5/SLC/MicroLogix style controller (PCCC data
                files N7 / B3); "logix" - a ControlLogix style controller
                with symbolic tags (tag list, Read Tag, multiple service
                and fragmented reads) for pycomm3's LogixDriver
        """
        self.mode = mode
        self.udts = dict(DEFAULT_UDTS)
        tags = DEFAULT_OMRON_TAGS if mode == "omron" else DEFAULT_LOGIX_TAGS
        self.logix_tags = {name: (t, v) for name, (t, v) in tags.items()}
        self.program_tags = {} if mode == "omron" else {
            program: dict(tags) for program, tags in DEFAULT_PROGRAM_TAGS.items()}
        self.denied_ranges = denied_ranges or []
        self.session_handle = 0

        # Device identity information
        self.vendor_id = 0x0001  # Rockwell
        self.device_type = 0x0E  # Programmable Logic Controller
        self.product_code = 0x0037
        self.revision_major = 1
        self.revision_minor = 0
        self.serial_number = 0x12345678
        self.product_name = {
            "slc": b"EIP Simulator PLC",
            "logix": b"1756-L83E/B LOGIX5583E Sim",
            "omron": b"NJ501-1300 Sim",
        }[mode]
        if mode == "omron":
            self.vendor_id = 47        # OMRON Corporation

        # Tag data (simulates Allen-Bradley style tags)
        self.tags: Dict[str, any] = {
            "TestDINT": 12345,
            "TestREAL": 3.14159,
            "TestArray": [100, 200, 300, 400, 500],
            "Counter": 0,
            "Status": 1,
        }

        # Integer file (N7 style)
        self.integer_file: Dict[int, int] = {}
        self._initialize_data()

    def _initialize_data(self):
        """Initialize sample data"""
        for i in range(256):
            self.integer_file[i] = i * 10

        self.integer_file[0] = 0x1234
        self.integer_file[1] = 0xABCD
        logger.info("Sample data initialized")

    def is_address_denied(self, address: int) -> bool:
        """Check if address is in denied range"""
        for start, end in self.denied_ranges:
            if start <= address <= end:
                return True
        return False

    def get_identity_response(self) -> bytes:
        """Build Identity Object response"""
        response = b""

        # Vendor ID
        response += struct.pack("<H", self.vendor_id)
        # Device Type
        response += struct.pack("<H", self.device_type)
        # Product Code
        response += struct.pack("<H", self.product_code)
        # Revision
        response += bytes([self.revision_major, self.revision_minor])
        # Status
        response += struct.pack("<H", 0x0000)
        # Serial Number
        response += struct.pack("<I", self.serial_number)
        # Product Name (length + string)
        response += bytes([len(self.product_name)])
        response += self.product_name

        return response

    def read_bit_file(self, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read words of the bit file B3 (each word holds 16 bits)"""
        if any(self.is_address_denied(address + i) for i in range(count)):
            return None, 0x14
        return [(address + i) & 0xFFFF for i in range(count)], 0

    def read_integer_file(self, address: int, count: int) -> Tuple[Optional[List[int]], int]:
        """Read from integer file"""
        if any(self.is_address_denied(address + i) for i in range(count)):
            return None, 0x14  # Path segment error

        data = []
        for i in range(count):
            data.append(self.integer_file.get(address + i, 0))

        return data, 0


class EtherNetIPProtocol(asyncio.Protocol):
    """EtherNet/IP Protocol Handler"""

    def __init__(self, device: EtherNetIPDevice):
        self.device = device
        self.transport = None
        self.buffer = b""
        self.session_handle = 0

    def connection_made(self, transport):
        self.transport = transport
        self.peer = peer_text(transport)
        logger.info(f"Connection from {self.peer}")

    def connection_lost(self, exc):
        logger.info(f"Connection closed: {getattr(self, 'peer', '?')}")

    def data_received(self, data: bytes):
        """Process received EtherNet/IP encapsulation"""
        self.buffer += data

        # EtherNet/IP encapsulation header is 24 bytes
        while len(self.buffer) >= 24:
            # Parse header
            command = struct.unpack("<H", self.buffer[0:2])[0]
            length = struct.unpack("<H", self.buffer[2:4])[0]
            session = struct.unpack("<I", self.buffer[4:8])[0]
            # bytes 8-12: status, 20-24: options (not used by the simulator)
            context = self.buffer[12:20]

            # Check if we have complete packet
            total_length = 24 + length
            if len(self.buffer) < total_length:
                break

            # Extract data
            enc_data = self.buffer[24:total_length]
            self.buffer = self.buffer[total_length:]

            # Process command
            try:
                response = self._process_command(command, session, context, enc_data)
                if response:
                    self.transport.write(response)
            except Exception as e:
                logger.error(f"Error processing command: {e}")

    def _process_command(self, command: int, session: int, context: bytes, data: bytes) -> Optional[bytes]:
        """Process EtherNet/IP command"""
        logger.debug(f"Command: {command:04X}, Session: {session:08X}")

        if command == EIP_CMD_REGISTER_SESSION:
            return self._handle_register_session(context)
        elif command == EIP_CMD_UNREGISTER_SESSION:
            return self._handle_unregister_session(session, context)
        elif command == EIP_CMD_LIST_IDENTITY:
            return self._handle_list_identity(context)
        elif command in (EIP_CMD_SEND_RR_DATA, EIP_CMD_SEND_UNIT_DATA) and (
            not self.session_handle or session != self.session_handle
        ):
            # No RegisterSession on this connection (or another handle): a
            # real device answers "invalid session handle" (0x0064)
            logger.warning(f"Request with invalid session handle {session:08X}")
            return self._make_response(command, session, context, b"", status=0x0064)
        elif command == EIP_CMD_SEND_RR_DATA:
            return self._handle_send_rr_data(session, context, data)
        elif command == EIP_CMD_LIST_SERVICES:
            return self._handle_list_services(context)
        elif command == EIP_CMD_SEND_UNIT_DATA:
            return self._handle_send_unit_data(session, context, data)
        else:
            logger.warning(f"Unsupported command: {command:04X}")
            return None

    def _handle_register_session(self, context: bytes) -> bytes:
        """Handle Register Session request"""
        self.device.session_handle += 1
        self.session_handle = self.device.session_handle

        logger.info(f"Session registered: {self.session_handle:08X}")

        # Response data: Protocol version (1) + Options flags (0)
        resp_data = struct.pack("<HH", 1, 0)

        return self._make_response(EIP_CMD_REGISTER_SESSION, self.session_handle, context, resp_data)

    def _handle_unregister_session(self, session: int, context: bytes) -> bytes:
        """Handle Unregister Session request"""
        logger.info(f"Session unregistered: {session:08X}")
        self.session_handle = 0
        return self._make_response(EIP_CMD_UNREGISTER_SESSION, 0, context, b"")

    def _handle_list_identity(self, context: bytes) -> bytes:
        """Handle List Identity request"""
        # Build identity item
        identity_data = self.device.get_identity_response()

        # Socket address (16 bytes)
        socket_addr = struct.pack(">HH", 2, 44818)  # sin_family, sin_port
        socket_addr += struct.pack(">I", 0)  # sin_addr
        socket_addr += b"\x00" * 8  # padding

        # ListIdentity ends the identity with a State byte (USINT);
        # 0x03 = "operational"
        identity_data += bytes([0x03])

        # Item: Type ID (0x0C) + Length + Protocol Version + Socket + Identity
        item = struct.pack("<HH", 0x000C, len(identity_data) + 2 + 16)
        item += struct.pack("<H", 1)  # Protocol version
        item += socket_addr
        item += identity_data

        # Item count + items
        resp_data = struct.pack("<H", 1) + item

        return self._make_response(EIP_CMD_LIST_IDENTITY, 0, context, resp_data)

    def _handle_list_services(self, context: bytes) -> bytes:
        """Handle List Services request"""
        # Communications service item
        service_name = b"Communications\x00\x00"
        item = struct.pack("<HH", 0x0100, 20)  # Type + Length
        item += struct.pack("<HH", 1, 0x0120)  # Version + Capability flags
        item += service_name

        resp_data = struct.pack("<H", 1) + item
        return self._make_response(EIP_CMD_LIST_SERVICES, 0, context, resp_data)

    def _handle_send_rr_data(self, session: int, context: bytes, data: bytes) -> bytes:
        """Handle SendRRData (CIP request/response)"""
        if len(data) < 6:
            return self._make_response(EIP_CMD_SEND_RR_DATA, session, context, b"", status=1)

        # Parse Common Packet Format
        # bytes 0-4: interface handle, 4-6: timeout (not used by the simulator)

        if len(data) < 8:
            return self._make_response(EIP_CMD_SEND_RR_DATA, session, context, b"", status=1)

        item_count = struct.unpack("<H", data[6:8])[0]

        # Parse items
        offset = 8
        items = []
        for _ in range(item_count):
            if offset + 4 > len(data):
                break
            type_id = struct.unpack("<H", data[offset:offset + 2])[0]
            item_len = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            item_data = data[offset + 4:offset + 4 + item_len]
            items.append((type_id, item_data))
            offset += 4 + item_len

        # Find unconnected data item (0x00B2)
        cip_data = None
        for type_id, item_data in items:
            if type_id == 0x00B2:
                cip_data = item_data
                break

        if cip_data is None:
            return self._make_response(EIP_CMD_SEND_RR_DATA, session, context, b"", status=1)

        # Process CIP request
        cip_response = self._process_cip_request(cip_data)

        # Build response
        resp_data = struct.pack("<I", 0)  # Interface handle
        resp_data += struct.pack("<H", 0)  # Timeout
        resp_data += struct.pack("<H", 2)  # Item count

        # Null address item
        resp_data += struct.pack("<HH", 0x0000, 0)

        # Unconnected data item
        resp_data += struct.pack("<HH", 0x00B2, len(cip_response))
        resp_data += cip_response

        return self._make_response(EIP_CMD_SEND_RR_DATA, session, context, resp_data)

    def _process_cip_request(self, data: bytes) -> bytes:
        """Process CIP request and return response"""
        if len(data) < 1:
            return bytes([0x80 | CIP_GET_ATTRIBUTE_ALL, 0x08, 0x00])

        service = data[0]

        if service == CIP_GET_ATTRIBUTE_ALL:
            return self._handle_get_attribute_all(data[1:])
        elif service == CIP_UNCONNECTED_SEND and data[2:4] == bytes([0x20, CIP_CLASS_CONNECTION_MANAGER]):
            # Unconnected Send: answer the embedded request directly
            body = data[2 + 2 * data[1]:]
            size = struct.unpack("<H", body[2:4])[0]
            return self._process_cip_request(body[4:4 + size])
        elif service in (CIP_FORWARD_OPEN, CIP_LARGE_FORWARD_OPEN):
            return self._handle_forward_open(service, data)
        elif service == CIP_FORWARD_CLOSE:
            # Reply: connection serial, vendor, originator serial (from the
            # request, after priority/ticks), application reply size, reserved
            body = data[2 + 2 * data[1]:]
            return bytes([CIP_FORWARD_CLOSE | 0x80, 0x00, 0x00, 0x00]) + body[2:10] + b"\x00\x00"
        else:
            # Unknown service: "service not supported" (0x08), as a real
            # device answers. A generic success let scanner code that
            # depends on the error status pass here and fail on hardware.
            return bytes([service | 0x80, 0x00, 0x08, 0x00])

    def _handle_get_attribute_all(self, path_data: bytes) -> bytes:
        """Handle Get Attribute All service"""
        if len(path_data) < 2:
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x00, 0x04, 0x00])  # Path segment error

        # path_data: path size (words), then the class segment 0x20 <class>
        class_id = path_data[2] if len(path_data) > 2 and path_data[1] == 0x20 else 0

        if class_id == CIP_CLASS_IDENTITY:
            identity_data = self.device.get_identity_response()
            # Reply header: service, reserved, general status, extended status size
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x00, 0x00, 0x00]) + identity_data
        else:
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x00, 0x08, 0x00])  # Service not supported

    def _handle_forward_open(self, service: int, data: bytes) -> bytes:
        """
        Forward Open: grant a connection (connected messaging for PCCC).

        Request after service + path: priority(1) ticks(1) O->T cid(4) T->O cid(4)
        conn serial(2) vendor(2) originator serial(4) ...
        """
        path_words = data[1]
        body = data[2 + 2 * path_words:]
        t_to_o_cid = body[6:10]
        conn_serial, vendor, originator = body[10:12], body[12:14], body[14:18]
        self.o_to_t_cid = struct.pack("<I", 0x10000000 + self.device.session_handle)
        reply = (self.o_to_t_cid + t_to_o_cid + conn_serial + vendor + originator
                 + struct.pack("<II", 0x00204001, 0x00204001)   # O->T / T->O API
                 + b"\x00\x00")                                 # application reply size, reserved
        return bytes([service | 0x80, 0x00, 0x00, 0x00]) + reply

    def _handle_send_unit_data(self, session: int, context: bytes, data: bytes) -> Optional[bytes]:
        """SendUnitData: connected CIP message (Execute PCCC typed reads)"""
        if len(data) < 8:
            return None
        items = []
        offset = 8
        for _ in range(struct.unpack("<H", data[6:8])[0]):
            type_id, item_len = struct.unpack("<HH", data[offset:offset + 4])
            items.append((type_id, data[offset + 4:offset + 4 + item_len]))
            offset += 4 + item_len
        address = next((d for t, d in items if t == 0x00A1), b"\x00" * 4)
        payload = next((d for t, d in items if t == 0x00B1), None)
        if payload is None or len(payload) < 3:
            return None
        sequence, cip = payload[:2], payload[2:]
        reply = self._process_connected_request(cip)
        resp = struct.pack("<IHH", 0, 0, 2)
        resp += struct.pack("<HH", 0x00A1, 4) + address
        resp += struct.pack("<HH", 0x00B1, len(sequence) + len(reply)) + sequence + reply
        return self._make_response(EIP_CMD_SEND_UNIT_DATA, session, context, resp)

    def _process_connected_request(self, cip: bytes) -> bytes:
        """Connected request: PCCC (SLC mode) or Logix services (Logix mode)"""
        service = cip[0]
        if self.device.mode in ("logix", "omron"):
            return self._process_logix_request(cip)
        if service != CIP_EXECUTE_PCCC:
            return bytes([service | 0x80, 0x00, 0x08, 0x00])      # service not supported
        path_words = cip[1]
        body = cip[2 + 2 * path_words:]
        requestor_id = body[:body[0]]                            # length-prefixed (7 bytes)
        pccc = body[len(requestor_id):]
        tns = pccc[2:4]
        head = bytes([CIP_EXECUTE_PCCC | 0x80, 0x00, 0x00, 0x00]) + requestor_id
        if pccc[0] != PCCC_CMD_TYPED or pccc[4] != PCCC_FNC_TYPED_READ:
            return head + bytes([pccc[0] | 0x40, 0x10]) + tns           # illegal command
        byte_size, file_number, file_type, element = pccc[5], pccc[6], pccc[7], pccc[8]
        count = byte_size // 2
        values, status = (None, PCCC_STS_ADDRESS_ERROR)
        if PCCC_FILE_TYPES.get(file_type) == "N" and file_number == 7:
            values, status = self.device.read_integer_file(element, count)
        elif PCCC_FILE_TYPES.get(file_type) == "B" and file_number == 3:
            values, status = self.device.read_bit_file(element, count)
        if values is None:
            return head + bytes([PCCC_CMD_TYPED | 0x40, PCCC_STS_ADDRESS_ERROR]) + tns
        return head + bytes([PCCC_CMD_TYPED | 0x40, 0x00]) + tns + b"".join(
            struct.pack("<H", v & 0xFFFF) for v in values)

    # ------------------------------------------------------------------
    # Logix mode
    # ------------------------------------------------------------------

    @staticmethod
    def _reply(service: int, status: int = CIP_OK, data: bytes = b"") -> bytes:
        return bytes([service | 0x80, 0x00, status, 0x00]) + data

    def _process_logix_request(self, cip: bytes) -> bytes:
        service = cip[0]
        path = cip[2:2 + 2 * cip[1]]
        body = cip[2 + 2 * cip[1]:]
        logix = self.device.mode == "logix"
        if service == CIP_MULTIPLE_SERVICE:
            return self._handle_multiple_service(body)
        if service in (CIP_READ_TAG, CIP_READ_TAG_FRAGMENTED) and path[:1] == b"\x91":
            return self._handle_read_tag(service, path, body)
        if not logix:
            # Omron NJ/NX: variables are read by name only
            return self._reply(service, CIP_SERVICE_NOT_SUPPORTED)
        cls, instance, program = self._parse_logical_path(path)
        if service == CIP_GET_ATTRIBUTE_ALL and cls == CIP_CLASS_PROGRAM_NAME:
            name = b"SimProgram"
            return self._reply(service, data=struct.pack("<H", len(name)) + name)
        if service == CIP_GET_INSTANCE_ATTRIBUTE_LIST and cls == CIP_CLASS_SYMBOL:
            return self._handle_tag_list(service, program)
        if service == CIP_GET_ATTRIBUTE_LIST and cls == CIP_CLASS_TEMPLATE:
            return self._handle_template_attributes(service, instance)
        if service == CIP_READ_TAG and cls == CIP_CLASS_TEMPLATE:
            return self._handle_template_read(service, instance, body)
        return self._reply(service, CIP_SERVICE_NOT_SUPPORTED)

    @staticmethod
    def _parse_logical_path(path: bytes) -> Tuple[Optional[int], int, Optional[str]]:
        """(class, instance, program) of a path: [symbolic Program:X] class instance"""
        program = None
        if path[:1] == b"\x91":
            length = path[1]
            program = path[2:2 + length].decode(errors="replace").replace("Program:", "", 1)
            path = path[2 + length + (length % 2):]
        cls = instance = None
        i = 0
        while i < len(path):
            segment = path[i]
            if segment in (0x20, 0x24):
                value, i = path[i + 1], i + 2
            elif segment in (0x21, 0x25):
                value, i = struct.unpack("<H", path[i + 2:i + 4])[0], i + 4
            else:
                break
            if segment in (0x20, 0x21):
                cls = value
            else:
                instance = value
        return cls, instance or 0, program

    # Tag list -----------------------------------------------------------------

    def _symbol_type(self, type_name: str, value) -> int:
        if type_name in self.device.udts:
            code = 0x8000 | self.device.udts[type_name][0]
        else:
            code = CIP_TYPE_CODES[type_name]
        if isinstance(value, list):
            code |= 1 << 13                                       # one array dimension
        return code

    def _handle_tag_list(self, service: int, program: Optional[str]) -> bytes:
        """Get Instance Attribute List on the symbol class (controller or program scope)"""
        if program is None:
            entries = [(name, self._symbol_type(t, v), v) for name, (t, v) in self.device.logix_tags.items()]
            # Program entries ("Program:<name>") tell pycomm3 which programs to upload
            entries += [(f"Program:{p}", 0x1068, None) for p in self.device.program_tags]
        elif program in self.device.program_tags:
            entries = [(name, self._symbol_type(t, v), v)
                       for name, (t, v) in self.device.program_tags[program].items()]
        else:
            return self._reply(service, CIP_PATH_DESTINATION_UNKNOWN)
        data = b""
        for instance, (name, symbol_type, value) in enumerate(entries, start=1):
            dims = [len(value), 0, 0] if isinstance(value, list) else [0, 0, 0]
            encoded = name.encode()
            data += (struct.pack("<I", instance) + struct.pack("<H", len(encoded)) + encoded
                     + struct.pack("<H", symbol_type)
                     + struct.pack("<III", 0, 0, 0x80000000)      # address, object address, base tag
                     + struct.pack("<III", *dims))
        return self._reply(service, data=data)

    # UDT templates ------------------------------------------------------------

    def _udt_by_template(self, instance: int):
        for name, (template_id, members) in self.device.udts.items():
            if template_id == instance:
                return name, members
        return None, None

    @staticmethod
    def _udt_layout(members):
        """[(member, type code, offset)] and the structure size (natural alignment, 4-byte padded)"""
        layout, offset = [], 0
        for member, type_name in members:
            code = CIP_TYPE_CODES[type_name]
            size = CIP_TYPES[code][2]
            offset = (offset + size - 1) // size * size
            layout.append((member, code, offset))
            offset += size
        return layout, (offset + 3) // 4 * 4

    def _template_bytes(self, name: str, members) -> bytes:
        layout, _ = self._udt_layout(members)
        info = b"".join(struct.pack("<HHI", 0, code, offset) for _, code, offset in layout)
        names = f"{name};n".encode() + b"\x00" + b"".join(m.encode() + b"\x00" for m, _ in members)
        return info + names

    def _handle_template_attributes(self, service: int, instance: int) -> bytes:
        name, members = self._udt_by_template(instance)
        if name is None:
            return self._reply(service, CIP_PATH_DESTINATION_UNKNOWN)
        _, size = self._udt_layout(members)
        definition_words = (len(self._template_bytes(name, members)) + 21 + 3) // 4
        data = (struct.pack("<H", 4)
                + struct.pack("<HHI", 4, 0, definition_words)     # object definition size
                + struct.pack("<HHI", 5, 0, size)                 # structure size
                + struct.pack("<HHH", 2, 0, len(members))         # member count
                + struct.pack("<HHH", 1, 0, instance))            # structure handle
        return self._reply(service, data=data)

    def _handle_template_read(self, service: int, instance: int, body: bytes) -> bytes:
        name, members = self._udt_by_template(instance)
        if name is None:
            return self._reply(service, CIP_PATH_DESTINATION_UNKNOWN)
        offset, size = struct.unpack("<IH", body[:6])
        data = self._template_bytes(name, members)
        data = data.ljust(offset + size, b"\x00")[offset:offset + size]
        return self._reply(service, data=data)

    # Read Tag -----------------------------------------------------------------

    @staticmethod
    def _parse_tag_path(path: bytes) -> Tuple[List[str], int]:
        """Symbolic segments (0x91) and the element index of the last one"""
        names, index, i = [], 0, 0
        while i < len(path):
            if path[i] == 0x91:
                length = path[i + 1]
                names.append(path[i + 2:i + 2 + length].decode(errors="replace"))
                i += 2 + length + (length % 2)
            elif path[i] == 0x28:
                index, i = path[i + 1], i + 2
            elif path[i] == 0x29:
                index, i = struct.unpack("<H", path[i + 2:i + 4])[0], i + 4
            elif path[i] == 0x2A:
                index, i = struct.unpack("<I", path[i + 2:i + 6])[0], i + 6
            else:
                break
        return names, index

    def _resolve(self, names: List[str]):
        """(type, value) of Tag, Tag.Member or Program:Name.Tag[.Member]; None if unknown"""
        if names and names[0].startswith("Program:"):
            scope = self.device.program_tags.get(names[0].replace("Program:", "", 1), {})
            names = names[1:]
        else:
            scope = self.device.logix_tags
        if not names or names[0] not in scope:
            return None
        type_name, value = scope[names[0]]
        for member in names[1:]:
            if type_name not in self.device.udts or not isinstance(value, dict):
                return None
            types = dict(self.device.udts[type_name][1])
            if member not in types:
                return None
            type_name, value = types[member], value[member]
        return type_name, value

    def _encode_values(self, type_name: str, values: list) -> Tuple[bytes, bytes]:
        """(reply type bytes, encoded values) for atomic, STRING (Omron) or UDT elements"""
        if type_name == "STRING":
            text = values[0].encode()
            return struct.pack("<H", OMRON_STRING_TYPE), struct.pack("<H", len(text)) + text
        if type_name in self.device.udts:
            template_id, members = self.device.udts[type_name]
            layout, size = self._udt_layout(members)
            data = b""
            for value in values:
                element = bytearray(size)
                for member, code, offset in layout:
                    struct.pack_into(CIP_TYPES[code][1], element, offset, value[member])
                data += bytes(element)
            return STRUCTURE_REPLY_TYPE + struct.pack("<H", template_id), data
        code = CIP_TYPE_CODES[type_name]
        fmt = CIP_TYPES[code][1]
        return struct.pack("<H", code), b"".join(struct.pack(fmt, v) for v in values)

    def _handle_read_tag(self, service: int, path: bytes, body: bytes) -> bytes:
        names, index = self._parse_tag_path(path)
        resolved = self._resolve(names)
        if resolved is None:
            return self._reply(service, CIP_PATH_DESTINATION_UNKNOWN)
        type_name, value = resolved
        elements = struct.unpack("<H", body[:2])[0] or 1
        values = value if isinstance(value, list) else [value]
        if index + elements > len(values):
            return self._reply(service, CIP_PATH_DESTINATION_UNKNOWN)
        type_bytes, payload = self._encode_values(type_name, values[index:index + elements])
        if service == CIP_READ_TAG:
            return self._reply(service, data=type_bytes + payload)
        offset = struct.unpack("<I", body[2:6])[0]
        chunk = payload[offset:offset + LOGIX_FRAGMENT_BYTES]
        status = CIP_PARTIAL_TRANSFER if offset + len(chunk) < len(payload) else CIP_OK
        return self._reply(service, status, type_bytes + chunk)

    def _handle_multiple_service(self, body: bytes) -> bytes:
        count = struct.unpack("<H", body[:2])[0]
        offsets = [struct.unpack("<H", body[2 + 2 * i:4 + 2 * i])[0] for i in range(count)] + [len(body)]
        replies = [self._process_logix_request(body[offsets[i]:offsets[i + 1]]) for i in range(count)]
        status = CIP_EMBEDDED_SERVICE_ERROR if any(r[2] for r in replies) else CIP_OK
        header = struct.pack("<H", count)
        position = 2 + 2 * count
        for reply in replies:
            header += struct.pack("<H", position)
            position += len(reply)
        return self._reply(CIP_MULTIPLE_SERVICE, status, header + b"".join(replies))

    def _make_response(self, command: int, session: int, context: bytes, data: bytes, status: int = 0) -> bytes:
        """Create EtherNet/IP response"""
        response = struct.pack("<H", command)
        response += struct.pack("<H", len(data))
        response += struct.pack("<I", session)
        response += struct.pack("<I", status)
        response += context
        response += struct.pack("<I", 0)  # Options
        response += data
        return response


async def run_server(host: str, port: int, denied_ranges: List[Tuple[int, int]], mode: str = "slc"):
    """Run EtherNet/IP simulator server ("slc" data files or "logix" tags)"""
    device = EtherNetIPDevice(denied_ranges, mode=mode)

    loop = asyncio.get_event_loop()
    server = await loop.create_server(
        lambda: EtherNetIPProtocol(device),
        host, port
    )

    addr = server.sockets[0].getsockname()
    logger.info(f"EtherNet/IP Simulator running on {addr[0]}:{addr[1]}")
    logger.info(f"Denied address ranges: {denied_ranges}")

    async with server:
        await server.serve_forever()


def main():
    parser = simulator_parser("EtherNet/IP PLC Simulator", 44818, "100-150")
    parser.add_argument("--mode", choices=["slc", "logix", "omron"], default="slc",
                        help="slc = PLC-5/SLC/MicroLogix data files (default), "
                             "logix = ControlLogix style symbolic tags (tag list, UDTs, program tags), "
                             "omron = Omron NJ/NX style variables (read by name only)")
    args = parser.parse_args()
    denied_ranges = parse_denied_ranges(args.denied)
    run_simulator(run_server(args.host, args.port, denied_ranges, args.mode), logger)


if __name__ == "__main__":
    main()
