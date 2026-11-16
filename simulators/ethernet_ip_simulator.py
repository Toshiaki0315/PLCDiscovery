#!/usr/bin/env python3
"""
EtherNet/IP (CIP) Simulator

Simulates an EtherNet/IP device for testing PLC Discovery tool.
Implements basic CIP Identity Object and simple data access.

Usage:
    python ethernet_ip_simulator.py [--host 127.0.0.1] [--port 44818]
"""

import argparse
import asyncio
import struct
import logging
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EtherNetIP-Simulator")

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

# CIP Class Codes
CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_ASSEMBLY = 0x04


class EtherNetIPDevice:
    """Simulated EtherNet/IP device"""
    
    def __init__(self, denied_ranges: Optional[List[Tuple[int, int]]] = None):
        self.denied_ranges = denied_ranges or []
        self.session_handle = 0
        
        # Device identity information
        self.vendor_id = 0x0001  # Rockwell
        self.device_type = 0x0E  # Programmable Logic Controller
        self.product_code = 0x0037
        self.revision_major = 1
        self.revision_minor = 0
        self.serial_number = 0x12345678
        self.product_name = b"EIP Simulator PLC"
        
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
        peername = transport.get_extra_info('peername')
        logger.info(f"Connection from {peername}")
    
    def connection_lost(self, exc):
        logger.info("Connection closed")
    
    def data_received(self, data: bytes):
        """Process received EtherNet/IP encapsulation"""
        self.buffer += data
        
        # EtherNet/IP encapsulation header is 24 bytes
        while len(self.buffer) >= 24:
            # Parse header
            command = struct.unpack("<H", self.buffer[0:2])[0]
            length = struct.unpack("<H", self.buffer[2:4])[0]
            session = struct.unpack("<I", self.buffer[4:8])[0]
            status = struct.unpack("<I", self.buffer[8:12])[0]
            context = self.buffer[12:20]
            options = struct.unpack("<I", self.buffer[20:24])[0]
            
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
        elif command == EIP_CMD_SEND_RR_DATA:
            return self._handle_send_rr_data(session, context, data)
        elif command == EIP_CMD_LIST_SERVICES:
            return self._handle_list_services(context)
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
        interface_handle = struct.unpack("<I", data[0:4])[0]
        timeout = struct.unpack("<H", data[4:6])[0]
        
        if len(data) < 8:
            return self._make_response(EIP_CMD_SEND_RR_DATA, session, context, b"", status=1)
        
        item_count = struct.unpack("<H", data[6:8])[0]
        
        # Parse items
        offset = 8
        items = []
        for _ in range(item_count):
            if offset + 4 > len(data):
                break
            type_id = struct.unpack("<H", data[offset:offset+2])[0]
            item_len = struct.unpack("<H", data[offset+2:offset+4])[0]
            item_data = data[offset+4:offset+4+item_len]
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
        else:
            # Generic success response
            return bytes([service | 0x80, 0x00, 0x00])
    
    def _handle_get_attribute_all(self, path_data: bytes) -> bytes:
        """Handle Get Attribute All service"""
        if len(path_data) < 2:
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x04, 0x00])  # Path segment error
        
        path_size = path_data[0]
        class_id = path_data[1] if len(path_data) > 1 else 0
        
        if class_id == CIP_CLASS_IDENTITY:
            identity_data = self.device.get_identity_response()
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x00, 0x00]) + identity_data
        else:
            return bytes([CIP_GET_ATTRIBUTE_ALL | 0x80, 0x08, 0x00])  # Service not supported
    
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


async def run_server(host: str, port: int, denied_ranges: List[Tuple[int, int]]):
    """Run EtherNet/IP simulator server"""
    device = EtherNetIPDevice(denied_ranges)
    
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
    parser = argparse.ArgumentParser(description="EtherNet/IP PLC Simulator")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind to (default 127.0.0.1; 0.0.0.0 = all interfaces)")
    parser.add_argument("--port", type=int, default=44818, help="Port to listen on")
    parser.add_argument("--denied", default="100-150",
                       help="Denied address ranges")
    args = parser.parse_args()
    
    denied_ranges = []
    if args.denied:
        for range_str in args.denied.split(","):
            if "-" in range_str:
                start, end = range_str.split("-")
                denied_ranges.append((int(start), int(end)))
    
    try:
        asyncio.run(run_server(args.host, args.port, denied_ranges))
    except KeyboardInterrupt:
        logger.info("Simulator stopped")


if __name__ == "__main__":
    main()


