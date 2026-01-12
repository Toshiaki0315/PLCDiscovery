"""
FINS Protocol Handler - Omron PLC Communication

Implements FINS/UDP and FINS/TCP protocol for Omron
CS/CJ/CP/NJ/NX series PLCs.
"""

import asyncio
import struct
import logging
from typing import List, Optional, Tuple

from ..config import (
    Protocol, DeviceType, StatusCode, NetworkConfig, PROTOCOL_PORTS
)
from .base import BaseProtocolHandler

logger = logging.getLogger(__name__)


# FINS Frame constants
FINS_ICF = 0x80          # Information Control Field (command)
FINS_RSV = 0x00          # Reserved
FINS_GCT = 0x02          # Permissible number of gateways
FINS_DNA = 0x00          # Destination network address (local)
FINS_DA1 = 0x00          # Destination node address (PLC node)
FINS_DA2 = 0x00          # Destination unit address (CPU unit)
FINS_SNA = 0x00          # Source network address (local)
FINS_SA1 = 0x00          # Source node address (client node)
FINS_SA2 = 0x00          # Source unit address

# FINS Memory Area codes
FINS_AREA_CODES = {
    DeviceType.DM: 0x82,     # DM Area (word)
    DeviceType.D: 0x82,      # Alias for DM
    DeviceType.HR: 0xB2,     # HR Area (word)
    DeviceType.W: 0xB1,      # W Area (word)
    DeviceType.IR: 0xDC,     # IR Area (word) - Actually CIO
    DeviceType.M: 0x30,      # CIO Area (bit) - for compatibility
}

# FINS Commands
FINS_CMD_MEMORY_READ = (0x01, 0x01)   # Memory area read
FINS_CMD_MEMORY_WRITE = (0x01, 0x02)  # Memory area write

# FINS Error codes
FINS_ERROR_CODES = {
    0x0000: "Normal completion",
    0x0001: "Service cancelled",
    0x0101: "Local node not in network",
    0x0102: "Token timeout",
    0x0103: "Retries failed",
    0x0104: "Too many send frames",
    0x0105: "Node address range error",
    0x0106: "Node address duplication",
    0x0201: "Destination node not in network",
    0x0202: "Unit missing",
    0x0203: "Third node missing",
    0x0204: "Destination node busy",
    0x0205: "Response timeout",
    0x0301: "Communications controller error",
    0x0302: "CPU Unit error",
    0x0303: "Controller error",
    0x0304: "Unit number error",
    0x0401: "Undefined command",
    0x0402: "Not supported by model/version",
    0x1001: "Memory area/bank error",
    0x1002: "Memory address out of range",
    0x1003: "Data size is not word",
    0x1101: "Access right not acquired",
    0x1102: "Service aborted",
    0x2002: "Read-only area",
    0x2003: "Write protected",
}


class FINSHandler(BaseProtocolHandler):
    """
    FINS protocol handler for Omron PLCs.
    
    Supports both UDP and TCP variants.
    
    Usage:
        async with FINSHandler("192.168.1.10") as handler:
            data, status = await handler.read_device_raw(DeviceType.DM, 0, 100)
    """
    
    protocol = Protocol.FINS
    DEFAULT_PORT_UDP = 9600
    DEFAULT_PORT_TCP = 9600
    MAX_READ_WORDS = 499  # FINS limit per read
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        config: Optional[NetworkConfig] = None,
        use_tcp: bool = False,
        source_node: int = 0,
        dest_node: int = 0
    ):
        """
        Initialize FINS handler.
        
        Args:
            ip_address: PLC IP address
            port: Port number (default 9600)
            config: Network configuration
            use_tcp: Use TCP instead of UDP
            source_node: Source node address (0-255)
            dest_node: Destination node address (0-255)
        """
        super().__init__(
            ip_address,
            port or self.DEFAULT_PORT_UDP,
            config
        )
        
        self.use_tcp = use_tcp
        self.source_node = source_node
        self.dest_node = dest_node
        
        self._transport = None
        self._protocol_instance = None
        self._reader = None
        self._writer = None
        self._sid = 0  # Service ID counter
    
    @property
    def max_read_size(self) -> int:
        return self.MAX_READ_WORDS
    
    async def connect(self) -> bool:
        """Establish connection to PLC"""
        try:
            if self.use_tcp:
                return await self._connect_tcp()
            else:
                return await self._connect_udp()
        except Exception as e:
            logger.error(f"FINS connection failed: {e}")
            return False
    
    async def _connect_tcp(self) -> bool:
        """Establish TCP connection"""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip_address, self.port),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            # Send FINS/TCP node address negotiation
            handshake = self._build_tcp_handshake()
            self._writer.write(handshake)
            await self._writer.drain()
            
            # Wait for response
            response = await asyncio.wait_for(
                self._reader.read(24),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if len(response) < 24:
                logger.error("Invalid FINS/TCP handshake response")
                return False
            
            # Parse response to get node addresses
            # Bytes 20-23 contain client and server node addresses
            self.source_node = response[19]
            self.dest_node = response[23]
            
            self._connected = True
            logger.info(f"FINS/TCP connected to {self.ip_address}:{self.port}")
            return True
            
        except asyncio.TimeoutError:
            logger.error("FINS/TCP connection timeout")
            return False
        except Exception as e:
            logger.error(f"FINS/TCP connection error: {e}")
            return False
    
    async def _connect_udp(self) -> bool:
        """Establish UDP connection"""
        try:
            loop = asyncio.get_event_loop()
            
            # Create UDP endpoint
            self._transport, self._protocol_instance = await loop.create_datagram_endpoint(
                lambda: FINSUDPProtocol(self),
                remote_addr=(self.ip_address, self.port)
            )
            
            self._connected = True
            logger.info(f"FINS/UDP connected to {self.ip_address}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"FINS/UDP connection error: {e}")
            return False
    
    async def disconnect(self):
        """Close connection"""
        try:
            if self.use_tcp:
                if self._writer:
                    self._writer.close()
                    await self._writer.wait_closed()
            else:
                if self._transport:
                    self._transport.close()
            
            self._connected = False
            logger.info(f"FINS disconnected from {self.ip_address}")
            
        except Exception as e:
            logger.warning(f"FINS disconnect error: {e}")
        finally:
            self._reader = None
            self._writer = None
            self._transport = None
            self._protocol_instance = None
    
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read raw device data from PLC.
        
        Args:
            device_type: Device type (DM, HR, W, etc.)
            start_address: Starting address
            count: Number of words to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        if not self._connected:
            return None, StatusCode.NG_COMM_ERROR
        
        try:
            # Build FINS command
            frame = self._build_read_command(device_type, start_address, count)
            
            # Send and receive
            if self.use_tcp:
                response = await self._send_tcp(frame)
            else:
                response = await self._send_udp(frame)
            
            if response is None:
                return None, StatusCode.NG_TIMEOUT
            
            # Parse response
            return self._parse_read_response(response)
            
        except Exception as e:
            logger.error(f"FINS read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    def _build_read_command(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> bytes:
        """Build FINS memory read command"""
        # Get memory area code
        area_code = FINS_AREA_CODES.get(device_type, 0x82)
        
        # Increment SID
        self._sid = (self._sid + 1) & 0xFF
        
        # Build FINS header
        header = bytes([
            FINS_ICF,           # ICF
            FINS_RSV,           # RSV
            FINS_GCT,           # GCT
            FINS_DNA,           # DNA (destination network)
            self.dest_node,     # DA1 (destination node)
            FINS_DA2,           # DA2 (destination unit)
            FINS_SNA,           # SNA (source network)
            self.source_node,   # SA1 (source node)
            FINS_SA2,           # SA2 (source unit)
            self._sid,          # SID (service ID)
        ])
        
        # Build command code
        cmd = bytes(FINS_CMD_MEMORY_READ)
        
        # Build command data
        # Address format: Area(1) + Address(2) + Bit(1)
        addr_high = (start_address >> 8) & 0xFF
        addr_low = start_address & 0xFF
        
        data = bytes([
            area_code,      # Memory area code
            addr_high,      # Address high byte
            addr_low,       # Address low byte
            0x00,           # Bit position (always 0 for word access)
            (count >> 8) & 0xFF,  # Count high byte
            count & 0xFF,         # Count low byte
        ])
        
        fins_frame = header + cmd + data
        
        # Wrap in TCP header if needed
        if self.use_tcp:
            return self._wrap_tcp_frame(fins_frame)
        
        return fins_frame
    
    def _build_tcp_handshake(self) -> bytes:
        """Build FINS/TCP node address negotiation request"""
        # FINS/TCP header
        header = bytes([
            0x46, 0x49, 0x4E, 0x53,  # "FINS"
            0x00, 0x00, 0x00, 0x0C,  # Length (12 bytes)
            0x00, 0x00, 0x00, 0x00,  # Command: Node address data send
            0x00, 0x00, 0x00, 0x00,  # Error code
            0x00, 0x00, 0x00, 0x00,  # Client node address (0 = auto)
        ])
        return header
    
    def _wrap_tcp_frame(self, fins_frame: bytes) -> bytes:
        """Wrap FINS frame with TCP header"""
        length = len(fins_frame) + 8
        header = bytes([
            0x46, 0x49, 0x4E, 0x53,  # "FINS"
            (length >> 24) & 0xFF,
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            0x00, 0x00, 0x00, 0x02,  # Command: FINS frame
            0x00, 0x00, 0x00, 0x00,  # Error code
        ])
        return header + fins_frame
    
    async def _send_tcp(self, frame: bytes) -> Optional[bytes]:
        """Send frame via TCP and receive response"""
        try:
            self._writer.write(frame)
            await self._writer.drain()
            
            # Read TCP header first
            header = await asyncio.wait_for(
                self._reader.read(16),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if len(header) < 16:
                return None
            
            # Parse length from header
            length = struct.unpack(">I", header[4:8])[0]
            
            # Read FINS frame
            fins_data = await asyncio.wait_for(
                self._reader.read(length - 8),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            return fins_data
            
        except asyncio.TimeoutError:
            logger.error("FINS/TCP read timeout")
            return None
        except Exception as e:
            logger.error(f"FINS/TCP send error: {e}")
            return None
    
    async def _send_udp(self, frame: bytes) -> Optional[bytes]:
        """Send frame via UDP and receive response"""
        if not self._protocol_instance:
            return None
        
        try:
            # Send request
            self._transport.sendto(frame)
            
            # Wait for response
            response = await asyncio.wait_for(
                self._protocol_instance.receive(),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            return response
            
        except asyncio.TimeoutError:
            logger.error("FINS/UDP read timeout")
            return None
        except Exception as e:
            logger.error(f"FINS/UDP send error: {e}")
            return None
    
    def _parse_read_response(
        self,
        response: bytes
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """Parse FINS read response"""
        if len(response) < 14:
            return None, StatusCode.NG_COMM_ERROR
        
        # Skip header (10 bytes) and command code (2 bytes)
        # Response format: Header(10) + Cmd(2) + EndCode(2) + Data...
        
        # Check end code (bytes 12-13)
        end_code = (response[12] << 8) | response[13]
        
        if end_code != 0x0000:
            error_msg = FINS_ERROR_CODES.get(end_code, f"Unknown error: {end_code:04X}")
            logger.warning(f"FINS error: {error_msg}")
            
            if end_code in (0x1001, 0x1002):
                return None, StatusCode.NG_ILLEGAL_ADDR
            elif end_code in (0x0205,):
                return None, StatusCode.NG_TIMEOUT
            else:
                return None, StatusCode.NG_COMM_ERROR
        
        # Extract data (starting from byte 14)
        data_bytes = response[14:]
        
        # Convert to word list
        words = []
        for i in range(0, len(data_bytes), 2):
            if i + 1 < len(data_bytes):
                # Big-endian word
                word = (data_bytes[i] << 8) | data_bytes[i + 1]
                words.append(word)
        
        return words, StatusCode.OK


class FINSUDPProtocol(asyncio.DatagramProtocol):
    """UDP Protocol handler for FINS"""
    
    def __init__(self, handler: FINSHandler):
        self.handler = handler
        self._response_future = None
        self._response_queue = asyncio.Queue()
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        # Put response in queue
        try:
            self._response_queue.put_nowait(data)
        except asyncio.QueueFull:
            logger.warning("FINS response queue full")
    
    def error_received(self, exc):
        logger.error(f"FINS UDP error: {exc}")
    
    async def receive(self) -> bytes:
        """Wait for and return next response"""
        return await self._response_queue.get()


# Register default port
PROTOCOL_PORTS[Protocol.FINS] = 9600


