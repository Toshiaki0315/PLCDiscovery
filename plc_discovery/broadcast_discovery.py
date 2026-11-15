"""
UDP Broadcast Discovery Module

Provides UDP broadcast-based discovery for PLCs.
This is faster than TCP port scanning for same-segment discovery.
"""

import asyncio
import ipaddress
import socket
import struct
from typing import Dict, List, Optional, Tuple, Callable
import logging

from .config import Protocol, PLCInfo, NetworkConfig, PROTOCOL_PORTS
from .utils import get_local_networks, get_manufacturer_from_mac

logger = logging.getLogger(__name__)


# SLMP UDP Discovery (Mitsubishi)
SLMP_DISCOVERY_PORT = 5001
SLMP_DISCOVERY_MAGIC = b"\x00\x00\x00\x00"  # Simplified discovery request

# EtherNet/IP UDP Discovery (List Identity)
EIP_DISCOVERY_PORT = 44818
EIP_LIST_IDENTITY_CMD = 0x0063

# Modbus Device Identification
MODBUS_DISCOVERY_PORT = 502


class UDPDiscoveryProtocol(asyncio.DatagramProtocol):
    """Base UDP discovery protocol"""
    
    def __init__(self, responses: Dict[str, bytes], timeout: float):
        self.responses = responses
        self.timeout = timeout
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle received datagram"""
        ip, port = addr
        logger.debug(f"UDP response from {ip}:{port}, {len(data)} bytes")
        self.responses[ip] = data
    
    def error_received(self, exc):
        logger.debug(f"UDP error: {exc}")
    
    def connection_lost(self, exc):
        pass


class BroadcastDiscovery:
    """
    UDP broadcast-based PLC discovery.
    
    Uses protocol-specific broadcast messages to discover PLCs
    on the same network segment.
    """
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self.discovered_plcs: Dict[str, PLCInfo] = {}
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
    
    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set progress callback"""
        self._progress_callback = callback
    
    def _report_progress(self, message: str, current: int = 0, total: int = 0):
        """Report progress"""
        if self._progress_callback:
            self._progress_callback(message, current, total)
        else:
            logger.info(message)
    
    async def discover_slmp_broadcast(self) -> List[PLCInfo]:
        """
        Discover SLMP devices using UDP broadcast.
        
        Sends SLMP discovery message to broadcast address.
        """
        self._report_progress("SLMP UDP broadcast discovery...")
        
        # Create SLMP discovery request (3E frame UDP)
        # This is a simplified discovery - actual implementation may vary
        request = self._build_slmp_discovery_request()
        
        responses = await self._send_broadcast(
            port=SLMP_DISCOVERY_PORT,
            data=request,
            timeout=self.config.discovery_timeout_ms / 1000
        )
        
        plcs = []
        for ip, response in responses.items():
            plc = self._parse_slmp_response(ip, response)
            if plc:
                plcs.append(plc)
                self.discovered_plcs[ip] = plc
        
        logger.info(f"SLMP broadcast: found {len(plcs)} devices")
        return plcs
    
    async def discover_eip_broadcast(self) -> List[PLCInfo]:
        """
        Discover EtherNet/IP devices using List Identity broadcast.
        
        This is the standard EtherNet/IP discovery mechanism.
        """
        self._report_progress("EtherNet/IP UDP broadcast discovery...")
        
        # Create List Identity request
        request = self._build_eip_list_identity_request()
        
        responses = await self._send_broadcast(
            port=EIP_DISCOVERY_PORT,
            data=request,
            timeout=self.config.discovery_timeout_ms / 1000
        )
        
        plcs = []
        for ip, response in responses.items():
            plc = self._parse_eip_response(ip, response)
            if plc:
                plcs.append(plc)
                self.discovered_plcs[ip] = plc
        
        logger.info(f"EtherNet/IP broadcast: found {len(plcs)} devices")
        return plcs
    
    async def discover_all_broadcast(self) -> List[PLCInfo]:
        """
        Discover all PLCs using multiple broadcast protocols.
        
        Runs all broadcast discovery methods in parallel.
        """
        self._report_progress("Starting UDP broadcast discovery for all protocols...")
        
        # Run discoveries in parallel
        results = await asyncio.gather(
            self.discover_slmp_broadcast(),
            self.discover_eip_broadcast(),
            return_exceptions=True
        )
        
        # Collect all results
        all_plcs = []
        for result in results:
            if isinstance(result, list):
                all_plcs.extend(result)
            elif isinstance(result, Exception):
                logger.warning(f"Broadcast discovery error: {result}")
        
        # Deduplicate by IP
        unique_plcs = {}
        for plc in all_plcs:
            if plc.ip_address not in unique_plcs:
                unique_plcs[plc.ip_address] = plc
        
        logger.info(f"Total broadcast discovery: {len(unique_plcs)} unique devices")
        return list(unique_plcs.values())
    
    async def _send_broadcast(
        self,
        port: int,
        data: bytes,
        timeout: float
    ) -> Dict[str, bytes]:
        """
        Send UDP broadcast and collect responses.
        
        Args:
            port: Destination port
            data: Data to send
            timeout: Response timeout in seconds
        
        Returns:
            Dictionary mapping IP address to response data
        """
        responses = {}
        
        try:
            # Directed broadcast address of every connected network (a PC may
            # have several, and 255.255.255.255 alone leaves only one interface)
            broadcasts = []
            for ip, netmask in get_local_networks():
                address = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).broadcast_address)
                if address not in broadcasts:
                    broadcasts.append(address)
            
            # Create UDP socket
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPDiscoveryProtocol(responses, timeout),
                family=socket.AF_INET,
                allow_broadcast=True,
            )
            
            try:
                # Enable broadcast
                sock = transport.get_extra_info('socket')
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                
                for broadcast in broadcasts + ["255.255.255.255"]:
                    logger.debug(f"Sending UDP broadcast to {broadcast}:{port}")
                    try:
                        transport.sendto(data, (broadcast, port))
                    except OSError as e:
                        logger.debug(f"Broadcast to {broadcast} failed: {e}")
                
                # Wait for responses
                await asyncio.sleep(timeout)
                
            finally:
                transport.close()
        
        except Exception as e:
            logger.warning(f"UDP broadcast error: {e}")
        
        return responses
    
    def _build_slmp_discovery_request(self) -> bytes:
        """Build SLMP discovery request"""
        # SLMP 3E frame for device information read
        # Subheader (request: 0x5000)
        subheader = struct.pack("<H", 0x5000)
        # Network number, PC number, I/O number, station number
        routing = struct.pack("<BBHB", 0x00, 0xFF, 0x03FF, 0x00)
        # Timer (unit: 250 ms)
        timer = struct.pack("<H", 0x0010)
        # Command: Read Type Name (0x0101), subcommand 0x0000
        command = struct.pack("<HH", 0x0101, 0x0000)
        # Data length = bytes after this field (timer + command + subcommand)
        data_length = struct.pack("<H", len(timer) + len(command))
        
        return subheader + routing + data_length + timer + command
    
    def _build_eip_list_identity_request(self) -> bytes:
        """Build EtherNet/IP List Identity request"""
        # EtherNet/IP encapsulation header
        command = struct.pack("<H", EIP_LIST_IDENTITY_CMD)  # List Identity
        length = struct.pack("<H", 0)  # Data length
        session = struct.pack("<I", 0)  # Session handle
        status = struct.pack("<I", 0)  # Status
        context = b"\x00" * 8  # Sender context
        options = struct.pack("<I", 0)  # Options
        
        return command + length + session + status + context + options
    
    def _parse_slmp_response(self, ip: str, data: bytes) -> Optional[PLCInfo]:
        """Parse SLMP discovery response"""
        if len(data) < 11:
            return None
        
        try:
            # Check response subheader
            subheader = struct.unpack("<H", data[0:2])[0]
            if subheader != 0xD000:
                return None
            
            return PLCInfo(
                ip_address=ip,
                protocol=Protocol.SLMP,
                port=SLMP_DISCOVERY_PORT,
                manufacturer="三菱電機/SLMP互換",
            )
        
        except Exception as e:
            logger.debug(f"SLMP parse error: {e}")
            return None
    
    def _parse_eip_response(self, ip: str, data: bytes) -> Optional[PLCInfo]:
        """Parse EtherNet/IP List Identity response"""
        if len(data) < 24:
            return None
        
        try:
            # Parse encapsulation header
            command = struct.unpack("<H", data[0:2])[0]
            if command != EIP_LIST_IDENTITY_CMD:
                return None
            
            length = struct.unpack("<H", data[2:4])[0]
            
            # Parse identity data
            plc = PLCInfo(
                ip_address=ip,
                protocol=Protocol.ETHERNET_IP,
                port=EIP_DISCOVERY_PORT,
            )
            
            # Try to extract more info from response
            if length > 0 and len(data) > 26:
                # Skip to identity item
                offset = 24
                if offset + 2 <= len(data):
                    item_count = struct.unpack("<H", data[offset:offset+2])[0]
                    offset += 2
                    
                    if item_count > 0 and offset + 4 <= len(data):
                        type_id = struct.unpack("<H", data[offset:offset+2])[0]
                        item_length = struct.unpack("<H", data[offset+2:offset+4])[0]
                        offset += 4
                        
                        if type_id == 0x000C and offset + item_length <= len(data):
                            # Identity item
                            # Skip protocol version (2) and socket address (16)
                            id_offset = offset + 2 + 16
                            
                            if id_offset + 8 <= len(data):
                                vendor_id = struct.unpack("<H", data[id_offset:id_offset+2])[0]
                                device_type = struct.unpack("<H", data[id_offset+2:id_offset+4])[0]
                                
                                # Map vendor ID to manufacturer
                                vendors = {
                                    0x0001: "ロックウェル",
                                    0x0002: "オムロン",
                                    0x0119: "キーエンス",
                                }
                                plc.manufacturer = vendors.get(vendor_id, f"Vendor {vendor_id}")
            
            return plc
        
        except Exception as e:
            logger.debug(f"EtherNet/IP parse error: {e}")
            return None
    
    def get_results(self) -> List[PLCInfo]:
        """Get all discovered PLCs"""
        return list(self.discovered_plcs.values())


async def discover_broadcast(
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None
) -> List[PLCInfo]:
    """
    Convenience function for broadcast discovery.
    
    Args:
        config: Network configuration
        progress_callback: Progress callback
    
    Returns:
        List of discovered PLCs
    """
    discovery = BroadcastDiscovery(config)
    if progress_callback:
        discovery.set_progress_callback(progress_callback)
    return await discovery.discover_all_broadcast()


