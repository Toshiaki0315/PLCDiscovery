"""
PLC Discovery Module - Network scanning and PLC detection

Supports:
- Same-segment UDP broadcast discovery
- User-specified IP range scanning
- Multi-protocol detection (SLMP, EtherNet/IP, Modbus/TCP, S7)
"""

import asyncio
import socket
import struct
from typing import Dict, List, Optional, Callable
import logging

from .config import (
    Protocol, PROTOCOL_PORTS, PLCInfo, NetworkConfig
)
from .utils import (
    get_network_info, get_subnet_hosts, parse_ip_range,
    is_port_open, get_manufacturer_from_mac, format_mac_address,
    get_timestamp, logger
)

# Try to import optional dependencies
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not available, ARP discovery disabled")


class PLCDiscovery:
    """
    PLC Discovery Engine
    
    Scans network for PLCs using multiple protocols and methods.
    """
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self.discovered_plcs: Dict[str, PLCInfo] = {}
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
    
    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set callback for progress updates: callback(message, current, total)"""
        self._progress_callback = callback
    
    def _report_progress(self, message: str, current: int = 0, total: int = 0):
        """Report progress to callback if set"""
        if self._progress_callback:
            self._progress_callback(message, current, total)
        else:
            logger.info(f"{message} ({current}/{total})" if total else message)
    
    async def discover_same_segment(self) -> List[PLCInfo]:
        """
        Discover PLCs on the same network segment.
        Uses ARP for MAC discovery and port scanning for protocol detection.
        """
        ip, netmask, broadcast = get_network_info()
        logger.info(f"Starting same-segment discovery from {ip}/{netmask}")
        
        # Get all hosts in subnet
        hosts = list(get_subnet_hosts(ip, netmask))
        total_hosts = len(hosts)
        
        self._report_progress(f"Scanning {total_hosts} hosts in subnet", 0, total_hosts)
        
        # First, do ARP scan if scapy is available
        mac_table = {}
        if SCAPY_AVAILABLE:
            mac_table = await self._arp_scan(ip, netmask)
        
        # Then scan each host for PLC protocols
        tasks = []
        for i, host_ip in enumerate(hosts):
            if host_ip != ip:  # Skip self
                tasks.append(self._probe_host(host_ip, mac_table.get(host_ip)))
        
        # Process in batches for rate limiting
        batch_size = self.config.max_concurrent * 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, PLCInfo):
                    self.discovered_plcs[result.ip_address] = result
            
            self._report_progress(
                f"Scanning hosts", 
                min(i + batch_size, len(tasks)), 
                len(tasks)
            )
        
        return list(self.discovered_plcs.values())
    
    async def discover_ip_range(self, ip_range: str) -> List[PLCInfo]:
        """
        Discover PLCs in a specified IP range.
        
        Args:
            ip_range: IP range in CIDR (192.168.1.0/24) or hyphen notation (192.168.1.1-255)
        """
        hosts = parse_ip_range(ip_range)
        total_hosts = len(hosts)
        
        if not hosts:
            logger.error(f"No valid hosts in range: {ip_range}")
            return []
        
        logger.info(f"Starting IP range discovery for {total_hosts} hosts")
        self._report_progress(f"Scanning {total_hosts} hosts", 0, total_hosts)
        
        # Scan each host
        tasks = [self._probe_host(host_ip, None) for host_ip in hosts]
        
        # Process in batches
        batch_size = self.config.max_concurrent * 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, PLCInfo):
                    self.discovered_plcs[result.ip_address] = result
            
            self._report_progress(
                f"Scanning hosts", 
                min(i + batch_size, len(tasks)), 
                len(tasks)
            )
        
        return list(self.discovered_plcs.values())
    
    async def _arp_scan(self, ip: str, netmask: str) -> Dict[str, str]:
        """
        Perform ARP scan to get MAC addresses.
        Returns dict mapping IP to MAC address.
        """
        if not SCAPY_AVAILABLE:
            return {}
        
        mac_table = {}
        try:
            # Build network string
            from ipaddress import IPv4Network
            network = IPv4Network(f"{ip}/{netmask}", strict=False)
            
            # Send ARP request
            conf.verb = 0  # Suppress scapy output
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            
            # Run ARP scan with timeout
            loop = asyncio.get_event_loop()
            answered, _ = await loop.run_in_executor(
                None,
                lambda: srp(arp_request, timeout=self.config.discovery_timeout_ms / 1000, verbose=False)
            )
            
            for sent, received in answered:
                mac_table[received.psrc] = received.hwsrc.upper()
                logger.debug(f"ARP: {received.psrc} -> {received.hwsrc}")
        
        except Exception as e:
            logger.warning(f"ARP scan failed: {e}")
        
        return mac_table
    
    async def _probe_host(self, ip: str, mac: Optional[str] = None) -> Optional[PLCInfo]:
        """
        Probe a single host for PLC protocols.
        Returns PLCInfo if a PLC is detected, None otherwise.
        """
        detected_protocols = []
        
        # Check each protocol port
        for protocol, port in PROTOCOL_PORTS.items():
            try:
                is_open = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda p=port: is_port_open(ip, p, self.config.discovery_timeout_ms / 1000)
                )
                
                if is_open:
                    detected_protocols.append((protocol, port))
                    logger.debug(f"Open port: {ip}:{port} ({protocol.name})")
            
            except Exception as e:
                logger.debug(f"Port scan error {ip}:{port}: {e}")
        
        if not detected_protocols:
            return None
        
        # Create PLCInfo with the first detected protocol
        protocol, port = detected_protocols[0]
        plc_info = PLCInfo(
            ip_address=ip,
            mac_address=mac,
            protocol=protocol,
            port=port,
            manufacturer=get_manufacturer_from_mac(mac) if mac else None
        )
        
        # Try to get detailed info using protocol-specific queries
        plc_info = await self._get_detailed_info(plc_info)
        
        return plc_info
    
    async def _get_detailed_info(self, plc_info: PLCInfo) -> PLCInfo:
        """
        Get detailed PLC information using protocol-specific queries.
        """
        try:
            if plc_info.protocol == Protocol.SLMP:
                plc_info = await self._query_slmp_info(plc_info)
            elif plc_info.protocol == Protocol.ETHERNET_IP:
                plc_info = await self._query_eip_info(plc_info)
            elif plc_info.protocol == Protocol.MODBUS_TCP:
                plc_info = await self._query_modbus_info(plc_info)
            elif plc_info.protocol == Protocol.S7:
                plc_info = await self._query_s7_info(plc_info)
            elif plc_info.protocol == Protocol.FINS:
                plc_info = await self._query_fins_info(plc_info)
        except Exception as e:
            logger.debug(f"Failed to get detailed info for {plc_info.ip_address}: {e}")
        
        return plc_info
    
    async def _query_slmp_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query SLMP device for CPU information"""
        try:
            from pymcprotocol import Type3E
            
            def _query():
                client = Type3E()
                client.connect(plc_info.ip_address, plc_info.port or 5001)
                try:
                    # Try to read CPU type
                    # SLMP doesn't have a standard CPU info command, 
                    # but successful connection confirms it's SLMP
                    plc_info.manufacturer = plc_info.manufacturer or "三菱電機/キーエンス"
                    plc_info.model = "SLMP対応PLC"
                except Exception:
                    pass
                finally:
                    client.close()
                return plc_info
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _query)
        
        except ImportError:
            logger.debug("pymcprotocol not available")
        except Exception as e:
            logger.debug(f"SLMP query failed: {e}")
        
        return plc_info
    
    async def _query_eip_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query EtherNet/IP device for Identity Object information"""
        try:
            from pycomm3 import CIPDriver
            
            def _query():
                with CIPDriver(plc_info.ip_address) as plc:
                    identity = plc.get_plc_info()
                    if identity:
                        plc_info.manufacturer = identity.get('vendor', plc_info.manufacturer)
                        plc_info.model = identity.get('product_name', plc_info.model)
                        plc_info.firmware_version = identity.get('revision', '')
                return plc_info
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _query)
        
        except ImportError:
            logger.debug("pycomm3 not available")
        except Exception as e:
            logger.debug(f"EtherNet/IP query failed: {e}")
        
        return plc_info
    
    async def _query_modbus_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query Modbus device for identification"""
        try:
            from pymodbus.client import ModbusTcpClient
            from .protocols.modbus import modbus_unit_kwargs
            
            def _query():
                client = ModbusTcpClient(
                    plc_info.ip_address, 
                    port=plc_info.port or 502,
                    timeout=self.config.request_timeout_ms / 1000
                )
                
                if client.connect():
                    try:
                        # Try to read device identification (MEI)
                        method = client.read_device_information
                        response = method(
                            read_code=0x01,  # Basic identification
                            object_id=0x00,
                            **modbus_unit_kwargs(method, 1)
                        )
                        
                        if response and not response.isError():
                            info = response.information
                            plc_info.manufacturer = info.get(0, b'').decode('utf-8', errors='ignore')
                            plc_info.model = info.get(1, b'').decode('utf-8', errors='ignore')
                            plc_info.firmware_version = info.get(2, b'').decode('utf-8', errors='ignore')
                        else:
                            plc_info.model = "Modbus/TCP対応機器"
                    except Exception:
                        plc_info.model = "Modbus/TCP対応機器"
                    finally:
                        client.close()
                
                return plc_info
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _query)
        
        except ImportError:
            logger.debug("pymodbus not available")
        except Exception as e:
            logger.debug(f"Modbus query failed: {e}")
        
        return plc_info
    
    async def _query_s7_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query Siemens S7 device for CPU information"""
        try:
            import snap7
            
            def _query():
                client = snap7.client.Client()
                client.connect(plc_info.ip_address, 0, 0)
                
                try:
                    # Get CPU info
                    info = client.get_cpu_info()
                    plc_info.manufacturer = "シーメンス"
                    plc_info.model = info.ModuleTypeName.decode('utf-8', errors='ignore').strip()
                    plc_info.cpu_type = info.ASName.decode('utf-8', errors='ignore').strip()
                except Exception:
                    plc_info.manufacturer = "シーメンス"
                    plc_info.model = "S7 PLC"
                finally:
                    client.disconnect()
                
                return plc_info
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _query)
        
        except ImportError:
            logger.debug("snap7 not available")
        except Exception as e:
            logger.debug(f"S7 query failed: {e}")
        
        return plc_info
    
    async def _query_fins_info(self, plc_info: PLCInfo) -> PLCInfo:
        """Query FINS device for information"""
        try:
            from .protocols.fins import FINSHandler
            from .config import DeviceType, StatusCode
            
            # Simple read to confirm connection
            handler = FINSHandler(
                ip_address=plc_info.ip_address,
                port=plc_info.port or 9600,
                config=self.config
            )
            
            if await handler.connect():
                try:
                    data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
                    if status == StatusCode.OK:
                        plc_info.manufacturer = plc_info.manufacturer or "オムロン"
                        plc_info.model = "FINS対応PLC"
                finally:
                    await handler.disconnect()
        except Exception as e:
            logger.debug(f"FINS query failed: {e}")
        
        return plc_info
    
    def get_results(self) -> List[PLCInfo]:
        """Get all discovered PLCs"""
        return list(self.discovered_plcs.values())
    
    def clear(self):
        """Clear discovery results"""
        self.discovered_plcs.clear()


async def discover_plcs(
    ip_range: Optional[str] = None,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None
) -> List[PLCInfo]:
    """
    Convenience function to discover PLCs.
    
    Args:
        ip_range: Optional IP range to scan. If None, scans same segment.
        config: Optional network configuration.
        progress_callback: Optional callback for progress updates.
    
    Returns:
        List of discovered PLCInfo objects.
    """
    discovery = PLCDiscovery(config)
    
    if progress_callback:
        discovery.set_progress_callback(progress_callback)
    
    if ip_range:
        return await discovery.discover_ip_range(ip_range)
    else:
        return await discovery.discover_same_segment()


