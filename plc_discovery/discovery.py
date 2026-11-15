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
from .probes import UDP_PROTOCOLS, verify_protocol
from .utils import (
    get_network_info, get_subnet_hosts, parse_ip_range, read_arp_cache,
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


ARP_SKIPPED_MESSAGE = (
    "ARP scan skipped: administrator (root) rights are required for raw packets. "
    "PLC discovery continues; MAC addresses are read from the OS ARP cache instead."
)

# Host count above which a scan-duration warning is logged (larger than a /20)
LARGE_SCAN_WARNING_HOSTS = 4096


class PLCDiscovery:
    """
    PLC Discovery Engine
    
    Scans network for PLCs using multiple protocols and methods.
    """
    
    def __init__(
        self,
        config: Optional[NetworkConfig] = None,
        protocols: Optional[List[Protocol]] = None
    ):
        """
        Args:
            config: Network configuration
            protocols: Protocols to probe (default: all). Restricting this
                shortens discovery, e.g. skipping the per-host FINS/UDP probe.
        """
        self.config = config or NetworkConfig()
        self.protocols = list(protocols) if protocols else list(PROTOCOL_PORTS)
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
        
        # Then scan each host for PLC protocols (skip self)
        await self._probe_hosts([h for h in hosts if h != ip], mac_table)
        await self._fill_macs_from_arp_cache()
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
        
        await self._probe_hosts(hosts, {})
        await self._fill_macs_from_arp_cache()
        return list(self.discovered_plcs.values())
    
    async def _fill_macs_from_arp_cache(self) -> None:
        """
        Fill in missing MAC addresses (and the manufacturer from the MAC OUI)
        from the operating system's ARP cache. The protocol probes have just
        contacted every detected PLC, so PLCs on the local segment are in the
        cache; reading it needs no administrator rights (unlike the scapy
        ARP scan). Hosts behind a router never appear there.
        """
        missing = [plc for plc in self.discovered_plcs.values() if not plc.mac_address]
        if not missing:
            return
        cache = await asyncio.get_running_loop().run_in_executor(None, read_arp_cache)
        filled = 0
        for plc in missing:
            mac = cache.get(plc.ip_address)
            if mac:
                plc.mac_address = mac
                plc.manufacturer = plc.manufacturer or get_manufacturer_from_mac(mac)
                filled += 1
        if filled:
            logger.info(f"MAC addresses of {filled} PLC(s) taken from the OS ARP cache")
        elif not cache:
            logger.info(
                "OS ARP cache is not readable or empty; MAC addresses stay blank "
                "(on recent macOS the ARP table is hidden from apps without Local Network access)"
            )
    
    async def _probe_hosts(self, hosts: List[str], mac_table: Dict[str, str]) -> None:
        """
        Probe hosts in batches. Coroutines are created per batch so a large
        range does not allocate (and leave unawaited) one coroutine per host.
        """
        total = len(hosts)
        batch_size = max(1, self.config.max_concurrent * 10)
        
        if total > LARGE_SCAN_WARNING_HOSTS:
            # Rough worst case: every port on every host times out
            ports = len(PROTOCOL_PORTS)
            worst_s = total / batch_size * ports * self.config.discovery_timeout_ms / 1000
            logger.warning(
                f"Scanning {total} hosts may take up to ~{worst_s / 60:.0f} minutes; "
                f"consider a narrower --ip-range"
            )
        
        for i in range(0, total, batch_size):
            batch = hosts[i:i + batch_size]
            results = await asyncio.gather(
                *(self._probe_host(h, mac_table.get(h)) for h in batch),
                return_exceptions=True
            )
            
            for result in results:
                if isinstance(result, PLCInfo):
                    self.discovered_plcs[result.ip_address] = result
            
            self._report_progress("Scanning hosts", min(i + batch_size, total), total)
    
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
            loop = asyncio.get_running_loop()
            answered, _ = await loop.run_in_executor(
                None,
                lambda: srp(arp_request, timeout=self.config.discovery_timeout_ms / 1000, verbose=False)
            )
            
            for sent, received in answered:
                mac_table[received.psrc] = received.hwsrc.upper()
                logger.debug(f"ARP: {received.psrc} -> {received.hwsrc}")
        
        except Exception as e:
            # Raw packet access needs administrator/root rights (scapy raises
            # PermissionError or its own exception mentioning the permission).
            # That is the normal case for a non-elevated GUI/CLI, not an error.
            text = str(e).lower()
            if isinstance(e, PermissionError) or "permission" in text or "not permitted" in text:
                logger.info(ARP_SKIPPED_MESSAGE)
                logger.debug(f"ARP scan permission error: {e}")
            else:
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
            if protocol not in self.protocols:
                continue
            try:
                # TCP protocols: skip the probe if the port is closed.
                # UDP protocols (FINS) have no connection to check first.
                if protocol not in UDP_PROTOCOLS:
                    is_open = await asyncio.get_running_loop().run_in_executor(
                        None,
                        lambda p=port: is_port_open(ip, p, self.config.discovery_timeout_ms / 1000)
                    )
                    if not is_open:
                        continue
                
                # An open port is not proof of a PLC (e.g. NAS on 5001):
                # require a valid protocol reply
                verified = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda p=port, proto=protocol: verify_protocol(
                        ip, p, proto, self.config.discovery_timeout_ms / 1000
                    )
                )
                if verified:
                    detected_protocols.append((protocol, port))
                    logger.debug(f"Verified {protocol.name} on {ip}:{port}")
                else:
                    logger.debug(f"Open port {ip}:{port} did not answer as {protocol.name}")
            
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
            elif plc_info.protocol in (Protocol.FINS, Protocol.FINS_TCP):
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
            
            loop = asyncio.get_running_loop()
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
            
            loop = asyncio.get_running_loop()
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
                    timeout=self.config.request_timeout_ms / 1000,
                    retries=0,
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
                            text = lambda key: info.get(key, b'').decode('utf-8', errors='ignore').strip()
                            # Keep values found earlier (e.g. MAC OUI) when a field is empty
                            plc_info.manufacturer = text(0) or plc_info.manufacturer
                            plc_info.model = text(1) or plc_info.model or "Modbus/TCP対応機器"
                            plc_info.firmware_version = text(2) or plc_info.firmware_version
                        else:
                            plc_info.model = plc_info.model or "Modbus/TCP対応機器"
                    except Exception:
                        plc_info.model = "Modbus/TCP対応機器"
                    finally:
                        client.close()
                
                return plc_info
            
            loop = asyncio.get_running_loop()
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
            
            loop = asyncio.get_running_loop()
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
                config=self.config,
                use_tcp=plc_info.protocol == Protocol.FINS_TCP,
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
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    protocols: Optional[List[Protocol]] = None
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
    discovery = PLCDiscovery(config, protocols)
    
    if progress_callback:
        discovery.set_progress_callback(progress_callback)
    
    if ip_range:
        return await discovery.discover_ip_range(ip_range)
    else:
        return await discovery.discover_same_segment()


