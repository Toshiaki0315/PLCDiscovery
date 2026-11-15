"""
Utility functions for PLC Discovery Tool
"""

import ipaddress
import logging
import socket
import struct
from datetime import datetime
from typing import Generator, List, Optional, Tuple

from .config import MANUFACTURER_OUI

# Library code must not configure the root logger; applications
# (plc_scanner.py, plc_gui.py) set up handlers and levels themselves.
logger = logging.getLogger(__name__)


def get_local_ip() -> str:
    """Get the local IP address of this machine"""
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_network_info() -> Tuple[str, str, str]:
    """Get local network information (IP, netmask, broadcast)"""
    try:
        import netifaces
        
        # Get the default gateway interface
        gws = netifaces.gateways()
        default_iface = gws.get('default', {}).get(netifaces.AF_INET, [None, None])[1]
        
        if default_iface:
            addrs = netifaces.ifaddresses(default_iface)
            if netifaces.AF_INET in addrs:
                info = addrs[netifaces.AF_INET][0]
                ip = info.get('addr', get_local_ip())
                netmask = info.get('netmask', '255.255.255.0')
                broadcast = info.get('broadcast', '255.255.255.255')
                return ip, netmask, broadcast
    except ImportError:
        logger.warning("netifaces not installed, using basic network detection")
    except Exception as e:
        logger.warning(f"Error getting network info: {e}")
    
    # Fallback
    local_ip = get_local_ip()
    return local_ip, "255.255.255.0", "255.255.255.255"


def get_subnet_hosts(ip: str, netmask: str) -> Generator[str, None, None]:
    """Generate all host IPs in the subnet"""
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    for host in network.hosts():
        yield str(host)


def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse IP range specification and return list of IPs
    
    Supports:
    - CIDR notation: "192.168.1.0/24"
    - Hyphen notation: "192.168.1.1-255"
    - Single IP: "192.168.1.10"
    """
    ips = []
    
    # CIDR notation
    if "/" in ip_range:
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            ips = [str(host) for host in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {ip_range} - {e}")
            
    # Hyphen notation
    elif "-" in ip_range:
        try:
            parts = ip_range.rsplit(".", 1)
            if len(parts) == 2:
                base_ip = parts[0]
                range_part = parts[1]
                
                if "-" in range_part:
                    start, end = range_part.split("-")
                    for i in range(int(start), int(end) + 1):
                        ips.append(f"{base_ip}.{i}")
                else:
                    ips.append(ip_range)
        except ValueError as e:
            logger.error(f"Invalid hyphen notation: {ip_range} - {e}")
            
    # Single IP
    else:
        try:
            ipaddress.IPv4Address(ip_range)
            ips.append(ip_range)
        except ValueError as e:
            logger.error(f"Invalid IP address: {ip_range} - {e}")
    
    return ips


def get_manufacturer_from_mac(mac_address: str) -> Optional[str]:
    """Get manufacturer name from MAC address OUI"""
    if not mac_address:
        return None
    
    # Normalize MAC address format
    mac = mac_address.upper().replace("-", ":")
    oui = mac[:8]  # First 3 bytes (XX:XX:XX)
    
    return MANUFACTURER_OUI.get(oui)


def format_mac_address(mac_bytes: bytes) -> str:
    """Format MAC address bytes to string"""
    return ":".join(f"{b:02X}" for b in mac_bytes)


def value_to_hex(value: int, word_size: int = 1) -> str:
    """Convert integer value to hexadecimal string"""
    if word_size == 1:
        return f"0x{value & 0xFFFF:04X}"
    elif word_size == 2:
        return f"0x{value & 0xFFFFFFFF:08X}"
    else:
        return hex(value)


def hex_to_value(hex_str: str) -> int:
    """Convert hexadecimal string to integer"""
    return int(hex_str, 16)


def get_timestamp() -> str:
    """Get current timestamp string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def get_file_timestamp() -> str:
    """Get timestamp string for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def split_range(start: int, end: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Split address range in half for binary search algorithm"""
    mid = (start + end) // 2
    return (start, mid), (mid + 1, end)


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open on the target IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def async_sleep(ms: int):
    """Async-compatible sleep in milliseconds"""
    import asyncio
    return asyncio.sleep(ms / 1000.0)


class RateLimiter:
    """Simple rate limiter for network requests"""
    
    def __init__(self, interval_ms: int):
        self.interval_ms = interval_ms
        self._last_call = 0
    
    async def wait(self):
        """Wait for the required interval"""
        import asyncio
        import time
        
        now = time.time() * 1000
        elapsed = now - self._last_call
        
        if elapsed < self.interval_ms:
            await asyncio.sleep((self.interval_ms - elapsed) / 1000.0)
        
        self._last_call = time.time() * 1000


class SessionCache:
    """Cache for inaccessible addresses within a session"""
    
    def __init__(self):
        self._denied_addresses: set = set()
    
    def add_denied(self, address: str):
        """Mark an address as inaccessible"""
        self._denied_addresses.add(address)
    
    def is_denied(self, address: str) -> bool:
        """Check if an address is known to be inaccessible"""
        return address in self._denied_addresses
    
    def get_all_denied(self) -> set:
        """Get all denied addresses"""
        return self._denied_addresses.copy()
    
    def clear(self):
        """Clear the cache"""
        self._denied_addresses.clear()


