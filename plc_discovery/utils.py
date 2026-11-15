"""
Utility functions for PLC Discovery Tool
"""

import ipaddress
import logging
import re
import socket
import struct
from datetime import datetime
from typing import Dict, Generator, List, Optional, Tuple

from .config import MANUFACTURER_OUI, StatusCode

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


def _networks_from_netifaces() -> Optional[List[Tuple[str, str]]]:
    try:
        import netifaces
    except ImportError:
        return None
    result = []
    for iface in netifaces.interfaces():
        for info in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            if info.get("addr") and info.get("netmask"):
                result.append((info["addr"], info["netmask"]))
    return result


_IFCONFIG_INET = re.compile(
    r"\binet (?:addr:)?(\d+\.\d+\.\d+\.\d+)\b.*?(?:netmask|Mask:)\s*(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)"
)
_CIDR = re.compile(r"\b(\d+\.\d+\.\d+\.\d+)/(\d{1,2})\b")


def parse_interface_listing(text: str) -> List[Tuple[str, str]]:
    """
    Parse IPv4 address/netmask pairs from "ifconfig" (macOS/BSD, also the
    old Linux "inet addr: ... Mask:" form), "ip -o -4 addr" (Linux) or
    "address/prefix" lines (Windows PowerShell Get-NetIPAddress).
    """
    result = []
    for line in text.splitlines():
        match = _IFCONFIG_INET.search(line)
        if match:
            address, mask = match.groups()
            if mask.lower().startswith("0x"):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            result.append((address, mask))
            continue
        match = _CIDR.search(line)
        if match and int(match.group(2)) <= 32:
            address, prefix = match.groups()
            result.append((address, str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)))
    return result


def _networks_from_os() -> List[Tuple[str, str]]:
    """IPv4 interfaces via the OS's own tools (no extra packages, no admin rights)"""
    import subprocess
    import sys
    
    if sys.platform.startswith("win"):
        commands = [[
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }",
        ]]
    elif sys.platform.startswith("linux"):
        commands = [["ip", "-o", "-4", "addr", "show"], ["ifconfig"]]
    else:
        commands = [["ifconfig"]]
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(f"{command[0]} failed: {e}")
            continue
        networks = parse_interface_listing(result.stdout.decode("ascii", errors="ignore"))
        if networks:
            return networks
    return []


def get_local_networks() -> List[Tuple[str, str]]:
    """
    All IPv4 networks this PC is connected to, as (local IP, netmask).
    
    Considers every interface (e.g. an office LAN and a separate control
    LAN) and works without a default gateway (isolated factory networks).
    Loopback, link-local (169.254.x.x, an unconfigured interface) and
    point-to-point /31-/32 addresses are excluded.
    """
    candidates = _networks_from_netifaces()
    if not candidates:
        candidates = _networks_from_os()
    if not candidates:
        # Last resort: the interface of the default route, assuming /24
        local_ip = get_local_ip()
        candidates = [(local_ip, "255.255.255.0")]
    
    networks: List[Tuple[str, str]] = []
    seen = set()
    for address, netmask in candidates:
        try:
            interface = ipaddress.IPv4Interface(f"{address}/{netmask}")
        except ValueError:
            continue
        if interface.ip.is_loopback or interface.ip.is_link_local or interface.network.prefixlen >= 31:
            continue
        if interface.network in seen:
            continue
        seen.add(interface.network)
        networks.append((str(interface.ip), str(interface.netmask)))
    return networks


def get_network_info() -> Tuple[str, str, str]:
    """
    Local network information (IP, netmask, broadcast) of the first
    connected network; see get_local_networks() for all of them.
    Falls back to the default-route address with /24.
    """
    networks = get_local_networks()
    if networks:
        ip, netmask = networks[0]
        broadcast = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).broadcast_address)
        return ip, netmask, broadcast
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
    - Last-octet range: "192.168.1.1-254"
    - Full range: "192.168.1.10-192.168.1.20"
    - Single IP: "192.168.1.10"
    
    Invalid specifications are logged and return an empty list.
    """
    ip_range = (ip_range or "").strip()
    
    # CIDR notation
    if "/" in ip_range:
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {ip_range} - {e}")
            return []
    
    # Hyphen notation
    if "-" in ip_range:
        try:
            first, last = (p.strip() for p in ip_range.split("-", 1))
            start = ipaddress.IPv4Address(first)
            if "." in last:
                end = ipaddress.IPv4Address(last)
            else:
                octet = int(last)
                if not 0 <= octet <= 255:
                    raise ValueError(f"last octet {octet} out of range 0-255")
                end = ipaddress.IPv4Address(int(start) & 0xFFFFFF00 | octet)
            if int(end) < int(start):
                raise ValueError("end address is lower than start address")
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError as e:
            logger.error(f"Invalid hyphen notation: {ip_range} - {e}")
            return []
    
    # Single IP
    try:
        ipaddress.IPv4Address(ip_range)
        return [ip_range]
    except ValueError as e:
        logger.error(f"Invalid IP address: {ip_range} - {e}")
        return []


def get_manufacturer_from_mac(mac_address: str) -> Optional[str]:
    """Get manufacturer name from MAC address OUI"""
    if not mac_address:
        return None
    
    # Normalize MAC address format
    mac = mac_address.upper().replace("-", ":")
    oui = mac[:8]  # First 3 bytes (XX:XX:XX)
    
    return MANUFACTURER_OUI.get(oui)


# An IPv4 address followed later on the same line by a MAC address; other
# columns (e.g. "at", or HW type/flags in /proc/net/arp) may lie in between
_ARP_IP_MAC = re.compile(
    r"(?<![\d.])(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?![\d.]).*?"
    r"(?<![0-9A-Fa-f:-])(?P<mac>[0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})(?![0-9A-Fa-f:-])"
)


def normalize_mac(mac: str) -> Optional[str]:
    """
    Normalize "0:1c:42:a:b:c" / "00-1C-42-0A-0B-0C" to "00:1C:42:0A:0B:0C".
    Returns None for invalid, all-zero and broadcast addresses.
    """
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
        return None
    normalized = ":".join(p.zfill(2).upper() for p in parts)
    if normalized in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return normalized


def parse_arp_table(text: str) -> Dict[str, str]:
    """
    Parse ARP cache listings into {ip: mac}. Understands the output of
    "arp -an" (macOS/BSD/Linux), "arp -a" (Windows) and /proc/net/arp.
    Incomplete entries are skipped.
    """
    table: Dict[str, str] = {}
    for line in text.splitlines():
        match = _ARP_IP_MAC.search(line)
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if mac:
            table[match.group("ip")] = mac
    return table


def read_arp_cache(timeout: float = 5.0) -> Dict[str, str]:
    """
    Read the operating system's ARP cache ({ip: mac}) without special
    privileges. Hosts on the local segment appear here once they have been
    contacted (e.g. by the protocol probes of a discovery run).
    Returns an empty dict if the cache cannot be read.
    """
    import subprocess
    import sys
    
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/arp", encoding="ascii", errors="ignore") as f:
                return parse_arp_table(f.read())
        except OSError:
            pass  # fall back to the arp command
    
    command = ["arp", "-a"] if sys.platform.startswith("win") else ["arp", "-an"]
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"Could not read ARP cache: {e}")
        return {}
    # Only IP and MAC (ASCII) are parsed; localized headers are ignored
    return parse_arp_table(result.stdout.decode("ascii", errors="ignore"))


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
        
        # Monotonic clock: unaffected by system clock changes (NTP, DST)
        now = time.monotonic() * 1000
        elapsed = now - self._last_call
        
        if self._last_call and elapsed < self.interval_ms:
            await asyncio.sleep((self.interval_ms - elapsed) / 1000.0)
        
        self._last_call = time.monotonic() * 1000


class SessionCache:
    """
    Cache for inaccessible addresses within a session.
    
    Stores the status that made each address inaccessible
    (NG_ILLEGAL_ADDR or NG_UNSUPPORTED) so it can be reported accurately.
    """
    
    def __init__(self):
        self._denied_addresses: Dict[str, Optional[StatusCode]] = {}
    
    def add_denied(self, address: str, status: Optional[StatusCode] = None):
        """Mark an address as inaccessible (status defaults to NG_ILLEGAL_ADDR)"""
        self._denied_addresses[address] = status or StatusCode.NG_ILLEGAL_ADDR
    
    def is_denied(self, address: str) -> bool:
        """Check if an address is known to be inaccessible"""
        return address in self._denied_addresses
    
    def get_status(self, address: str) -> Optional[StatusCode]:
        """Status recorded for a denied address (None if not denied)"""
        return self._denied_addresses.get(address)
    
    def __len__(self) -> int:
        return len(self._denied_addresses)
    
    def get_all_denied(self) -> set:
        """Get all denied addresses"""
        return set(self._denied_addresses)
    
    def get_all_statuses(self) -> Dict[str, StatusCode]:
        """Get denied addresses with their status"""
        return dict(self._denied_addresses)
    
    def clear(self):
        """Clear the cache"""
        self._denied_addresses.clear()
