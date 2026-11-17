"""
Names used on the command line and in configuration files, and the enum
values they stand for. The CLI, the configuration loader and the GUI all
parse through these functions, so an alias accepted in one place is
accepted everywhere.
"""

from typing import Dict, Optional

from .config import DeviceType, Protocol
from .data_types import ByteOrder

# Protocol names and aliases (case-insensitive)
PROTOCOL_NAMES: Dict[str, Protocol] = {
    "slmp": Protocol.SLMP,
    "mc": Protocol.SLMP,
    "eip": Protocol.ETHERNET_IP,
    "ethernet_ip": Protocol.ETHERNET_IP,
    "cip": Protocol.ETHERNET_IP,
    "modbus": Protocol.MODBUS_TCP,
    "modbus_tcp": Protocol.MODBUS_TCP,
    "s7": Protocol.S7,
    "s7comm": Protocol.S7,
    "fins": Protocol.FINS,
    "fins_udp": Protocol.FINS,
    "fins_tcp": Protocol.FINS_TCP,
    "fins-tcp": Protocol.FINS_TCP,
}

# Byte order names (the ByteOrder values): little, big, little_swap, big_swap
BYTE_ORDER_NAMES: Dict[str, ByteOrder] = {order.value: order for order in ByteOrder}


def parse_protocol(name: Optional[str]) -> Optional[Protocol]:
    """Protocol for a name or alias such as "slmp", "eip", "fins-tcp" (None if unknown)"""
    if not name:
        return None
    return PROTOCOL_NAMES.get(str(name).strip().lower())


def parse_device_type(name: Optional[str]) -> Optional[DeviceType]:
    """Device type for a name such as "D", "dm", "HR" (None if unknown)"""
    if not name:
        return None
    try:
        return DeviceType(str(name).strip().upper())
    except ValueError:
        return None


def parse_byte_order(name: Optional[str]) -> Optional[ByteOrder]:
    """Byte order for "little", "big", "little_swap" or "big_swap" (None if unknown)"""
    if not name:
        return None
    return BYTE_ORDER_NAMES.get(str(name).strip().lower())
