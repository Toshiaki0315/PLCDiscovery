"""
PLC Protocol Handlers

This module provides protocol-specific implementations for communicating
with various PLC manufacturers and protocols.

Supported Protocols:
- SLMP (Mitsubishi MC Protocol): Mitsubishi, Keyence, Panasonic
- Modbus/TCP: Schneider, ABB, many generic PLCs
- EtherNet/IP: Rockwell/Allen-Bradley, Omron
- S7: Siemens S7 series
- FINS: Omron FINS protocol
"""

from .base import BaseProtocolHandler
from .ethernet_ip import EtherNetIPHandler
from .fins import FINSHandler
from .modbus import ModbusHandler, ModbusRTUOverTCPHandler
from .s7 import S7Handler
from .slmp import SLMPBinaryHandler, SLMPHandler

__all__ = [
    "BaseProtocolHandler",
    "SLMPHandler",
    "SLMPBinaryHandler",
    "ModbusHandler",
    "ModbusRTUOverTCPHandler",
    "EtherNetIPHandler",
    "S7Handler",
    "FINSHandler",
]
