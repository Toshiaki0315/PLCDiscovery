"""
Modbus/TCP Protocol Handler

Supports:
- Modbus/TCP compatible PLCs (Schneider, ABB, Siemens, etc.)
- Function codes: 01 (Read Coils), 02 (Read Discrete Inputs),
                  03 (Read Holding Registers), 04 (Read Input Registers)
"""

import asyncio
from typing import List, Optional, Tuple
import logging

from .base import BaseProtocolHandler
from ..config import Protocol, DeviceType, StatusCode, PROTOCOL_PORTS

logger = logging.getLogger(__name__)

# Device type mapping to Modbus function type
MODBUS_DEVICE_MAP = {
    DeviceType.D: "holding",     # Holding Registers (like D registers)
    DeviceType.HR: "holding",    # Holding Registers
    DeviceType.IR: "input",      # Input Registers
    DeviceType.M: "coil",        # Coils (like M relays)
    DeviceType.W: "holding",     # Holding Registers
    DeviceType.R: "input",       # Input Registers
    DeviceType.X: "discrete",    # Discrete Inputs
    DeviceType.Y: "coil",        # Coils
}

# Modbus TCP constants
MODBUS_PORT = 502
MODBUS_MAX_READ_REGISTERS = 125  # Maximum registers per request
MODBUS_MAX_READ_COILS = 2000     # Maximum coils per request


class ModbusHandler(BaseProtocolHandler):
    """
    Modbus/TCP Protocol Handler
    
    Implements communication with Modbus/TCP compatible PLCs
    using the pymodbus library.
    """
    
    protocol = Protocol.MODBUS_TCP
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        unit_id: int = 1,
        **kwargs
    ):
        super().__init__(ip_address, port or PROTOCOL_PORTS.get(Protocol.MODBUS_TCP, MODBUS_PORT), **kwargs)
        self._client = None
        self._unit_id = unit_id
    
    @property
    def max_read_size(self) -> int:
        """Maximum registers that can be read in a single request"""
        return MODBUS_MAX_READ_REGISTERS
    
    async def connect(self) -> bool:
        """Establish Modbus/TCP connection"""
        try:
            from pymodbus.client import ModbusTcpClient
            
            def _connect():
                client = ModbusTcpClient(
                    host=self.ip_address,
                    port=self.port,
                    timeout=self.config.request_timeout_ms / 1000
                )
                if client.connect():
                    return client
                return None
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            
            if self._client:
                self._connected = True
                logger.info(f"Modbus connected to {self.ip_address}:{self.port}")
                return True
            else:
                logger.error(f"Modbus connection failed: {self.ip_address}:{self.port}")
                return False
            
        except ImportError:
            logger.error("pymodbus library not installed")
            return False
        except Exception as e:
            logger.error(f"Modbus connection failed: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Close Modbus/TCP connection"""
        if self._client:
            try:
                def _disconnect():
                    self._client.close()
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"Modbus disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"Modbus disconnected from {self.ip_address}")
    
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read device data using Modbus/TCP protocol.
        
        Args:
            device_type: Device type (D, HR, IR, M, etc.)
            start_address: Starting address
            count: Number of points to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        # Get Modbus device type
        modbus_type = MODBUS_DEVICE_MAP.get(device_type)
        if not modbus_type:
            logger.warning(f"Unsupported device type for Modbus: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            def _read():
                if modbus_type == "holding":
                    return self._client.read_holding_registers(
                        address=start_address,
                        count=count,
                        device_id=self._unit_id
                    )
                elif modbus_type == "input":
                    return self._client.read_input_registers(
                        address=start_address,
                        count=count,
                        device_id=self._unit_id
                    )
                elif modbus_type == "coil":
                    return self._client.read_coils(
                        address=start_address,
                        count=count,
                        device_id=self._unit_id
                    )
                elif modbus_type == "discrete":
                    return self._client.read_discrete_inputs(
                        address=start_address,
                        count=count,
                        device_id=self._unit_id
                    )
                return None
            
            result = await self._run_blocking(_read)
            
            if result is None:
                return None, StatusCode.NG_COMM_ERROR
            
            # Check for errors
            if result.isError():
                # Get exception code if available
                exception_code = getattr(result, 'exception_code', 0)
                if exception_code == 2:  # Illegal data address
                    logger.debug(f"Modbus illegal address: {device_type.value}{start_address}")
                    return None, StatusCode.NG_ILLEGAL_ADDR
                elif exception_code == 1:  # Illegal function
                    logger.debug(f"Modbus illegal function: {device_type.value}")
                    return None, StatusCode.NG_UNSUPPORTED
                else:
                    logger.debug(f"Modbus error: exception_code={exception_code}")
                    return None, StatusCode.NG_COMM_ERROR
            
            # Extract data
            if modbus_type in ["holding", "input"]:
                data = list(result.registers)
            elif modbus_type in ["coil", "discrete"]:
                # pymodbus pads the bit list to a multiple of 8; keep only
                # the requested points so addresses are not duplicated
                data = [1 if bit else 0 for bit in result.bits[:count]]
            else:
                data = []
            
            return data, StatusCode.OK
            
        except asyncio.TimeoutError:
            logger.debug(f"Modbus read timeout: {device_type.value}{start_address}")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            logger.debug(f"Modbus read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def read_device_identification(self) -> dict:
        """
        Read Modbus device identification.
        
        Returns:
            Dictionary with device identification info
        """
        info = {
            "manufacturer": "Unknown",
            "product_code": "Unknown",
            "revision": "Unknown",
        }
        
        if not self._connected or not self._client:
            return info
        
        try:
            def _read_id():
                # Try to read device identification (Function code 0x2B)
                return self._client.read_device_information(
                    slave=self._unit_id
                )
            
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _read_id),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if result and not result.isError():
                if hasattr(result, 'information'):
                    info_data = result.information
                    info["manufacturer"] = info_data.get(0x00, b"").decode('ascii', errors='ignore')
                    info["product_code"] = info_data.get(0x01, b"").decode('ascii', errors='ignore')
                    info["revision"] = info_data.get(0x02, b"").decode('ascii', errors='ignore')
            
        except Exception as e:
            logger.debug(f"Failed to read device identification: {e}")
        
        return info


class ModbusRTUOverTCPHandler(ModbusHandler):
    """
    Modbus RTU over TCP Handler
    
    For devices that use Modbus RTU framing over TCP
    (common in serial-to-Ethernet converters).
    """
    
    def __init__(self, ip_address: str, port: Optional[int] = None, **kwargs):
        super().__init__(ip_address, port or 502, **kwargs)
    
    # Note: RTU over TCP uses the same client as standard Modbus TCP
    # The framing is handled by some serial gateways transparently
