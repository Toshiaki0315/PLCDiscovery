"""
EtherNet/IP Protocol Handler - CIP Communication

Supports:
- Omron (NJ/NX series)
- Rockwell/Allen-Bradley (ControlLogix, CompactLogix)
- Keyence (KV-8000 series)
- Yaskawa, CODESYS-based PLCs
"""

import asyncio
from typing import List, Optional, Tuple, Dict
import logging

from .base import BaseProtocolHandler
from ..config import Protocol, DeviceType, StatusCode, PROTOCOL_PORTS

logger = logging.getLogger(__name__)

# Device type mapping for pycomm3
EIP_DEVICE_MAP = {
    DeviceType.D: "N",     # Integer file (AB)
    DeviceType.DM: "DM",   # Data memory (Omron)
    DeviceType.HR: "N",    # Integer file
    DeviceType.M: "B",     # Bit file
}


class EtherNetIPHandler(BaseProtocolHandler):
    """
    EtherNet/IP (CIP) Protocol Handler
    
    Implements communication with EtherNet/IP compatible PLCs.
    """
    
    protocol = Protocol.ETHERNET_IP
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        slot: int = 0,
        **kwargs
    ):
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.ETHERNET_IP], **kwargs)
        self._client = None
        self._slot = slot
        self._plc_type = None  # 'ab' for Allen-Bradley, 'omron' for Omron
    
    async def connect(self) -> bool:
        """Establish EtherNet/IP connection"""
        try:
            from pycomm3 import LogixDriver
            
            def _connect():
                client = LogixDriver(self.ip_address, slot=self._slot)
                client.open()
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = 'ab'
            logger.info(f"EtherNet/IP connected to {self.ip_address}")
            return True
            
        except ImportError:
            logger.error("pycomm3 library not installed")
            return False
        except Exception as e:
            logger.warning(f"LogixDriver connection failed: {e}, trying CIPDriver")
            return await self._connect_generic()
    
    async def _connect_generic(self) -> bool:
        """Connect using generic CIP driver"""
        try:
            from pycomm3 import CIPDriver
            
            def _connect():
                client = CIPDriver(self.ip_address)
                client.open()
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = 'generic'
            logger.info(f"EtherNet/IP (Generic) connected to {self.ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"EtherNet/IP connection failed: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Close EtherNet/IP connection"""
        if self._client:
            try:
                def _disconnect():
                    self._client.close()
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"EtherNet/IP disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"EtherNet/IP disconnected from {self.ip_address}")
    
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read device data using EtherNet/IP protocol.
        
        For Allen-Bradley, uses tag-based reading.
        For generic CIP, uses object-based reading.
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        try:
            if self._plc_type == 'ab':
                return await self._read_ab_style(device_type, start_address, count)
            else:
                return await self._read_generic_style(device_type, start_address, count)
                
        except asyncio.TimeoutError:
            logger.debug(f"EtherNet/IP read timeout")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            error_str = str(e).lower()
            if "path" in error_str or "not found" in error_str:
                return None, StatusCode.NG_ILLEGAL_ADDR
            logger.debug(f"EtherNet/IP read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def _read_ab_style(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read data using Allen-Bradley tag style.
        
        Constructs tag names like "N7:0", "B3:0", etc.
        """
        try:
            # Build tag name based on device type
            file_letter = EIP_DEVICE_MAP.get(device_type, "N")
            file_number = 7  # Default file number
            
            # For integer files, read as array
            tag_name = f"{file_letter}{file_number}:{start_address}"
            
            def _read():
                if count == 1:
                    result = self._client.read(tag_name)
                    if result.value is not None:
                        return [result.value]
                    return None
                else:
                    # Read array
                    result = self._client.read(f"{tag_name}{{count}}")
                    if result.value is not None:
                        return list(result.value)
                    return None
            
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data is not None:
                return data, StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except Exception as e:
            logger.debug(f"AB-style read error: {e}")
            raise
    
    async def _read_generic_style(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read data using generic CIP object access.
        
        Uses Assembly Object or custom object access.
        """
        try:
            def _read():
                # Try to get assembly instance
                # Assembly Object: Class 0x04
                from pycomm3.cip import Services, ClassCode
                
                # Read from assembly instance
                result = self._client.generic_message(
                    service=Services.get_attribute_all,
                    class_code=ClassCode.assembly,
                    instance=start_address,
                    connected=False
                )
                
                if result and result.value:
                    # Convert bytes to word list
                    data = result.value
                    words = []
                    for i in range(0, len(data) - 1, 2):
                        word = data[i] | (data[i + 1] << 8)
                        words.append(word)
                    return words[:count]
                return None
            
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data is not None:
                return data, StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except Exception as e:
            logger.debug(f"Generic CIP read error: {e}")
            raise
    
    async def read_tag(self, tag_name: str) -> Tuple[Optional[any], StatusCode]:
        """
        Read a named tag (Allen-Bradley style).
        
        Args:
            tag_name: Full tag name (e.g., "MyTag", "MyArray[0]")
        
        Returns:
            Tuple of (value or None, status code)
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        if self._plc_type != 'ab':
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            def _read():
                return self._client.read(tag_name)
            
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if result and result.value is not None:
                return result.value, StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except Exception as e:
            logger.debug(f"Tag read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def get_plc_info(self) -> Dict:
        """Get PLC identity information"""
        info = {
            "manufacturer": "Unknown",
            "model": "Unknown",
            "firmware_version": "Unknown",
        }
        
        if not self._connected or not self._client:
            return info
        
        try:
            def _get_info():
                if hasattr(self._client, 'get_plc_info'):
                    return self._client.get_plc_info()
                elif hasattr(self._client, 'info'):
                    return self._client.info
                return None
            
            loop = asyncio.get_event_loop()
            plc_info = await loop.run_in_executor(None, _get_info)
            
            if plc_info:
                info["manufacturer"] = plc_info.get('vendor', 'Unknown')
                info["model"] = plc_info.get('product_name', 'Unknown')
                info["firmware_version"] = plc_info.get('revision', 'Unknown')
                
        except Exception as e:
            logger.debug(f"Failed to get PLC info: {e}")
        
        return info


