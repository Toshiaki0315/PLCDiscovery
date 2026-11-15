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

# Device type mapping to PLC-5/SLC/MicroLogix data files (file letter, file number).
# Data-file addressing ("N7:0") is only understood by SLC-style controllers;
# Logix and generic CIP devices use symbolic tags (see read_tag()).
EIP_DEVICE_MAP = {
    DeviceType.D: ("N", 7),    # Integer file N7
    DeviceType.HR: ("N", 7),   # Integer file N7
    DeviceType.M: ("B", 3),    # Bit file B3 (read as 16-bit words)
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
        self._plc_type = None  # 'logix', 'slc' or 'generic'

    def _connection_path(self, include_slot: bool) -> str:
        """
        Build the pycomm3 connection path ("ip:port" or "ip:port/slot").

        pycomm3 reads the port and slot only from the path string; keyword
        arguments such as ``slot=`` are silently ignored.
        """
        path = f"{self.ip_address}:{self.port}"
        if include_slot and self._slot:
            path += f"/{self._slot}"
        return path
    
    async def connect(self) -> bool:
        """Establish EtherNet/IP connection"""
        try:
            from pycomm3 import LogixDriver
            
            def _connect():
                client = LogixDriver(self._connection_path(include_slot=True))
                client.open()
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = 'logix'
            logger.info(f"EtherNet/IP (Logix) connected to {self.ip_address}:{self.port}")
            return True
            
        except ImportError:
            logger.error("pycomm3 library not installed")
            return False
        except Exception as e:
            logger.warning(f"LogixDriver connection failed: {e}, trying SLCDriver")
            if await self._connect_slc():
                return True
            return await self._connect_generic()
    
    async def _connect_slc(self) -> bool:
        """Connect using the PLC-5/SLC/MicroLogix driver (data-file addressing)"""
        try:
            from pycomm3 import SLCDriver
            
            def _connect():
                client = SLCDriver(self._connection_path(include_slot=True))
                client.open()
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = 'slc'
            logger.info(f"EtherNet/IP (SLC) connected to {self.ip_address}:{self.port}")
            return True
        except Exception as e:
            logger.warning(f"SLCDriver connection failed: {e}, trying CIPDriver")
            self._client = None
            return False
    
    async def _connect_generic(self) -> bool:
        """Connect using generic CIP driver"""
        try:
            from pycomm3 import CIPDriver
            
            def _connect():
                client = CIPDriver(self._connection_path(include_slot=False))
                client.open()
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = 'generic'
            logger.info(f"EtherNet/IP (Generic) connected to {self.ip_address}:{self.port}")
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
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        try:
            if self._plc_type == 'slc':
                return await self._read_ab_style(device_type, start_address, count)
            # Logix / generic CIP devices have no numeric device addresses.
            # Returning data from another object under these addresses would
            # be misleading, so report the device type as unsupported.
            logger.warning(
                f"Address-based read of {device_type.value} is not supported on "
                f"{self._plc_type} EtherNet/IP devices; use read_tag() instead"
            )
            return None, StatusCode.NG_UNSUPPORTED
                
        except asyncio.TimeoutError:
            logger.debug(f"EtherNet/IP read timeout")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            error_str = str(e).lower()
            if isinstance(e, LookupError) or "path" in error_str or "not found" in error_str:
                logger.debug(f"EtherNet/IP address error: {e}")
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
        mapping = EIP_DEVICE_MAP.get(device_type)
        if mapping is None:
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            file_letter, file_number = mapping
            tag_name = f"{file_letter}{file_number}:{start_address}"
            
            def _read():
                if count == 1:
                    result = self._client.read(tag_name)
                    if result.error:
                        raise LookupError(f"{tag_name}: {result.error}")
                    return [result.value]
                # Array read: "N7:0{10}" reads 10 elements
                result = self._client.read(f"{tag_name}{{{count}}}")
                if result.error:
                    raise LookupError(f"{tag_name}{{{count}}}: {result.error}")
                return list(result.value)
            
            data = await self._run_blocking(_read)
            
            if data is not None:
                return data, StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except Exception as e:
            logger.debug(f"AB-style read error: {e}")
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
        
        if self._plc_type not in ('logix', 'slc'):
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


