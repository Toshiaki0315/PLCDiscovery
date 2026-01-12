"""
S7 Protocol Handler - Siemens S7 Communication

Supports:
- Siemens S7-300 series
- Siemens S7-400 series
- Siemens S7-1200 series
- Siemens S7-1500 series
"""

import asyncio
from typing import List, Optional, Tuple, Dict
import logging

from .base import BaseProtocolHandler
from ..config import Protocol, DeviceType, StatusCode, PROTOCOL_PORTS

logger = logging.getLogger(__name__)

# S7 Area codes
S7_AREA_PE = 0x81    # Process inputs
S7_AREA_PA = 0x82    # Process outputs
S7_AREA_MK = 0x83    # Merkers (flags)
S7_AREA_DB = 0x84    # Data blocks
S7_AREA_CT = 0x1C    # Counters
S7_AREA_TM = 0x1D    # Timers

# Device type to S7 area mapping
S7_DEVICE_MAP = {
    DeviceType.X: S7_AREA_PE,   # Inputs
    DeviceType.Y: S7_AREA_PA,   # Outputs
    DeviceType.M: S7_AREA_MK,   # Merkers
    DeviceType.DB: S7_AREA_DB,  # Data blocks
    DeviceType.D: S7_AREA_DB,   # Data (map to DB)
}


class S7Handler(BaseProtocolHandler):
    """
    Siemens S7 Protocol Handler
    
    Implements communication with Siemens S7 PLCs using snap7.
    """
    
    protocol = Protocol.S7
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        rack: int = 0,
        slot: int = 0,
        **kwargs
    ):
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.S7], **kwargs)
        self._client = None
        self._rack = rack
        self._slot = slot
    
    async def connect(self) -> bool:
        """Establish S7 connection"""
        try:
            import snap7
            
            def _connect():
                client = snap7.client.Client()
                # Try different slot configurations for different S7 series
                # S7-300/400: rack=0, slot=2
                # S7-1200/1500: rack=0, slot=0 or slot=1
                try:
                    client.connect(self.ip_address, self._rack, self._slot)
                    return client
                except Exception:
                    # Try alternative slot
                    alt_slot = 2 if self._slot == 0 else 0
                    client.connect(self.ip_address, self._rack, alt_slot)
                    return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(f"S7 connected to {self.ip_address} (rack={self._rack}, slot={self._slot})")
            return True
            
        except ImportError:
            logger.error("snap7 library not installed")
            return False
        except Exception as e:
            logger.error(f"S7 connection failed: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Close S7 connection"""
        if self._client:
            try:
                def _disconnect():
                    self._client.disconnect()
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"S7 disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"S7 disconnected from {self.ip_address}")
    
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read device data using S7 protocol.
        
        Args:
            device_type: Device type (DB, M, X, Y)
            start_address: Starting address (byte offset for DB)
            count: Number of words to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        area = S7_DEVICE_MAP.get(device_type)
        if area is None:
            logger.warning(f"Unsupported device type for S7: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            # Calculate byte length (count is in words, each word is 2 bytes)
            byte_count = count * 2
            
            def _read():
                if area == S7_AREA_DB:
                    # For data blocks, need DB number
                    # Use start_address as DB number, read from byte 0
                    db_number = start_address if start_address > 0 else 1
                    return self._client.db_read(db_number, 0, byte_count)
                else:
                    # For other areas (M, I, Q)
                    return self._client.read_area(area, 0, start_address, byte_count)
            
            loop = asyncio.get_event_loop()
            data_bytes = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data_bytes:
                # Convert bytes to word list (big-endian for S7)
                words = []
                for i in range(0, len(data_bytes) - 1, 2):
                    word = (data_bytes[i] << 8) | data_bytes[i + 1]
                    words.append(word)
                return words, StatusCode.OK
            
            return None, StatusCode.NG_COMM_ERROR
                
        except asyncio.TimeoutError:
            logger.debug(f"S7 read timeout: {device_type.value}{start_address}")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            error_str = str(e).lower()
            # Check for typical S7 errors
            if "area" in error_str or "address" in error_str or "db" in error_str:
                return None, StatusCode.NG_ILLEGAL_ADDR
            logger.debug(f"S7 read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def read_db(
        self,
        db_number: int,
        start_byte: int,
        size: int
    ) -> Tuple[Optional[bytes], StatusCode]:
        """
        Read from a specific data block.
        
        Args:
            db_number: Data block number
            start_byte: Starting byte offset
            size: Number of bytes to read
        
        Returns:
            Tuple of (raw bytes or None, status code)
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        try:
            def _read():
                return self._client.db_read(db_number, start_byte, size)
            
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data:
                return bytes(data), StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except asyncio.TimeoutError:
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            logger.debug(f"DB read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def read_merkers(
        self,
        start_byte: int,
        size: int
    ) -> Tuple[Optional[bytes], StatusCode]:
        """
        Read merker (flag) memory.
        
        Args:
            start_byte: Starting byte offset
            size: Number of bytes to read
        
        Returns:
            Tuple of (raw bytes or None, status code)
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        try:
            def _read():
                return self._client.mb_read(start_byte, size)
            
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data:
                return bytes(data), StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR
            
        except asyncio.TimeoutError:
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            logger.debug(f"Merker read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def get_cpu_info(self) -> Dict:
        """
        Get CPU information from S7 PLC.
        
        Returns:
            Dictionary with CPU information
        """
        info = {
            "manufacturer": "シーメンス",
            "model": "Unknown",
            "cpu_type": "Unknown",
            "serial_number": "Unknown",
            "order_code": "Unknown",
        }
        
        if not self._connected or not self._client:
            return info
        
        try:
            def _get_info():
                return self._client.get_cpu_info()
            
            loop = asyncio.get_event_loop()
            cpu_info = await loop.run_in_executor(None, _get_info)
            
            if cpu_info:
                info["model"] = cpu_info.ModuleTypeName.decode('utf-8', errors='ignore').strip()
                info["cpu_type"] = cpu_info.ASName.decode('utf-8', errors='ignore').strip()
                info["serial_number"] = cpu_info.SerialNumber.decode('utf-8', errors='ignore').strip()
                info["order_code"] = cpu_info.OrderCode.decode('utf-8', errors='ignore').strip()
                
        except Exception as e:
            logger.debug(f"Failed to get CPU info: {e}")
        
        return info
    
    async def get_cpu_state(self) -> str:
        """
        Get CPU run state.
        
        Returns:
            CPU state string ("RUN", "STOP", "UNKNOWN")
        """
        if not self._connected or not self._client:
            return "UNKNOWN"
        
        try:
            def _get_state():
                return self._client.get_cpu_state()
            
            loop = asyncio.get_event_loop()
            state = await loop.run_in_executor(None, _get_state)
            
            state_map = {
                0x00: "UNKNOWN",
                0x04: "STOP",
                0x08: "RUN",
            }
            return state_map.get(state, "UNKNOWN")
            
        except Exception as e:
            logger.debug(f"Failed to get CPU state: {e}")
            return "UNKNOWN"


