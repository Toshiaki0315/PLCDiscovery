"""
S7 Protocol Handler - Siemens S7 Communication

Supports:
- Siemens S7-300 series
- Siemens S7-400 series
- Siemens S7-1200 series
- Siemens S7-1500 series
"""

import asyncio
from typing import List, Optional, Tuple
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
    # snap7 sends the start as a bit address in 3 bytes: byte offsets above
    # 0x1FFFFF wrap around (word 1048581 read DB1.DBW10). Word index limit:
    MAX_ADDRESS = 0xFFFFF
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        rack: int = 0,
        slot: int = 0,
        db_number: int = 1,
        **kwargs
    ):
        """
        Addressing used by read_device_raw():
            Addresses are 16-bit word indexes, i.e. byte offset = address * 2.
            DB/D read from data block ``db_number`` (e.g. DB1 address 5 = DB1.DBW10),
            M/X/Y read the merker/input/output areas (M address 5 = MW10).
        """
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.S7], **kwargs)
        self._client = None
        self._rack = rack
        self._slot = slot
        self._db_number = db_number
    
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
                    client.connect(self.ip_address, self._rack, self._slot, self.port)
                    return client, self._slot
                except Exception:
                    # Try alternative slot
                    alt_slot = 2 if self._slot == 0 else 0
                    client.connect(self.ip_address, self._rack, alt_slot, self.port)
                    return client, alt_slot
            
            loop = asyncio.get_running_loop()
            self._client, used_slot = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(
                f"S7 connected to {self.ip_address}:{self.port} "
                f"(rack={self._rack}, slot={used_slot})"
            )
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
                
                loop = asyncio.get_running_loop()
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
            start_address: Starting word index (byte offset = address * 2)
            count: Number of words to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        area = S7_DEVICE_MAP.get(device_type)
        if area is None:
            logger.warning(f"Unsupported device type for S7: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            # Addresses are word indexes: byte offset = address * 2
            byte_offset = start_address * 2
            byte_count = count * 2
            
            def _read():
                if area == S7_AREA_DB:
                    return self._client.db_read(self._db_number, byte_offset, byte_count)
                if area == S7_AREA_MK:
                    return self._client.mb_read(byte_offset, byte_count)
                if area == S7_AREA_PE:
                    return self._client.eb_read(byte_offset, byte_count)
                if area == S7_AREA_PA:
                    return self._client.ab_read(byte_offset, byte_count)
                raise ValueError(f"Unsupported S7 area: {area}")
            
            data_bytes = await self._run_blocking(_read)
            
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
            # Errors reported by the CPU for the requested area/address
            if "area" in error_str or "address" in error_str or "db" in error_str:
                return None, StatusCode.NG_ILLEGAL_ADDR
            # Anything else is a transport problem (connection reset, ISO/TCP
            # error, job timeout): snap7 does not reconnect by itself, so
            # re-establish the connection before the next request
            self._needs_reconnect = True
            logger.debug(f"S7 read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
