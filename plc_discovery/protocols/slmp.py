"""
SLMP Protocol Handler - Mitsubishi MC Protocol (3E Frame)

Supports:
- Mitsubishi Electric (MELSEC iQ-R, iQ-F, Q series)
- Keyence (KV series)
- Panasonic, Toshiba, Hitachi, Sharp (SLMP compatible)
"""

import asyncio
from typing import List, Optional, Tuple
import logging

from .base import BaseProtocolHandler
from ..config import Protocol, DeviceType, StatusCode, PROTOCOL_PORTS

logger = logging.getLogger(__name__)

# Device type mapping for pymcprotocol
SLMP_DEVICE_MAP = {
    DeviceType.D: "D",    # Data register
    DeviceType.M: "M",    # Internal relay
    DeviceType.W: "W",    # Link register
    DeviceType.R: "R",    # File register
    DeviceType.X: "X",    # Input
    DeviceType.Y: "Y",    # Output
    DeviceType.B: "B",    # Link relay
    DeviceType.SM: "SM",  # Special relay
}


class SLMPHandler(BaseProtocolHandler):
    """
    SLMP (Seamless Message Protocol) / MC Protocol Handler
    
    Implements communication with SLMP-compatible PLCs using
    the 3E frame format.
    """
    
    protocol = Protocol.SLMP
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        **kwargs
    ):
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.SLMP], **kwargs)
        self._client = None
    
    async def connect(self) -> bool:
        """Establish SLMP connection"""
        try:
            from pymcprotocol import Type3E
            
            def _connect():
                client = Type3E()
                client.connect(self.ip_address, self.port)
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(f"SLMP connected to {self.ip_address}:{self.port}")
            return True
            
        except ImportError:
            logger.error("pymcprotocol library not installed")
            return False
        except Exception as e:
            logger.error(f"SLMP connection failed: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Close SLMP connection"""
        if self._client:
            try:
                def _disconnect():
                    self._client.close()
                
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"SLMP disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"SLMP disconnected from {self.ip_address}")
    
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read device data using SLMP protocol.
        
        Args:
            device_type: Device type (D, M, W, etc.)
            start_address: Starting address
            count: Number of points to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        if not self._connected or not self._client:
            return None, StatusCode.NG_COMM_ERROR
        
        # Get SLMP device name
        slmp_device = SLMP_DEVICE_MAP.get(device_type)
        if not slmp_device:
            logger.warning(f"Unsupported device type for SLMP: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED
        
        try:
            def _read():
                # Use batch read for word devices
                if device_type in [DeviceType.D, DeviceType.W, DeviceType.R]:
                    return self._client.batchread_wordunits(
                        headdevice=f"{slmp_device}{start_address}",
                        readsize=count
                    )
                # Use bit read for bit devices
                elif device_type in [DeviceType.M, DeviceType.X, DeviceType.Y, DeviceType.B, DeviceType.SM]:
                    return self._client.batchread_bitunits(
                        headdevice=f"{slmp_device}{start_address}",
                        readsize=count
                    )
                else:
                    return self._client.batchread_wordunits(
                        headdevice=f"{slmp_device}{start_address}",
                        readsize=count
                    )
            
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _read),
                timeout=self.config.request_timeout_ms / 1000
            )
            
            if data is not None:
                return list(data), StatusCode.OK
            else:
                return None, StatusCode.NG_COMM_ERROR
                
        except asyncio.TimeoutError:
            logger.debug(f"SLMP read timeout: {device_type.value}{start_address}")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            error_str = str(e).lower()
            # Check for illegal address error
            if "illegal" in error_str or "0x4001" in error_str or "c055" in error_str:
                logger.debug(f"SLMP illegal address: {device_type.value}{start_address}")
                return None, StatusCode.NG_ILLEGAL_ADDR
            logger.debug(f"SLMP read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
    
    async def read_cpu_info(self) -> dict:
        """
        Read CPU information from SLMP device.
        
        Returns:
            Dictionary with CPU information
        """
        info = {
            "manufacturer": "三菱電機/SLMP互換",
            "model": "Unknown",
            "cpu_type": "Unknown",
        }
        
        # SLMP doesn't have a standardized CPU info command,
        # but we can try reading special registers for some models
        
        return info


class SLMPBinaryHandler(SLMPHandler):
    """
    SLMP Binary protocol handler (4E Frame).
    
    For high-speed communication with newer PLCs.
    """
    
    def __init__(self, ip_address: str, port: Optional[int] = None, **kwargs):
        super().__init__(ip_address, port or 5000, **kwargs)
    
    async def connect(self) -> bool:
        """Establish SLMP Binary connection"""
        try:
            from pymcprotocol import Type4E
            
            def _connect():
                client = Type4E()
                client.connect(self.ip_address, self.port)
                return client
            
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(f"SLMP Binary connected to {self.ip_address}:{self.port}")
            return True
            
        except ImportError:
            # Fall back to 3E frame
            logger.info("Type4E not available, falling back to Type3E")
            return await super().connect()
        except Exception as e:
            logger.error(f"SLMP Binary connection failed: {e}")
            return False


