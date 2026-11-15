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


# SLMP end codes meaning the requested device/address/size is invalid
# (the PLC answered; the address range itself is the problem)
SLMP_ADDRESS_END_CODES = (
    "c051", "c052", "c053", "c054",  # number of points out of range
    "c055",                          # file/device data error
    "c056",                          # request exceeds the maximum address
    "c05b",                          # CPU cannot access the specified device
    "c05c",                          # request content error (device specification)
)


# Binary response framing: (header size, subheader, offset of the 2-byte data length)
#   3E: D0 00 | net | pc | io(2) | station | length(2)                     -> 9 bytes
#   4E: D4 00 | serial(2) | 00 00 | net | pc | io(2) | station | length(2) -> 13 bytes
_FRAME_LAYOUT = {
    "3E": (9, b"\xD0\x00", 7),
    "4E": (13, b"\xD4\x00", 11),
}


def _framed_client_class(frame: str):
    """
    pymcprotocol client whose _recv() reads exactly one complete response.
    
    pymcprotocol reads a response with a single recv(). A response split over
    several TCP segments (e.g. 900 words = ~1.8 KB on a 1.5 KB MTU LAN) was
    then decoded with the missing bytes as 0 and reported as valid data, and
    the rest of the response was read as the next reply. A closed connection
    (recv() == b"") was decoded as all-zero data as well.
    """
    if frame == "4E":
        from pymcprotocol import Type4E as Base
    else:
        from pymcprotocol import Type3E as Base
    header_size, subheader, length_offset = _FRAME_LAYOUT[frame]
    
    class FramedClient(Base):
        def _recv_exact(self, size: int) -> bytes:
            buf = bytearray()
            while len(buf) < size:
                chunk = self._sock.recv(size - len(buf))
                if not chunk:
                    raise ConnectionError("SLMP connection closed by the PLC")
                buf += chunk
            return bytes(buf)
        
        def _recv(self) -> bytes:
            header = self._recv_exact(header_size)
            if header[:2] != subheader:
                raise ConnectionError(f"unexpected SLMP response header: {header[:2].hex()}")
            length = int.from_bytes(header[length_offset:length_offset + 2], "little")
            return header + self._recv_exact(length)
    
    FramedClient.__name__ = f"Framed{Base.__name__}"
    return FramedClient


# Exceptions raised when the PLC answered with an end code: the connection is fine
_PLC_ANSWER_ERRORS = ("MCProtocolError", "UnsupportedComandError")


class SLMPHandler(BaseProtocolHandler):
    """
    SLMP (Seamless Message Protocol) / MC Protocol Handler
    
    Implements communication with SLMP-compatible PLCs using
    the 3E frame format.
    """
    
    protocol = Protocol.SLMP
    FRAME = "3E"
    
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
            client_class = _framed_client_class(self.FRAME)
            
            def _connect():
                client = client_class()
                # Socket timeout follows the configured request timeout
                # (pymcprotocol's own default is 2 s)
                client.soc_timeout = self.config.request_timeout_ms / 1000
                client.connect(self.ip_address, self.port)
                return client
            
            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(f"SLMP ({self.FRAME}) connected to {self.ip_address}:{self.port}")
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
                
                loop = asyncio.get_running_loop()
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
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
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
            
            data = await self._run_blocking(_read)
            
            if data is not None:
                # pymcprotocol decodes words as signed; report raw 16-bit
                # values (0-65535) like the other protocols
                return [v & 0xFFFF for v in data], StatusCode.OK
            else:
                return None, StatusCode.NG_COMM_ERROR
                
        except (asyncio.TimeoutError, TimeoutError) as e:
            # Includes pymcprotocol's socket timeout (distinct from
            # asyncio.TimeoutError on Python 3.10): the late reply may still
            # arrive, so never reuse this connection
            self._needs_reconnect = True
            logger.debug(f"SLMP read timeout: {device_type.value}{start_address} ({e})")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            if type(e).__name__ not in _PLC_ANSWER_ERRORS:
                # Transport-level failure (closed/reset connection, framing
                # error): re-establish the connection before the next request
                self._needs_reconnect = True
            return None, self._classify_error(e, device_type, start_address)
    
    @staticmethod
    def _classify_error(e: Exception, device_type: DeviceType, start_address: int) -> StatusCode:
        """Map a pymcprotocol exception to a status code"""
        if type(e).__name__ == "UnsupportedComandError":
            logger.debug(f"SLMP command not supported: {device_type.value}")
            return StatusCode.NG_UNSUPPORTED
        
        error_str = str(e).lower()
        end_code = getattr(e, "errorcode", None)
        code_str = str(end_code).lower() if end_code is not None else error_str
        
        if any(c in code_str for c in SLMP_ADDRESS_END_CODES) or \
                "illegal" in error_str or "0x4001" in error_str:
            logger.debug(f"SLMP illegal address: {device_type.value}{start_address} ({e})")
            return StatusCode.NG_ILLEGAL_ADDR
        
        logger.debug(f"SLMP read error: {e}")
        return StatusCode.NG_COMM_ERROR
    
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
    
    FRAME = "4E"
    
    def __init__(self, ip_address: str, port: Optional[int] = None, **kwargs):
        super().__init__(ip_address, port or 5000, **kwargs)
