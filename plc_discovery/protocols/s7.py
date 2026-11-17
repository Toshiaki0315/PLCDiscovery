"""
S7 Protocol Handler - Siemens S7 Communication

Supports:
- Siemens S7-300 series
- Siemens S7-400 series
- Siemens S7-1200 series
- Siemens S7-1500 series
"""

import asyncio
import re
import struct
from typing import Dict, List, Optional, Tuple
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

# S7 data item return codes sent by the CPU (the PLC answered)
_S7_ITEM_CODES = {
    0x03: StatusCode.NG_ILLEGAL_ADDR,   # accessing the object not allowed
    0x05: StatusCode.NG_ILLEGAL_ADDR,   # invalid address / address out of range
    0x0A: StatusCode.NG_ILLEGAL_ADDR,   # object does not exist (e.g. past the DB end)
    0x06: StatusCode.NG_UNSUPPORTED,    # data type not supported
    0x07: StatusCode.NG_UNSUPPORTED,    # data type inconsistent
}

# The same answers as worded by snap7 1.x (C library)
_S7_ITEM_TEXTS = (
    ("item not available", StatusCode.NG_ILLEGAL_ADDR),
    ("object does not exist", StatusCode.NG_ILLEGAL_ADDR),
    ("address out of range", StatusCode.NG_ILLEGAL_ADDR),
    ("invalid address", StatusCode.NG_ILLEGAL_ADDR),
    ("access denied", StatusCode.NG_ILLEGAL_ADDR),
    ("not allowed", StatusCode.NG_ILLEGAL_ADDR),
    ("invalid transport size", StatusCode.NG_UNSUPPORTED),
    ("data type", StatusCode.NG_UNSUPPORTED),
)

_S7_RETURN_CODE = re.compile(r"\(0x([0-9a-f]{2})\)")

# SZL 0x001C (component identification): records of a 2-byte index and 32
# bytes of text. Index 1 = automation system name, 2 = module name,
# 5 = serial number, 7 = module type name (e.g. "CPU 1515-2 PN").
SZL_COMPONENT_ID = 0x001C
SZL_COMPONENT_RECORD_LENGTH = 34
SZL_COMPONENT_INDEXES = range(0x0001, 0x000C)


def parse_szl_component_ids(data: bytes) -> Dict[int, str]:
    """
    Records of an SZL 0x001C reply as {index: text}.

    Accepts the records alone (snap7 1.x strips the SZL header) or preceded
    by the LENTHDR / N_DR words (python-snap7 3.x keeps them). Returns {} if
    the data is not in the record format.
    """
    record_length = SZL_COMPONENT_RECORD_LENGTH
    if len(data) >= 4:
        length_dr, count = struct.unpack(">HH", data[:4])
        if length_dr >= 4 and 4 + length_dr * count <= len(data) and len(data) % length_dr != 0:
            data, record_length = data[4:4 + length_dr * count], length_dr
    records: Dict[int, str] = {}
    for start in range(0, len(data) - record_length + 1, record_length):
        index = struct.unpack(">H", data[start:start + 2])[0]
        if index not in SZL_COMPONENT_INDEXES:
            return {}
        text = data[start + 2:start + record_length].split(b"\x00")[0]
        records[index] = text.decode("ascii", errors="ignore").strip()
    return records


def read_s7_identity(client) -> Dict[str, str]:
    """
    Model ("CPU 1515-2 PN") and automation system name of a connected snap7
    client, from SZL 0x001C. Falls back to client.get_cpu_info() when the
    reply is not in the record format (python-snap7 3.x's own server).
    """
    fields: Dict[str, str] = {}
    try:
        szl = client.read_szl(SZL_COMPONENT_ID, 0)
        size = int(szl.Header.LengthDR) * max(1, int(szl.Header.NDR))
        records = parse_szl_component_ids(bytes(szl.Data[:size]))
    except Exception as e:
        logger.debug(f"S7 SZL 0x001C read failed: {e}")
        records = {}
    if records:
        fields["model"] = records.get(0x0007) or records.get(0x0002, "")
        fields["cpu_type"] = records.get(0x0001, "")
        return fields
    info = client.get_cpu_info()
    fields["model"] = info.ModuleTypeName.decode("utf-8", errors="ignore").strip()
    fields["cpu_type"] = info.ASName.decode("utf-8", errors="ignore").strip()
    return fields


def classify_s7_error(error: Exception) -> Optional[StatusCode]:
    """
    Status for an error the CPU reported about the requested item, or None
    for a transport failure.
    
    snap7 3.x raises "Read operation failed: Object does not exist (0x0a)";
    snap7 1.x "CPU : Item not available". Neither mentions "address" or
    "area", so such answers (e.g. a read past the end of a DB) used to be
    taken for communication failures: retries, reconnects and then the
    rest of the range reported as NG_COMM_ERROR.
    """
    text = str(error).lower()
    match = _S7_RETURN_CODE.search(text)
    if match and "read operation failed" in text:
        # Other codes (e.g. 0x01 hardware error) are not about the address:
        # a communication error, but the connection itself is fine
        return _S7_ITEM_CODES.get(int(match.group(1), 16), StatusCode.NG_COMM_ERROR)
    for fragment, status in _S7_ITEM_TEXTS:
        if fragment in text:
            return status
    # Older wording kept from the previous classification
    if "area" in text or "address" in text:
        return StatusCode.NG_ILLEGAL_ADDR
    return None


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
            status = classify_s7_error(e)
            if status is not None:
                # The CPU answered with an item return code: the connection
                # is fine, so it is not re-established
                logger.debug(f"S7 {status.value}: {device_type.value}{start_address} ({e})")
                return None, status
            # Anything else is a transport problem (connection reset, ISO/TCP
            # error, job timeout): snap7 does not reconnect by itself, so
            # re-establish the connection before the next request
            self._needs_reconnect = True
            logger.debug(f"S7 read error: {e}")
            return None, StatusCode.NG_COMM_ERROR
