"""
SLMP Protocol Handler - Mitsubishi MC Protocol (3E / 4E Frame)

Supports:
- Mitsubishi Electric (MELSEC iQ-R, iQ-F, Q series)
- Keyence (KV series)
- Panasonic, Toshiba, Hitachi, Sharp (SLMP compatible)
- 3E or 4E frame, binary or ASCII code (targets[].options.frame / ascii;
  discovery finds the setting the PLC's port answers)
- TCP or UDP (protocol slmp-udp, Protocol.SLMP_UDP): a port opened for UDP
"""

import asyncio
import logging
import socket
from typing import Any, List, Optional, Tuple

from ..config import PROTOCOL_PORTS, DeviceType, Protocol, StatusCode
from .base import BaseProtocolHandler

logger = logging.getLogger(__name__)

# Device type mapping for pymcprotocol
SLMP_DEVICE_MAP = {
    DeviceType.D: "D",  # Data register
    DeviceType.M: "M",  # Internal relay
    DeviceType.W: "W",  # Link register
    DeviceType.R: "R",  # File register
    DeviceType.X: "X",  # Input
    DeviceType.Y: "Y",  # Output
    DeviceType.B: "B",  # Link relay
    DeviceType.SM: "SM",  # Special relay
    DeviceType.L: "L",  # Latch relay
    DeviceType.ZR: "ZR",  # File register (serial numbers)
    DeviceType.SD: "SD",  # Special register
    DeviceType.TN: "TN",  # Timer current value
    DeviceType.CN: "CN",  # Counter current value
}

# Bit devices (read with batch read in bit units)
SLMP_BIT_DEVICES = frozenset({DeviceType.M, DeviceType.X, DeviceType.Y, DeviceType.B, DeviceType.SM, DeviceType.L})

# Devices whose numbers are hexadecimal on MELSEC (pymcprotocol parses the
# number after the device name in base 16 for these)
SLMP_HEX_DEVICES = (DeviceType.X, DeviceType.Y, DeviceType.B, DeviceType.W)
SLMP_HEX_NAMES = frozenset(d.value for d in SLMP_HEX_DEVICES)


def slmp_head_device(device_type: DeviceType, address: int) -> str:
    """
    pymcprotocol head device string for an address.

    Addresses are integers throughout the tool. X/Y/B/W numbers are parsed
    as hexadecimal by pymcprotocol, so "W100" would read W256; format them in
    hex with a leading 0 (pymcprotocol reads "WA0" as device "WA").
    """
    name = SLMP_DEVICE_MAP[device_type]
    if device_type in SLMP_HEX_DEVICES:
        return f"{name}0{address:X}"
    return f"{name}{address}"


# SLMP end codes meaning the requested device/address/size is invalid
# (the PLC answered; the address range itself is the problem)
SLMP_ADDRESS_END_CODES = (
    "c051",
    "c052",
    "c053",
    "c054",  # number of points out of range
    "c055",  # file/device data error
    "c056",  # request exceeds the maximum address
    "c05b",  # CPU cannot access the specified device
    "c05c",  # request content error (device specification)
    # Detected by the CPU itself (Q/L/iQ-R built-in Ethernet answers these
    # instead of C056 for a device outside the configured range)
    "4030",  # the specified device name cannot be handled
    "4031",  # the specified device number is outside the range
)


# Response framing: (header size, subheader, offset of the data length,
# size of the data length field)
#   3E binary: D0 00 | net | pc | io(2) | station | length(2)                     -> 9 bytes
#   4E binary: D4 00 | serial(2) | 00 00 | net | pc | io(2) | station | length(2) -> 13 bytes
#   ASCII: the same fields as hexadecimal text ("D000" ... length as 4 characters)
_FRAME_LAYOUT = {
    ("3E", False): (9, b"\xd0\x00", 7, 2),
    ("4E", False): (13, b"\xd4\x00", 11, 2),
    ("3E", True): (18, b"D000", 14, 4),
    ("4E", True): (26, b"D400", 22, 4),
}


# Largest datagram read over UDP (an answer of 960 words in ASCII is ~3.9 KB)
SLMP_UDP_MAX_DATAGRAM = 65535


def _framed_client_class(frame: str, ascii_code: bool = False, udp: bool = False) -> Any:
    """
    pymcprotocol client whose _recv() reads exactly one complete response.

    pymcprotocol reads a response with a single recv(). A response split over
    several TCP segments (e.g. 900 words = ~1.8 KB on a 1.5 KB MTU LAN) was
    then decoded with the missing bytes as 0 and reported as valid data, and
    the rest of the response was read as the next reply. A closed connection
    (recv() == b"") was decoded as all-zero data as well.

    In ASCII code the device number of X/Y/B/W is written in hexadecimal
    (as GX Works shows it); pymcprotocol writes it in decimal, so X1F would
    read X31. The number is formatted here instead.

    Over UDP (pymcprotocol speaks TCP only) one datagram carries one whole
    answer. UDP has no connection: connect() cannot tell whether the PLC is
    there, a request that is not answered times out, and an answer that
    comes late could be taken for the next one - which is why the handler
    opens a new socket (new local port) after every timeout, as it
    reconnects TCP.
    """
    if frame == "4E":
        from pymcprotocol import Type4E as Base
    else:
        from pymcprotocol import Type3E as Base
    header_size, subheader, length_offset, length_size = _FRAME_LAYOUT[(frame, ascii_code)]

    class FramedClient(Base):
        def connect(self, ip: str, port: int) -> None:
            if not udp:
                super().connect(ip, port)
                return
            self._ip, self._port = ip, port
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self.soc_timeout)
            self._sock.connect((ip, port))  # fixes the peer: datagrams from others are dropped
            self._is_connected = True

        def _recv_exact(self, size: int) -> bytes:
            buf = bytearray()
            while len(buf) < size:
                chunk = self._sock.recv(size - len(buf))
                if not chunk:
                    raise ConnectionError("SLMP connection closed by the PLC")
                buf += chunk
            return bytes(buf)

        def _recv(self) -> bytes:
            if udp:
                return self._recv_datagram()
            header = self._recv_exact(header_size)
            if header[: len(subheader)].upper() != subheader:
                raise ConnectionError(f"unexpected SLMP response header: {header[: len(subheader)].hex()}")
            field = header[length_offset : length_offset + length_size]
            if ascii_code:
                try:
                    length = int(field.decode("ascii"), 16)
                except ValueError:
                    raise ConnectionError(f"unexpected SLMP response length: {field!r}") from None
            else:
                length = int.from_bytes(field, "little")
            return header + self._recv_exact(length)

        def _recv_datagram(self) -> bytes:
            datagram = self._sock.recv(SLMP_UDP_MAX_DATAGRAM)
            if datagram[: len(subheader)].upper() != subheader or len(datagram) < header_size:
                raise ConnectionError(f"unexpected SLMP response: {datagram[: len(subheader)].hex()}")
            field = datagram[length_offset : length_offset + length_size]
            try:
                length = int(field.decode("ascii"), 16) if ascii_code else int.from_bytes(field, "little")
            except ValueError:
                raise ConnectionError(f"unexpected SLMP response length: {field!r}") from None
            if len(datagram) != header_size + length:
                raise ConnectionError(f"SLMP datagram of {len(datagram)} bytes, {header_size + length} expected")
            return bytes(datagram)

        def _make_devicedata(self, device: str) -> bytes:
            # slmp_head_device() names X/Y/B/W with one letter ("B" is
            # also a hex digit, so the name cannot be split off the number)
            name = device[:1].upper()
            if not ascii_code or name not in SLMP_HEX_NAMES:
                data: bytes = super()._make_devicedata(device)
                return data
            # Device code (2 characters, "X*") and the number in hexadecimal
            number = device[1:].upper().lstrip("0") or "0"
            return (name + "*").encode() + number.rjust(6, "0").encode()

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
    # Device number field: 3 bytes for the Q/L series command format that
    # pymcprotocol uses by default (a larger number raises OverflowError)
    MAX_ADDRESS = 0xFFFFFF

    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        frame: int = 0,
        ascii: int = 0,
        udp: int = 0,
        **kwargs: Any,
    ):
        """
        Args:
            frame: 3 or 4 (targets[].options.frame): the frame the PLC's
                port is set to. 0 keeps the class default (3E).
            ascii: 1 when the port's communication data code is ASCII
                (targets[].options.ascii); 0 = binary
            udp: 1 for a port opened for UDP (protocol slmp-udp); 0 = TCP
        """
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.SLMP], **kwargs)
        self._client: Any = None
        if frame:
            self.FRAME = f"{frame}E"
        self._ascii = bool(ascii)
        self._udp = bool(udp)
        if self._udp:
            self.protocol = Protocol.SLMP_UDP

    @property
    def settings_text(self) -> str:
        """The frame, data code and transport, e.g. "3E" or "4E ASCII UDP" """
        return self.FRAME + (" ASCII" if self._ascii else "") + (" UDP" if self._udp else "")

    async def connect(self) -> bool:
        """Establish SLMP connection"""
        try:
            client_class = _framed_client_class(self.FRAME, self._ascii, self._udp)

            def _connect():
                client = client_class()
                if self._ascii:
                    client.setaccessopt(commtype="ascii")
                # Socket timeout follows the configured request timeout
                # (pymcprotocol's own default is 2 s)
                client.soc_timeout = self.config.request_timeout_ms / 1000
                client.connect(self.ip_address, self.port)
                return client

            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            logger.info(f"SLMP ({self.settings_text}) connected to {self.ip_address}:{self.port}")
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
        self, device_type: DeviceType, start_address: int, count: int
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

        headdevice = slmp_head_device(device_type, start_address)

        try:

            def _read():
                # Bit devices are read in bit units, every other device in words
                if device_type in SLMP_BIT_DEVICES:
                    return self._client.batchread_bitunits(headdevice=headdevice, readsize=count)
                return self._client.batchread_wordunits(headdevice=headdevice, readsize=count)

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

        if any(c in code_str for c in SLMP_ADDRESS_END_CODES) or "illegal" in error_str:
            logger.debug(f"SLMP illegal address: {device_type.value}{start_address} ({e})")
            return StatusCode.NG_ILLEGAL_ADDR

        logger.debug(f"SLMP read error: {e}")
        return StatusCode.NG_COMM_ERROR


class SLMPBinaryHandler(SLMPHandler):
    """
    SLMP Binary protocol handler (4E Frame).

    For high-speed communication with newer PLCs.
    """

    FRAME = "4E"

    def __init__(self, ip_address: str, port: Optional[int] = None, **kwargs: Any):
        super().__init__(ip_address, port or 5000, **kwargs)
