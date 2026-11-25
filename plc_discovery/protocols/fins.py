"""
FINS Protocol Handler - Omron PLC Communication

Implements FINS/UDP and FINS/TCP protocol for Omron
CS/CJ/CP/NJ/NX series PLCs.
"""

import asyncio
import ipaddress
import logging
import struct
from typing import Dict, List, Optional, Tuple

from ..config import DeviceType, NetworkConfig, Protocol, StatusCode
from ..utils import wait_for
from .base import BaseProtocolHandler

logger = logging.getLogger(__name__)


# FINS Frame constants
FINS_ICF = 0x80  # Information Control Field (command)
FINS_RSV = 0x00  # Reserved
FINS_GCT = 0x02  # Permissible number of gateways
FINS_DNA = 0x00  # Destination network address (local)
FINS_DA1 = 0x00  # Destination node address (PLC node)
FINS_DA2 = 0x00  # Destination unit address (CPU unit)
FINS_SNA = 0x00  # Source network address (local)
FINS_SA1 = 0x00  # Source node address (client node)
FINS_SA2 = 0x00  # Source unit address

# FINS Memory Area codes
FINS_AREA_CODES = {
    DeviceType.DM: 0x82,  # DM Area (word)
    DeviceType.D: 0x82,  # Alias for DM
    DeviceType.HR: 0xB2,  # HR Area (word)
    DeviceType.W: 0xB1,  # W Area (word)
    # IR is not offered: area 0xDC holds the index registers, whose values
    # are 4 bytes each, so they were decoded as unrelated 16-bit words (and
    # the CIO area that "IR" once named on older models is read as M).
    # A request for IR is answered NG_UNSUPPORTED.
    DeviceType.M: 0xB0,  # CIO Area (word access; 0x30 is bit access = 1 byte/point)
}

# End code bits that are flags, not errors:
#   MRES bit 7 (0x8000): network relay error flag
#   SRES bit 7 (0x0080): fatal CPU error flag
#   SRES bit 6 (0x0040): non-fatal CPU error flag (e.g. battery low)
FINS_END_CODE_MASK = 0x7F3F

# FINS Commands
FINS_CMD_MEMORY_READ = (0x01, 0x01)  # Memory area read
FINS_CMD_CONTROLLER_DATA_READ = (0x05, 0x01)  # Controller data read (CPU model / version)
# Controller data reply: CPU unit model (20 bytes) and version (20 bytes) first
FINS_CONTROLLER_MODEL_BYTES = 20
FINS_CONTROLLER_VERSION_BYTES = 20

# FINS end codes (Omron FINS Commands Reference Manual: MRES/SRES)
FINS_ERROR_CODES = {
    0x0000: "Normal completion",
    0x0001: "Service canceled",
    0x0101: "Local node not in network",
    0x0102: "Token timeout",
    0x0103: "Retries failed",
    0x0104: "Too many send frames",
    0x0105: "Node address range error",
    0x0106: "Node address duplication",
    0x0201: "Destination node not in network",
    0x0202: "Unit missing",
    0x0203: "Third node missing",
    0x0204: "Destination node busy",
    0x0205: "Response timeout",
    0x0301: "Communications controller error",
    0x0302: "CPU Unit error",
    0x0303: "Controller error",
    0x0304: "Unit number error",
    0x0401: "Undefined command",
    0x0402: "Not supported by model/version",
    0x0501: "Destination address setting error",
    0x0502: "No routing tables",
    0x0503: "Routing table error",
    0x0504: "Too many relays",
    0x1001: "Command too long",
    0x1002: "Command too short",
    0x1003: "Elements/data don't match",
    0x1004: "Command format error",
    0x1005: "Header error",
    0x1101: "Area classification missing",
    0x1102: "Access size error",
    0x1103: "Address range error",
    0x1104: "Address range exceeded",
    0x1106: "Program missing",
    0x1109: "Relational error",
    0x110A: "Duplicate data access",
    0x110B: "Response too long",
    0x110C: "Parameter error",
    0x2002: "Protected",
    0x2101: "Read-only",
}

# End codes reported by the PLC for the requested addresses: the address
# does not exist on this CPU (learned as inaccessible by binary search)
# 0x110B "Response too long": more words requested than this model returns
# in one response; smaller reads succeed, so it is split like an address
# error instead of being reported as a communication failure
FINS_ILLEGAL_ADDRESS_CODES = (0x1103, 0x1104, 0x110B)

# The memory area or the command itself is not available on this model;
# splitting the range cannot help
FINS_UNSUPPORTED_CODES = (0x0401, 0x0402, 0x1101)

# The PLC did not answer in time (relayed through a gateway / network)
FINS_TIMEOUT_CODES = (0x0205,)


def _last_octet(ip_address: str) -> int:
    """Last octet of an IPv4 address (FINS node by automatic conversion); 0 if not IPv4"""
    try:
        return int(ipaddress.IPv4Address(ip_address)) & 0xFF
    except ValueError:
        return 0


class FINSHandler(BaseProtocolHandler):
    """
    FINS protocol handler for Omron PLCs.

    Supports both UDP and TCP variants.

    Usage:
        async with FINSHandler("192.168.1.10") as handler:
            data, status = await handler.read_device_raw(DeviceType.DM, 0, 100)
    """

    protocol = Protocol.FINS
    DEFAULT_PORT_UDP = 9600
    DEFAULT_PORT_TCP = 9600
    MAX_READ_WORDS = 499  # FINS protocol limit per read (reads use SAFE_READ_WORDS)
    MAX_ADDRESS = 0xFFFF  # word address is 2 bytes in the read command

    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        config: Optional[NetworkConfig] = None,
        use_tcp: bool = False,
        source_node: Optional[int] = None,
        dest_node: Optional[int] = None,
    ):
        """
        Initialize FINS handler.

        Args:
            ip_address: PLC IP address
            port: Port number (default 9600)
            config: Network configuration
            use_tcp: Use TCP instead of UDP
            source_node: FINS node of this PC (SA1). Default: FINS/UDP uses the
                last octet of the local IP address, FINS/TCP lets the PLC assign it.
            dest_node: FINS node of the PLC (DA1). Default: last octet of the
                PLC's IP address (Omron automatic address conversion); with
                FINS/TCP the PLC reports its node during the handshake.
        """
        super().__init__(ip_address, port or self.DEFAULT_PORT_UDP, config)

        self.use_tcp = use_tcp
        if use_tcp:
            # Per-instance protocol so max_read_size/logging reflect FINS/TCP
            self.protocol = Protocol.FINS_TCP
        for name, value in (("source_node", source_node), ("dest_node", dest_node)):
            if value is not None and not 0 <= value <= 254:
                raise ValueError(f"{name} must be 0-254, got {value}")
        self._source_node_explicit = source_node is not None
        self.source_node = source_node if source_node is not None else 0
        self.dest_node = dest_node if dest_node is not None else _last_octet(ip_address)

        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol_instance: Optional["FINSUDPProtocol"] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._sid = 0  # Service ID counter
        # Why the last request got no usable response: NG_TIMEOUT when the
        # PLC did not answer in time, NG_COMM_ERROR for a transport failure
        # (connection reset, unexpected frame). Set by _send_tcp / _send_udp.
        self._send_failure: Optional[StatusCode] = None

    async def connect(self) -> bool:
        """Establish connection to PLC"""
        try:
            if self.use_tcp:
                return await self._connect_tcp()
            else:
                return await self._connect_udp()
        except Exception as e:
            logger.error(f"FINS connection failed: {e}")
            return False

    async def _connect_tcp(self) -> bool:
        """Establish TCP connection"""
        try:
            reader, writer = await wait_for(
                asyncio.open_connection(self.ip_address, self.port), timeout=self.config.request_timeout_ms / 1000
            )
            self._reader, self._writer = reader, writer

            # Send FINS/TCP node address negotiation
            handshake = self._build_tcp_handshake()
            writer.write(handshake)
            await writer.drain()

            # Wait for response (16-byte header + client node + server node)
            try:
                response = await wait_for(reader.readexactly(24), timeout=self.config.request_timeout_ms / 1000)
            except asyncio.IncompleteReadError:
                logger.error("Invalid FINS/TCP handshake response")
                await self._close_tcp()
                return False

            if response[:4] != b"FINS" or struct.unpack(">I", response[12:16])[0] != 0:
                logger.error("FINS/TCP handshake rejected")
                await self._close_tcp()
                return False

            # Parse response to get node addresses
            # Bytes 20-23 contain client and server node addresses
            self.source_node = response[19]
            self.dest_node = response[23]

            self._connected = True
            logger.info(f"FINS/TCP connected to {self.ip_address}:{self.port}")
            return True

        except asyncio.TimeoutError:
            logger.error("FINS/TCP connection timeout")
            await self._close_tcp()
            return False
        except Exception as e:
            logger.error(f"FINS/TCP connection error: {e}")
            await self._close_tcp()
            return False

    async def _close_tcp(self) -> None:
        """Close a (possibly half-open) TCP stream without raising"""
        writer, self._reader, self._writer = self._writer, None, None
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"FINS/TCP close error: {e}")

    async def _connect_udp(self) -> bool:
        """Establish UDP connection"""
        try:
            loop = asyncio.get_running_loop()

            # Create UDP endpoint
            transport, protocol_instance = await loop.create_datagram_endpoint(
                lambda: FINSUDPProtocol(self), remote_addr=(self.ip_address, self.port or 9600)
            )
            self._transport, self._protocol_instance = transport, protocol_instance

            # Default SA1: last octet of the local address used to reach the PLC
            if not self._source_node_explicit:
                sockname = transport.get_extra_info("sockname")
                self.source_node = _last_octet(sockname[0]) if sockname else 0

            # UDP has no handshake: confirm a FINS node answers (any FINS
            # reply, even an error end code) with a read-only 1-word DM read
            frame = self._build_read_command(DeviceType.DM, 0, 1)
            if await self._send_udp(frame, self._sid) is None:
                logger.error(f"FINS/UDP: no response from {self.ip_address}:{self.port}")
                transport.close()
                self._transport = None
                self._protocol_instance = None
                return False

            self._connected = True
            logger.info(f"FINS/UDP connected to {self.ip_address}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"FINS/UDP connection error: {e}")
            return False

    async def disconnect(self):
        """Close connection"""
        try:
            if self.use_tcp:
                await self._close_tcp()
            elif self._transport:
                self._transport.close()
            logger.info(f"FINS disconnected from {self.ip_address}")
        except Exception as e:
            logger.warning(f"FINS disconnect error: {e}")
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            self._transport = None
            self._protocol_instance = None

    async def read_device_raw(
        self, device_type: DeviceType, start_address: int, count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read raw device data from PLC.

        Args:
            device_type: Device type (DM, HR, W, etc.)
            start_address: Starting address
            count: Number of words to read

        Returns:
            Tuple of (data list or None, status code)
        """
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        if not self._connected:
            return None, StatusCode.NG_COMM_ERROR

        if device_type not in FINS_AREA_CODES:
            # Never fall back to another area: the DM values would be
            # recorded under the requested device's addresses
            logger.warning(f"Unsupported device type for FINS: {device_type}")
            return None, StatusCode.NG_UNSUPPORTED

        try:
            # Build FINS command
            frame = self._build_read_command(device_type, start_address, count)
            sid = self._sid

            # Send and receive
            if self.use_tcp:
                response = await self._send_tcp(frame, sid)
            else:
                response = await self._send_udp(frame, sid)

            if response is None:
                return None, self._send_failure or StatusCode.NG_TIMEOUT

            # Parse response
            return self._parse_read_response(response)

        except Exception as e:
            logger.error(f"FINS read error: {e}")
            return None, StatusCode.NG_COMM_ERROR

    def _build_read_command(self, device_type: DeviceType, start_address: int, count: int) -> bytes:
        """Build FINS memory read command"""
        # Get memory area code (read_device_raw rejects other device types)
        area_code = FINS_AREA_CODES[device_type]

        # Increment SID
        self._sid = (self._sid + 1) & 0xFF

        # Build FINS header
        header = bytes(
            [
                FINS_ICF,  # ICF
                FINS_RSV,  # RSV
                FINS_GCT,  # GCT
                FINS_DNA,  # DNA (destination network)
                self.dest_node,  # DA1 (destination node)
                FINS_DA2,  # DA2 (destination unit)
                FINS_SNA,  # SNA (source network)
                self.source_node,  # SA1 (source node)
                FINS_SA2,  # SA2 (source unit)
                self._sid,  # SID (service ID)
            ]
        )

        # Build command code
        cmd = bytes(FINS_CMD_MEMORY_READ)

        # Build command data
        # Address format: Area(1) + Address(2) + Bit(1)
        addr_high = (start_address >> 8) & 0xFF
        addr_low = start_address & 0xFF

        data = bytes(
            [
                area_code,  # Memory area code
                addr_high,  # Address high byte
                addr_low,  # Address low byte
                0x00,  # Bit position (always 0 for word access)
                (count >> 8) & 0xFF,  # Count high byte
                count & 0xFF,  # Count low byte
            ]
        )

        fins_frame = header + cmd + data

        # Wrap in TCP header if needed
        if self.use_tcp:
            return self._wrap_tcp_frame(fins_frame)

        return fins_frame

    def _build_command(self, command: Tuple[int, int], data: bytes) -> bytes:
        """FINS frame (TCP-wrapped when needed) for any command, with the next SID"""
        self._sid = (self._sid + 1) & 0xFF
        header = bytes(
            [
                FINS_ICF,
                FINS_RSV,
                FINS_GCT,
                FINS_DNA,
                self.dest_node,
                FINS_DA2,
                FINS_SNA,
                self.source_node,
                FINS_SA2,
                self._sid,
            ]
        )
        frame = header + bytes(command) + data
        return self._wrap_tcp_frame(frame) if self.use_tcp else frame

    async def read_controller_data(self) -> Optional[Dict[str, str]]:
        """
        CPU unit model ("CJ2M-CPU33") and version ("02.01") with Controller
        Data Read (05 01, read-only). None when the PLC does not answer it
        (the caller falls back to generic names).
        """
        if not await self._ensure_fresh_connection() or not self._connected:
            return None
        await self._rate_limiter.wait()  # same packet interval as data reads
        try:
            frame = self._build_command(FINS_CMD_CONTROLLER_DATA_READ, b"\x00")
            sid = self._sid
            send = self._send_tcp if self.use_tcp else self._send_udp
            response = await send(frame, sid, FINS_CMD_CONTROLLER_DATA_READ)
        except Exception as e:
            logger.debug(f"FINS controller data read failed: {e}")
            return None
        if not response or len(response) < 14:
            return None
        if ((response[12] << 8) | response[13]) & FINS_END_CODE_MASK:
            logger.debug(f"FINS controller data read end code 0x{response[12]:02X}{response[13]:02X}")
            return None
        data = response[14:]

        def text(raw: bytes) -> str:
            return raw.split(b"\x00")[0].decode("ascii", errors="ignore").strip()

        model = text(data[:FINS_CONTROLLER_MODEL_BYTES])
        version = text(data[FINS_CONTROLLER_MODEL_BYTES : FINS_CONTROLLER_MODEL_BYTES + FINS_CONTROLLER_VERSION_BYTES])
        return {"model": model, "version": version} if model else None

    def _build_tcp_handshake(self) -> bytes:
        """Build FINS/TCP node address negotiation request"""
        client_node = self.source_node if self._source_node_explicit else 0  # 0 = auto
        return (
            b"FINS"
            + struct.pack(">III", 12, 0x00000000, 0)  # length, node address data send, error
            + struct.pack(">I", client_node)
        )

    def _wrap_tcp_frame(self, fins_frame: bytes) -> bytes:
        """Wrap FINS frame with TCP header"""
        length = len(fins_frame) + 8
        header = bytes(
            [
                0x46,
                0x49,
                0x4E,
                0x53,  # "FINS"
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
                0x00,
                0x00,
                0x00,
                0x02,  # Command: FINS frame
                0x00,
                0x00,
                0x00,
                0x00,  # Error code
            ]
        )
        return header + fins_frame

    @staticmethod
    def _response_matches(response: bytes, sid: int, command: Tuple[int, int] = FINS_CMD_MEMORY_READ) -> bool:
        """Check that a FINS frame is the response to the request with this SID and command"""
        return (
            len(response) >= 12
            and (response[0] & 0x40) != 0  # ICF: response frame
            and response[9] == sid  # SID echoes the request
            and response[10:12] == bytes(command)
        )

    async def _send_tcp(
        self, frame: bytes, sid: int, command: Tuple[int, int] = FINS_CMD_MEMORY_READ
    ) -> Optional[bytes]:
        """
        Send frame via TCP and receive response.

        Any timeout, short read or unexpected frame leaves the stream at an
        unknown position, so the connection is re-established before the
        next request.
        """
        timeout = self.config.request_timeout_ms / 1000
        self._send_failure = None
        try:
            reader, writer = self._reader, self._writer
            if reader is None or writer is None:
                raise ConnectionError("FINS/TCP is not connected")
            writer.write(frame)
            await writer.drain()

            # FINS/TCP header: "FINS" + length + command + error code
            header = await wait_for(reader.readexactly(16), timeout=timeout)
            if header[:4] != b"FINS":
                raise ValueError("FINS/TCP header magic mismatch")

            length = int(struct.unpack(">I", header[4:8])[0])
            if length < 8:
                raise ValueError(f"FINS/TCP invalid length: {length}")

            # Read FINS frame (length counts command + error code + frame)
            fins_data = await wait_for(reader.readexactly(length - 8), timeout=timeout)

            tcp_error = struct.unpack(">I", header[12:16])[0]
            if tcp_error != 0:
                raise ValueError(f"FINS/TCP error code: 0x{tcp_error:08X}")

            if not self._response_matches(fins_data, sid, command):
                raise ValueError("FINS/TCP response does not match request SID")

            return fins_data

        except asyncio.TimeoutError:
            # Expected while unanswered ranges are narrowed down: the status
            # of the data point reports it, not an error line per request
            logger.debug("FINS/TCP read timeout")
            self._send_failure = StatusCode.NG_TIMEOUT
        except Exception as e:
            logger.error(f"FINS/TCP send error: {e}")
            self._send_failure = StatusCode.NG_COMM_ERROR
        self._needs_reconnect = True
        return None

    async def _send_udp(
        self, frame: bytes, sid: int, command: Tuple[int, int] = FINS_CMD_MEMORY_READ
    ) -> Optional[bytes]:
        """
        Send frame via UDP and receive the matching response.

        Late responses to earlier (timed-out) requests are discarded by SID,
        so they can never be taken as data for the current request.
        """
        if not self._protocol_instance or not self._transport:
            self._send_failure = StatusCode.NG_COMM_ERROR
            return None
        self._send_failure = None

        loop = asyncio.get_running_loop()
        timeout = self.config.request_timeout_ms / 1000

        try:
            # Discard stale responses still queued from earlier requests
            self._protocol_instance.drain()

            # Send request
            self._transport.sendto(frame)

            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                response = await wait_for(self._protocol_instance.receive(), timeout=remaining)
                if self._response_matches(response, sid, command):
                    return response
                logger.debug("FINS/UDP: discarded unmatched/stale response")

        except asyncio.TimeoutError:
            logger.debug("FINS/UDP read timeout")
            self._send_failure = StatusCode.NG_TIMEOUT
            return None
        except Exception as e:
            logger.error(f"FINS/UDP send error: {e}")
            self._send_failure = StatusCode.NG_COMM_ERROR
            return None

    def _parse_read_response(self, response: bytes) -> Tuple[Optional[List[int]], StatusCode]:
        """Parse FINS read response"""
        if len(response) < 14:
            return None, StatusCode.NG_COMM_ERROR

        # Skip header (10 bytes) and command code (2 bytes)
        # Response format: Header(10) + Cmd(2) + EndCode(2) + Data...

        # Check end code (bytes 12-13), ignoring relay/CPU status flag bits
        raw_end_code = (response[12] << 8) | response[13]
        end_code = raw_end_code & FINS_END_CODE_MASK
        if raw_end_code != end_code:
            logger.debug(f"FINS end code flags set: 0x{raw_end_code:04X}")

        if end_code != 0x0000:
            error_msg = FINS_ERROR_CODES.get(end_code, "Unknown error")
            if end_code in FINS_ILLEGAL_ADDRESS_CODES:
                # Expected while binary search narrows down the valid range
                logger.debug(f"FINS end code 0x{end_code:04X}: {error_msg}")
            else:
                logger.warning(f"FINS end code 0x{end_code:04X}: {error_msg}")

            if end_code in FINS_ILLEGAL_ADDRESS_CODES:
                return None, StatusCode.NG_ILLEGAL_ADDR
            if end_code in FINS_UNSUPPORTED_CODES:
                return None, StatusCode.NG_UNSUPPORTED
            if end_code in FINS_TIMEOUT_CODES:
                return None, StatusCode.NG_TIMEOUT
            return None, StatusCode.NG_COMM_ERROR

        # Extract data (starting from byte 14)
        data_bytes = response[14:]

        # Convert to word list
        words = []
        for i in range(0, len(data_bytes), 2):
            if i + 1 < len(data_bytes):
                # Big-endian word
                word = (data_bytes[i] << 8) | data_bytes[i + 1]
                words.append(word)

        return words, StatusCode.OK


class FINSUDPProtocol(asyncio.DatagramProtocol):
    """UDP Protocol handler for FINS"""

    def __init__(self, handler: FINSHandler):
        self.handler = handler
        self._response_future = None
        self._response_queue: "asyncio.Queue[bytes]" = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Put response in queue
        try:
            self._response_queue.put_nowait(data)
        except asyncio.QueueFull:
            logger.warning("FINS response queue full")

    def error_received(self, exc):
        logger.error(f"FINS UDP error: {exc}")

    async def receive(self) -> bytes:
        """Wait for and return next response"""
        return await self._response_queue.get()

    def drain(self) -> None:
        """Discard all queued responses"""
        while True:
            try:
                self._response_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
