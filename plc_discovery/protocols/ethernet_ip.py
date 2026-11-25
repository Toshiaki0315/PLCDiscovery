"""
EtherNet/IP Protocol Handler - CIP Communication

Supports:
- Omron (NJ/NX series)
- Rockwell/Allen-Bradley (ControlLogix, CompactLogix)
- Keyence (KV-8000 series)
- Yaskawa, CODESYS-based PLCs
"""

import asyncio
import logging
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..config import PROTOCOL_PORTS, DataPoint, DeviceType, Protocol, StatusCode
from ..utils import get_timestamp
from .base import BaseProtocolHandler
from .cip_symbolic import (
    MAX_BATCH_REQUEST_BYTES,
    MAX_BATCH_TAGS,
    READ_SINGLY,
    FragmentedRead,
    SymbolicReadError,
    read_symbolic,
    read_symbolic_batch,
    split_element_count,
)

logger = logging.getLogger(__name__)

# Device type mapping to PLC-5/SLC/MicroLogix data files (file letter, file number).
# Data-file addressing ("N7:0") is only understood by SLC-style controllers;
# Logix and generic CIP devices use symbolic tags, which this tool does not read.
EIP_DEVICE_MAP = {
    DeviceType.D: ("N", 7),  # Integer file N7
    DeviceType.HR: ("N", 7),  # Integer file N7
    DeviceType.M: ("B", 3),  # Bit file B3 (read as 16-bit words)
}


# CIP identity values for controllers that support data-file addressing
ROCKWELL_VENDOR_ID = 1
CIP_PRODUCT_TYPE_PLC = 0x0E  # "Programmable Logic Controller"

# PLC-5/SLC/MicroLogix data-file limits as encoded by pycomm3's SLCDriver:
# the element number and the byte size of a read are single bytes
SLC_MAX_ELEMENT = 255
SLC_MAX_READ_WORDS = 100  # 200 bytes (byte size field max 255)


def is_slc_identity(identity: Optional[Dict]) -> bool:
    """
    True if a ListIdentity reply looks like a Rockwell PLC-5/SLC/MicroLogix.

    Requires vendor Rockwell, product type PLC, and a product name that is
    not a Control/CompactLogix controller (those use symbolic tags and are
    handled by LogixDriver). MicroLogix names are accepted.
    """
    if not identity:
        return False
    vendor = identity.get("vendor_id", identity.get("vendor"))
    product_type = identity.get("product_type")
    name = str(identity.get("product_name", ""))
    vendor_ok = vendor == ROCKWELL_VENDOR_ID or "rockwell" in str(vendor).lower() or "allen" in str(vendor).lower()
    type_ok = product_type == CIP_PRODUCT_TYPE_PLC or "programmable logic controller" in str(product_type).lower()
    name = name.lower()
    is_logix = "logix" in name and "micrologix" not in name
    return vendor_ok and type_ok and not is_logix


class EtherNetIPHandler(BaseProtocolHandler):
    """
    EtherNet/IP (CIP) Protocol Handler

    Implements communication with EtherNet/IP compatible PLCs.
    """

    protocol = Protocol.ETHERNET_IP

    def __init__(self, ip_address: str, port: Optional[int] = None, slot: int = 0, **kwargs: Any):
        super().__init__(ip_address, port or PROTOCOL_PORTS[Protocol.ETHERNET_IP], **kwargs)
        self._client: Any = None
        self._slot = slot
        self._plc_type: Optional[str] = None  # 'logix', 'slc' or 'generic'
        # Cleared when a generic CIP controller rejects Multiple Service
        self._multiple_service_ok = True
        # Logix tag list and data types read on the first connection, reused
        # when reconnecting (see _connect_logix_first)
        self._logix_definitions: Optional[Tuple[Dict[str, Any], Dict[str, Any]]] = None
        # Which controller and program they were read from (see _logix_identity)
        self._logix_identity: Optional[Tuple[Any, ...]] = None

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

    @property
    def max_read_size(self) -> int:
        """SLC-style reads are limited to a 255-byte payload by pycomm3"""
        size = super().max_read_size
        if self._plc_type == "slc":
            return min(size, SLC_MAX_READ_WORDS)
        return size

    async def connect(self) -> bool:
        """
        Establish EtherNet/IP connection.

        The first connection tries Logix, then SLC, then generic CIP. A
        reconnect (e.g. after a timeout) goes straight to the driver that
        worked before instead of repeating the whole fallback chain.
        """
        if self._plc_type == "slc":
            return await self._connect_slc()
        if self._plc_type == "generic":
            return await self._connect_generic()
        return await self._connect_logix_first()

    async def _connect_logix_first(self) -> bool:
        """Try LogixDriver, falling back to SLC and generic CIP"""
        try:
            from pycomm3 import LogixDriver

            definitions = self._logix_definitions

            def _connect():
                path = self._connection_path(include_slot=True)
                if definitions is not None:
                    # Reconnect (e.g. after a timeout): pycomm3 would upload
                    # the whole tag list and every UDT again - hundreds of
                    # requests it sends without the packet interval. Reuse
                    # what the first connection read - if this is still the
                    # controller it was read from.
                    client = LogixDriver(path, init_tags=False)
                    client.open()
                    same = _logix_identity(client) == self._logix_identity
                    if same and hasattr(client, "_tags") and hasattr(client, "_data_types"):
                        client._tags, client._data_types = dict(definitions[0]), dict(definitions[1])
                        # Tags are requested by name, not by the instance ID
                        # in the reused list: after a program download the
                        # IDs may belong to other tags, and another tag's
                        # value would be recorded under the old name
                        if isinstance(getattr(client, "_cfg", None), dict):
                            client._cfg["use_instance_ids"] = False
                        return client
                    client.close()
                    if not same:
                        logger.warning(
                            f"EtherNet/IP (Logix): {self.ip_address} answers as another controller or program "
                            "than before; its tag list is read again"
                        )
                client = LogixDriver(path)
                client.open()
                return client

            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = "logix"
            if definitions is None or _logix_identity(self._client) != self._logix_identity:
                self._logix_identity = _logix_identity(self._client)
                tags = getattr(self._client, "_tags", None)
                data_types = getattr(self._client, "_data_types", None)
                if isinstance(tags, dict) and isinstance(data_types, dict):
                    self._logix_definitions = (dict(tags), dict(data_types))
                logger.info(
                    f"EtherNet/IP (Logix): tag list of {len(tags) if isinstance(tags, dict) else 0} tags read "
                    "from the controller (requests sent by pycomm3 without the packet interval; once per run)"
                )
            logger.info(f"EtherNet/IP (Logix) connected to {self.ip_address}:{self.port}")
            return True

        except ImportError:
            logger.error("pycomm3 library not installed")
            return False
        except Exception as e:
            if self._plc_type == "logix":
                # It answered as a Logix controller before: a reconnect that
                # fails (CPU busy, link still down) must not turn it into a
                # "generic CIP" device for the rest of the session - its tag
                # list would be gone and tags would be read over a path
                # without the slot. The next reconnect tries Logix again.
                logger.warning(f"EtherNet/IP (Logix) reconnect to {self.ip_address}:{self.port} failed: {e}")
                self._client = None
                self._connected = False
                return False
            # Expected for non-Logix controllers: not worth a warning
            logger.info(f"Not a Logix controller ({e}); trying SLC driver")
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
                try:
                    identity = client._list_identity()
                except Exception as e:
                    identity = None
                    logger.debug(f"ListIdentity failed: {e}")
                if not is_slc_identity(identity):
                    # SLCDriver.open() only registers a CIP session, which any
                    # EtherNet/IP device accepts. Data-file reads would then fail
                    # and be misreported as illegal addresses.
                    client.close()
                    raise ConnectionError(f"not an SLC/PLC-5/MicroLogix controller (identity: {identity})")
                return client

            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = "slc"
            logger.info(f"EtherNet/IP (SLC) connected to {self.ip_address}:{self.port}")
            return True
        except Exception as e:
            logger.info(f"Not an SLC/PLC-5/MicroLogix controller ({e}); using generic CIP")
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

            loop = asyncio.get_running_loop()
            self._client = await loop.run_in_executor(None, _connect)
            self._connected = True
            self._plc_type = "generic"
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

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, _disconnect)
            except Exception as e:
                logger.debug(f"EtherNet/IP disconnect error: {e}")
            finally:
                self._client = None
                self._connected = False
                logger.info(f"EtherNet/IP disconnected from {self.ip_address}")

    async def read_device_raw(
        self, device_type: DeviceType, start_address: int, count: int
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
            if self._plc_type == "slc":
                return await self._read_ab_style(device_type, start_address, count)
            # Logix / generic CIP devices have no numeric device addresses.
            # Returning data from another object under these addresses would
            # be misleading, so report the device type as unsupported.
            logger.warning(
                f"Address-based read of {device_type.value} is not supported on "
                f"{self._plc_type} EtherNet/IP devices (symbolic tags only)"
            )
            return None, StatusCode.NG_UNSUPPORTED

        except asyncio.TimeoutError:
            logger.debug("EtherNet/IP read timeout")
            return None, StatusCode.NG_TIMEOUT
        except Exception as e:
            error_str = str(e).lower()
            if isinstance(e, _RefusedForNow):
                # Answered, but not about the address (program mode, node
                # busy): not learned as inaccessible, and no reconnect
                logger.debug(f"EtherNet/IP read refused: {e}")
                return None, StatusCode.NG_COMM_ERROR
            if isinstance(e, LookupError) or "path" in error_str or "not found" in error_str:
                logger.debug(f"EtherNet/IP address error: {e}")
                return None, StatusCode.NG_ILLEGAL_ADDR
            # Transport problem (pycomm3 CommError, socket error): the CIP
            # session is unusable, re-establish it before the next request
            self._needs_reconnect = True
            logger.debug(f"EtherNet/IP read error: {e}")
            return None, StatusCode.NG_COMM_ERROR

    async def _read_ab_style(
        self, device_type: DeviceType, start_address: int, count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read data using Allen-Bradley tag style.

        Constructs tag names like "N7:0", "B3:0", etc.
        """
        mapping = EIP_DEVICE_MAP.get(device_type)
        if mapping is None:
            return None, StatusCode.NG_UNSUPPORTED

        if start_address < 0 or start_address + count - 1 > SLC_MAX_ELEMENT:
            # Data files hold elements 0-255 and pycomm3 encodes the element
            # number in one byte (a larger one raises DataError before
            # anything is sent, which looked like a transport failure)
            logger.debug(
                f"SLC element out of range: {device_type.value}{start_address} " f"x{count} (max {SLC_MAX_ELEMENT})"
            )
            return None, StatusCode.NG_ILLEGAL_ADDR

        try:
            file_letter, file_number = mapping
            tag_name = f"{file_letter}{file_number}:{start_address}"

            def _read():
                name = tag_name if count == 1 else f"{tag_name}{{{count}}}"  # "N7:0{10}" reads 10 elements
                result = self._client.read(name)
                if result.error:
                    if _is_address_error(result.error):
                        raise LookupError(f"{name}: {result.error}")
                    raise _RefusedForNow(f"{name}: {result.error}")
                return [result.value] if count == 1 else list(result.value)

            data = await self._run_blocking(_read)

            if data is not None:
                # pycomm3 decodes N/B file words as signed INT; report raw
                # 16-bit values (0-65535) like the other protocols
                return [int(v) & 0xFFFF for v in data], StatusCode.OK
            return None, StatusCode.NG_COMM_ERROR

        except Exception as e:
            logger.debug(f"AB-style read error: {e}")
            raise

    # ------------------------------------------------------------------
    # Symbolic tags (Logix controllers; Omron NJ/NX and other generic CIP
    # devices that accept Read Tag on symbolic names)
    # ------------------------------------------------------------------

    @property
    def uses_address_ranges(self) -> bool:
        """Only SLC-style devices have numeric data files (N7, B3)"""
        return self._plc_type == "slc"

    @property
    def supports_tags(self) -> bool:
        """
        True when tags can be read by name: through LogixDriver (Logix), or
        with raw Read Tag requests on a generic CIP connection (Omron NJ/NX).
        """
        return self._plc_type in ("logix", "generic") and self._client is not None

    def tag_scan_list(self) -> List[str]:
        """
        Tags for a full scan, from the tag list the LogixDriver read when
        connecting: controller-scope and program-scope ("Program:P.Tag")
        tags, atomic and structures (UDTs, reported member by member).
        Arrays are read from element 0 (first MAX_TAG_ARRAY_ELEMENTS
        elements). Generic CIP devices (Omron NJ/NX) offer no tag list: the
        variables must be named with --tags, so the list is empty.
        """
        if self._plc_type != "logix" or not self.supports_tags:
            return []
        names = []
        for name, info in sorted((getattr(self._client, "tags", None) or {}).items()):
            if info.get("tag_type") not in ("atomic", "struct"):
                continue
            dims = [d for d in (info.get("dimensions") or []) if d]
            if len(dims) > 1:
                # Multi-dimensional array: every index must be given. Only
                # its first element is read ("Name[0]{n}" is not a valid
                # request and was reported as an invalid tag).
                names.append(f"{name}[{','.join('0' for _ in dims)}]")
            elif dims:
                names.append(f"{name}[0]{{{min(dims[0], MAX_TAG_ARRAY_ELEMENTS)}}}")
            else:
                names.append(name)
        return names

    async def read_tags(self, tags: List[str]) -> List[DataPoint]:
        """
        Read symbolic tags (read-only) and report one data point per value.

        Goes through the same safeguards as address reads: packet interval
        (one request per batch of TAG_BATCH_SIZE tags), request timeout with
        reconnect before the next request, and per-tag errors reported as
        NG_ILLEGAL_ADDR (tag not found) instead of failing the batch.
        Array reads ("Tag[0]{10}") give one data point per element and
        structures one per member ("Tag.Member").
        """
        if self._plc_type == "generic":
            points = await self._read_tags_generic(tags)
        else:
            points = await self._read_tags_logix(tags)
        self.partial_points = []
        return self._learn_denied_tags(points)

    def _learn_denied_tags(self, points: List[DataPoint]) -> List[DataPoint]:
        """
        Record tags the controller itself rejected (not found, not
        published, unsupported type) as denied, so they are listed in
        access_denied_log like device addresses. Timeouts and communication
        errors are not recorded.
        """
        for point in points:
            if point.status in self._PERMANENT_FAILURES:
                self._session_cache.add_denied(point.address, point.status)
        return points

    async def _read_tags_logix(self, tags: List[str]) -> List[DataPoint]:
        """Read tags through LogixDriver, TAG_BATCH_SIZE per request"""
        results: List[DataPoint] = []
        # What has been read so far, for a caller that is interrupted (Ctrl+C,
        # the GUI's stop button) in the middle of a long tag list
        self.partial_points = results
        link_lost = False
        for batch in _logix_batches(tags):
            if self._plc_type == "slc":
                # Data-file controllers have no tags
                results += [_tag_point(split_element_count(t)[0], StatusCode.NG_UNSUPPORTED) for t in batch]
                continue
            if (
                link_lost
                or not await self._ensure_fresh_connection()
                or not self._connected
                or self._client is None
                or self._plc_type != "logix"
            ):
                # The link is down (the client is gone after a reconnect that
                # failed): a communication error, not "unsupported" - that
                # would be learned as denied and taken for an answer.
                # One reconnect attempt per call: a PLC that is off cost a
                # connection timeout for every remaining batch, and one that
                # is restarting got a burst of connection attempts.
                link_lost = True
                results += [_tag_point(split_element_count(t)[0], StatusCode.NG_COMM_ERROR) for t in batch]
                continue
            await self._rate_limiter.wait()
            started = time.monotonic()
            try:

                def _read():
                    replies = self._client.read(*batch)
                    return replies if isinstance(replies, list) else [replies]

                replies = await self._run_blocking(_read)
            except asyncio.TimeoutError:
                self._audit_tag_read(batch, StatusCode.NG_TIMEOUT, started)
                results += [_tag_point(split_element_count(t)[0], StatusCode.NG_TIMEOUT) for t in batch]
                continue
            except Exception as e:
                self._needs_reconnect = True
                logger.debug(f"EtherNet/IP tag read error: {e}")
                self._audit_tag_read(batch, StatusCode.NG_COMM_ERROR, started)
                results += [_tag_point(split_element_count(t)[0], StatusCode.NG_COMM_ERROR) for t in batch]
                continue
            self._audit_tag_read(batch, StatusCode.OK, started)
            definitions = getattr(self._client, "data_types", None)
            for name, reply in zip(batch, replies):
                results.extend(_tag_points(name, reply, definitions if isinstance(definitions, dict) else None))
        return results

    async def _read_tags_generic(self, tags: List[str]) -> List[DataPoint]:
        """
        Read tags with raw symbolic Read Tag (Omron NJ/NX: published
        variables, structure members by name). Single values go in Multiple
        Service batches; array reads ("V[0]{10}") one request each
        (fragmented). Every request - batches, single reads and the re-reads
        of batched tags whose reply did not fit - waits for the packet
        interval. A controller that rejects Multiple Service is remembered
        and read one tag per request from then on. A CIP error reply is a
        per-tag status; a transport failure fails the request's tags and
        reconnects before the next one.
        """
        outcomes: Dict[int, List[DataPoint]] = {}
        try:
            return await self._read_tag_groups(tags, outcomes)
        except asyncio.CancelledError:
            # Interrupted: what was read so far, for the caller to save
            self.partial_points = [point for index in sorted(outcomes) for point in outcomes[index]]
            raise

    async def _read_fragments(self, client: Any, tag: str) -> Any:
        """(value, type name) of an array read, or the SymbolicReadError that ended it"""
        try:
            reading = FragmentedRead(tag)
            while not await self._run_blocking(lambda: reading.step(client)):
                await self._rate_limiter.wait()
            return reading.result()
        except SymbolicReadError as e:
            return e

    async def _read_tag_groups(self, tags: List[str], outcomes: Dict[int, List[DataPoint]]) -> List[DataPoint]:
        """The requests of _read_tags_generic; ``outcomes`` is filled as the tags are read"""
        queue: Deque[List[Tuple[int, str]]] = deque(
            [[(index, tag) for index, tag in group] for group in _generic_request_groups(list(enumerate(tags)))]
        )
        link_lost = False
        while queue:
            group = queue.popleft()
            if len(group) > 1 and not self._multiple_service_ok:
                queue.extendleft(reversed([[item] for item in group]))
                continue
            names = [tag for _, tag in group]
            if link_lost or not await self._ensure_fresh_connection() or not self._connected or not self._client:
                link_lost = True  # one reconnect attempt per call (see _read_tags_logix)
                for index, tag in group:
                    outcomes[index] = [_tag_point(split_element_count(tag)[0], StatusCode.NG_COMM_ERROR)]
                continue
            await self._rate_limiter.wait()
            client = self._client

            interval = self.config.packet_interval_ms / 1000

            def read(client: Any = client, names: List[str] = names) -> Tuple[List[Any], bool]:
                if len(names) == 1:
                    return [_capture(read_symbolic, client, names[0], interval)], True
                return read_symbolic_batch(client, names)

            started = time.monotonic()
            try:
                if len(names) == 1 and split_element_count(names[0])[1] > 1:
                    # An array: one request per fragment, each after the
                    # packet interval and with its own timeout
                    results, supported = [await self._read_fragments(client, names[0])], True
                else:
                    results, supported = await self._run_blocking(read)
            except asyncio.TimeoutError:
                self._audit_tag_read(names, StatusCode.NG_TIMEOUT, started)
                for index, tag in group:
                    outcomes[index] = [_tag_point(split_element_count(tag)[0], StatusCode.NG_TIMEOUT)]
                continue
            except Exception as e:
                self._needs_reconnect = True
                logger.debug(f"EtherNet/IP tag read error: {e}")
                self._audit_tag_read(names, StatusCode.NG_COMM_ERROR, started)
                for index, tag in group:
                    outcomes[index] = [_tag_point(split_element_count(tag)[0], StatusCode.NG_COMM_ERROR)]
                continue
            self._audit_tag_read(names, StatusCode.OK, started)
            if not supported:
                logger.info("Multiple Service not supported by the controller: reading one tag per request")
                self._multiple_service_ok = False
            retry: List[Tuple[int, str]] = []
            for (index, tag), outcome in zip(group, results):
                if outcome is READ_SINGLY:
                    retry.append((index, tag))
                elif isinstance(outcome, SymbolicReadError):
                    logger.debug(f"Tag {tag}: {outcome}")
                    outcomes[index] = [_tag_point(split_element_count(tag)[0], outcome.status)]
                else:
                    outcomes[index] = _value_points(tag, outcome[0], outcome[1])
            # Tags whose batched reply did not fit: separate requests, each
            # after the packet interval (never a burst inside one call)
            queue.extendleft(reversed([[item] for item in retry]))
        return [point for index in sorted(outcomes) for point in outcomes[index]]


def _logix_identity(client: Any) -> Tuple[Any, ...]:
    """Serial number, product, revision and program name LogixDriver read when it connected"""
    info = getattr(client, "info", None)
    if not isinstance(info, dict):
        return ()
    return tuple(str(info.get(key)) for key in ("serial", "product_code", "revision", "name"))


class _RefusedForNow(Exception):
    """The controller answered with a status that is not about the address"""


# Error texts of pycomm3 that are about the state of the controller or the
# link, not about the address: the next scan may well read the same address
# Whole phrases as pycomm3 words them (its PCCC and CIP status tables and
# its own messages), never single words: pycomm3 puts the tag name into
# some messages ("Tag doesn't exist - Pump1_Busy"), and a missing tag
# called ConnectionStatus or Cycle_Timeout was taken for a busy controller.
_TRANSIENT_ERROR_TEXTS = (
    # PCCC (SLC / PLC-5 / MicroLogix)
    "processor is in program mode",
    "remote node cannot buffer command",
    "plc has a problem and will not communicate",
    "remote node host is missing, disconnected, or shut down",
    "host could not complete function due to hardware fault",
    "not acknowledged (nak)",
    "no reponse, check com settings",  # (sic)
    "no data returned",
    "unknown status",
    # CIP (Logix)
    "insufficient resource",
    "device state conflict",
    "object state conflict",
    "no buffer memory",
    "connection in use",
    "connection not found",
    "connection timeout",
    "unconnected message timeout",
    "application out of connections",
    "controller in upload or download mode",
    "controller in faulted mode",
    "module not in run state",
    # pycomm3 could not make sense of the reply
    "failed to parse reply",
    "failed parsing tag read reply",
    "one or more fragment responses failed",
    "unknown error",
)
# pycomm3's messages for a tag that is not in the controller (they carry the
# tag name): always about the address, whatever the tag is called
_MISSING_TAG_TEXTS = ("tag doesn't exist", "failed to get tag data for")


def _is_address_error(error: Any) -> bool:
    """False for an error reply that says nothing about the address (see _TRANSIENT_ERROR_TEXTS)"""
    text = str(error).lower()
    if text.startswith(_MISSING_TAG_TEXTS):
        return True
    return not any(phrase in text for phrase in _TRANSIENT_ERROR_TEXTS)


def _logix_batches(tags: List[str]) -> List[List[str]]:
    """
    Tags grouped per LogixDriver.read() call: TAG_BATCH_SIZE single values,
    an array read ("Tag[0]{1000}") alone. pycomm3 reads a large array with
    one request per fragment, back to back; in a batch of 20 arrays that was
    hundreds of requests inside one call, under one request timeout.
    """
    batches: List[List[str]] = []
    batch: List[str] = []
    for tag in tags:
        if split_element_count(tag)[1] > 1:
            if batch:
                batches.append(batch)
                batch = []
            batches.append([tag])
            continue
        batch.append(tag)
        if len(batch) == TAG_BATCH_SIZE:
            batches.append(batch)
            batch = []
    if batch:
        batches.append(batch)
    return batches


def _capture(func, *args):
    """func(*args), or the SymbolicReadError it raised (other errors propagate)"""
    try:
        return func(*args)
    except SymbolicReadError as e:
        return e


def _generic_request_groups(tags: List[Tuple[int, str]]) -> List[List[Tuple[int, str]]]:
    """Consecutive single-value tags batched (MAX_BATCH_TAGS); element-count reads alone"""
    groups: List[List[Tuple[int, str]]] = []
    batch: List[Tuple[int, str]] = []
    for item in tags:
        tag = item[1]
        if tag.rstrip().endswith("}"):
            if batch:
                groups.append(batch)
                batch = []
            groups.append([item])
            continue
        batch.append(item)
        if len(batch) >= MAX_BATCH_TAGS or sum(len(t) + 8 for _, t in batch) >= MAX_BATCH_REQUEST_BYTES:
            groups.append(batch)
            batch = []
    if batch:
        groups.append(batch)
    return groups


# Tags per read request batch (LogixDriver packs them into multi-service packets)
TAG_BATCH_SIZE = 20

# Elements read from each array tag in a full scan
MAX_TAG_ARRAY_ELEMENTS = 1000


# Hex digits of the integer CIP types (two per byte); other integers are
# sized by their value
_CIP_HEX_DIGITS = {
    "BOOL": 2,
    "SINT": 2,
    "USINT": 2,
    "BYTE": 2,
    "INT": 4,
    "UINT": 4,
    "WORD": 4,
    "DINT": 8,
    "UDINT": 8,
    "DWORD": 8,
    "LINT": 16,
    "ULINT": 16,
    "LWORD": 16,
}


def _tag_hex(value: int, type_name: Optional[str] = None) -> str:
    """
    Hex of a tag's integer value in the width of its CIP type, so a DINT
    of -1 reads 0xFFFFFFFF (not 0xFFFF) and 64-bit values keep all their
    bits. Without a known type (structure members) the width is the
    smallest of 16 / 32 / 64 bits holding the value.
    """
    digits = _CIP_HEX_DIGITS.get((type_name or "").split("[")[0].strip().upper())
    if digits is None:
        if -0x8000 <= value <= 0xFFFF:
            digits = 4
        elif -0x80000000 <= value <= 0xFFFFFFFF:
            digits = 8
        else:
            digits = 16
    return f"0x{value & ((1 << (4 * digits)) - 1):0{digits}X}"


def _tag_point(name: str, status: StatusCode, value: Any = None, type_name: Optional[str] = None) -> DataPoint:
    """Data point for one tag value (``type_name``: its CIP type when known)"""
    point = DataPoint(address=name, status=status, timestamp=get_timestamp(), is_tag=True)
    if status != StatusCode.OK:
        return point
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        point.value = value
        point.raw_hex = _tag_hex(value, type_name)
    elif isinstance(value, float):
        point.data_type = "REAL"
        point.converted_value = value
        point.display_value = f"{value:.7g}"
    else:
        point.converted_value = value
        point.display_value = str(value)
    return point


def _tag_points(name: str, reply: Any, data_types: Optional[Dict[str, Any]] = None) -> List[DataPoint]:
    """
    Data points for one LogixDriver reply (Tag(tag, value, type, error)).
    ``data_types``: the controller's structure definitions (LogixDriver's
    data_types), giving the type of each structure member.
    """
    if reply is None or getattr(reply, "error", None):
        error = getattr(reply, "error", "no reply")
        logger.debug(f"Tag {name}: {error}")
        # Only an error about the tag itself makes it "inaccessible" (learned
        # and listed as denied); a busy controller is a communication error
        status = (
            StatusCode.NG_ILLEGAL_ADDR if reply is not None and _is_address_error(error) else StatusCode.NG_COMM_ERROR
        )
        return [_tag_point(name.split("{")[0], status)]
    reply_type = getattr(reply, "type", None)
    return _value_points(name, reply.value, reply_type if isinstance(reply_type, str) else None, data_types)


def _member_type(data_types: Optional[Dict[str, Any]], struct_name: Optional[str], member: str) -> Optional[str]:
    """Type name of a structure member from the structure definitions (None when unknown)"""
    if not data_types or not struct_name:
        return None
    try:
        definition = data_types[struct_name.split("[")[0].strip()]
        member_type = definition["internal_tags"][member]["data_type_name"]
    except (KeyError, TypeError, AttributeError):
        return None
    return member_type if isinstance(member_type, str) else None


def _value_points(
    name: str, value: Any, type_name: Optional[str] = None, data_types: Optional[Dict[str, Any]] = None
) -> List[DataPoint]:
    """
    Data points for a tag value: one per array element ("Tag[i]") and per
    structure member ("Tag.Member", nested: "Tag.Sub.Member", "Tag[1].Member").
    ``type_name`` is the CIP type of the value (of each element for arrays).
    """
    if isinstance(value, list):
        base = name.split("{")[0]
        prefix, _, first = base.rpartition("[")
        if prefix and first.rstrip("]").isdigit():
            start = int(first.rstrip("]"))
        else:
            prefix, start = base, 0
        points = []
        for i, element in enumerate(value):
            points += _flatten(f"{prefix}[{start + i}]", element, type_name, data_types)
        return points
    return _flatten(name.split("{")[0], value, type_name, data_types)


def _flatten(
    name: str, value: Any, type_name: Optional[str] = None, data_types: Optional[Dict[str, Any]] = None
) -> List[DataPoint]:
    # A structure's members have their own types: taken from the structure
    # definitions when the controller provided them (Logix), else unknown
    # (the hex width then follows the value)
    if isinstance(value, dict):
        points = []
        for member, member_value in value.items():
            member_type = _member_type(data_types, type_name, member)
            points += _flatten(f"{name}.{member}", member_value, member_type, data_types)
        return points
    if isinstance(value, list):
        points = []
        for i, element in enumerate(value):
            points += _flatten(f"{name}[{i}]", element, type_name, data_types)
        return points
    return [_tag_point(name, StatusCode.OK, value, type_name)]
