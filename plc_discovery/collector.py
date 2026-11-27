"""
Data Collector Module - PLC Data Collection with Binary Search Error Recovery

This module provides comprehensive data collection from PLCs with:
- Automatic protocol detection and handler selection
- Full scan mode for factory downtime
- Range-specified mode for production time
- Binary search algorithm for error recovery
- Session-based learning for inaccessible addresses
"""

import asyncio
import functools
from typing import Any, Callable, Dict, List, Optional, Union

from .config import (
    DEFAULT_DEVICE_RANGES,
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
    TagRange,
)
from .protocols.base import BaseProtocolHandler
from .protocols.cip_symbolic import split_element_count
from .protocols.ethernet_ip import EtherNetIPHandler
from .protocols.fins import FINSHandler
from .protocols.modbus import ModbusHandler
from .protocols.s7 import S7Handler
from .protocols.slmp import SLMPHandler
from .utils import get_timestamp, logger, status_counts, success_rate_text

# Protocol to handler mapping
PROTOCOL_HANDLERS: Dict[Protocol, Callable[..., BaseProtocolHandler]] = {
    Protocol.SLMP: SLMPHandler,
    Protocol.ETHERNET_IP: EtherNetIPHandler,
    Protocol.MODBUS_TCP: ModbusHandler,
    Protocol.S7: S7Handler,
    Protocol.FINS: FINSHandler,
    Protocol.FINS_TCP: functools.partial(FINSHandler, use_tcp=True),
    Protocol.SLMP_UDP: functools.partial(SLMPHandler, udp=1),
}


class PLCDataCollector:
    """
    PLC Data Collector

    Collects device data from PLCs with automatic error recovery
    using binary search algorithm.
    """

    def __init__(self, plc_info: PLCInfo, config: Optional[NetworkConfig] = None):
        self.plc_info = plc_info
        self.config = config or NetworkConfig()
        self._handler: Optional[BaseProtocolHandler] = None
        # Why connect() failed before reaching the PLC (bad options etc.)
        self.connect_error: Optional[str] = None
        self._collected_data: List[DataPoint] = []
        self._denied_addresses: set = set()
        self._denied_statuses: Dict[str, StatusCode] = {}
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
        # Set by collect_items() for the rest of a scan once a range found
        # the PLC unreachable: one reconnect attempt per scan, not per range
        self.skip_reconnect = False
        # Requests / answers / response ms (total, max) of handlers already
        # closed: disconnect() drops the handler, and the statistics are
        # read after it (a reconnect during a scan keeps the same handler)
        self._request_totals = [0, 0, 0.0, 0.0]
        # A handler already closed saw the device close the connection
        # before answering anything (see closed_by_device)
        self._closed_by_device = False

    def set_progress_callback(self, callback: Callable[[str, int, int], None]) -> None:
        """Set callback for progress updates"""
        self._progress_callback = callback

    def _report_progress(self, message: str, current: int = 0, total: int = 0) -> None:
        """Report progress to callback if set"""
        if self._progress_callback:
            self._progress_callback(message, current, total)
        else:
            logger.info(f"{message} ({current}/{total})" if total else message)

    @property
    def is_connected(self) -> bool:
        """True when a protocol handler is connected to the PLC"""
        return self._handler is not None and self._handler.is_connected

    async def connect(self) -> bool:
        """
        Connect to PLC using appropriate protocol handler.

        Returns:
            True if connection successful
        """
        protocol = self.plc_info.protocol
        if not protocol:
            logger.error(f"No protocol specified for {self.plc_info.ip_address}")
            return False

        handler_class = PROTOCOL_HANDLERS.get(protocol)
        if not handler_class:
            logger.error(f"No handler for protocol: {protocol}")
            return False

        self._absorb_request_counts()
        try:
            self._handler = handler_class(
                ip_address=self.plc_info.ip_address,
                port=self.plc_info.port,
                config=self.config,
                **(self.plc_info.options or {}),
            )
        except (TypeError, ValueError) as e:
            # Unknown option name (TypeError) or out-of-range value (ValueError):
            # fail this target only, the caller continues with the others
            self.connect_error = f"invalid options {self.plc_info.options}: {e}"
            logger.error(f"Invalid options for {protocol.name}: {self.plc_info.options} ({e})")
            return False

        connected = await self._handler.connect()
        self._keep_detected_settings()
        return connected

    def _keep_detected_settings(self) -> None:
        """
        Settings the handler found out (SLMP frame / data code) are kept in
        the target's options for the next connection, so they are not
        detected again; the CPU model and the settings it answered go to
        the target's model / note (scan summary), a name the user gave wins.
        """
        handler = self._handler
        detected = getattr(handler, "detected_options", None)
        if isinstance(detected, dict) and detected:
            self.plc_info.options = {**detected, **(self.plc_info.options or {})}
        identity = getattr(handler, "identity", None)
        if isinstance(identity, dict) and not self.plc_info.note:
            from .discovery import apply_slmp_identity

            model, options = self.plc_info.model, dict(self.plc_info.options or {})
            apply_slmp_identity(self.plc_info, identity)
            self.plc_info.model = model or self.plc_info.model
            self.plc_info.options = options
        elif isinstance(detected, dict) and detected and not self.plc_info.note:
            # Settled by a read the PLC answered (no model name answer)
            from .discovery import slmp_settings_note

            self.plc_info.note = slmp_settings_note(
                f"{detected['frame']}E", bool(detected["ascii"]), self.plc_info.protocol == Protocol.SLMP_UDP
            )

    def _handler_closed_by_device(self) -> bool:
        return getattr(self._handler, "closed_before_answer", False) is True

    @property
    def closed_by_device(self) -> bool:
        """
        The device closed the connection before answering anything - for a
        PLC typically because its connections are all in use (a gateway or
        a GOT connected), told apart from a PLC that does not answer
        """
        return self._closed_by_device or self._handler_closed_by_device()

    def _absorb_request_counts(self) -> None:
        """Add the current handler's request counts to the totals (before it is dropped)"""
        handler = self._handler
        if handler is None or not isinstance(getattr(handler, "request_count", None), int):
            return
        totals = self._request_totals
        totals[0] += handler.request_count
        totals[1] += handler.answered_count
        totals[2] += handler.response_ms_total
        totals[3] = max(totals[3], handler.response_ms_max)
        handler.request_count = handler.answered_count = 0
        handler.response_ms_total = handler.response_ms_max = 0.0

    async def disconnect(self):
        """Disconnect from PLC"""
        if self._handler:
            # Save denied addresses before disconnect
            self._denied_addresses = self._handler.get_denied_addresses()
            self._denied_statuses = self._handler.get_denied_statuses()
            await self._handler.disconnect()
            self._closed_by_device = self._closed_by_device or self._handler_closed_by_device()
            self._keep_detected_settings()
            self._absorb_request_counts()
            self._handler = None

    async def _ensure_link(self) -> bool:
        """
        Make sure the handler is connected before reading.

        A handler whose reconnect failed (PLC power-cycled, cable pulled)
        stays disconnected; it is reconnected here on every collection so a
        periodic scan recovers as soon as the PLC is reachable again.
        """
        handler = self._handler
        if handler is None:
            return False
        if handler.is_connected:
            return True
        if self.skip_reconnect:
            # The reconnect has just failed for an earlier range of this
            # scan: the other ranges do not each wait for another
            # connection timeout (and delay the other PLCs)
            return False
        logger.info(f"Connection to {self.plc_info.ip_address} lost; reconnecting")
        if not await handler.reconnect():
            return False
        logger.info(f"Reconnected to {self.plc_info.ip_address}")
        return True

    def _unreachable_points(self, device_range: DeviceRange) -> List[DataPoint]:
        """NG_COMM_ERROR points for a range that could not be read (not learned)"""
        logger.warning(
            f"{self.plc_info.ip_address} unreachable: "
            f"{device_range.device_type.value}{device_range.start_address}-"
            f"{device_range.device_type.value}{device_range.end_address} reported as NG_COMM_ERROR"
        )
        return comm_error_points(device_range)

    def _read_error_points(self, device_range: DeviceRange, error: Exception) -> List[DataPoint]:
        """
        NG_COMM_ERROR points for a range whose read raised an unexpected
        exception (library or handler bug, broken link): every requested
        address still appears in the output. The connection is re-established
        before the next read.
        """
        logger.error(
            f"Error reading {device_range.device_type.value}{device_range.start_address}-"
            f"{device_range.device_type.value}{device_range.end_address}: {error}; reported as NG_COMM_ERROR"
        )
        if self._handler is not None:
            self._handler.mark_needs_reconnect()
        return comm_error_points(device_range)

    def _tag_error_points(self, tags: List[str], error: Exception) -> List[DataPoint]:
        """
        NG_COMM_ERROR points for tags whose read raised an unexpected
        exception (as _read_error_points for address ranges): every
        requested tag still appears in the output and the scan continues.
        """
        logger.error(f"Error reading {len(tags)} tag(s): {error or type(error).__name__}; reported as NG_COMM_ERROR")
        if self._handler is not None:
            self._handler.partial_points = []
            self._handler.mark_needs_reconnect()
        return comm_error_points(TagRange(list(tags)))

    def _keep_partial_points(self) -> None:
        """
        Interrupted (Ctrl+C) in the middle of a range: keep the points of
        the chunks already read, so the caller can still write them.
        """
        if self._handler is not None:
            self._collected_data.extend(self._handler.partial_points)
            self._handler.partial_points = []

    async def collect_full_scan(self) -> List[DataPoint]:
        """
        Perform full scan of all default device ranges.

        This mode is intended for factory downtime and collects
        all available device data.

        Returns:
            List of DataPoint objects
        """
        if not self._handler:
            logger.error("Not connected to PLC")
            return []

        protocol = self.plc_info.protocol

        # Logix (symbolic tags, no numeric addresses): read every tag of the
        # controller's tag list instead of the data-file ranges. Devices
        # without a tag list (Omron NJ/NX) fall through: their variables are
        # read with --tags.
        tag_handler: Any = self._handler  # EtherNetIPHandler offers the tag API
        tags: List[str] = []
        linked: Optional[bool] = None
        if hasattr(tag_handler, "tag_scan_list"):
            # The link first: after an outage a Logix handler has no client
            # until it reconnects, and "no tags" then sent the scan to the
            # data-file ranges - 512 rows of NG_UNSUPPORTED, learned as denied
            linked = await self._ensure_link()
            if linked and getattr(tag_handler, "supports_tags", False) is True:
                tags = tag_handler.tag_scan_list()
        if tags:
            self._report_progress(f"Full scan of {len(tags)} tags on {self.plc_info.ip_address}", 0, 1)
            self._collected_data = []
            try:
                self._collected_data = await tag_handler.read_tags(tags)
            except asyncio.CancelledError:
                self._keep_partial_points()  # thousands of tags: keep those already read
                raise
            except Exception as e:
                self._collected_data = self._tag_error_points(tags, e)
            self._report_progress(f"Full scan complete. Collected {len(self._collected_data)} data points.", 1, 1)
            return self._collected_data

        device_ranges = DEFAULT_DEVICE_RANGES.get(protocol, []) if protocol else []

        if not device_ranges:
            logger.warning(f"No default device ranges for protocol: {protocol}")
            return []

        self._collected_data = []
        total_ranges = len(device_ranges)

        if not (await self._ensure_link() if linked is None else linked):
            # Report every address as a communication error instead of
            # returning nothing, so the output shows the PLC was unreachable.
            # EtherNet/IP data-file ranges only apply to SLC-style devices;
            # a Logix / Omron controller gets the single "ALL" row instead.
            if not self._handler.uses_address_ranges:
                logger.warning(f"{self.plc_info.ip_address} unreachable: full scan reported as NG_COMM_ERROR")
                self._collected_data = unreached_points(protocol, None)
                return self._collected_data
            for device_range in device_ranges:
                self._collected_data.extend(self._unreachable_points(device_range))
            return self._collected_data

        self._report_progress(f"Starting full scan of {self.plc_info.ip_address}", 0, total_ranges)

        for i, device_range in enumerate(device_ranges):
            self._report_progress(
                f"Scanning {device_range.device_type.value} "
                f"({device_range.start_address}-{device_range.end_address})",
                i + 1,
                total_ranges,
            )

            try:
                data_points = await self._handler.read_device_range(device_range)
            except asyncio.CancelledError:
                self._keep_partial_points()
                raise
            except Exception as e:
                # Continue with the next range - don't stop on errors
                data_points = self._read_error_points(device_range, e)
            self._collected_data.extend(data_points)

        self._report_progress(
            f"Full scan complete. Collected {len(self._collected_data)} data points.", total_ranges, total_ranges
        )

        return self._collected_data

    async def collect_range(self, device_type: DeviceType, start_address: int, end_address: int) -> List[DataPoint]:
        """
        Collect data from a specific device range.

        Args:
            device_type: Type of device to read (D, M, etc.)
            start_address: Starting address
            end_address: Ending address

        Returns:
            List of DataPoint objects
        """
        if not self._handler:
            logger.error("Not connected to PLC")
            return []

        device_range = DeviceRange(device_type, start_address, end_address)

        if not await self._ensure_link():
            data_points = self._unreachable_points(device_range)
            self._collected_data.extend(data_points)
            return data_points

        self._report_progress(f"Reading {device_type.value}{start_address}-{device_type.value}{end_address}")

        try:
            data_points = await self._handler.read_device_range(device_range)
        except asyncio.CancelledError:
            self._keep_partial_points()
            raise
        except Exception as e:
            data_points = self._read_error_points(device_range, e)
        self._collected_data.extend(data_points)

        self._report_progress(
            f"Collected {len(data_points)} data points from "
            f"{device_type.value}{start_address}-{device_type.value}{end_address}"
        )
        return data_points

    async def collect_tags(self, tags: List[str]) -> List[DataPoint]:
        """
        Read symbolic tags (EtherNet/IP Logix controllers). On other
        devices every tag is reported NG_UNSUPPORTED.
        """
        if not self._handler:
            logger.error("Not connected to PLC")
            return []
        if not await self._ensure_link():
            points = [
                DataPoint(address=t, status=StatusCode.NG_COMM_ERROR, timestamp=get_timestamp(), is_tag=True)
                for t in tags
            ]
        elif hasattr(self._handler, "read_tags"):
            tag_handler: Any = self._handler
            try:
                points = await tag_handler.read_tags(tags)
            except asyncio.CancelledError:
                self._keep_partial_points()
                raise
            except Exception as e:
                points = self._tag_error_points(tags, e)
        else:
            points = [
                DataPoint(address=t, status=StatusCode.NG_UNSUPPORTED, timestamp=get_timestamp(), is_tag=True)
                for t in tags
            ]
        self._collected_data.extend(points)
        return points

    async def collect_with_interval(
        self,
        device_type: DeviceType,
        start_address: int,
        end_address: int,
        interval_seconds: float,
        duration_seconds: Optional[float] = None,
        max_iterations: Optional[int] = None,
    ) -> List[List[DataPoint]]:
        """
        Collect data repeatedly at specified intervals.

        Args:
            device_type: Type of device to read
            start_address: Starting address
            end_address: Ending address
            interval_seconds: Interval between reads
            duration_seconds: Total duration (optional)
            max_iterations: Maximum number of iterations (optional)

        Returns:
            List of DataPoint lists (one per iteration)
        """
        all_results = []
        iteration = 0
        loop = asyncio.get_running_loop()
        start_time = loop.time()

        while True:
            iteration += 1
            self._report_progress(f"Iteration {iteration}")

            # Collect data (keep only this iteration in _collected_data)
            self.clear_data()
            data_points = await self.collect_range(device_type, start_address, end_address)
            all_results.append(data_points)

            # Check termination conditions before waiting
            if max_iterations and iteration >= max_iterations:
                break

            # Fixed-rate schedule: the next iteration starts interval_seconds
            # after the previous one started, regardless of read duration
            next_start = start_time + iteration * interval_seconds
            if duration_seconds and next_start - start_time >= duration_seconds:
                break

            await asyncio.sleep(max(0.0, next_start - loop.time()))

        return all_results

    def get_collected_data(self) -> List[DataPoint]:
        """Get all collected data points"""
        return self._collected_data

    def get_denied_addresses(self) -> set:
        """Get addresses that were marked as inaccessible"""
        if self._handler:
            return self._handler.get_denied_addresses()
        return self._denied_addresses

    def get_denied_statuses(self) -> Dict[str, StatusCode]:
        """Get inaccessible addresses with their status"""
        if self._handler:
            return self._handler.get_denied_statuses()
        return dict(self._denied_statuses)

    def get_statistics(self) -> Dict:
        """
        Get collection statistics.

        Returns:
            Dictionary with statistics
        """
        total = len(self._collected_data)
        counts = status_counts(self._collected_data)

        return {
            "total_points": total,
            "success_count": counts[StatusCode.OK],
            "illegal_address_count": counts[StatusCode.NG_ILLEGAL_ADDR],
            "timeout_count": counts[StatusCode.NG_TIMEOUT],
            "error_count": counts[StatusCode.NG_COMM_ERROR],
            "unsupported_count": counts[StatusCode.NG_UNSUPPORTED],
            "success_rate": success_rate_text(counts[StatusCode.OK], total),
            "denied_addresses": len(self.get_denied_addresses()),
            **self.request_statistics(),
        }

    def request_statistics(self) -> Dict[str, Any]:
        """
        Requests sent to the PLC and its response times (answered requests;
        ms, rounded to 0.1), over every connection of this collector. Empty
        before a connection was made.
        """
        requests, answered, total_ms, max_ms = self._request_totals
        handler = self._handler
        if handler is not None and isinstance(getattr(handler, "request_count", None), int):
            requests += handler.request_count
            answered += handler.answered_count
            total_ms += handler.response_ms_total
            max_ms = max(max_ms, handler.response_ms_max)
        elif not requests:
            return {}  # never connected (or a stand-in handler without the counters)
        return {
            "requests": requests,
            "avg_response_ms": round(total_ms / answered, 1) if answered else None,
            "max_response_ms": round(max_ms, 1) if answered else None,
        }

    def clear_data(self):
        """Clear collected data"""
        self._collected_data = []

    async def __aenter__(self) -> "PLCDataCollector":
        """Async context manager entry"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit (exceptions propagate)"""
        await self.disconnect()


async def collect_plc_data(
    plc_info: PLCInfo,
    mode: ScanMode = ScanMode.FULL,
    device_type: Optional[DeviceType] = None,
    start_address: int = 0,
    end_address: int = 0,
    interval_seconds: float = 0,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> List[DataPoint]:
    """
    Convenience function to collect PLC data.

    Args:
        plc_info: PLC information (IP, protocol, etc.)
        mode: Scan mode (full or range)
        device_type: Device type for range mode
        start_address: Start address for range mode
        end_address: End address for range mode
        interval_seconds: Interval for repeated collection
        config: Network configuration
        progress_callback: Progress callback function

    Returns:
        List of DataPoint objects
    """
    async with PLCDataCollector(plc_info, config) as collector:
        if progress_callback:
            collector.set_progress_callback(progress_callback)

        if mode == ScanMode.FULL:
            return await collector.collect_full_scan()
        elif mode == ScanMode.RANGE and device_type:
            if interval_seconds > 0:
                results = await collector.collect_with_interval(
                    device_type, start_address, end_address, interval_seconds, max_iterations=1
                )
                return results[0] if results else []
            else:
                return await collector.collect_range(device_type, start_address, end_address)
        else:
            logger.error(f"Invalid mode or missing parameters: {mode}")
            return []


# Address of the row standing for a whole full scan that could not be read
FULL_SCAN_ADDRESS = "ALL"


def comm_error_points(item: Union[DeviceRange, TagRange]) -> List[DataPoint]:
    """
    NG_COMM_ERROR data points for every address (or tag) of a requested
    range that could not be read at all, so the output still lists them.
    Not learned as inaccessible: communication errors are transient.
    """
    timestamp = get_timestamp()
    if isinstance(item, TagRange):
        return [
            DataPoint(
                address=split_element_count(tag)[0], status=StatusCode.NG_COMM_ERROR, timestamp=timestamp, is_tag=True
            )
            for tag in item.tags
        ]
    prefix = item.device_type.value
    return [
        DataPoint(address=f"{prefix}{address}", status=StatusCode.NG_COMM_ERROR, timestamp=timestamp)
        for address in range(item.start_address, item.end_address + 1)
    ]


def unreached_points(
    protocol: Optional[Protocol], items: Optional[List[Union[DeviceRange, TagRange]]]
) -> List[DataPoint]:
    """
    NG_COMM_ERROR points for everything a scan would have read when the PLC
    could not be connected: the requested ranges / tags, or (items None) the
    protocol's full-scan ranges.
    """
    if items is None:
        if protocol == Protocol.ETHERNET_IP:
            # Data files (D/M = N7/B3) exist on SLC-style devices only; a
            # Logix / Omron controller has tags. Without a connection the kind
            # is unknown: one row says the whole full scan could not be read.
            return [DataPoint(address=FULL_SCAN_ADDRESS, status=StatusCode.NG_COMM_ERROR, timestamp=get_timestamp())]
        items = list(DEFAULT_DEVICE_RANGES.get(protocol, [])) if protocol else []
    points: List[DataPoint] = []
    for item in items:
        points.extend(comm_error_points(item))
    return points


async def collect_item(collector: "PLCDataCollector", item: Union[DeviceRange, TagRange]) -> List[DataPoint]:
    """Collect one DeviceRange or TagRange of a range-mode scan"""
    if isinstance(item, TagRange):
        return await collector.collect_tags(item.tags)
    return await collector.collect_range(item.device_type, item.start_address, item.end_address)


def get_handler_for_protocol(protocol: Protocol) -> Optional[Callable[..., BaseProtocolHandler]]:
    """Get the handler factory (class or partial) for a given protocol"""
    return PROTOCOL_HANDLERS.get(protocol)
