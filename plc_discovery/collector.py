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
from typing import Dict, List, Optional, Callable, Type
import logging

from .config import (
    Protocol, DeviceType, DeviceRange, DataPoint, StatusCode,
    PLCInfo, NetworkConfig, ScanMode, DEFAULT_DEVICE_RANGES
)
from .protocols.base import BaseProtocolHandler
from .protocols.slmp import SLMPHandler
from .protocols.ethernet_ip import EtherNetIPHandler
from .protocols.modbus import ModbusHandler
from .protocols.s7 import S7Handler
from .protocols.fins import FINSHandler
from .utils import get_timestamp, logger

# Protocol to handler mapping
PROTOCOL_HANDLERS: Dict[Protocol, Callable[..., BaseProtocolHandler]] = {
    Protocol.SLMP: SLMPHandler,
    Protocol.ETHERNET_IP: EtherNetIPHandler,
    Protocol.MODBUS_TCP: ModbusHandler,
    Protocol.S7: S7Handler,
    Protocol.FINS: FINSHandler,
    Protocol.FINS_TCP: functools.partial(FINSHandler, use_tcp=True),
}


class PLCDataCollector:
    """
    PLC Data Collector
    
    Collects device data from PLCs with automatic error recovery
    using binary search algorithm.
    """
    
    def __init__(
        self,
        plc_info: PLCInfo,
        config: Optional[NetworkConfig] = None
    ):
        self.plc_info = plc_info
        self.config = config or NetworkConfig()
        self._handler: Optional[BaseProtocolHandler] = None
        # Why connect() failed before reaching the PLC (bad options etc.)
        self.connect_error: Optional[str] = None
        self._collected_data: List[DataPoint] = []
        self._denied_addresses: set = set()
        self._denied_statuses: Dict[str, StatusCode] = {}
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
    
    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def _report_progress(self, message: str, current: int = 0, total: int = 0):
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
        
        try:
            self._handler = handler_class(
                ip_address=self.plc_info.ip_address,
                port=self.plc_info.port,
                config=self.config,
                **(self.plc_info.options or {})
            )
        except (TypeError, ValueError) as e:
            # Unknown option name (TypeError) or out-of-range value (ValueError):
            # fail this target only, the caller continues with the others
            self.connect_error = f"invalid options {self.plc_info.options}: {e}"
            logger.error(f"Invalid options for {protocol.name}: {self.plc_info.options} ({e})")
            return False
        
        return await self._handler.connect()
    
    async def disconnect(self):
        """Disconnect from PLC"""
        if self._handler:
            # Save denied addresses before disconnect
            self._denied_addresses = self._handler.get_denied_addresses()
            self._denied_statuses = self._handler.get_denied_statuses()
            await self._handler.disconnect()
            self._handler = None
    
    async def _ensure_link(self) -> bool:
        """
        Make sure the handler is connected before reading.
        
        A handler whose reconnect failed (PLC power-cycled, cable pulled)
        stays disconnected; it is reconnected here on every collection so a
        periodic scan recovers as soon as the PLC is reachable again.
        """
        if self._handler.is_connected:
            return True
        logger.info(f"Connection to {self.plc_info.ip_address} lost; reconnecting")
        self._handler._needs_reconnect = True
        if not await self._handler._ensure_fresh_connection():
            return False
        # The PLC is back: forget the failures from the outage so the circuit
        # breaker and lost-link detection do not block the first reads
        self._handler._comm_failure_streak = 0
        self._handler.reset_circuit_breaker()
        logger.info(f"Reconnected to {self.plc_info.ip_address}")
        return True
    
    def _unreachable_points(self, device_range: DeviceRange) -> List[DataPoint]:
        """NG_COMM_ERROR points for a range that could not be read (not learned)"""
        logger.warning(
            f"{self.plc_info.ip_address} unreachable: "
            f"{device_range.device_type.value}{device_range.start_address}-"
            f"{device_range.device_type.value}{device_range.end_address} reported as NG_COMM_ERROR"
        )
        return self._handler._failed_points(
            device_range.device_type, device_range.start_address, device_range.end_address,
            StatusCode.NG_COMM_ERROR, learn=False
        )
    
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
        device_ranges = DEFAULT_DEVICE_RANGES.get(protocol, [])
        
        if not device_ranges:
            logger.warning(f"No default device ranges for protocol: {protocol}")
            return []
        
        self._collected_data = []
        total_ranges = len(device_ranges)
        
        if not await self._ensure_link():
            # Report every address as a communication error instead of
            # returning nothing, so the output shows the PLC was unreachable
            for device_range in device_ranges:
                self._collected_data.extend(self._unreachable_points(device_range))
            return self._collected_data
        
        self._report_progress(
            f"Starting full scan of {self.plc_info.ip_address}",
            0, total_ranges
        )
        
        for i, device_range in enumerate(device_ranges):
            self._report_progress(
                f"Scanning {device_range.device_type.value} "
                f"({device_range.start_address}-{device_range.end_address})",
                i + 1, total_ranges
            )
            
            try:
                data_points = await self._handler.read_device_range(device_range)
                self._collected_data.extend(data_points)
            except Exception as e:
                logger.error(f"Error scanning {device_range.device_type.value}: {e}")
                # Continue with next range - don't stop on errors
        
        self._report_progress(
            f"Full scan complete. Collected {len(self._collected_data)} data points.",
            total_ranges, total_ranges
        )
        
        return self._collected_data
    
    async def collect_range(
        self,
        device_type: DeviceType,
        start_address: int,
        end_address: int
    ) -> List[DataPoint]:
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
        
        self._report_progress(
            f"Reading {device_type.value}{start_address}-{device_type.value}{end_address}"
        )
        
        try:
            data_points = await self._handler.read_device_range(device_range)
            self._collected_data.extend(data_points)
            
            self._report_progress(
                f"Collected {len(data_points)} data points from "
                f"{device_type.value}{start_address}-{device_type.value}{end_address}"
            )
            
            return data_points
        except Exception as e:
            logger.error(f"Error collecting range: {e}")
            return []
    
    async def collect_with_interval(
        self,
        device_type: DeviceType,
        start_address: int,
        end_address: int,
        interval_seconds: float,
        duration_seconds: Optional[float] = None,
        max_iterations: Optional[int] = None
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
            data_points = await self.collect_range(
                device_type, start_address, end_address
            )
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
        success = sum(1 for dp in self._collected_data if dp.status == StatusCode.OK)
        illegal = sum(1 for dp in self._collected_data if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        timeout = sum(1 for dp in self._collected_data if dp.status == StatusCode.NG_TIMEOUT)
        error = sum(1 for dp in self._collected_data if dp.status == StatusCode.NG_COMM_ERROR)
        unsupported = sum(1 for dp in self._collected_data if dp.status == StatusCode.NG_UNSUPPORTED)
        
        return {
            "total_points": total,
            "success_count": success,
            "illegal_address_count": illegal,
            "timeout_count": timeout,
            "error_count": error,
            "unsupported_count": unsupported,
            "success_rate": f"{(success / total * 100):.2f}%" if total > 0 else "N/A",
            "denied_addresses": len(self.get_denied_addresses()),
        }
    
    def clear_data(self):
        """Clear collected data"""
        self._collected_data = []
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
        return False


async def collect_plc_data(
    plc_info: PLCInfo,
    mode: ScanMode = ScanMode.FULL,
    device_type: Optional[DeviceType] = None,
    start_address: int = 0,
    end_address: int = 0,
    interval_seconds: float = 0,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None
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
                    device_type, start_address, end_address,
                    interval_seconds, max_iterations=1
                )
                return results[0] if results else []
            else:
                return await collector.collect_range(
                    device_type, start_address, end_address
                )
        else:
            logger.error(f"Invalid mode or missing parameters: {mode}")
            return []


def get_handler_for_protocol(protocol: Protocol) -> Optional[Callable[..., BaseProtocolHandler]]:
    """Get the handler factory (class or partial) for a given protocol"""
    return PROTOCOL_HANDLERS.get(protocol)


