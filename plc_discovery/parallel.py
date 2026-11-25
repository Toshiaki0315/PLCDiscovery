"""
Parallel PLC Processing Module

Provides concurrent processing of multiple PLCs with rate limiting
and proper error isolation.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .audit_log import get_audit_logger
from .collector import PLCDataCollector, unreached_points
from .config import DataPoint, DeviceRange, NetworkConfig, PLCInfo, ScanMode, StatusCode
from .discovery import target_labels
from .scan_runner import collect_items, no_answer_error
from .utils import success_rate_text

logger = logging.getLogger(__name__)


@dataclass
class PLCScanResult:
    """Result of scanning a single PLC"""

    plc_info: PLCInfo
    data_points: List[DataPoint]
    denied_addresses: set
    success: bool
    error_message: Optional[str]
    start_time: datetime
    end_time: datetime
    denied_statuses: Dict[str, StatusCode] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        """Get scan duration in milliseconds"""
        return (self.end_time - self.start_time).total_seconds() * 1000

    @property
    def statistics(self) -> Dict[str, Any]:
        """Get statistics for this scan"""
        total = len(self.data_points)
        success_count = sum(1 for dp in self.data_points if dp.status == StatusCode.OK)

        return {
            "total_points": total,
            "success_count": success_count,
            "error_count": total - success_count,
            "denied_addresses": len(self.denied_addresses),
            "duration_ms": self.duration_ms,
            "success_rate": success_rate_text(success_count, total),
        }


class ParallelPLCScanner:
    """
    Parallel PLC scanner with concurrency control.

    Scans multiple PLCs concurrently with configurable max_concurrent limit.
    Each PLC scan is isolated so errors in one don't affect others.
    """

    def __init__(
        self,
        config: Optional[NetworkConfig] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        self.config = config or NetworkConfig()
        self.progress_callback = progress_callback
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._results: Dict[str, PLCScanResult] = {}
        self._audit = get_audit_logger()

    def _report_progress(self, message: str, current: int = 0, total: int = 0) -> None:
        """Report progress"""
        if self.progress_callback:
            self.progress_callback(message, current, total)
        else:
            logger.info(f"{message} ({current}/{total})" if total else message)

    async def scan_multiple_plcs(
        self, plcs: List[PLCInfo], mode: ScanMode = ScanMode.FULL, device_ranges: Optional[List[DeviceRange]] = None
    ) -> Dict[str, PLCScanResult]:
        """
        Scan multiple PLCs concurrently.

        Args:
            plcs: List of PLCs to scan
            mode: Scan mode (FULL or RANGE)
            device_ranges: Device ranges for RANGE mode

        Returns:
            Dictionary mapping each target's label (see target_labels) to its result
        """
        if not plcs:
            return {}

        # Create semaphore for concurrency control
        # At least 1: a semaphore of 0 never lets a scan start (waits for good)
        max_concurrent = max(1, self.config.max_concurrent)
        self._semaphore = asyncio.Semaphore(max_concurrent)

        self._report_progress(
            f"Starting parallel scan of {len(plcs)} PLCs (max {max_concurrent} concurrent)", 0, len(plcs)
        )

        # Create tasks for each PLC
        tasks = [
            self._scan_single_plc_with_semaphore(plc, mode, device_ranges, i, len(plcs)) for i, plc in enumerate(plcs)
        ]

        # Run all tasks and gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results (keyed by IP, or "IP (PROTOCOL:port)" when several
        # targets share an IP, so no result is overwritten)
        for plc, label, result in zip(plcs, target_labels(plcs), results):
            if isinstance(result, BaseException):
                self._results[label] = PLCScanResult(
                    plc_info=plc,
                    data_points=[],
                    denied_addresses=set(),
                    success=False,
                    error_message=str(result),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                )
            else:
                self._results[label] = result

        # Report completion
        successful = sum(1 for r in self._results.values() if r.success)
        self._report_progress(f"Parallel scan complete: {successful}/{len(plcs)} successful", len(plcs), len(plcs))

        return self._results

    async def _scan_single_plc_with_semaphore(
        self, plc: PLCInfo, mode: ScanMode, device_ranges: Optional[List[DeviceRange]], index: int, total: int
    ) -> PLCScanResult:
        """Scan a single PLC with semaphore for concurrency control"""
        if self._semaphore is None:
            return await self._scan_single_plc(plc, mode, device_ranges, index, total)
        async with self._semaphore:
            return await self._scan_single_plc(plc, mode, device_ranges, index, total)

    async def _scan_single_plc(
        self, plc: PLCInfo, mode: ScanMode, device_ranges: Optional[List[DeviceRange]], index: int, total: int
    ) -> PLCScanResult:
        """Scan a single PLC"""
        start_time = datetime.now()
        data_points = []
        denied_addresses = set()
        denied_statuses: Dict[str, StatusCode] = {}
        error_message = None
        success = False

        self._report_progress(f"Scanning {plc.ip_address}", index + 1, total)

        try:
            async with PLCDataCollector(plc, self.config) as collector:
                connected = collector.is_connected
                self._audit.log_connect(
                    plc.ip_address, plc.protocol.name if plc.protocol else "UNKNOWN", plc.port or 0, connected
                )

                if not connected:
                    reason = getattr(collector, "connect_error", None)
                    raise ConnectionError(
                        f"Failed to connect to {plc.ip_address}:{plc.port} "
                        f"({plc.protocol.name if plc.protocol else 'UNKNOWN'})" + (f": {reason}" if reason else "")
                    )

                data_points = await collect_items(
                    collector, None if mode == ScanMode.FULL else list(device_ranges or [])
                )

                denied_addresses = collector.get_denied_addresses()
                denied_statuses = collector.get_denied_statuses()
                # Connected but nothing answered: a failure, with the data
                # (every address NG_TIMEOUT / NG_COMM_ERROR) kept
                error_message = no_answer_error(data_points)
                success = error_message is None
                if error_message:
                    logger.error(f"Error scanning {plc.ip_address}: {error_message}")
                    self._audit.log_error(f"Scan failed: {error_message}", {"plc_ip": plc.ip_address})

        except Exception as e:
            error_message = str(e)
            logger.error(f"Error scanning {plc.ip_address}: {e}")
            self._audit.log_error(f"Scan failed: {e}", {"plc_ip": plc.ip_address})
            if not data_points:
                # PLC off or unreachable: still report every requested
                # address as NG_COMM_ERROR, as a sequential scan does
                data_points = unreached_points(
                    plc.protocol, None if mode == ScanMode.FULL else list(device_ranges or [])
                )

        end_time = datetime.now()

        result = PLCScanResult(
            plc_info=plc,
            data_points=data_points,
            denied_addresses=denied_addresses,
            success=success,
            error_message=error_message,
            start_time=start_time,
            end_time=end_time,
            denied_statuses=denied_statuses,
        )

        # Log scan completion
        stats = result.statistics
        self._audit.log_scan_complete(
            plc.ip_address, stats["total_points"], stats["success_count"], stats["error_count"], result.duration_ms
        )

        return result

    def get_results(self) -> Dict[str, PLCScanResult]:
        """Get all scan results"""
        return self._results

    def get_aggregate_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics across all PLCs"""
        total_plcs = len(self._results)
        successful_plcs = sum(1 for r in self._results.values() if r.success)
        total_points = sum(len(r.data_points) for r in self._results.values())
        total_success = sum(
            sum(1 for dp in r.data_points if dp.status == StatusCode.OK) for r in self._results.values()
        )
        total_denied = sum(len(r.denied_addresses) for r in self._results.values())
        total_duration = sum(r.duration_ms for r in self._results.values())

        return {
            "total_plcs": total_plcs,
            "successful_plcs": successful_plcs,
            "failed_plcs": total_plcs - successful_plcs,
            "total_data_points": total_points,
            "successful_reads": total_success,
            "failed_reads": total_points - total_success,
            "total_denied_addresses": total_denied,
            "total_duration_ms": total_duration,
            "average_duration_ms": total_duration / total_plcs if total_plcs > 0 else 0,
            "success_rate": success_rate_text(total_success, total_points),
        }


async def scan_plcs_parallel(
    plcs: List[PLCInfo],
    mode: ScanMode = ScanMode.FULL,
    device_ranges: Optional[List[DeviceRange]] = None,
    config: Optional[NetworkConfig] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, PLCScanResult]:
    """
    Convenience function to scan multiple PLCs in parallel.

    Args:
        plcs: List of PLCs to scan
        mode: Scan mode
        device_ranges: Device ranges for RANGE mode
        config: Network configuration
        progress_callback: Progress callback

    Returns:
        Dictionary mapping each target's label to its scan result: the IP,
        or "IP (PROTOCOL:port)" when several targets share an IP (see
        target_labels)
    """
    scanner = ParallelPLCScanner(config, progress_callback)
    return await scanner.scan_multiple_plcs(plcs, mode, device_ranges)
