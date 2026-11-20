"""
Scan plumbing shared by the CLI (plc_scanner.py) and the GUI (plc_gui.py).

- ResultWriter: writes one target's data and newly denied addresses to CSV
  and the database; write failures are reported, never raised.
- collect_items: reads the requested ranges / tags in order (or a full scan).
- CycleRunner: one read of a target (collect, convert, write), the periodic
  status report, the per-outage error notification and the fixed-period wait.
"""

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, NamedTuple, Optional
from typing import Protocol as Interface
from typing import Sequence, Set, Tuple, Union

from .collector import PLCDataCollector, collect_item
from .config import DataPoint, DeviceRange, PLCInfo, StatusCode, TagRange
from .conversion import apply_data_type_conversion
from .data_types import ByteOrder, DataType, DataTypeManager
from .database import DatabaseExporter
from .notifications import NotificationManager, NotificationType
from .output import CSVExporter
from .thresholds import Threshold, ThresholdMonitor

logger = logging.getLogger(__name__)

ScanItem = Union[DeviceRange, TagRange]
# Sends one notification: called with a function that takes the notifier
Notify = Callable[[Callable[[Any], Awaitable[Any]]], Awaitable[None]]


class Display(Interface):
    """What ResultWriter prints through (RichProgressDisplay in the CLI)"""

    def print_info(self, message: str) -> None:
        """Print an informational line"""

    def print_error(self, message: str) -> None:
        """Print an error line"""


class ResultWriter:
    """
    Writes one PLC's data / newly denied addresses to CSV and the database.

    Write failures (e.g. a CSV locked by Excel on Windows, a full disk) are
    reported and counted but never raised, so a scan or a long periodic
    monitoring run keeps going. Denied addresses that could not be written
    are retried on the next call.

    Without a display (GUI) messages only go to the log.
    """

    def __init__(
        self,
        plc_info: PLCInfo,
        exporter: CSVExporter,
        display: Optional[Display] = None,
        db_exporter: Optional[DatabaseExporter] = None,
        label: Optional[str] = None,
        daily: bool = False,
    ):
        self.ip = plc_info.ip_address
        self.protocol = plc_info.protocol.name if plc_info.protocol else None
        self.port = plc_info.port
        # "IP (PROTOCOL:port)" when another target shares the IP (target_labels)
        self.label = label or self.ip
        self.shared_ip = self.label != self.ip
        self.exporter = exporter
        # Periodic scans with output.periodic_csv: daily append to one file a day
        self.daily = daily
        self.display = display
        self.db_exporter = db_exporter
        self._exported_denied: Set[str] = set()
        # Only the count and the first message: a long monitoring run with a
        # CSV locked for hours must not grow memory with every cycle
        self.error_count = 0
        self.first_error: Optional[str] = None

    def _failed(self, what: str, error: Exception) -> None:
        message = f"{self.label}: failed to write {what}: {error}"
        self.error_count += 1
        if self.first_error is None:
            self.first_error = message
        if self.display is not None:
            self.display.print_error(message)
        logger.error(message)

    def error_summary(self, context: str = "") -> Optional[str]:
        """'N write error(s)[ context]; first: ...', or None without errors"""
        if not self.error_count:
            return None
        return f"{self.error_count} write error(s){context}; first: {self.first_error}"

    def _info(self, message: str) -> None:
        if self.display is not None:
            self.display.print_info(message)
        else:
            # GUI: per-cycle details stay out of the log pane
            logger.debug(message)

    def export_points(self, points: List[DataPoint]) -> Optional[str]:
        if not points:
            return None
        path = None
        try:
            # Protocol and port in the file name only when the IP is shared
            tag = f"{self.protocol}_{self.port}" if self.shared_ip else None
            hex_addresses = self.exporter.hex_addresses and self.protocol == "SLMP"
            if self.daily:
                path = self.exporter.append_plc_data(points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
            else:
                path = self.exporter.export_plc_data(points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
        except Exception as e:
            self._failed("data CSV", e)
        if self.db_exporter and self.db_exporter.is_enabled:
            try:
                db_count = self.db_exporter.export_plc_data(points, self.ip, protocol=self.protocol, port=self.port)
                self._info(f"Saved {db_count} records to database")
            except Exception as e:
                self._failed("data to database", e)
        return path

    def export_new_denied(self, denied: Set[str], statuses: Optional[Dict[str, StatusCode]] = None) -> Optional[str]:
        """Append only addresses not yet written in this session"""
        new = set(denied) - self._exported_denied
        if not new:
            return None
        try:
            # plc_ip column: the label, so targets sharing an IP stay apart
            # (the plain IP otherwise, as before)
            path = self.exporter.export_denied_addresses(new, self.label, statuses=statuses)
        except Exception as e:
            self._failed("access denied log", e)
            return None  # not marked as exported: retried next time
        self._exported_denied.update(new)
        if self.db_exporter and self.db_exporter.is_enabled:
            try:
                self.db_exporter.export_denied_addresses(
                    new, self.ip, statuses=statuses, protocol=self.protocol, port=self.port
                )
            except Exception as e:
                self._failed("denied addresses to database", e)
        return path


async def collect_items(collector: PLCDataCollector, items: Optional[Sequence[ScanItem]]) -> List[DataPoint]:
    """Read the requested ranges / tags in order; ``None`` runs a full scan"""
    if items is None:
        return await collector.collect_full_scan()
    points: List[DataPoint] = []
    for item in items:
        points.extend(await collect_item(collector, item))
    return points


def status_report_message(
    points_by_target: Dict[str, List[DataPoint]],
    unreachable: List[str],
    iteration: int,
) -> Tuple[str, bool]:
    """
    Text of a periodic status report: per target, the OK / NG counts of the
    latest cycle. Returns (message, has_problems).
    """
    lines = [f"Cycle {iteration}"]
    problems = bool(unreachable)
    for label, points in points_by_target.items():
        if label in unreachable:
            lines.append(f"{label}: not reachable")
            continue
        ok = sum(1 for p in points if p.status == StatusCode.OK)
        ng = len(points) - ok
        problems = problems or ng > 0
        lines.append(f"{label}: OK {ok} / NG {ng}")
    return "\n".join(lines), problems


def next_cycle_wait(interval: float, cycle_started: float) -> float:
    """Seconds until the next cycle: a fixed period, minus the time spent reading"""
    return max(0.0, interval - (asyncio.get_running_loop().time() - cycle_started))


class CycleResult(NamedTuple):
    points: List[DataPoint]
    path: Optional[str]
    denied_path: Optional[str]


async def _no_notify(send: Callable[[Any], Awaitable[Any]]) -> None:
    return None


class CycleRunner:
    """
    The part of a scan that the CLI and the GUI share: what one read of a
    target does, and what happens between periodic cycles.

    ``items`` are the requested ranges / tags, or None for a full scan.
    ``notify`` sends a notification and never raises (the CLI's and the
    GUI's own helpers); ``notifier`` gives the status report interval.
    """

    def __init__(
        self,
        items: Optional[Sequence[ScanItem]],
        *,
        data_type: Optional[DataType] = None,
        byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
        type_manager: Optional[DataTypeManager] = None,
        notifier: Any = None,
        notify: Optional[Notify] = None,
        thresholds: Optional[ThresholdMonitor] = None,
    ):
        self.items = None if items is None else list(items)
        self.data_type = data_type
        self.byte_order = byte_order
        self.type_manager = type_manager
        self.notifier = notifier
        self._notify: Notify = notify or _no_notify
        self._last_report = asyncio.get_running_loop().time()
        # Target -> loop time its current outage was first seen
        self._down: Dict[str, float] = {}
        # Length of each target's latest finished outage (for PLC_RECOVERED)
        self._last_downtime: Dict[str, float] = {}
        # Targets last reported as not reachable: what the receiver believes
        self._reported_down: Set[str] = set()
        self.thresholds = thresholds
        # Targets already checked for thresholds outside the scanned ranges
        self._threshold_coverage_checked: Set[str] = set()

    async def read(self, collector: PLCDataCollector, writer: ResultWriter) -> CycleResult:
        """Collect, convert and write one target; denied addresses are logged once"""
        if self.items is not None:
            collector.clear_data()
        points = await collect_items(collector, self.items)
        points = apply_data_type_conversion(points, self.data_type, self.byte_order, self.type_manager)
        path = writer.export_points(points)
        denied_path = writer.export_new_denied(collector.get_denied_addresses(), collector.get_denied_statuses())
        return CycleResult(points, path, denied_path)

    async def report_if_due(
        self, points_by_target: Dict[str, List[DataPoint]], unreachable: List[str], iteration: int
    ) -> None:
        """Send the STATUS_REPORT summary when its interval has passed"""
        notifier = self.notifier
        if not (notifier and notifier.report_interval_seconds):
            return
        now = asyncio.get_running_loop().time()
        if now - self._last_report < notifier.report_interval_seconds:
            return
        self._last_report = now
        message, problems = status_report_message(points_by_target, unreachable, iteration)
        await self._notify(lambda n: n.notify_status_report(message, has_problems=problems, iteration=iteration))

    async def check_thresholds(self, target: str, points: List[DataPoint], plc_ip: str) -> None:
        """THRESHOLD_EXCEEDED for each limit this cycle newly crossed"""
        if not self.thresholds:
            return
        if points and target not in self._threshold_coverage_checked:
            # Once per target, on the first cycle that read anything: a limit
            # on an address outside the ranges / tags would never be checked
            self._threshold_coverage_checked.add(target)
            for threshold in self.thresholds.unmatched(points):
                logger.warning(
                    f"{target}: threshold {threshold.label} is never checked: "
                    f"{threshold.address} is not in the scanned ranges / tags"
                )

        def may_notify(threshold: Threshold) -> bool:
            key = NotificationManager.threshold_key(target, threshold.label)
            return not self._suppressed(NotificationType.THRESHOLD_EXCEEDED, key)

        for threshold, value in self.thresholds.check(target, points, may_notify):
            logger.warning(f"{target}: threshold {threshold.label} exceeded (value {value:g})")
            # notify() sends right away, before the loop moves on
            label, address = threshold.label, threshold.address
            await self._notify(lambda n: n.notify_threshold(target, label, value, plc_ip=plc_ip, address=address))

    def _suppressed(self, event_type: NotificationType, key: str) -> bool:
        """True while the notifier's min_interval would drop this event"""
        notifier = self.notifier
        return isinstance(notifier, NotificationManager) and notifier.is_suppressed(event_type, key)

    async def track_outage(self, target: str, reachable: bool, plc_ip: str) -> None:
        """
        A PLC_UNREACHABLE notification when a target stops answering (once
        per outage) and PLC_RECOVERED with the downtime when it answers again.

        A change the notifier would throttle (min_interval) is not marked as
        reported and is retried on the next cycle, so the receiver always
        ends up with the target's current state (a PLC that flaps and then
        stays down is not left looking reachable).
        """
        now = asyncio.get_running_loop().time()
        if reachable:
            down_since = self._down.pop(target, None)
            if down_since is not None:
                self._last_downtime[target] = now - down_since
            if target in self._reported_down and not self._suppressed(NotificationType.PLC_RECOVERED, target):
                self._reported_down.discard(target)
                downtime = self._last_downtime.get(target, 0.0)
                await self._notify(lambda n: n.notify_recovered(target, plc_ip=plc_ip, downtime_seconds=downtime))
            return
        self._down.setdefault(target, now)
        if target not in self._reported_down and not self._suppressed(NotificationType.PLC_UNREACHABLE, target):
            self._reported_down.add(target)
            await self._notify(lambda n: n.notify_unreachable(target, plc_ip=plc_ip))
