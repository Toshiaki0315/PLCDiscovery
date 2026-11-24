"""
Scan plumbing shared by the CLI (plc_scanner.py) and the GUI (plc_gui.py).

- ResultWriter: writes one target's data and newly denied addresses to CSV
  and the database; write failures are reported, never raised.
- collect_items: reads the requested ranges / tags in order (or a full scan).
- CycleRunner: one read of a target (collect, convert, write), the periodic
  status report, the per-outage error notification and the fixed-period wait.
"""

import asyncio
import functools
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
# Sends one notification: called with a function that takes the notifier.
# Returns False when it could not be delivered to any destination (None, as
# older helpers return, counts as delivered).
Notify = Callable[[Callable[[Any], Awaitable[Any]]], Awaitable[Optional[bool]]]

# After a state-change notification (outage, recovery, threshold) could not
# be delivered, it is offered again on later cycles, but not before this
# many seconds: an unreachable webhook must not add its timeouts and
# retries to every read cycle.
NOTIFY_RETRY_SECONDS = 60.0

# How long a read cycle waits for a notification to be sent. A webhook that
# does not answer takes its timeout and retries (about half a minute by
# default): the send then finishes in the background while the PLCs keep
# being read on schedule.
NOTIFY_WAIT_SECONDS = 2.0


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
        instance: Optional[str] = None,
    ):
        self.ip = plc_info.ip_address
        self.protocol = plc_info.protocol.name if plc_info.protocol else None
        self.port = plc_info.port
        # Set when another target has the same IP, protocol and port (two
        # Modbus units behind one gateway; see target_instances): part of
        # the file name and of the protocol stored in the database, so the
        # targets' rows are never mixed or compared with each other
        self.instance = instance
        self.db_protocol = f"{self.protocol}/{instance}" if instance and self.protocol else self.protocol
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
            if tag and self.instance:
                tag = f"{tag}_{self.instance}"
            hex_addresses = self.exporter.hex_addresses and self.protocol == "SLMP"
            if self.daily:
                path = self.exporter.append_plc_data(points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
            else:
                path = self.exporter.export_plc_data(points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
        except Exception as e:
            self._failed("data CSV", e)
        if self.db_exporter and self.db_exporter.is_enabled:
            try:
                db_count = self.db_exporter.export_plc_data(points, self.ip, protocol=self.db_protocol, port=self.port)
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
                    new, self.ip, statuses=statuses, protocol=self.db_protocol, port=self.port
                )
            except Exception as e:
                self._failed("denied addresses to database", e)
        return path


async def collect_items(collector: PLCDataCollector, items: Optional[Sequence[ScanItem]]) -> List[DataPoint]:
    """Read the requested ranges / tags in order; ``None`` runs a full scan"""
    if items is None:
        return await collector.collect_full_scan()
    points: List[DataPoint] = []
    collector.skip_reconnect = False
    try:
        for item in items:
            points.extend(await collect_item(collector, item))
            # PLC off: the remaining ranges are reported NG_COMM_ERROR
            # without another reconnect attempt each (the next scan tries)
            collector.skip_reconnect = not collector.is_connected
    finally:
        collector.skip_reconnect = False
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


# Statuses of a request the PLC did not answer (as opposed to an answer
# saying that the address is invalid or unsupported)
NO_ANSWER_STATUSES = (StatusCode.NG_TIMEOUT, StatusCode.NG_COMM_ERROR)


def _requested(points: Sequence[DataPoint]) -> List[DataPoint]:
    """The points a request was sent for (not those reported from the session's learned addresses)"""
    return [point for point in points if not point.cached]


def plc_answered(points: Sequence[DataPoint]) -> bool:
    """
    True when the PLC answered at least one request of a read (with data or
    with an address error). False when requests went unanswered (timeout,
    communication error) and nothing shows an answer: the PLC is hung,
    switched off or disconnected, even if the transport still looks
    connected (UDP has no connection; a TCP connection survives a pulled
    cable for a long time).

    Not an answer of the PLC, so neither proof nor disproof:
    - an address the session learned as inaccessible (no request is sent for
      it; it is in every cycle's result, whether the PLC is on or off)
    - NG_UNSUPPORTED, which is mostly decided without a request (a device
      type the protocol does not have, tags on a PLC without tags)
    Nothing requested (no points, or only such points) says nothing: True.
    """
    requested = _requested(points)
    if not any(point.status in NO_ANSWER_STATUSES for point in requested):
        return True
    return any(point.status in (StatusCode.OK, StatusCode.NG_ILLEGAL_ADDR) for point in requested)


def no_answer_error(points: Sequence[DataPoint]) -> Optional[str]:
    """Why a scan whose requests all went unanswered is a failure (None otherwise)"""
    if plc_answered(points):
        return None
    requested = _requested(points)
    counts = ", ".join(
        f"{sum(1 for p in requested if p.status == status)} {status.value}"
        for status in NO_ANSWER_STATUSES
        if any(p.status == status for p in requested)
    )
    unanswered = sum(1 for p in requested if p.status in NO_ANSWER_STATUSES)
    return f"the PLC answered none of the {unanswered} addresses read ({counts})"


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
        # (event type, key) -> loop time before which an undelivered
        # state-change notification is not offered again
        self._retry_at: Dict[Tuple[NotificationType, str], float] = {}
        # Notifications still being sent in the background (slow webhook)
        self._in_flight: Dict[Tuple[NotificationType, str], "asyncio.Future[Any]"] = {}

    async def read(self, collector: PLCDataCollector, writer: ResultWriter) -> CycleResult:
        """Collect, convert and write one target; denied addresses are logged once"""
        if self.items is not None:
            collector.clear_data()
        points = await collect_items(collector, self.items)
        points = apply_data_type_conversion(points, self.data_type, self.byte_order, self.type_manager)
        path = writer.export_points(points)
        denied_path = writer.export_new_denied(collector.get_denied_addresses(), collector.get_denied_statuses())
        return CycleResult(points, path, denied_path)

    def save_partial(self, collector: PLCDataCollector, writer: ResultWriter) -> CycleResult:
        """
        Convert and write what a read that was interrupted (stopped by the
        user) had collected so far, with the addresses it had learned as
        inaccessible. Nothing is written when nothing was read.
        """
        points = apply_data_type_conversion(
            list(collector.get_collected_data()), self.data_type, self.byte_order, self.type_manager
        )
        if not points:
            return CycleResult(points, None, None)
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
        await self._deliver(
            NotificationType.STATUS_REPORT,
            "",
            lambda n: n.notify_status_report(message, has_problems=problems, iteration=iteration),
        )

    async def check_thresholds(self, target: str, points: List[DataPoint], plc_ip: str) -> None:
        """
        THRESHOLD_EXCEEDED for each limit newly exceeded, THRESHOLD_CLEARED
        when a notified excursion is over; crossings are logged every time.
        """
        if not self.thresholds:
            return
        if points and target not in self._threshold_coverage_checked:
            # Once per target, on the first cycle that read anything: a limit
            # on an address outside the ranges / tags would never be checked
            self._threshold_coverage_checked.add(target)
            for threshold in self.thresholds.unmatched(points, target, plc_ip):
                logger.warning(
                    f"{target}: threshold {threshold.label} is never checked: "
                    f"{threshold.address} is not in the scanned ranges / tags"
                )

        def may_notify(threshold: Threshold, kind: str) -> bool:
            exceeded, cleared = NotificationType.THRESHOLD_EXCEEDED, NotificationType.THRESHOLD_CLEARED
            event_type, opposite = (cleared, exceeded) if kind == "cleared" else (exceeded, cleared)
            key = NotificationManager.threshold_key(target, threshold.label)
            # One at a time per limit: while "exceeded" is still being sent
            # (slow webhook), "cleared" waits - it would otherwise arrive
            # first and leave the receiver believing the limit is exceeded
            if (opposite, key) in self._in_flight:
                return False
            return not self._suppressed(event_type, key)

        now = asyncio.get_running_loop().time()
        check = self.thresholds.evaluate(target, points, may_notify, plc_ip=plc_ip, now=now)
        # Logged on every crossing, even while its notification is throttled
        for event in check.crossed:
            logger.warning(f"{target}: threshold {event.threshold.label} exceeded (value {event.value:g})")
        for event in check.returned:
            logger.info(
                f"{target}: threshold {event.threshold.label} back to normal "
                f"(value {event.value:g}, outside for {event.duration:.0f}s)"
            )
        # Sent right away. One that could not be delivered is handed back
        # and offered again on a later cycle.
        monitor = self.thresholds
        for event in check.exceeded:
            label, address, value = event.threshold.label, event.threshold.address, event.value
            await self._deliver(
                NotificationType.THRESHOLD_EXCEEDED,
                NotificationManager.threshold_key(target, label),
                lambda n: n.notify_threshold(target, label, value, plc_ip=plc_ip, address=address),
                on_failed=functools.partial(monitor.delivery_failed, target, event, "exceeded"),
            )
        for event in check.cleared:
            label, address, value, duration = (
                event.threshold.label,
                event.threshold.address,
                event.value,
                event.duration,
            )
            await self._deliver(
                NotificationType.THRESHOLD_CLEARED,
                NotificationManager.threshold_key(target, label),
                lambda n: n.notify_threshold_cleared(
                    target, label, value, duration_seconds=duration, plc_ip=plc_ip, address=address
                ),
                on_failed=functools.partial(monitor.delivery_failed, target, event, "cleared"),
            )

    def warn_unknown_threshold_targets(self, names: Sequence[str]) -> None:
        """Warn about thresholds limited to a target that is not scanned (labels and IPs)"""
        if not self.thresholds:
            return
        for threshold in self.thresholds.unknown_targets(names):
            logger.warning(
                f"threshold {threshold.label} is never checked: target {threshold.target} is not scanned "
                f"(use one of: {', '.join(dict.fromkeys(names))})"
            )

    def _suppressed(self, event_type: NotificationType, key: str) -> bool:
        """
        True while this event must wait: it is still being sent, the
        notifier's min_interval would drop it, or its last delivery failed
        less than NOTIFY_RETRY_SECONDS ago
        """
        if (event_type, key) in self._in_flight:
            return True
        retry_at = self._retry_at.get((event_type, key))
        if retry_at is not None and asyncio.get_running_loop().time() < retry_at:
            return True
        notifier = self.notifier
        return isinstance(notifier, NotificationManager) and notifier.is_suppressed(event_type, key)

    async def _deliver(
        self,
        event_type: NotificationType,
        key: str,
        send: Callable[[Any], Awaitable[Any]],
        on_delivered: Optional[Callable[[], None]] = None,
        on_failed: Optional[Callable[[], None]] = None,
    ) -> None:
        """
        Send a notification without holding up the read cycle.

        ``on_delivered`` runs once a destination received it; ``on_failed``
        when none did - the caller then leaves the change unreported, so it
        is offered again (after NOTIFY_RETRY_SECONDS) and the receiver ends
        up with the current state even if the webhook was down when the
        change happened.

        The cycle waits at most NOTIFY_WAIT_SECONDS: a slow send finishes
        in the background (the callbacks run then) and the same event is
        not offered again meanwhile.
        """
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(self._notify(send))
        self._in_flight[(event_type, key)] = task

        def finished(done: "asyncio.Future[Any]") -> None:
            self._in_flight.pop((event_type, key), None)
            failed = done.cancelled() or done.exception() is not None or done.result() is False
            if failed:
                self._retry_at[(event_type, key)] = loop.time() + NOTIFY_RETRY_SECONDS
                logger.warning(
                    f"Notification '{event_type.value}'{f' for {key}' if key else ''} "
                    "was not delivered; it will be retried"
                )
                if on_failed:
                    on_failed()
            else:
                self._retry_at.pop((event_type, key), None)
                if on_delivered:
                    on_delivered()

        task.add_done_callback(finished)
        # asyncio.wait, not wait_for: before Python 3.12 wait_for drops a
        # cancellation that arrives just as the notification finishes, and
        # the read cycle would then ignore the request to stop
        done, _ = await asyncio.wait({task}, timeout=NOTIFY_WAIT_SECONDS)
        if not done:
            logger.info(f"Notification '{event_type.value}' is taking long; reading continues meanwhile")
        elif not task.cancelled() and task.exception() is not None:
            # _notify helpers do not raise; a custom one might
            logger.debug(f"Notification '{event_type.value}' failed: {task.exception()}")

    async def drain(self, timeout: float = 15.0) -> None:
        """Wait (bounded) for notifications still being sent, e.g. before the run ends"""
        pending = [task for task in self._in_flight.values() if not task.done()]
        if pending:
            await asyncio.wait(pending, timeout=timeout)

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
                downtime = self._last_downtime.get(target, 0.0)
                await self._deliver(
                    NotificationType.PLC_RECOVERED,
                    target,
                    lambda n: n.notify_recovered(target, plc_ip=plc_ip, downtime_seconds=downtime),
                    on_delivered=lambda: self._reported_down.discard(target),
                )
            return
        self._down.setdefault(target, now)
        if target not in self._reported_down and not self._suppressed(NotificationType.PLC_UNREACHABLE, target):
            # Marked as reported only once a destination received it: the
            # webhook is often down together with the PLC (network failure)
            await self._deliver(
                NotificationType.PLC_UNREACHABLE,
                target,
                lambda n: n.notify_unreachable(target, plc_ip=plc_ip),
                on_delivered=lambda: self._reported_down.add(target),
            )
