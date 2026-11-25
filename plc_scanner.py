#!/usr/bin/env python3
"""
PLC Scanner - Factory PLC Auto-Detection and Data Collection Tool

A comprehensive tool for discovering and collecting data from
multi-vendor PLCs in factory environments.

Usage:
    # Discovery mode (same segment)
    python plc_scanner.py --mode discover

    # Discovery with IP range
    python plc_scanner.py --mode discover --ip-range "192.168.1.0/24"

    # Full scan mode
    python plc_scanner.py --mode full --target 192.168.1.10

    # Range scan with data type conversion
    python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 100-199 --data-type FLOAT

    # Using configuration file
    python plc_scanner.py --config plc_config.yaml

    # Generate configuration template
    python plc_scanner.py --generate-config

Author: PLC Discovery Team
License: MIT
"""

import argparse
import asyncio
import contextlib
import dataclasses
import logging
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from plc_discovery.audit_log import close_audit_logger, get_audit_logger, init_audit_logger
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.cli_args import (  # noqa: F401  (re-exported for existing imports)
    BYTE_ORDER_MAP,
    DATA_TYPE_MAP,
    NETWORK_OPTIONS,
    create_network_config,
    get_device_type_from_string,
    get_protocol_from_string,
    network_option_errors,
    parse_address_range,
    parse_args,
    parse_tag_list,
    parse_targets,
    resolve_device_ranges,
    resolve_device_ranges_only,
    resolve_discovery_protocols,
    resolve_mode_and_interval,
    resolve_output_settings,
    resolve_thresholds,
)
from plc_discovery.collector import FULL_SCAN_ADDRESS, PLCDataCollector, unreached_points
from plc_discovery.config import (
    PROTOCOL_PORTS,
    DataPoint,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
    TagRange,
)
from plc_discovery.config_loader import (
    MIN_INTERVAL_SECONDS,
    ConfigLoader,
    generate_config_template,
    log_level_number,
)
from plc_discovery.conversion import (  # noqa: F401
    _split_address,
    apply_data_type_conversion,
    load_type_mapping,
    resolve_data_types,
)
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.discovery import (
    PLCDiscovery,
    discover_plcs,
    merge_discovery_results,
    target_instances,
    target_labels,
)
from plc_discovery.notifications import NotificationManager
from plc_discovery.output import CSVExporter
from plc_discovery.progress import RichProgressDisplay
from plc_discovery.report import ReportConfig, ReportFormat, create_report
from plc_discovery.scan_runner import (  # noqa: F401  (status_report_message re-exported)
    CycleRunner,
    ResultWriter,
    ScanItem,
    collect_items,
    cycle_start,
    next_cycle_wait,
    no_answer_error,
    plc_answered,
    status_report_message,
)
from plc_discovery.thresholds import Threshold, ThresholdMonitor
from plc_discovery.utils import get_timestamp, ip_range_error, sorted_addresses, wait_for

logger = logging.getLogger(__name__)


async def run_discovery(
    ip_ranges: List[str],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: Optional[DatabaseExporter] = None,
    protocols: Optional[List[Protocol]] = None,
    errors: Optional[List[str]] = None,
) -> List[PLCInfo]:
    """
    Run PLC discovery (same segment when ip_ranges is empty).

    Output failures (CSV/database) are reported and appended to ``errors``;
    the discovered PLCs are still displayed and returned.
    """
    audit = get_audit_logger()

    display.print_info("Starting PLC Discovery...")
    if protocols:
        display.print_info(f"Probing protocols: {', '.join(p.name for p in protocols)}")
    audit.log_discovery_start(ip_ranges)

    plcs = []

    # Broadcast discovery first - on the local segments only, so not when
    # the user limited the search to IP ranges: broadcasts go out on every
    # interface (office LAN included) and answers from outside the ranges
    # would be listed. The ranges are covered by the TCP scan below.
    if ip_ranges:
        display.print_info("UDP broadcast discovery skipped: the search is limited to the given IP range(s)")
    else:
        try:
            display.print_info("Trying UDP broadcast discovery...")
            broadcast = BroadcastDiscovery(config)
            broadcast_plcs = await broadcast.discover_all_broadcast(protocols=protocols)
            plcs.extend(broadcast_plcs)
        except Exception as e:
            display.print_warning(f"Broadcast discovery failed: {e}")

    # Then TCP port scanning
    tcp_plcs: List[PLCInfo] = []
    if ip_ranges:
        for ip_range in ip_ranges:
            display.print_info(f"Scanning IP range: {ip_range}")
            tcp_plcs.extend(await discover_plcs(ip_range, config, protocols=protocols))
    else:
        display.print_info("Scanning same network segment...")
        tcp_plcs = await discover_plcs(None, config, protocols=protocols)

    # Broadcast results are limited to the requested protocols too
    if protocols:
        plcs = [p for p in plcs if p.protocol in protocols]

    # Merge results: one entry per IP, protocol and port (a host answering
    # several protocols - multi-protocol PLC or simulators - is listed per
    # protocol). The TCP scan verified the protocol and read the identity,
    # so its entries win; broadcast adds hosts the scan did not reach.
    plcs = merge_discovery_results(tcp_plcs, plcs)

    # Log and display results
    audit.log_discovery_result(len(plcs), [p.to_dict() for p in plcs])

    if plcs:
        hosts = len({p.ip_address for p in plcs})
        display.print_success(
            f"Discovered {len(plcs)} PLC endpoint(s)" + (f" on {hosts} host(s)" if hosts != len(plcs) else "")
        )
        try:
            filepath = exporter.export_discovery_results(plcs)
            display.print_info(f"Results saved to: {filepath}")
        except Exception as e:
            message = f"Failed to write discovery CSV: {e}"
            display.print_error(message)
            if errors is not None:
                errors.append(message)

        # Save to database if enabled
        if db_exporter and db_exporter.is_enabled:
            try:
                # One row per IP, protocol and port (database schema v2)
                db_count = db_exporter.export_discovery_results(plcs)
                display.print_info(f"Saved {db_count} PLCs to database")
            except Exception as e:
                message = f"Failed to save discovery results to database: {e}"
                display.print_error(message)
                if errors is not None:
                    errors.append(message)

        display.print_discovery_results([p.to_dict() for p in plcs])
    else:
        display.print_warning("No PLCs discovered")

    return plcs


async def run_parallel_scan(
    plcs: List[PLCInfo],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    mode: ScanMode,
    device_ranges: Optional[List[ScanItem]] = None,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: Optional[DatabaseExporter] = None,
) -> Dict[str, "ScanOutcome"]:
    """
    Scan several PLCs at once, at most config.max_concurrent at a time.

    Each target is scanned exactly like a sequential scan (run_single_scan:
    audit log, NG_COMM_ERROR rows when it cannot be connected, CSV and
    database output), so both paths behave the same. Results are keyed by
    target label (see target_labels).
    """
    limit = max(1, config.max_concurrent)
    display.print_info(f"Starting parallel scan of {len(plcs)} PLCs (max {limit} concurrent)...")
    semaphore = asyncio.Semaphore(limit)

    tasks: List["asyncio.Future[ScanOutcome]"] = []

    async def scan(label: str, plc_info: PLCInfo, instance: Optional[str]) -> ScanOutcome:
        async with semaphore:
            outcome = await scan_target(
                plc_info,
                config,
                exporter,
                display,
                mode,
                device_ranges,
                data_type,
                byte_order,
                type_manager,
                db_exporter,
                label,
                instance,
            )
        if outcome.interrupted:
            # Python 3.10 delivers Ctrl+C as KeyboardInterrupt to whatever
            # is running: when that was this target's read, only this target
            # stopped and the others ran to their end. Stop them as well.
            for task in tasks:
                if task is not asyncio.current_task():
                    task.cancel()
        return outcome

    labels = target_labels(plcs)
    tasks.extend(
        asyncio.ensure_future(scan(label, plc, instance))
        for label, plc, instance in zip(labels, plcs, target_instances(plcs))
    )
    try:
        # return_exceptions: on Ctrl+C gather waits until every target has
        # stopped. Without it, a target still waiting for its turn ended
        # the wait at once, and the targets being scanned were cancelled a
        # second time before they had written what they had read.
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        _uncancel_current_task()
    # A target that was still waiting for its turn when the scan was
    # interrupted was not scanned and is not reported (as in a sequential scan)
    # (nor one whose task ended on a second Ctrl+C: its exception must not
    # take the results of the others with it)
    results = {
        label: task.result()
        for label, task in zip(labels, tasks)
        if task.done() and not task.cancelled() and task.exception() is None
    }
    display.print_scan_results(
        {
            label: {
                "success": o.success,
                "error_message": o.error,
                "statistics": {
                    "total_points": len(o.data_points),
                    "success_count": sum(1 for p in o.data_points if p.status == StatusCode.OK),
                    "error_count": sum(1 for p in o.data_points if p.status != StatusCode.OK),
                },
            }
            for label, o in results.items()
        }
    )
    return results


async def scan_target(
    plc_info: PLCInfo,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    mode: ScanMode,
    device_ranges: Optional[List[ScanItem]],
    data_type: Optional[DataType],
    byte_order: ByteOrder,
    type_manager: Optional[DataTypeManager],
    db_exporter: Optional[DatabaseExporter],
    label: str,
    instance: Optional[str],
) -> "ScanOutcome":
    """
    run_single_scan for one of several targets: an unexpected error of this
    target is its own failure and never stops the scan of the others; its
    addresses are still written as NG_COMM_ERROR.
    """
    try:
        return await run_single_scan(
            plc_info,
            config,
            exporter,
            display,
            mode,
            device_ranges,
            data_type,
            byte_order,
            type_manager,
            db_exporter,
            label=label,
            instance=instance,
        )
    except Exception as e:
        outcome = ScanOutcome(plc_info.ip_address, label=label, error=str(e) or type(e).__name__)
        display.print_error(f"{label}: {outcome.error}")
        outcome.data_points = _unreached_points(plc_info, mode, device_ranges)
        writer = ResultWriter(plc_info, exporter, display, db_exporter, label=label, instance=instance)
        writer.export_points(outcome.data_points)
        return outcome


@dataclasses.dataclass
class ScanOutcome:
    """Result of scanning a single PLC from the CLI"""

    ip_address: str
    data_points: List[DataPoint] = dataclasses.field(default_factory=list)
    denied_addresses: Set[str] = dataclasses.field(default_factory=set)
    success: bool = False
    interrupted: bool = False
    error: Optional[str] = None
    # Name in results/reports: the IP, or "IP (PROTOCOL:port)" when several
    # targets share the IP (see target_labels)
    label: Optional[str] = None

    def __post_init__(self):
        if self.label is None:
            self.label = self.ip_address


def _target_error(label: str, reason: Optional[str]) -> str:
    """Report line for a target whose scan failed"""
    return f"{label}: {reason or 'scan failed'}"


def _uncancel_current_task() -> None:
    """Clear a pending cancellation after handling Ctrl+C (Python 3.11+)"""
    task = asyncio.current_task()
    uncancel = getattr(task, "uncancel", None)
    cancelling = getattr(task, "cancelling", None)
    if uncancel is not None and cancelling is not None:
        while cancelling():
            uncancel()


def _range_labels(device_ranges: Optional[List[ScanItem]]) -> List[str]:
    return [
        (
            r.label
            if isinstance(r, TagRange)
            else f"{r.device_type.value}{r.start_address}-{r.device_type.value}{r.end_address}"
        )
        for r in (device_ranges or [])
    ] or ["ALL"]


def _unreached_points(plc_info: PLCInfo, mode: ScanMode, device_ranges: Optional[List[ScanItem]]) -> List[DataPoint]:
    """NG_COMM_ERROR points for the requested ranges / tags (full scan: every range)"""
    return unreached_points(plc_info.protocol, None if mode == ScanMode.FULL else list(device_ranges or []))


def _protocol_name(plc_info: PLCInfo) -> str:
    return plc_info.protocol.name if plc_info.protocol else "UNKNOWN"


def _check_connected(
    collector: PLCDataCollector, plc_info: PLCInfo, outcome: ScanOutcome, display: RichProgressDisplay
) -> bool:
    """Log the connection result; record an error in outcome on failure"""
    audit = get_audit_logger()
    connected = collector.is_connected
    audit.log_connect(plc_info.ip_address, _protocol_name(plc_info), plc_info.port or 0, connected)
    if not connected:
        outcome.error = f"Failed to connect to {plc_info.ip_address}:{plc_info.port} ({_protocol_name(plc_info)})"
        reason = getattr(collector, "connect_error", None)
        if reason:
            outcome.error += f": {reason}"
        display.print_error(outcome.error)
        audit.log_error(outcome.error, {"plc_ip": plc_info.ip_address})
    return connected


async def run_single_scan(
    plc_info: PLCInfo,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    mode: ScanMode,
    device_ranges: Optional[List[ScanItem]] = None,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: Optional[DatabaseExporter] = None,
    label: Optional[str] = None,
    instance: Optional[str] = None,
) -> ScanOutcome:
    """
    Run a single (non-periodic) scan on one PLC.

    ``label`` names the target in output when several targets share its IP;
    ``instance`` tells it from targets with the same IP, protocol and port
    (see target_instances).

    Connection failures are reported in the returned outcome instead of
    raising, so remaining targets are still scanned.
    """
    audit = get_audit_logger()
    ip = plc_info.ip_address
    outcome = ScanOutcome(ip, label=label)
    writer = ResultWriter(plc_info, exporter, display, db_exporter, label=label, instance=instance)
    labels = _range_labels(device_ranges)
    loop = asyncio.get_running_loop()

    display.print_info(f"Connecting to {ip}...")
    if data_type:
        display.print_info(f"Data type conversion: {data_type.value} ({byte_order.value})")

    collector = PLCDataCollector(plc_info, config)
    stats: Optional[Dict[str, Any]] = None
    denied_statuses: Dict[str, StatusCode] = {}
    try:
        async with collector:
            if not _check_connected(collector, plc_info, outcome, display):
                # Still write every requested address as NG_COMM_ERROR, so the
                # output shows what could not be read (PLC off or unreachable)
                outcome.data_points = _unreached_points(plc_info, mode, device_ranges)
                filepath = writer.export_points(outcome.data_points)
                if filepath:
                    display.print_info(f"Unreachable addresses saved to: {filepath}")
                return outcome

            audit.log_scan_start(ip, mode.value, labels)
            scan_started = loop.time()

            if mode == ScanMode.FULL:
                display.print_info("Running full scan...")
            else:
                display.print_info(f"Scanning {', '.join(labels)}")
            try:
                outcome.data_points = await collect_items(
                    collector, None if mode == ScanMode.FULL else list(device_ranges or [])
                )
            except (asyncio.CancelledError, KeyboardInterrupt):
                # Ctrl+C in the middle of a scan (a full scan can take
                # hours): what has been read so far is written like a
                # finished scan, instead of being thrown away
                outcome.interrupted = True
                _uncancel_current_task()
                outcome.data_points = list(collector.get_collected_data())
                display.print_warning(
                    f"Scan interrupted by user; saving the {len(outcome.data_points)} data points read so far"
                )

            outcome.denied_addresses = collector.get_denied_addresses()
            denied_statuses = collector.get_denied_statuses()
            stats = collector.get_statistics()
            audit.log_scan_complete(
                ip,
                stats["total_points"],
                stats["success_count"],
                # Every point that was not read (as in the database and the
                # scan summary), not only the communication errors
                stats["total_points"] - stats["success_count"],
                (loop.time() - scan_started) * 1000,
            )
    except (asyncio.CancelledError, KeyboardInterrupt):
        # Ctrl+C while connecting, or while the connection was being closed
        # after the scan. The scan's data must not depend on how long the
        # PLC takes to answer the close: it is written below either way.
        outcome.interrupted = True
        _uncancel_current_task()
        try:
            await wait_for(collector.disconnect(), timeout=2)
        except (Exception, asyncio.CancelledError) as e:
            logger.debug(f"{ip}: disconnect after interruption: {e!r}")
        if stats is None:
            display.print_warning(f"{ip}: interrupted by user before anything was read")
            outcome.error = "interrupted before the scan started"
            return outcome
        display.print_warning(f"Scan interrupted by user; saving the {len(outcome.data_points)} data points read")
    except Exception as e:
        audit.log_error(str(e), {"plc_ip": ip})
        raise
    if stats is None:
        return outcome  # not connected: reported above

    outcome.data_points = apply_data_type_conversion(outcome.data_points, data_type, byte_order, type_manager)
    filepath = writer.export_points(outcome.data_points)
    if filepath:
        display.print_success(f"Data saved to: {filepath}")

    if outcome.data_points and (data_type or type_manager):
        display.print_info("Sample converted values:")
        for dp in outcome.data_points[:5]:
            if dp.converted_value is not None:
                display.print(f"  {dp.address}: {dp.display_value} ({dp.data_type})")

    denied_path = writer.export_new_denied(outcome.denied_addresses, denied_statuses)
    if denied_path:
        display.print_info(f"Denied addresses logged to: {denied_path}")

    display.print_statistics(stats)
    if writer.error_count:
        outcome.error = writer.error_summary()
    elif not plc_answered(outcome.data_points):
        # Connected, but not one request was answered (PLC hung, cable
        # pulled after connecting, wrong unit behind a gateway): the data
        # is written as read, and the scan is a failure, not a success
        outcome.error = no_answer_error(outcome.data_points)
        display.print_error(_target_error(outcome.label or ip, outcome.error))
    else:
        # Also when interrupted: the run then ends as "interrupted" (130)
        outcome.success = True
    return outcome


async def run_periodic_scan(
    plc_infos: List[PLCInfo],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    device_ranges: List[ScanItem],
    interval: float,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: Optional[DatabaseExporter] = None,
    notifier: Optional[NotificationManager] = None,
    thresholds: Optional[List[Threshold]] = None,
) -> List[ScanOutcome]:
    """
    Periodic range scan of one or more PLCs until Ctrl+C.

    With notification_settings.report_interval_minutes, a STATUS_REPORT
    summary of the latest cycle is sent at that interval. ``thresholds``
    send THRESHOLD_EXCEEDED when a value crosses its limit.

    All targets stay connected (keeping their session cache of denied
    addresses) and are read one after another in every cycle, so every
    target is scanned at the same interval. Each cycle is exported per PLC.
    """
    audit = get_audit_logger()
    loop = asyncio.get_running_loop()
    labels = _range_labels(device_ranges)
    # Keyed by target label, not IP: targets sharing an IP (one PLC over two
    # protocols, local simulators) are each scanned and reported
    targets = list(zip(target_labels(plc_infos), plc_infos))
    outcomes = {key: ScanOutcome(p.ip_address, label=key) for key, p in targets}
    daily = getattr(exporter, "periodic_csv", "per_cycle") == "daily"
    writers = {
        key: ResultWriter(p, exporter, display, db_exporter, label=key, daily=daily, instance=instance)
        for (key, p), instance in zip(targets, target_instances(plc_infos))
    }
    ips = {key: p.ip_address for key, p in targets}

    async with contextlib.AsyncExitStack() as stack:
        collectors: Dict[str, PLCDataCollector] = {}
        # Targets that answered at least once (at start or in a later cycle)
        reached: Set[str] = set()
        for key, plc_info in targets:
            display.print_info(f"Connecting to {key}...")
            collector = await stack.enter_async_context(PLCDataCollector(plc_info, config))
            if _check_connected(collector, plc_info, outcomes[key], display):
                reached.add(key)
            elif getattr(collector, "connect_error", None):
                # Invalid options (set before any connection attempt):
                # retrying cannot help
                continue
            else:
                # PLC off or unreachable now: keep it in the cycle. Every cycle
                # retries the connection and logs NG_COMM_ERROR until it answers
                display.print_warning(f"{key}: not reachable yet; retrying every cycle")
            collectors[key] = collector
            audit.log_scan_start(plc_info.ip_address, ScanMode.RANGE.value, labels)

        if not collectors:
            return list(outcomes.values())

        display.print_info(
            f"Scanning {', '.join(labels)} on {len(collectors)} PLC(s) every {interval:g}s " f"(Ctrl+C to stop)"
        )
        started_at = loop.time()
        runner = CycleRunner(
            device_ranges,
            data_type=data_type,
            byte_order=byte_order,
            type_manager=type_manager,
            notifier=notifier,
            notify=lambda send: _notify(notifier, send),
            thresholds=ThresholdMonitor(thresholds or []),
        )
        # A threshold's target: a label or an IP of one of the targets
        runner.warn_unknown_threshold_targets([name for key in collectors for name in (key, ips[key])])
        interrupted = False
        # Targets not answering in their latest cycle
        down: Set[str] = set()
        # Targets with a cycle written, and the one being read: a target
        # stopped during its first read keeps what it had read so far
        written: Set[str] = set()
        reading: Optional[str] = None
        try:
            iteration = 0
            cycle_started: Optional[float] = None
            while True:
                iteration += 1
                cycle_started = cycle_start(interval, cycle_started)
                display.print_info(f"Iteration {iteration}")

                for key, collector in collectors.items():
                    read_failed = False
                    try:
                        reading = key
                        points = (await runner.read(collector, writers[key])).points
                        written.add(key)
                    except Exception as e:
                        # Never ends the monitoring (of every target): this
                        # cycle of this target is lost and it counts as down
                        display.print_error(f"{key}: read failed: {e or type(e).__name__}")
                        logger.debug(f"{key}: read failed", exc_info=True)
                        points, read_failed = [], True
                        # No longer being read: a stop while waiting must
                        # not save the rest of this failed cycle
                        reading = None
                    # Reachable = connected and answering: a handler without a
                    # connection to lose (FINS/UDP) or with one that outlives
                    # the PLC stays "connected" while nothing is answered
                    answering = collector.is_connected and plc_answered(points) and not read_failed
                    if answering:
                        down.discard(key)
                    else:
                        down.add(key)
                    if key not in reached and answering:
                        reached.add(key)
                        outcomes[key].error = None
                        display.print_success(f"{key}: connected")
                    outcomes[key].data_points = points
                    # PLC_UNREACHABLE once per outage, PLC_RECOVERED when it answers again
                    await runner.track_outage(key, answering, ips[key])
                    await runner.check_thresholds(key, points, ips[key])

                await runner.report_if_due(
                    {key: outcomes[key].data_points for key in collectors},
                    [key for key in collectors if key in down],
                    iteration,
                )

                wait = next_cycle_wait(interval, cycle_started)
                if wait == 0.0:
                    display.print_warning(f"Cycle took longer than the {interval:g}s interval; starting next cycle now")
                else:
                    display.print_info(f"Waiting {wait:.1f} seconds...")
                await asyncio.sleep(wait)
        except (asyncio.CancelledError, KeyboardInterrupt):
            display.print_warning("Scan interrupted by user")
            interrupted = True
            _uncancel_current_task()
            if reading is not None and reading not in written:
                # Stopped during the first read of this target (a long range
                # can take minutes): saved like an interrupted single scan,
                # instead of leaving no data at all. Later cycles are not:
                # the completed ones are already written.
                partial = runner.save_partial(collectors[reading], writers[reading])
                if partial.points:
                    outcomes[reading].data_points = partial.points
                    display.print_warning(
                        f"{reading}: saving the {len(partial.points)} data points of the first cycle read so far"
                    )
        # Release the PLCs before waiting for notifications a slow webhook
        # is still receiving (the collectors keep their data and statistics)
        for key, collector in collectors.items():
            try:
                await collector.disconnect()
            except Exception as e:
                logger.debug(f"{key}: disconnect failed: {e}")
        await runner.drain()

        for key, collector in collectors.items():
            outcome = outcomes[key]
            outcome.interrupted = interrupted
            outcome.denied_addresses = collector.get_denied_addresses()
            writers[key].export_new_denied(outcome.denied_addresses, collector.get_denied_statuses())
            stats = collector.get_statistics()
            audit.log_scan_complete(
                ips[key],
                stats["total_points"],
                stats["success_count"],
                stats["total_points"] - stats["success_count"],
                (loop.time() - started_at) * 1000,
            )
            display.print_info(f"Last cycle statistics for {key}:")
            display.print_statistics(stats)
            if key not in reached:
                pass  # never answered: keep the connection error from the start
            elif writers[key].error_count:
                outcome.error = writers[key].error_summary(" during monitoring")
            elif not plc_answered(outcome.data_points):
                # Not answering when the monitoring ended
                outcome.error = no_answer_error(outcome.data_points)
            else:
                outcome.success = True

    return list(outcomes.values())


UNDETECTED_PROTOCOL = (
    "no PLC protocol answered (check the PLC power and network, "
    "or specify the protocol with --protocol / targets[].protocol)"
)


async def resolve_target(
    ip: str,
    protocol: Optional[Protocol],
    port: Optional[int],
    config: NetworkConfig,
    display: RichProgressDisplay,
    base: Optional[PLCInfo] = None,
) -> Optional[PLCInfo]:
    """
    Build PLCInfo for a target, auto-detecting the protocol if not given.

    Returns None when no protocol answers: the target is reported as
    failed instead of being scanned as SLMP, which produced a misleading
    "Failed to connect ... (SLMP)" for a protocol nobody asked for.
    """
    if protocol:
        plc_info = base or PLCInfo(ip_address=ip)
        plc_info.protocol = protocol
        plc_info.port = port or PROTOCOL_PORTS.get(protocol)
        return plc_info

    # With a port but no protocol, the protocols are tried on that port:
    # probing the standard ports and then overwriting the port paired the
    # detected protocol with a port it was never seen on
    display.print_info(f"Detecting protocol for {ip}{f' on port {port}' if port else ''}...")
    detected = await PLCDiscovery(config, port=port)._probe_host(ip)
    if detected and detected.protocol:
        display.print_success(f"Detected: {detected.protocol.name}")
        if base:
            detected.manufacturer = base.manufacturer or detected.manufacturer
            detected.model = base.model or detected.model
            detected.options = dict(base.options)
        return detected

    display.print_error(f"{ip}: {UNDETECTED_PROTOCOL}")
    return None


async def _notify(
    notifier: Optional[NotificationManager], send: Callable[[NotificationManager], Awaitable[Any]]
) -> bool:
    """
    Send a notification if configured; never let it break the scan.

    Returns False when it could not be delivered to any destination (the
    caller may offer a state change again on a later cycle).
    """
    if notifier is None:
        return True
    try:
        return NotificationManager.delivered(await send(notifier))
    except Exception as e:
        logger.warning(f"Notification failed: {e}")
        return False


def _exit_with_errors(prefix: str, errors: List[str]) -> None:
    """Print each error and exit with status 1"""
    for error in errors:
        print(f"{prefix}: {error}")
    sys.exit(1)


def _configure_logging(args: argparse.Namespace) -> None:
    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,
    )
    quiet_third_party_loggers(args.verbose)


def _apply_config_logging(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> None:
    """
    Apply the config file's logging section: ``level`` (unless --verbose /
    --quiet is given, which win) and ``file`` (log lines are also appended
    to that file, in ``format``). A log file that cannot be opened is
    reported and never stops the run.
    """
    if config_loader is None:
        return
    settings = config_loader.get_logging_settings()
    root = logging.getLogger()
    level = log_level_number(settings.get("level"))
    if config_loader.is_set("logging", "level") and level is not None and not (args.verbose or args.quiet):
        root.setLevel(level)
        quiet_third_party_loggers(level <= logging.DEBUG)
    log_file = settings.get("file")
    if log_file:
        try:
            path = Path(str(log_file)).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(path, encoding="utf-8")
            handler.setFormatter(
                logging.Formatter(str(settings.get("format") or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            )
            root.addHandler(handler)
        except Exception as e:
            logger.warning(f"Cannot write the log file {log_file}: {e}")


def _load_config(args: argparse.Namespace) -> Optional[ConfigLoader]:
    """The validated config file (--config), or None; exits on errors"""
    if not args.config:
        return None
    if not Path(args.config).is_file():
        _exit_with_errors("Config error", [f"file not found: {args.config}"])
    config_loader = ConfigLoader(args.config)
    try:
        config_loader.load()
    except Exception as e:
        _exit_with_errors("Config error", [str(e)])
    try:
        errors = config_loader.validate()
    except Exception as e:
        # A value of an unexpected type somewhere: still a config error,
        # never a traceback
        errors = [f"invalid configuration: {e}"]
    if errors:
        _exit_with_errors("Config error", errors)
    return config_loader


def _resolve_run_settings(
    args: argparse.Namespace, config_loader: Optional[ConfigLoader]
) -> Tuple[str, float, NetworkConfig]:
    """(mode name, interval, NetworkConfig) from the options; exits on errors"""
    mode_name, interval = resolve_mode_and_interval(args, config_loader)
    if not math.isfinite(interval) or interval < 0 or (mode_name == "range" and 0 < interval < MIN_INTERVAL_SECONDS):
        _exit_with_errors(
            "Error", [f"--interval must be 0 (single scan) or >= {MIN_INTERVAL_SECONDS:g} seconds, got {interval}"]
        )
    option_errors = network_option_errors(args)
    if option_errors:
        _exit_with_errors("Error", option_errors)
    return mode_name, interval, create_network_config(args, config_loader)


def _init_audit(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> Optional[str]:
    """Start the audit log (--audit-log or logging.audit_log); returns its path"""
    audit_file: Optional[str] = args.audit_log
    if config_loader and not audit_file:
        configured = config_loader.get_logging_settings().get("audit_log")
        audit_file = str(configured) if configured else None
    if audit_file:
        init_audit_logger(audit_file, enabled=True)
        get_audit_logger().log_session_start({"args": vars(args)})
    return audit_file


def _create_exporter(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> CSVExporter:
    """CSV exporter with the output directory, encoding and CSV options"""
    output_dir, encoding = resolve_output_settings(args, config_loader)
    output_settings = config_loader.get_output_settings() if config_loader else {}
    hex_addresses = args.hex_addresses
    if hex_addresses is None and config_loader:
        hex_addresses = bool(output_settings.get("hex_addresses", False))
    exporter = CSVExporter(output_dir, encoding, hex_addresses=bool(hex_addresses))
    periodic_csv = args.periodic_csv
    if periodic_csv is None and config_loader:
        periodic_csv = output_settings.get("periodic_csv")
    exporter.periodic_csv = periodic_csv or "per_cycle"
    return exporter


def _create_db_exporter(
    args: argparse.Namespace, config_loader: Optional[ConfigLoader], display: RichProgressDisplay
) -> Optional[DatabaseExporter]:
    """Database output from --database or the config file (optional)"""
    if args.no_database:
        return None
    db_config = None
    database_settings = config_loader.get_output_settings().get("database") if config_loader else None
    if not isinstance(database_settings, dict):
        database_settings = {}  # no config file, or "database:" left empty
    if args.database:
        # --database only says where: retention and size limits still come
        # from the config file. Without them the default 30-day retention
        # deleted the history a config with max_history_days: 0 was keeping.
        db_config = DatabaseConfig.from_dict({**database_settings, "enabled": True, "path": args.database})
    elif database_settings.get("enabled"):
        db_config = DatabaseConfig.from_dict(database_settings)
    if db_config and args.db_track_history is not None:
        db_config.track_history = args.db_track_history
    if not (db_config and db_config.enabled):
        return None
    try:
        db_exporter = DatabaseExporter(db_config)
    except Exception as e:
        display.print_warning(f"Failed to initialize database: {e}")
        return None
    display.print_info(f"Database output enabled: {db_config.path}")
    return db_exporter


def _create_notifier(
    config_loader: Optional[ConfigLoader], display: RichProgressDisplay
) -> Optional[NotificationManager]:
    """Notifications (webhook / Slack / Teams) from the config file"""
    if not (config_loader and config_loader.config.get("notifications")):
        return None
    notifier = NotificationManager.from_config(config_loader.config)
    display.print_info(f"Notifications enabled: {len(notifier._handlers)} handler(s)")
    return notifier


@dataclasses.dataclass
class _RunResults:
    """What one run of the CLI found, for notifications, the report and the exit code"""

    plcs: List[PLCInfo] = dataclasses.field(default_factory=list)
    data_points: Dict[str, List[DataPoint]] = dataclasses.field(default_factory=dict)
    denied_addresses: Dict[str, List[str]] = dataclasses.field(default_factory=dict)
    failed_targets: List[str] = dataclasses.field(default_factory=list)
    # "label: reason" for each failed target, shown in the report
    target_errors: List[str] = dataclasses.field(default_factory=list)
    output_errors: List[str] = dataclasses.field(default_factory=list)
    interrupted: bool = False
    # Targets a scan was run for (fewer than plcs when the run was interrupted)
    scanned: int = 0

    def add_failure(self, label: str, reason: Optional[str]) -> None:
        self.failed_targets.append(label)
        self.target_errors.append(_target_error(label, reason))

    def add(
        self, label: str, success: bool, error: Optional[str], data_points: List[DataPoint], denied: Set[str]
    ) -> None:
        """Record one target's scan result"""
        self.scanned += 1
        if not success:
            self.add_failure(label, error)
        if data_points:
            self.data_points[label] = data_points
        if denied:
            self.denied_addresses[label] = sorted_addresses(denied)


async def _run_discover(
    args: argparse.Namespace,
    config_loader: Optional[ConfigLoader],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: Optional[DatabaseExporter],
    notifier: Optional[NotificationManager],
    results: _RunResults,
) -> None:
    ip_ranges = [args.ip_range] if args.ip_range else (config_loader.get_ip_ranges() if config_loader else [])
    range_errors = [e for e in map(ip_range_error, ip_ranges) if e]
    if range_errors:
        for error in range_errors:
            display.print_error(error)
        sys.exit(1)
    discovered = await run_discovery(
        ip_ranges,
        config,
        exporter,
        display,
        db_exporter,
        resolve_discovery_protocols(args, config_loader),
        errors=results.output_errors,
    )
    results.plcs = discovered if discovered else []
    await _notify(notifier, lambda n: n.notify_discovery(len(results.plcs), [p.to_dict() for p in results.plcs]))


async def _resolve_targets(args, config_loader, config, display):
    """(targets to scan, targets whose protocol could not be detected); exits without targets"""
    targets = parse_targets(args.target) if args.target else []
    protocol = get_protocol_from_string(args.protocol) if args.protocol else None
    plc_infos: List[PLCInfo] = []
    undetected: List[str] = []
    if config_loader and not targets:
        for target in config_loader.get_targets():
            # --protocol / --port win over the file's targets, like every
            # other command-line option. The file's port and options belong
            # to the file's protocol: with another protocol they are not
            # used (Modbus frames were sent to the SLMP port otherwise).
            other_protocol = protocol is not None and protocol != target.protocol
            base = dataclasses.replace(target, options={}) if other_protocol else target
            port = args.port or (None if other_protocol else target.port)
            resolved = await resolve_target(
                target.ip_address, protocol or target.protocol, port, config, display, base=base
            )
            if resolved:
                plc_infos.append(resolved)
            else:
                undetected.append(target.ip_address)
    else:
        if not targets:
            display.print_error("--target is required for full/range modes")
            sys.exit(1)
        for ip in targets:
            resolved = await resolve_target(ip, protocol, args.port, config, display)
            if resolved:
                plc_infos.append(resolved)
            else:
                undetected.append(ip)
    if not plc_infos and not undetected:
        display.print_error("No targets specified")
        sys.exit(1)
    return plc_infos, undetected


THRESHOLDS_IGNORED = "Thresholds are watched in periodic range scans only (--interval); ignored"


async def _run_scans(
    args: argparse.Namespace,
    config_loader: Optional[ConfigLoader],
    mode_name: str,
    interval: float,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: Optional[DatabaseExporter],
    notifier: Optional[NotificationManager],
    data_types: Tuple[Optional[DataType], ByteOrder, Optional[DataTypeManager]],
    thresholds: List[Threshold],
    results: _RunResults,
) -> None:
    # Validate ranges before connecting to anything
    mode = ScanMode.FULL if mode_name == "full" else ScanMode.RANGE
    device_ranges = resolve_device_ranges(args, config_loader) if mode == ScanMode.RANGE else None
    data_type, byte_order, type_manager = data_types

    plc_infos, undetected = await _resolve_targets(args, config_loader, config, display)
    # Names already used in the results: a detected target that is alone on
    # its IP is named by the IP, as is an undetected one. Two targets on one
    # IP (other ports) of which only one answered shared that name, and the
    # NG_COMM_ERROR rows of the other were replaced in the report.
    used_labels = set(target_labels(plc_infos))
    for ip in undetected:
        label, repeat = ip, 0
        while label in used_labels:
            repeat += 1
            label = f"{ip} (protocol not detected)" + (f" #{repeat}" if repeat > 1 else "")
        used_labels.add(label)
        # No protocol answered (PLC off): still write what was asked for as
        # NG_COMM_ERROR, like a target whose protocol was given. A full
        # scan has no ranges without a protocol: one row for the whole scan.
        unread = unreached_points(None, list(device_ranges) if device_ranges is not None else None) or [
            DataPoint(address=FULL_SCAN_ADDRESS, status=StatusCode.NG_COMM_ERROR, timestamp=get_timestamp())
        ]
        filepath = ResultWriter(PLCInfo(ip_address=ip), exporter, display, db_exporter).export_points(unread)
        if filepath:
            display.print_info(f"Unreachable addresses saved to: {filepath}")
        results.add(label, False, UNDETECTED_PROTOCOL, unread, set())

    if mode == ScanMode.FULL and interval > 0:
        display.print_warning("--interval is ignored in full scan mode")
    if thresholds and not (mode == ScanMode.RANGE and interval > 0):
        display.print_warning(THRESHOLDS_IGNORED)
    elif thresholds:
        display.print_info(f"Watching {len(thresholds)} threshold(s): {', '.join(t.label for t in thresholds)}")

    # Undetected targets are listed (without protocol) in the report
    results.plcs = plc_infos + [PLCInfo(ip_address=ip) for ip in undetected]

    if not plc_infos:
        return  # nothing could be scanned; reported as failed
    if mode == ScanMode.RANGE and interval > 0:
        # Periodic: all targets in turn every cycle
        if len(plc_infos) > 1 and config.max_concurrent > 1:
            display.print_info("Periodic scans read targets one after another (--max-concurrent not used)")
        outcomes = await run_periodic_scan(
            plc_infos,
            config,
            exporter,
            display,
            device_ranges or [],
            interval,
            data_type,
            byte_order,
            type_manager,
            db_exporter,
            notifier,
            thresholds,
        )
        for outcome in outcomes:
            results.add(
                outcome.label or outcome.ip_address,
                outcome.success,
                outcome.error,
                outcome.data_points,
                outcome.denied_addresses,
            )
            results.interrupted = results.interrupted or outcome.interrupted
    elif len(plc_infos) > 1 and config.max_concurrent > 1:
        parallel = await run_parallel_scan(
            plc_infos, config, exporter, display, mode, device_ranges, data_type, byte_order, type_manager, db_exporter
        )
        for label, outcome in parallel.items():
            results.add(label, outcome.success, outcome.error, outcome.data_points, outcome.denied_addresses)
            results.interrupted = results.interrupted or outcome.interrupted
        # Interrupted while every remaining target was still waiting for its turn
        results.interrupted = results.interrupted or len(parallel) < len(plc_infos)
    else:
        # Single or sequential scan
        for label, plc_info, instance in zip(target_labels(plc_infos), plc_infos, target_instances(plc_infos)):
            outcome = await scan_target(
                plc_info,
                config,
                exporter,
                display,
                mode,
                device_ranges,
                data_type,
                byte_order,
                type_manager,
                db_exporter,
                label,
                instance,
            )
            results.add(label, outcome.success, outcome.error, outcome.data_points, outcome.denied_addresses)
            if outcome.interrupted:
                # Ctrl+C: the remaining targets are not scanned
                results.interrupted = True
                break


def _resolve_data_types_or_exit(args, config_loader, display):
    """Data type options (CLI, then type mapping file / config file)"""
    try:
        data_type, byte_order, type_manager = resolve_data_types(args, config_loader)
    except Exception as e:
        display.print_error(f"Failed to load type mapping: {e}")
        sys.exit(1)
    if args.type_mapping:
        display.print_info(f"Loaded type mapping from: {args.type_mapping}")
    elif type_manager:
        display.print_info("Using data type mappings from config file")
    return data_type, byte_order, type_manager


async def _notify_scan_end(
    notifier: Optional[NotificationManager], mode_name: str, results: _RunResults, duration: float
) -> None:
    failed = results.failed_targets
    # One error notification for all failed targets (each send can take
    # several seconds when the endpoint is unreachable)
    if failed:
        await _notify(
            notifier,
            lambda n: n.notify_error(
                f"Scan failed for {len(failed)} target(s): {', '.join(failed)}",
                plc_ip=failed[0] if len(failed) == 1 else None,
                failed_targets=failed,
            ),
        )
    # Interrupted: the targets that were never scanned are not "successful"
    total = results.scanned if results.interrupted else len(results.plcs)
    total = max(total, len(failed))
    await _notify(
        notifier,
        lambda n: n.notify_scan_complete(
            total,
            total - len(failed),
            len(failed),
            duration,
            mode=mode_name,
            interrupted=results.interrupted,
        ),
    )


def _write_report(
    args: argparse.Namespace,
    output_dir: str,
    mode_name: str,
    interval: float,
    display: RichProgressDisplay,
    results: _RunResults,
    started_at: datetime,
    completed_at: datetime,
) -> None:
    """The --report file; a failure counts as an output error"""
    display.print_info("Generating report...")
    format_map = {
        "html": ReportFormat.HTML,
        "pdf": ReportFormat.PDF,
        "json": ReportFormat.JSON,
    }
    report_config = ReportConfig(
        format=format_map[args.report],
        output_path=output_dir,
        title=args.report_title,
        company_name=args.report_company,
        theme=args.report_theme,
    )
    report_mode = mode_name
    if mode_name == "range" and interval > 0:
        # Periodic monitoring: data_points hold the last cycle only
        report_mode = f"range (periodic every {interval:g}s, last cycle)"
        display.print_info("Report contains the last monitoring cycle; per-cycle data is in the CSV files")
    generator, report_data = create_report(
        plcs=results.plcs,
        data_points=results.data_points,
        denied_addresses=results.denied_addresses,
        scan_mode=report_mode,
        started_at=started_at,
        completed_at=completed_at,
        config=report_config,
        errors=results.target_errors + results.output_errors,
    )
    try:
        report_path = generator.save(report_data, args.report_output)
        display.print_success(f"Report saved to: {report_path}")
    except Exception as e:
        # Counted like a CSV/database write failure: the requested
        # report does not exist, so the run must not exit with 0
        # (e.g. --report pdf without weasyprint/pdfkit)
        message = f"Report generation failed: {e}"
        display.print_error(message)
        results.output_errors.append(message)


def _final_status(display: RichProgressDisplay, results: _RunResults) -> int:
    """Print the closing line; returns the exit code"""
    if results.interrupted:
        display.print_warning("Scan stopped by user.")
        return 130
    if results.output_errors:
        display.print_error(f"Finished, but {len(results.output_errors)} output error(s) occurred")
        return 1
    if results.failed_targets:
        display.print_error(
            f"Scan finished with errors: {len(results.failed_targets)} target(s) failed "
            f"({', '.join(results.failed_targets)})"
        )
        return 1
    display.print_success("Scan completed successfully.")
    return 0


def _close_run(db_exporter: Optional[DatabaseExporter], audit_file: Optional[str], exit_code: int) -> None:
    """End the database scan session and the audit log"""
    if db_exporter:
        try:
            db_exporter.end_session(
                {
                    0: "completed",
                    1: "completed with errors",
                    130: "interrupted",
                }.get(exit_code, f"exit {exit_code}")
            )
        except Exception as e:
            logger.warning(f"Failed to close database session: {e}")
        db_exporter.close()
    if audit_file:
        get_audit_logger().log_session_end()
        close_audit_logger()


async def run_cli() -> Optional[int]:
    """
    The whole run; returns the exit code (None or 0: success).

    Returned, not raised with sys.exit(): on Python 3.10 a run interrupted
    with Ctrl+C finishes inside asyncio.run()'s shutdown, where a SystemExit
    raised in the task ended as "Task exception was never retrieved" with a
    traceback, even with --quiet.
    """
    args = parse_args()

    if args.generate_config:
        try:
            generate_config_template(args.generate_config)
        except (OSError, ValueError) as e:  # exists, wrong extension, directory missing or not writable
            print(f"Error: {e}")
            sys.exit(1)
        return None

    _configure_logging(args)
    config_loader = _load_config(args)
    _apply_config_logging(args, config_loader)
    mode_name, interval, config = _resolve_run_settings(args, config_loader)
    display = RichProgressDisplay(use_rich=not args.no_rich)
    if not args.quiet and not args.no_rich:
        display.print_header()

    # Checked before anything is opened: an invalid --threshold or type
    # mapping ended the run after the audit session had started (left
    # without its end) and the database had already been cleaned up
    data_types = _resolve_data_types_or_exit(args, config_loader, display)
    try:
        thresholds = resolve_thresholds(args, config_loader)
        # What the run will read, checked here as well: a mistyped --range,
        # --target or --discover-protocols was found only after the audit
        # and database sessions had started, and was then sent to the
        # notification destinations as a scan error of a PLC
        if mode_name == "discover":
            resolve_discovery_protocols(args, config_loader)
        else:
            if args.target:
                parse_targets(args.target)
            if mode_name == "range":
                resolve_device_ranges(args, config_loader)
    except ValueError as e:
        display.print_error(str(e))
        sys.exit(1)

    audit_file = _init_audit(args, config_loader)
    try:
        exporter = _create_exporter(args, config_loader)
    except OSError as e:
        # A file of that name, or a place that cannot be written: say so,
        # and end the audit log's session, instead of a traceback
        display.print_error(f"Cannot use the output directory: {e}")
        _close_run(None, audit_file, 1)
        sys.exit(1)
    db_exporter = _create_db_exporter(args, config_loader, display)
    notifier = _create_notifier(config_loader, display)
    if mode_name == "discover" and getattr(args, "threshold", None):
        display.print_warning(THRESHOLDS_IGNORED)

    results = _RunResults()
    exit_code = 0
    try:
        started_at = datetime.now()

        # Tag all database rows of this run with one scan session
        if db_exporter and db_exporter.is_enabled:
            try:
                db_exporter.begin_session(mode_name)
            except Exception as e:
                # Locked by another program at this moment: the PLCs are
                # still scanned and the CSV files written. Later database
                # writes are tried, and reported, one by one.
                display.print_warning(f"Database session could not be started ({e}); the scan continues")

        if mode_name == "discover":
            await _run_discover(args, config_loader, config, exporter, display, db_exporter, notifier, results)
        else:
            await _run_scans(
                args,
                config_loader,
                mode_name,
                interval,
                config,
                exporter,
                display,
                db_exporter,
                notifier,
                data_types,
                thresholds,
                results,
            )

        completed_at = datetime.now()
        if mode_name != "discover":
            await _notify_scan_end(notifier, mode_name, results, (completed_at - started_at).total_seconds())
        if args.report:
            _write_report(
                args, str(exporter.output_dir), mode_name, interval, display, results, started_at, completed_at
            )
        exit_code = _final_status(display, results)

    except SystemExit as e:
        # Invalid ranges / targets found after the session started
        exit_code = e.code if isinstance(e.code, int) else 1
        raise
    except (KeyboardInterrupt, asyncio.CancelledError):
        display.print_warning("Operation cancelled by user.")
        _uncancel_current_task()
        exit_code = 130
    except Exception as e:
        message = str(e)
        display.print_error(message)
        if args.verbose:
            import traceback

            traceback.print_exc()
        exit_code = 1
        await _notify(notifier, lambda n: n.notify_error(message))
    finally:
        _close_run(db_exporter, audit_file, exit_code)

    return exit_code


async def main():
    """Main entry point: run, then exit with the run's exit code"""
    exit_code = await run_cli()
    if exit_code:
        sys.exit(exit_code)


def make_streams_safe() -> None:
    """
    Never crash on characters the console/file encoding cannot represent:
    e.g. output redirected to a file on Japanese Windows is CP932, which has
    no ✓/ℹ and no "ü" in some device names. Such characters become "?".
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def quiet_third_party_loggers(verbose: bool) -> None:
    """
    Communication libraries log their own expected failures as ERROR with
    full tracebacks (e.g. pycomm3 while EtherNet/IP falls back from the
    Logix to the SLC driver, pymodbus for a refused connection). This tool
    reports those outcomes itself, so show the libraries' logs only with -v.
    """
    level = logging.DEBUG if verbose else logging.CRITICAL
    for name in ("pycomm3", "pymodbus"):
        logging.getLogger(name).setLevel(level)


def cli():
    """Console-script entry point (``plc-scanner``)"""
    make_streams_safe()
    try:
        exit_code = asyncio.run(run_cli())
    except KeyboardInterrupt:
        # Second Ctrl+C or Python 3.10 (where the loop itself is interrupted)
        sys.exit(130)
    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    cli()
