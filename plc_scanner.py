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

import asyncio
import contextlib
import dataclasses
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

from plc_discovery.config import (
    Protocol, ScanMode, PLCInfo, DataPoint,
    NetworkConfig, DeviceRange, StatusCode, PROTOCOL_PORTS, TagRange
)
from plc_discovery.discovery import (
    PLCDiscovery, discover_plcs, merge_discovery_results, target_labels
)
from plc_discovery.collector import PLCDataCollector, collect_item
from plc_discovery.output import CSVExporter
from plc_discovery.utils import ip_range_error, sorted_addresses
from plc_discovery.config_loader import MIN_INTERVAL_SECONDS, ConfigLoader, generate_config_template
from plc_discovery.audit_log import init_audit_logger, get_audit_logger, close_audit_logger
from plc_discovery.parallel import ParallelPLCScanner, scan_plcs_parallel
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.progress import RichProgressDisplay, get_display, is_rich_available
from plc_discovery.data_types import DataType, ByteOrder, DataTypeManager
from plc_discovery.notifications import NotificationManager
from plc_discovery.database import (
    DatabaseExporter, DatabaseConfig, get_database_exporter
)
from plc_discovery.report import (
    ReportGenerator, ReportConfig, ReportFormat, ReportData, ScanSummary,
    create_report, generate_html_report
)

from plc_discovery.cli_args import (  # noqa: F401  (re-exported for existing imports)
    BYTE_ORDER_MAP, DATA_TYPE_MAP, NETWORK_OPTIONS, create_network_config,
    get_device_type_from_string, get_protocol_from_string, network_option_errors, parse_address_range,
    parse_args, parse_tag_list, parse_targets, resolve_device_ranges, resolve_device_ranges_only,
    resolve_discovery_protocols, resolve_mode_and_interval, resolve_output_settings,
)
from plc_discovery.conversion import (  # noqa: F401
    _split_address, apply_data_type_conversion, load_type_mapping, resolve_data_types,
)

logger = logging.getLogger(__name__)


async def run_discovery(
    ip_ranges: List[str],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: DatabaseExporter = None,
    protocols: Optional[List[Protocol]] = None,
    errors: Optional[List[str]] = None
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
    
    # Try broadcast discovery first
    try:
        display.print_info("Trying UDP broadcast discovery...")
        broadcast = BroadcastDiscovery(config)
        broadcast_plcs = await broadcast.discover_all_broadcast()
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
    audit.log_discovery_result(
        len(plcs),
        [p.to_dict() for p in plcs]
    )
    
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
    device_ranges: Optional[List[DeviceRange]] = None,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: DatabaseExporter = None
) -> Dict:
    """Run parallel scan on multiple PLCs"""
    display.print_info(f"Starting parallel scan of {len(plcs)} PLCs...")
    
    scanner = ParallelPLCScanner(config)
    results = await scanner.scan_multiple_plcs(plcs, mode, device_ranges)
    
    # Export results for each PLC (keyed by target label, see target_labels)
    for label, result in results.items():
        if not result.success:
            display.print_error(f"{label}: {result.error_message}")
        
        writer = _ResultWriter(result.plc_info, exporter, display, db_exporter, label=label)
        if result.data_points:
            # Apply data type conversion
            result.data_points = apply_data_type_conversion(
                result.data_points, data_type, byte_order, type_manager
            )
            writer.export_points(result.data_points)
        
        if result.denied_addresses:
            writer.export_new_denied(result.denied_addresses, result.denied_statuses)
        
        if writer.errors and result.success:
            result.success = False
            result.error_message = f"{len(writer.errors)} write error(s); first: {writer.errors[0]}"
    
    # Display results
    result_dicts = {
        ip: {
            "success": r.success,
            "error_message": r.error_message,
            "statistics": r.statistics,
        }
        for ip, r in results.items()
    }
    display.print_scan_results(result_dicts)
    
    # Display aggregate statistics
    stats = scanner.get_aggregate_statistics()
    display.print_statistics(stats)
    
    return results


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
    if uncancel is not None:
        while task.cancelling():
            uncancel()


async def _collect_ranges(
    collector: PLCDataCollector,
    device_ranges: List[DeviceRange]
) -> List[DataPoint]:
    """Collect all device ranges in order"""
    points: List[DataPoint] = []
    for device_range in device_ranges:
        points.extend(await collect_item(collector, device_range))
    return points


class _ResultWriter:
    """
    Writes one PLC's data / newly denied addresses to CSV and the database.
    
    Write failures (e.g. a CSV locked by Excel on Windows, a full disk) are
    reported and counted but never raised, so a scan or a long periodic
    monitoring run keeps going. Denied addresses that could not be written
    are retried on the next call.
    """
    
    def __init__(self, plc_info: PLCInfo, exporter: CSVExporter, display: RichProgressDisplay,
                 db_exporter: Optional[DatabaseExporter] = None, label: Optional[str] = None):
        self.ip = plc_info.ip_address
        self.protocol = plc_info.protocol.name if plc_info.protocol else None
        self.port = plc_info.port
        # "IP (PROTOCOL:port)" when another target shares the IP (target_labels)
        self.label = label or self.ip
        self.shared_ip = self.label != self.ip
        self.exporter = exporter
        # Periodic scans with output.periodic_csv: daily append to one file a day
        self.daily = False
        self.display = display
        self.db_exporter = db_exporter
        self._exported_denied: Set[str] = set()
        self.errors: List[str] = []
    
    def _failed(self, what: str, error: Exception) -> None:
        message = f"{self.label}: failed to write {what}: {error}"
        self.errors.append(message)
        self.display.print_error(message)
        logger.error(message)
    
    def export_points(self, points: List[DataPoint]) -> Optional[str]:
        if not points:
            return None
        path = None
        try:
            # Protocol and port in the file name only when the IP is shared
            tag = f"{self.protocol}_{self.port}" if self.shared_ip else None
            hex_addresses = self.exporter.hex_addresses and self.protocol == "SLMP"
            if self.daily:
                path = self.exporter.append_plc_data(
                    points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
            else:
                path = self.exporter.export_plc_data(
                    points, self.ip, target_tag=tag, hex_addresses=hex_addresses)
        except Exception as e:
            self._failed("data CSV", e)
        if self.db_exporter and self.db_exporter.is_enabled:
            try:
                db_count = self.db_exporter.export_plc_data(
                    points, self.ip, protocol=self.protocol, port=self.port
                )
                self.display.print_info(f"Saved {db_count} records to database")
            except Exception as e:
                self._failed("data to database", e)
        return path
    
    def export_new_denied(self, denied: Set[str],
                          statuses: Optional[Dict[str, StatusCode]] = None) -> Optional[str]:
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


def _range_labels(device_ranges: Optional[List[DeviceRange]]) -> List[str]:
    return [
        r.label if isinstance(r, TagRange)
        else f"{r.device_type.value}{r.start_address}-{r.device_type.value}{r.end_address}"
        for r in (device_ranges or [])
    ] or ["ALL"]


def _protocol_name(plc_info: PLCInfo) -> str:
    return plc_info.protocol.name if plc_info.protocol else "UNKNOWN"


def _check_connected(collector: PLCDataCollector, plc_info: PLCInfo,
                     outcome: ScanOutcome, display: RichProgressDisplay) -> bool:
    """Log the connection result; record an error in outcome on failure"""
    audit = get_audit_logger()
    connected = collector.is_connected
    audit.log_connect(plc_info.ip_address, _protocol_name(plc_info), plc_info.port or 0, connected)
    if not connected:
        outcome.error = (
            f"Failed to connect to {plc_info.ip_address}:{plc_info.port} ({_protocol_name(plc_info)})"
        )
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
    device_ranges: Optional[List[DeviceRange]] = None,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: DatabaseExporter = None,
    label: Optional[str] = None
) -> ScanOutcome:
    """
    Run a single (non-periodic) scan on one PLC.
    
    ``label`` names the target in output when several targets share its IP.
    
    Connection failures are reported in the returned outcome instead of
    raising, so remaining targets are still scanned.
    """
    audit = get_audit_logger()
    ip = plc_info.ip_address
    outcome = ScanOutcome(ip, label=label)
    writer = _ResultWriter(plc_info, exporter, display, db_exporter, label=label)
    labels = _range_labels(device_ranges)
    loop = asyncio.get_running_loop()
    
    display.print_info(f"Connecting to {ip}...")
    if data_type:
        display.print_info(f"Data type conversion: {data_type.value} ({byte_order.value})")
    
    try:
        async with PLCDataCollector(plc_info, config) as collector:
            if not _check_connected(collector, plc_info, outcome, display):
                return outcome
            
            audit.log_scan_start(ip, mode.value, labels)
            scan_started = loop.time()
            
            if mode == ScanMode.FULL:
                display.print_info("Running full scan...")
                outcome.data_points = await collector.collect_full_scan()
            else:
                display.print_info(f"Scanning {', '.join(labels)}")
                outcome.data_points = await _collect_ranges(collector, device_ranges or [])
            
            outcome.denied_addresses = collector.get_denied_addresses()
            denied_statuses = collector.get_denied_statuses()
            stats = collector.get_statistics()
            audit.log_scan_complete(
                ip, stats["total_points"], stats["success_count"], stats["error_count"],
                (loop.time() - scan_started) * 1000
            )
    except Exception as e:
        audit.log_error(str(e), {"plc_ip": ip})
        raise
    
    outcome.data_points = apply_data_type_conversion(
        outcome.data_points, data_type, byte_order, type_manager
    )
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
    if writer.errors:
        outcome.error = f"{len(writer.errors)} write error(s); first: {writer.errors[0]}"
    else:
        outcome.success = True
    return outcome


async def run_periodic_scan(
    plc_infos: List[PLCInfo],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    device_ranges: List[DeviceRange],
    interval: float,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: DatabaseExporter = None,
    notifier: Optional[NotificationManager] = None
) -> List[ScanOutcome]:
    """
    Periodic range scan of one or more PLCs until Ctrl+C.
    
    With notification_settings.report_interval_minutes, a STATUS_REPORT
    summary of the latest cycle is sent at that interval.
    
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
    writers = {
        key: _ResultWriter(p, exporter, display, db_exporter, label=key)
        for key, p in targets
    }
    for writer in writers.values():
        writer.daily = getattr(exporter, "periodic_csv", "per_cycle") == "daily"
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
            f"Scanning {', '.join(labels)} on {len(collectors)} PLC(s) every {interval:g}s "
            f"(Ctrl+C to stop)"
        )
        started_at = loop.time()
        last_report = started_at
        interrupted = False
        try:
            iteration = 0
            while True:
                iteration += 1
                cycle_started = loop.time()
                display.print_info(f"Iteration {iteration}")
                
                for key, collector in collectors.items():
                    collector.clear_data()
                    points = await _collect_ranges(collector, device_ranges)
                    if key not in reached and collector.is_connected:
                        reached.add(key)
                        outcomes[key].error = None
                        display.print_success(f"{key}: connected")
                    points = apply_data_type_conversion(points, data_type, byte_order, type_manager)
                    outcomes[key].data_points = points
                    writers[key].export_points(points)
                    writers[key].export_new_denied(
                        collector.get_denied_addresses(), collector.get_denied_statuses()
                    )
                
                if (notifier and notifier.report_interval_seconds
                        and loop.time() - last_report >= notifier.report_interval_seconds):
                    last_report = loop.time()
                    message, problems = status_report_message(
                        {key: outcomes[key].data_points for key in collectors},
                        [key for key in collectors if key not in reached],
                        iteration,
                    )
                    await _notify(notifier, lambda n: n.notify_status_report(
                        message, has_problems=problems, iteration=iteration,
                    ))
                
                wait = max(0.0, interval - (loop.time() - cycle_started))
                if wait == 0.0:
                    display.print_warning(
                        f"Cycle took longer than the {interval:g}s interval; starting next cycle now"
                    )
                else:
                    display.print_info(f"Waiting {wait:.1f} seconds...")
                await asyncio.sleep(wait)
        except (asyncio.CancelledError, KeyboardInterrupt):
            display.print_warning("Scan interrupted by user")
            interrupted = True
            _uncancel_current_task()
        
        for key, collector in collectors.items():
            outcome = outcomes[key]
            outcome.interrupted = interrupted
            outcome.denied_addresses = collector.get_denied_addresses()
            writers[key].export_new_denied(outcome.denied_addresses, collector.get_denied_statuses())
            stats = collector.get_statistics()
            audit.log_scan_complete(
                ips[key], stats["total_points"], stats["success_count"], stats["error_count"],
                (loop.time() - started_at) * 1000
            )
            display.print_info(f"Last cycle statistics for {key}:")
            display.print_statistics(stats)
            if key not in reached:
                pass   # never answered: keep the connection error from the start
            elif writers[key].errors:
                outcome.error = (
                    f"{len(writers[key].errors)} write error(s) during monitoring; "
                    f"first: {writers[key].errors[0]}"
                )
            else:
                outcome.success = True
    
    return list(outcomes.values())


UNDETECTED_PROTOCOL = (
    "no PLC protocol answered (check the PLC power and network, "
    "or specify the protocol with --protocol / targets[].protocol)"
)


def status_report_message(
    points_by_target: Dict[str, List[DataPoint]],
    unreachable: List[str],
    iteration: int,
) -> tuple:
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


async def resolve_target(
    ip: str,
    protocol: Optional[Protocol],
    port: Optional[int],
    config: NetworkConfig,
    display: RichProgressDisplay,
    base: Optional[PLCInfo] = None
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
    
    display.print_info(f"Detecting protocol for {ip}...")
    detected = await PLCDiscovery(config)._probe_host(ip)
    if detected and detected.protocol:
        display.print_success(f"Detected: {detected.protocol.name}")
        if port:
            detected.port = port
        if base:
            detected.manufacturer = base.manufacturer or detected.manufacturer
            detected.model = base.model or detected.model
            detected.options = dict(base.options)
        return detected
    
    display.print_error(f"{ip}: {UNDETECTED_PROTOCOL}")
    return None


async def _notify(notifier: Optional[NotificationManager], send) -> None:
    """Send a notification if configured; never let it break the scan"""
    if notifier is None:
        return
    try:
        await send(notifier)
    except Exception as e:
        logger.warning(f"Notification failed: {e}")


async def main():
    """Main entry point"""
    args = parse_args()
    
    # Handle generate-config
    if args.generate_config:
        try:
            generate_config_template(args.generate_config)
        except FileExistsError as e:
            print(f"Error: {e}")
            sys.exit(1)
        return
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    quiet_third_party_loggers(args.verbose)
    
    # Load configuration file if specified
    config_loader = None
    if args.config:
        if not Path(args.config).is_file():
            print(f"Config error: file not found: {args.config}")
            sys.exit(1)
        config_loader = ConfigLoader(args.config)
        try:
            config_loader.load()
        except Exception as e:
            print(f"Config error: {e}")
            sys.exit(1)
        
        # Validate configuration
        errors = config_loader.validate()
        if errors:
            for error in errors:
                print(f"Config error: {error}")
            sys.exit(1)
    
    mode_name, interval = resolve_mode_and_interval(args, config_loader)
    if mode_name == "range" and 0 < interval < MIN_INTERVAL_SECONDS:
        print(f"Error: --interval must be 0 (single scan) or >= {MIN_INTERVAL_SECONDS:g} seconds")
        sys.exit(1)
    
    # Create network config
    option_errors = network_option_errors(args)
    if option_errors:
        for error in option_errors:
            print(f"Error: {error}")
        sys.exit(1)
    config = create_network_config(args, config_loader)
    
    # Initialize audit logger
    audit_file = args.audit_log
    if config_loader and not audit_file:
        log_settings = config_loader.get_logging_settings()
        audit_file = log_settings.get("audit_log")
    
    if audit_file:
        init_audit_logger(audit_file, enabled=True)
        get_audit_logger().log_session_start({"args": vars(args)})
    
    # Create display
    display = RichProgressDisplay(use_rich=not args.no_rich)
    if not args.quiet and not args.no_rich:
        display.print_header()
    
    # Create exporter
    output_dir, encoding = resolve_output_settings(args, config_loader)
    hex_addresses = args.hex_addresses
    if hex_addresses is None and config_loader:
        hex_addresses = bool(config_loader.get_output_settings().get("hex_addresses", False))
    exporter = CSVExporter(output_dir, encoding, hex_addresses=bool(hex_addresses))
    periodic_csv = args.periodic_csv
    if periodic_csv is None and config_loader:
        periodic_csv = config_loader.get_output_settings().get("periodic_csv")
    exporter.periodic_csv = periodic_csv or "per_cycle"
    
    # Initialize database exporter (optional)
    db_exporter = None
    if not args.no_database:
        db_config = None
        
        # Check CLI argument first
        if args.database:
            db_config = DatabaseConfig(
                enabled=True,
                path=args.database,
                track_history=args.db_track_history
            )
        # Then check config file
        elif config_loader:
            output_settings = config_loader.get_output_settings()
            if output_settings.get("database", {}).get("enabled"):
                db_config = DatabaseConfig.from_dict(output_settings.get("database", {}))
        
        if db_config and db_config.enabled:
            try:
                db_exporter = DatabaseExporter(db_config)
                display.print_info(f"Database output enabled: {db_config.path}")
            except Exception as e:
                display.print_warning(f"Failed to initialize database: {e}")
    
    # Notifications (webhook / Slack / Teams) from the config file
    notifier: Optional[NotificationManager] = None
    if config_loader and config_loader.config.get("notifications"):
        notifier = NotificationManager.from_config(config_loader.config)
        display.print_info(f"Notifications enabled: {len(notifier._handlers)} handler(s)")
    
    # Parse data type options (CLI, then type mapping file / config file)
    try:
        data_type, byte_order, type_manager = resolve_data_types(args, config_loader)
    except Exception as e:
        display.print_error(f"Failed to load type mapping: {e}")
        sys.exit(1)
    if args.type_mapping:
        display.print_info(f"Loaded type mapping from: {args.type_mapping}")
    elif type_manager:
        display.print_info("Using data type mappings from config file")
    
    # Track scan results for report generation
    scan_start_time = None
    all_plcs: List[PLCInfo] = []
    all_data_points: Dict[str, List[DataPoint]] = {}
    all_denied_addresses: Dict[str, List[str]] = {}
    failed_targets: List[str] = []
    # "label: reason" for each failed target, shown in the report
    target_errors: List[str] = []
    output_errors: List[str] = []
    interrupted = False
    exit_code = 0
    
    try:
        from datetime import datetime
        scan_start_time = datetime.now()
        
        # Tag all database rows of this run with one scan session
        if db_exporter and db_exporter.is_enabled:
            db_exporter.begin_session(mode_name)
        
        if mode_name == "discover":
            ip_ranges = [args.ip_range] if args.ip_range else (
                config_loader.get_ip_ranges() if config_loader else []
            )
            range_errors = [e for e in map(ip_range_error, ip_ranges) if e]
            if range_errors:
                for error in range_errors:
                    display.print_error(error)
                exit_code = 1
                sys.exit(1)
            discovered = await run_discovery(
                ip_ranges, config, exporter, display, db_exporter,
                resolve_discovery_protocols(args, config_loader),
                errors=output_errors,
            )
            all_plcs = discovered if discovered else []
            await _notify(notifier, lambda n: n.notify_discovery(
                len(all_plcs), [p.to_dict() for p in all_plcs]
            ))
        
        else:
            # Validate ranges before connecting to anything
            mode = ScanMode.FULL if mode_name == "full" else ScanMode.RANGE
            device_ranges = resolve_device_ranges(args, config_loader) if mode == ScanMode.RANGE else None
            
            # Get targets
            targets = parse_targets(args.target) if args.target else []
            protocol = get_protocol_from_string(args.protocol) if args.protocol else None
            
            plc_infos: List[PLCInfo] = []
            # Targets whose protocol could not be detected: failed, not scanned
            undetected: List[str] = []
            if config_loader and not targets:
                for target in config_loader.get_targets():
                    resolved = await resolve_target(
                        target.ip_address, target.protocol, target.port,
                        config, display, base=target
                    )
                    if resolved:
                        plc_infos.append(resolved)
                    else:
                        undetected.append(target.ip_address)
            else:
                if not targets:
                    display.print_error("--target is required for full/range modes")
                    exit_code = 1
                    sys.exit(1)
                for ip in targets:
                    resolved = await resolve_target(ip, protocol, args.port, config, display)
                    if resolved:
                        plc_infos.append(resolved)
                    else:
                        undetected.append(ip)
            
            if not plc_infos and not undetected:
                display.print_error("No targets specified")
                exit_code = 1
                sys.exit(1)
            
            for ip in undetected:
                failed_targets.append(ip)
                target_errors.append(_target_error(ip, UNDETECTED_PROTOCOL))
            
            if mode == ScanMode.FULL and interval > 0:
                display.print_warning("--interval is ignored in full scan mode")
            
            # Undetected targets are listed (without protocol) in the report
            all_plcs = plc_infos + [PLCInfo(ip_address=ip) for ip in undetected]
            
            if not plc_infos:
                pass   # nothing could be scanned; reported as failed below
            elif mode == ScanMode.RANGE and interval > 0:
                # Periodic: all targets in turn every cycle
                if len(plc_infos) > 1 and config.max_concurrent > 1:
                    display.print_info("Periodic scans read targets one after another (--max-concurrent not used)")
                outcomes = await run_periodic_scan(
                    plc_infos, config, exporter, display, device_ranges, interval,
                    data_type, byte_order, type_manager, db_exporter, notifier
                )
                for outcome in outcomes:
                    if not outcome.success:
                        failed_targets.append(outcome.label)
                        target_errors.append(_target_error(outcome.label, outcome.error))
                    if outcome.data_points:
                        all_data_points[outcome.label] = outcome.data_points
                    if outcome.denied_addresses:
                        all_denied_addresses[outcome.label] = sorted_addresses(outcome.denied_addresses)
                    interrupted = interrupted or outcome.interrupted
            elif len(plc_infos) > 1 and config.max_concurrent > 1:
                results = await run_parallel_scan(
                    plc_infos, config, exporter, display,
                    mode, device_ranges, data_type, byte_order, type_manager,
                    db_exporter
                )
                for label, result in results.items():
                    if not result.success:
                        failed_targets.append(label)
                        target_errors.append(_target_error(label, result.error_message))
                    if result.data_points:
                        all_data_points[label] = result.data_points
                    if result.denied_addresses:
                        all_denied_addresses[label] = sorted_addresses(result.denied_addresses)
            else:
                # Single or sequential scan
                for label, plc_info in zip(target_labels(plc_infos), plc_infos):
                    outcome = await run_single_scan(
                        plc_info, config, exporter, display,
                        mode, device_ranges,
                        data_type, byte_order, type_manager, db_exporter,
                        label=label,
                    )
                    if not outcome.success:
                        failed_targets.append(label)
                        target_errors.append(_target_error(label, outcome.error))
                    if outcome.data_points:
                        all_data_points[label] = outcome.data_points
                    if outcome.denied_addresses:
                        all_denied_addresses[label] = sorted_addresses(outcome.denied_addresses)
        
        scan_end_time = datetime.now()
        if mode_name != "discover":
            # One error notification for all failed targets (each send can take
            # several seconds when the endpoint is unreachable)
            if failed_targets:
                await _notify(notifier, lambda n: n.notify_error(
                    f"Scan failed for {len(failed_targets)} target(s): {', '.join(failed_targets)}",
                    plc_ip=failed_targets[0] if len(failed_targets) == 1 else None,
                    failed_targets=failed_targets,
                ))
            await _notify(notifier, lambda n: n.notify_scan_complete(
                len(all_plcs),
                len(all_plcs) - len(failed_targets),
                len(failed_targets),
                (scan_end_time - scan_start_time).total_seconds(),
                mode=mode_name,
                interrupted=interrupted,
            ))
        
        # Generate report if requested
        if args.report:
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
                plcs=all_plcs,
                data_points=all_data_points,
                denied_addresses=all_denied_addresses,
                scan_mode=report_mode,
                started_at=scan_start_time,
                completed_at=scan_end_time,
                config=report_config,
                errors=target_errors + output_errors,
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
                output_errors.append(message)
        
        if interrupted:
            display.print_warning("Scan stopped by user.")
            exit_code = 130
        elif output_errors:
            display.print_error(f"Finished, but {len(output_errors)} output error(s) occurred")
            exit_code = 1
        elif failed_targets:
            display.print_error(
                f"Scan finished with errors: {len(failed_targets)} target(s) failed "
                f"({', '.join(failed_targets)})"
            )
            exit_code = 1
        else:
            display.print_success("Scan completed successfully.")
        
    except (KeyboardInterrupt, asyncio.CancelledError):
        display.print_warning("Operation cancelled by user.")
        _uncancel_current_task()
        exit_code = 130
    except Exception as e:
        display.print_error(str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()
        exit_code = 1
        await _notify(notifier, lambda n: n.notify_error(str(e)))
    finally:
        # Close database
        if db_exporter:
            try:
                db_exporter.end_session({
                    0: "completed",
                    1: "completed with errors",
                    130: "interrupted",
                }.get(exit_code, f"exit {exit_code}"))
            except Exception as e:
                logger.warning(f"Failed to close database session: {e}")
            db_exporter.close()
        
        # Close audit logger
        if audit_file:
            get_audit_logger().log_session_end()
            close_audit_logger()
    
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
        asyncio.run(main())
    except KeyboardInterrupt:
        # Second Ctrl+C or Python 3.10 (where the loop itself is interrupted)
        sys.exit(130)


if __name__ == "__main__":
    cli()
