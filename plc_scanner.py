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
import dataclasses
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from plc_discovery.config import (
    Protocol, DeviceType, ScanMode, PLCInfo, DataPoint,
    NetworkConfig, DeviceRange, StatusCode, PROTOCOL_PORTS
)
from plc_discovery.discovery import PLCDiscovery, discover_plcs
from plc_discovery.collector import PLCDataCollector
from plc_discovery.output import CSVExporter, ReportGenerator
from plc_discovery.utils import parse_ip_range
from plc_discovery.config_loader import ConfigLoader, generate_config_template
from plc_discovery.audit_log import init_audit_logger, get_audit_logger, close_audit_logger
from plc_discovery.parallel import ParallelPLCScanner, scan_plcs_parallel
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.progress import RichProgressDisplay, get_display, is_rich_available
from plc_discovery.data_types import (
    DataType, ByteOrder, DataTypeConverter, DataTypeManager, DataTypeMapping
)
from plc_discovery.database import (
    DatabaseExporter, DatabaseConfig, get_database_exporter
)
from plc_discovery.report import (
    ReportGenerator, ReportConfig, ReportFormat, ReportData, ScanSummary,
    create_report, generate_html_report
)

logger = logging.getLogger(__name__)

# Data type string mapping
DATA_TYPE_MAP = {
    "WORD": DataType.WORD,
    "INT16": DataType.INT16,
    "DWORD": DataType.DWORD,
    "INT32": DataType.INT32,
    "QWORD": DataType.QWORD,
    "INT64": DataType.INT64,
    "FLOAT": DataType.FLOAT,
    "DOUBLE": DataType.DOUBLE,
    "BCD16": DataType.BCD16,
    "BCD32": DataType.BCD32,
    "STRING": DataType.STRING,
    "BIT": DataType.BIT,
    "BOOL": DataType.BOOL,
    "RAW": DataType.RAW,
}

BYTE_ORDER_MAP = {
    "little": ByteOrder.LITTLE_ENDIAN,
    "big": ByteOrder.BIG_ENDIAN,
    "little_swap": ByteOrder.LITTLE_ENDIAN_WORD_SWAP,
    "big_swap": ByteOrder.BIG_ENDIAN_WORD_SWAP,
}


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="PLC Scanner - Factory PLC Auto-Detection and Data Collection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover PLCs on same network segment
  python plc_scanner.py --mode discover

  # Discover PLCs in specific IP range  
  python plc_scanner.py --mode discover --ip-range "192.168.1.0/24"

  # Full scan of a specific PLC
  python plc_scanner.py --mode full --target 192.168.1.10

  # Range specified scan
  python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-1000

  # Range scan with data type conversion (FLOAT)
  python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 100-199 --data-type FLOAT

  # Range scan with type mapping file
  python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-500 --type-mapping types.json

  # Use configuration file
  python plc_scanner.py --config plc_config.yaml

  # Scan multiple PLCs in parallel
  python plc_scanner.py --mode full --target 192.168.1.10,192.168.1.20 --max-concurrent 3

  # Generate configuration template
  python plc_scanner.py --generate-config
        """
    )
    
    # Configuration file
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file (YAML or JSON)"
    )
    
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate a configuration file template"
    )
    
    # Mode selection
    parser.add_argument(
        "--mode", "-m",
        choices=["discover", "full", "range"],
        default=None,
        help="Operation mode: discover, full, or range "
             "(default: scan.mode from --config, otherwise discover)"
    )
    
    # Target specification
    parser.add_argument(
        "--target", "-t",
        help="Target PLC IP address(es), comma-separated for multiple"
    )
    
    parser.add_argument(
        "--ip-range", "-r",
        help="IP range to scan (CIDR or hyphen notation, e.g., 192.168.1.0/24)"
    )
    
    # Protocol selection
    parser.add_argument(
        "--protocol", "-p",
        choices=["slmp", "eip", "modbus", "s7"],
        help="Force specific protocol (auto-detected if not specified)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        help="Override default port for the protocol"
    )
    
    # Device/range specification
    parser.add_argument(
        "--device", "-d",
        choices=["D", "M", "W", "R", "DM", "HR", "IR", "DB", "X", "Y"],
        default="D",
        help="Device type to read (default: D)"
    )
    
    parser.add_argument(
        "--range",
        help="Address range to read (e.g., 0-1000)"
    )
    
    # Data type conversion options
    parser.add_argument(
        "--data-type",
        choices=list(DATA_TYPE_MAP.keys()),
        help="Data type for conversion (e.g., FLOAT, DWORD, INT32)"
    )
    
    parser.add_argument(
        "--byte-order",
        choices=["little", "big", "little_swap", "big_swap"],
        default="little",
        help="Order of multi-word values: little=CDAB (low word first), big=ABCD, "
             "little_swap=DCBA, big_swap=BADC (default: little)"
    )
    
    parser.add_argument(
        "--type-mapping",
        help="Path to type mapping file (JSON/YAML) for address-specific conversions"
    )
    
    # Timing parameters
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=None,
        help="Interval between scans in seconds for continuous range mode "
             "(default: scan.interval_seconds from --config, otherwise 0 = single scan)"
    )
    
    parser.add_argument(
        "--packet-interval",
        type=int,
        default=50,
        help="Wait time between packets in ms (default: 50)"
    )
    
    parser.add_argument(
        "--retry-interval",
        type=int,
        default=200,
        help="Wait time before retry in ms (default: 200)"
    )
    
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=5000,
        help="Request timeout in ms (default: 5000)"
    )
    
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=1,
        help="Maximum concurrent PLC connections (default: 1)"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir", "-o",
        default="./plc_scan_results",
        help="Output directory for CSV files (default: ./plc_scan_results)"
    )
    
    parser.add_argument(
        "--encoding",
        choices=["utf-8", "shift-jis"],
        default="utf-8",
        help="Output file encoding (default: utf-8)"
    )
    
    # Audit logging
    parser.add_argument(
        "--audit-log",
        help="Path to audit log file"
    )
    
    # Database output
    parser.add_argument(
        "--database",
        help="Enable SQLite database output (specify path, e.g., ./plc_data.db)"
    )
    
    parser.add_argument(
        "--no-database",
        action="store_true",
        help="Disable database output (overrides config file)"
    )
    
    parser.add_argument(
        "--db-track-history",
        action="store_true",
        default=True,
        help="Track value changes in database (default: True)"
    )
    
    # Report generation
    parser.add_argument(
        "--report",
        choices=["html", "pdf", "json"],
        help="Generate report in specified format"
    )
    
    parser.add_argument(
        "--report-output",
        help="Report output path (auto-generated if not specified)"
    )
    
    parser.add_argument(
        "--report-title",
        default="PLC Discovery レポート",
        help="Report title"
    )
    
    parser.add_argument(
        "--report-company",
        default="",
        help="Company name for report header"
    )
    
    parser.add_argument(
        "--report-theme",
        choices=["default", "dark", "light"],
        default="default",
        help="Report theme (default: default)"
    )
    
    # Verbosity
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "--no-rich",
        action="store_true",
        help="Disable rich console output"
    )
    
    return parser.parse_args()


def get_protocol_from_string(protocol_str: str) -> Optional[Protocol]:
    """Convert protocol string to Protocol enum"""
    if not protocol_str:
        return None
    mapping = {
        "slmp": Protocol.SLMP,
        "eip": Protocol.ETHERNET_IP,
        "modbus": Protocol.MODBUS_TCP,
        "s7": Protocol.S7,
    }
    return mapping.get(protocol_str.lower())


def get_device_type_from_string(device_str: str) -> Optional[DeviceType]:
    """Convert device string to DeviceType enum"""
    if not device_str:
        return None
    mapping = {
        "D": DeviceType.D,
        "M": DeviceType.M,
        "W": DeviceType.W,
        "R": DeviceType.R,
        "DM": DeviceType.DM,
        "HR": DeviceType.HR,
        "IR": DeviceType.IR,
        "DB": DeviceType.DB,
        "X": DeviceType.X,
        "Y": DeviceType.Y,
    }
    return mapping.get(device_str.upper())


def parse_address_range(range_str: str) -> tuple:
    """Parse address range string (e.g., '0-1000') to (start, end)"""
    if not range_str:
        return 0, 999
    
    parts = range_str.split("-")
    if len(parts) == 2:
        return int(parts[0]), int(parts[1])
    else:
        addr = int(parts[0])
        return addr, addr


def create_network_config(args, config_loader: Optional[ConfigLoader] = None) -> NetworkConfig:
    """Create NetworkConfig from command line arguments or config file"""
    if config_loader:
        return config_loader.get_network_config()
    
    return NetworkConfig(
        packet_interval_ms=args.packet_interval,
        retry_interval_ms=args.retry_interval,
        request_timeout_ms=args.request_timeout,
        max_concurrent=args.max_concurrent,
    )


def parse_targets(target_str: str) -> List[str]:
    """Parse comma-separated target IPs"""
    if not target_str:
        return []
    return [ip.strip() for ip in target_str.split(",")]


def load_type_mapping(path: str) -> DataTypeManager:
    """Load type mapping from file"""
    manager = DataTypeManager()
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            if path.endswith('.json'):
                config = json.load(f)
            else:
                try:
                    import yaml
                    config = yaml.safe_load(f)
                except ImportError:
                    raise ImportError("PyYAML required for YAML type mapping files")
        
        return DataTypeManager.from_config(config)
    except Exception as e:
        logger.error(f"Failed to load type mapping: {e}")
        raise


def _split_address(address: str) -> Optional[tuple]:
    """Split an address like "D100" into ("D", 100); None if not parseable"""
    match = re.fullmatch(r"([A-Za-z]*)(\d+)", address or "")
    if not match:
        return None
    return match.group(1), int(match.group(2))


def apply_data_type_conversion(
    data_points: List[DataPoint],
    data_type: Optional[DataType],
    byte_order: ByteOrder,
    type_manager: Optional[DataTypeManager] = None
) -> List[DataPoint]:
    """
    Apply data type conversion to data points.
    
    Multi-word types (DWORD, FLOAT, DOUBLE, ...) combine the value with the
    following points, but only when they are consecutive addresses that were
    read successfully. The combined value is stored on the first address and
    the consumed words are kept in raw_words.
    
    Args:
        data_points: List of data points to convert
        data_type: Default data type (if type_manager not used)
        byte_order: Byte order for conversion
        type_manager: Type manager for address-specific mappings
            (takes precedence over data_type)
    
    Returns:
        New list of data points with converted values
    """
    if not data_type and not type_manager:
        return data_points
    
    result: List[DataPoint] = []
    i = 0
    while i < len(data_points):
        dp = data_points[i]
        parsed = _split_address(dp.address)
        
        if dp.value is None or dp.status != StatusCode.OK:
            result.append(dp)
            i += 1
            continue
        
        # Determine data type for this address
        if type_manager and parsed:
            dt, bo = type_manager.get_type_for_address(parsed[1])
        else:
            dt, bo = data_type, byte_order
        
        if dt is None:
            result.append(dp)
            i += 1
            continue
        
        word_count = max(DataTypeConverter.get_word_count(dt) or 1, 1)
        
        # Collect the following consecutive, successfully read words
        group = [dp]
        if word_count > 1 and parsed:
            prefix, number = parsed
            for j in range(1, word_count):
                if i + j >= len(data_points):
                    break
                nxt = data_points[i + j]
                if (nxt.value is None or nxt.status != StatusCode.OK
                        or _split_address(nxt.address) != (prefix, number + j)):
                    break
                group.append(nxt)
        
        if len(group) < word_count:
            # Not enough consecutive valid words: keep the raw point
            result.append(dp)
            i += 1
            continue
        
        words = [g.value for g in group]
        converted = DataTypeConverter.convert(words, dt, bo)
        result.append(dataclasses.replace(
            dp,
            data_type=dt.value,
            converted_value=converted,
            display_value=DataTypeConverter.to_string(converted, dt),
            raw_words=words if word_count > 1 else None,
        ))
        i += word_count
    
    return result


async def run_discovery(
    ip_ranges: List[str],
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: DatabaseExporter = None
) -> List[PLCInfo]:
    """Run PLC discovery (same segment when ip_ranges is empty)"""
    audit = get_audit_logger()
    
    display.print_info("Starting PLC Discovery...")
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
            tcp_plcs.extend(await discover_plcs(ip_range, config))
    else:
        display.print_info("Scanning same network segment...")
        tcp_plcs = await discover_plcs(None, config)
    
    # Merge results (deduplicate by IP)
    existing_ips = {p.ip_address for p in plcs}
    for plc in tcp_plcs:
        if plc.ip_address not in existing_ips:
            plcs.append(plc)
            existing_ips.add(plc.ip_address)
    
    # Log and display results
    audit.log_discovery_result(
        len(plcs),
        [p.to_dict() for p in plcs]
    )
    
    if plcs:
        filepath = exporter.export_discovery_results(plcs)
        display.print_success(f"Discovered {len(plcs)} PLC(s)")
        display.print_info(f"Results saved to: {filepath}")
        
        # Save to database if enabled
        if db_exporter and db_exporter.is_enabled:
            db_count = db_exporter.export_discovery_results(plcs)
            display.print_info(f"Saved {db_count} PLCs to database")
        
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
    
    # Export results for each PLC
    for ip, result in results.items():
        if not result.success:
            display.print_error(f"{ip}: {result.error_message}")
        
        if result.data_points:
            # Apply data type conversion
            converted_points = apply_data_type_conversion(
                result.data_points, data_type, byte_order, type_manager
            )
            result.data_points = converted_points
            exporter.export_plc_data(converted_points, ip)
            
            # Save to database if enabled
            if db_exporter and db_exporter.is_enabled:
                db_exporter.export_plc_data(converted_points, ip)
        
        if result.denied_addresses:
            exporter.export_denied_addresses(result.denied_addresses, ip)
            
            # Save denied addresses to database
            if db_exporter and db_exporter.is_enabled:
                db_exporter.export_denied_addresses(result.denied_addresses, ip)
    
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
        points.extend(await collector.collect_range(
            device_range.device_type,
            device_range.start_address,
            device_range.end_address
        ))
    return points


async def run_single_scan(
    plc_info: PLCInfo,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    mode: ScanMode,
    device_ranges: Optional[List[DeviceRange]] = None,
    interval: float = 0,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: DatabaseExporter = None
) -> ScanOutcome:
    """
    Run scan on a single PLC.
    
    Connection failures are reported in the returned outcome instead of
    raising, so remaining targets are still scanned.
    """
    audit = get_audit_logger()
    ip = plc_info.ip_address
    protocol_name = plc_info.protocol.name if plc_info.protocol else "UNKNOWN"
    outcome = ScanOutcome(ip)
    device_ranges = device_ranges or []
    
    display.print_info(f"Connecting to {ip}...")
    
    if data_type:
        display.print_info(f"Data type conversion: {data_type.value} ({byte_order.value})")
    
    def export_points(points: List[DataPoint]) -> Optional[str]:
        if not points:
            return None
        path = exporter.export_plc_data(points, ip)
        if db_exporter and db_exporter.is_enabled:
            db_count = db_exporter.export_plc_data(points, ip)
            display.print_info(f"Saved {db_count} records to database")
        return path
    
    exported_denied: Set[str] = set()
    
    def export_new_denied(denied: Set[str]) -> Optional[str]:
        """Append only addresses not yet written in this session"""
        new = set(denied) - exported_denied
        if not new:
            return None
        exported_denied.update(new)
        path = exporter.export_denied_addresses(new, ip)
        if db_exporter and db_exporter.is_enabled:
            db_exporter.export_denied_addresses(new, ip)
        return path
    
    loop = asyncio.get_running_loop()
    stats: Dict[str, Any] = {}
    
    try:
        async with PLCDataCollector(plc_info, config) as collector:
            connected = collector.is_connected
            audit.log_connect(ip, protocol_name, plc_info.port or 0, connected)
            
            if not connected:
                outcome.error = f"Failed to connect to {ip}:{plc_info.port} ({protocol_name})"
                display.print_error(outcome.error)
                audit.log_error(outcome.error, {"plc_ip": ip})
                return outcome
            
            range_labels = [
                f"{r.device_type.value}{r.start_address}-{r.device_type.value}{r.end_address}"
                for r in device_ranges
            ] or ["ALL"]
            audit.log_scan_start(ip, mode.value, range_labels)
            scan_started = loop.time()
            
            if mode == ScanMode.FULL:
                display.print_info("Running full scan...")
                outcome.data_points = await collector.collect_full_scan()
            elif interval > 0:
                # Continuous mode: export every iteration, stop on Ctrl+C
                display.print_info(f"Scanning {', '.join(range_labels)} every {interval:g}s")
                try:
                    iteration = 0
                    while True:
                        iteration += 1
                        started = loop.time()
                        display.print_info(f"Iteration {iteration}")
                        
                        collector.clear_data()
                        points = await _collect_ranges(collector, device_ranges)
                        points = apply_data_type_conversion(
                            points, data_type, byte_order, type_manager
                        )
                        outcome.data_points = points
                        export_points(points)
                        export_new_denied(collector.get_denied_addresses())
                        
                        wait = max(0.0, interval - (loop.time() - started))
                        display.print_info(f"Waiting {wait:.1f} seconds...")
                        await asyncio.sleep(wait)
                except (asyncio.CancelledError, KeyboardInterrupt):
                    display.print_warning("Scan interrupted by user")
                    outcome.interrupted = True
                    _uncancel_current_task()
            else:
                display.print_info(f"Scanning {', '.join(range_labels)}")
                outcome.data_points = await _collect_ranges(collector, device_ranges)
            
            outcome.denied_addresses = collector.get_denied_addresses()
            stats = collector.get_statistics()
            
            audit.log_scan_complete(
                ip,
                stats["total_points"],
                stats["success_count"],
                stats["error_count"],
                (loop.time() - scan_started) * 1000
            )
    
    except Exception as e:
        audit.log_error(str(e), {"plc_ip": ip})
        raise
    
    if interval <= 0 or mode == ScanMode.FULL:
        # Single scan: convert and export once
        outcome.data_points = apply_data_type_conversion(
            outcome.data_points, data_type, byte_order, type_manager
        )
        filepath = export_points(outcome.data_points)
        if filepath:
            display.print_success(f"Data saved to: {filepath}")
    
    if outcome.data_points and (data_type or type_manager):
        display.print_info("Sample converted values:")
        for dp in outcome.data_points[:5]:
            if dp.converted_value is not None:
                display.print(f"  {dp.address}: {dp.display_value} ({dp.data_type})")
    
    denied_path = export_new_denied(outcome.denied_addresses)
    if denied_path:
        display.print_info(f"Denied addresses logged to: {denied_path}")
    
    display.print_statistics(stats)
    outcome.success = True
    return outcome


async def resolve_target(
    ip: str,
    protocol: Optional[Protocol],
    port: Optional[int],
    config: NetworkConfig,
    display: RichProgressDisplay,
    base: Optional[PLCInfo] = None
) -> PLCInfo:
    """Build PLCInfo for a target, auto-detecting the protocol if not given"""
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
        return detected
    
    display.print_warning(f"Could not detect protocol for {ip}, defaulting to SLMP")
    return PLCInfo(
        ip_address=ip,
        protocol=Protocol.SLMP,
        port=port or PROTOCOL_PORTS[Protocol.SLMP]
    )


def resolve_mode_and_interval(args, config_loader: Optional[ConfigLoader]) -> tuple:
    """
    Resolve operation mode and periodic interval: CLI first, then settings
    written explicitly in the config file. A config file without scan.mode
    never triggers a full scan by default.
    """
    mode_name = args.mode
    if not mode_name and config_loader and config_loader.is_set("scan", "mode"):
        mode_name = config_loader.get_scan_mode().value
    mode_name = mode_name or "discover"
    
    interval = args.interval
    if interval is None:
        interval = config_loader.get_scan_interval() if config_loader else 0.0
    return mode_name, interval


def resolve_device_ranges(args, config_loader: Optional[ConfigLoader]) -> List[DeviceRange]:
    """Device ranges for range mode: --range, then config scan.device_ranges, then 0-999"""
    if args.range:
        start_addr, end_addr = parse_address_range(args.range)
        return [DeviceRange(get_device_type_from_string(args.device), start_addr, end_addr)]
    if config_loader:
        ranges = config_loader.get_device_ranges()
        if ranges:
            return ranges
    start_addr, end_addr = parse_address_range(None)
    return [DeviceRange(get_device_type_from_string(args.device), start_addr, end_addr)]


async def main():
    """Main entry point"""
    args = parse_args()
    
    # Handle generate-config
    if args.generate_config:
        generate_config_template("plc_config.yaml")
        return
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True,
    )
    
    # Load configuration file if specified
    config_loader = None
    if args.config:
        config_loader = ConfigLoader(args.config)
        config_loader.load()
        
        # Validate configuration
        errors = config_loader.validate()
        if errors:
            for error in errors:
                print(f"Config error: {error}")
            sys.exit(1)
    
    mode_name, interval = resolve_mode_and_interval(args, config_loader)
    
    # Create network config
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
    display = RichProgressDisplay()
    if not args.quiet and not args.no_rich:
        display.print_header()
    
    # Create exporter
    output_dir = args.output_dir
    encoding = args.encoding
    if config_loader:
        output_settings = config_loader.get_output_settings()
        output_dir = output_settings.get("directory", output_dir)
        encoding = output_settings.get("encoding", encoding)
    
    exporter = CSVExporter(output_dir, encoding)
    
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
    
    # Parse data type options
    data_type = DATA_TYPE_MAP.get(args.data_type) if args.data_type else None
    byte_order = BYTE_ORDER_MAP.get(args.byte_order, ByteOrder.LITTLE_ENDIAN)
    type_manager = None
    
    # Load type mapping from file or config
    if args.type_mapping:
        try:
            type_manager = load_type_mapping(args.type_mapping)
            display.print_info(f"Loaded type mapping from: {args.type_mapping}")
        except Exception as e:
            display.print_error(f"Failed to load type mapping: {e}")
            sys.exit(1)
    elif config_loader:
        # Try to get type mapping from config file
        type_manager = config_loader.get_data_type_manager()
        if type_manager:
            display.print_info("Using data type mappings from config file")
        
        # Get default data type from config if not specified on CLI
        if not data_type:
            data_type = config_loader.get_default_data_type()
        
        # Get byte order from config
        if args.byte_order == "little":  # Only if using default
            byte_order = config_loader.get_default_byte_order()
    
    # Track scan results for report generation
    scan_start_time = None
    all_plcs: List[PLCInfo] = []
    all_data_points: Dict[str, List[DataPoint]] = {}
    all_denied_addresses: Dict[str, List[str]] = {}
    failed_targets: List[str] = []
    interrupted = False
    exit_code = 0
    
    try:
        from datetime import datetime
        scan_start_time = datetime.now()
        
        if mode_name == "discover":
            ip_ranges = [args.ip_range] if args.ip_range else (
                config_loader.get_ip_ranges() if config_loader else []
            )
            discovered = await run_discovery(ip_ranges, config, exporter, display, db_exporter)
            all_plcs = discovered if discovered else []
        
        else:
            # Get targets
            targets = parse_targets(args.target) if args.target else []
            protocol = get_protocol_from_string(args.protocol) if args.protocol else None
            
            plc_infos: List[PLCInfo] = []
            if config_loader and not targets:
                for target in config_loader.get_targets():
                    plc_infos.append(await resolve_target(
                        target.ip_address, target.protocol, target.port,
                        config, display, base=target
                    ))
            else:
                if not targets:
                    display.print_error("--target is required for full/range modes")
                    sys.exit(1)
                for ip in targets:
                    plc_infos.append(await resolve_target(ip, protocol, args.port, config, display))
            
            if not plc_infos:
                display.print_error("No targets specified")
                sys.exit(1)
            
            mode = ScanMode.FULL if mode_name == "full" else ScanMode.RANGE
            device_ranges = resolve_device_ranges(args, config_loader) if mode == ScanMode.RANGE else None
            
            if mode == ScanMode.FULL and interval > 0:
                display.print_warning("--interval is ignored in full scan mode")
            
            all_plcs = plc_infos
            
            if len(plc_infos) > 1 and config.max_concurrent > 1:
                if interval > 0:
                    display.print_warning("--interval is ignored for parallel scans")
                results = await run_parallel_scan(
                    plc_infos, config, exporter, display,
                    mode, device_ranges, data_type, byte_order, type_manager,
                    db_exporter
                )
                for ip, result in results.items():
                    if not result.success:
                        failed_targets.append(ip)
                    if result.data_points:
                        all_data_points[ip] = result.data_points
                    if result.denied_addresses:
                        all_denied_addresses[ip] = list(result.denied_addresses)
            else:
                # Single or sequential scan
                for plc_info in plc_infos:
                    outcome = await run_single_scan(
                        plc_info, config, exporter, display,
                        mode, device_ranges, interval,
                        data_type, byte_order, type_manager, db_exporter
                    )
                    if not outcome.success:
                        failed_targets.append(plc_info.ip_address)
                    if outcome.data_points:
                        all_data_points[plc_info.ip_address] = outcome.data_points
                    if outcome.denied_addresses:
                        all_denied_addresses[plc_info.ip_address] = list(outcome.denied_addresses)
                    if outcome.interrupted:
                        interrupted = True
                        break
        
        scan_end_time = datetime.now()
        if interrupted:
            display.print_warning("Scan stopped by user.")
            exit_code = 130
        elif failed_targets:
            display.print_error(
                f"Scan finished with errors: {len(failed_targets)} target(s) failed "
                f"({', '.join(failed_targets)})"
            )
            exit_code = 1
        else:
            display.print_success("Scan completed successfully.")
        
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
            
            generator, report_data = create_report(
                plcs=all_plcs,
                data_points=all_data_points,
                denied_addresses=all_denied_addresses,
                scan_mode=mode_name,
                started_at=scan_start_time,
                completed_at=scan_end_time,
                config=report_config
            )
            
            try:
                report_path = generator.save(report_data, args.report_output)
                display.print_success(f"Report saved to: {report_path}")
            except ImportError as e:
                display.print_warning(f"Report generation failed: {e}")
            except Exception as e:
                display.print_error(f"Report generation error: {e}")
        
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
    finally:
        # Close database
        if db_exporter:
            db_exporter.close()
        
        # Close audit logger
        if audit_file:
            get_audit_logger().log_session_end()
            close_audit_logger()
    
    if exit_code:
        sys.exit(exit_code)


def cli():
    """Console-script entry point (``plc-scanner``)"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Second Ctrl+C or Python 3.10 (where the loop itself is interrupted)
        sys.exit(130)


if __name__ == "__main__":
    cli()
