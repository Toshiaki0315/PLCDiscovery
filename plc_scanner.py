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
import sys
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from plc_discovery.config import (
    Protocol, DeviceType, ScanMode, PLCInfo, DataPoint,
    NetworkConfig, DeviceRange, PROTOCOL_PORTS
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
        default="discover",
        help="Operation mode: discover, full, or range (default: discover)"
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
        help="Byte order for multi-byte values (default: little)"
    )
    
    parser.add_argument(
        "--type-mapping",
        help="Path to type mapping file (JSON/YAML) for address-specific conversions"
    )
    
    # Timing parameters
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=0,
        help="Interval between scans in seconds (for continuous operation)"
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


def apply_data_type_conversion(
    data_points: List[DataPoint],
    data_type: Optional[DataType],
    byte_order: ByteOrder,
    type_manager: Optional[DataTypeManager] = None
) -> List[DataPoint]:
    """
    Apply data type conversion to data points.
    
    Args:
        data_points: List of data points to convert
        data_type: Default data type (if type_manager not used)
        byte_order: Byte order for conversion
        type_manager: Type manager for address-specific mappings
    
    Returns:
        Updated list of data points with converted values
    """
    if not data_type and not type_manager:
        return data_points
    
    word_count = DataTypeConverter.get_word_count(data_type) if data_type else 1
    
    # For multi-word types, we need to group consecutive addresses
    if data_type and word_count and word_count > 1:
        return _convert_multi_word_type(data_points, data_type, byte_order, word_count)
    
    # Single-word conversion or type manager based
    for dp in data_points:
        if dp.value is None:
            continue
        
        # Determine data type for this address
        if type_manager:
            # Extract numeric address from string like "D100"
            addr_num = int(''.join(filter(str.isdigit, dp.address)))
            dt, bo = type_manager.get_type_for_address(addr_num)
        else:
            dt, bo = data_type, byte_order
        
        # Convert
        converted = DataTypeConverter.convert([dp.value], dt, bo)
        display = DataTypeConverter.to_string(converted, dt)
        
        dp.data_type = dt.value
        dp.converted_value = converted
        dp.display_value = display
    
    return data_points


def _convert_multi_word_type(
    data_points: List[DataPoint],
    data_type: DataType,
    byte_order: ByteOrder,
    word_count: int
) -> List[DataPoint]:
    """Convert multi-word data types (DWORD, FLOAT, etc.)"""
    result = []
    
    # Group by consecutive addresses
    i = 0
    while i < len(data_points):
        dp = data_points[i]
        
        if dp.value is None:
            result.append(dp)
            i += 1
            continue
        
        # Collect words for this value
        words = [dp.value]
        raw_words = [dp.value]
        
        # Try to get consecutive addresses
        for j in range(1, word_count):
            if i + j < len(data_points):
                next_dp = data_points[i + j]
                if next_dp.value is not None:
                    words.append(next_dp.value)
                    raw_words.append(next_dp.value)
        
        if len(words) == word_count:
            # Convert
            converted = DataTypeConverter.convert(words, data_type, byte_order)
            display = DataTypeConverter.to_string(converted, data_type)
            
            # Create new data point for the converted value
            new_dp = DataPoint(
                address=dp.address,
                value=dp.value,
                raw_hex=dp.raw_hex,
                status=dp.status,
                timestamp=dp.timestamp,
                data_type=data_type.value,
                converted_value=converted,
                display_value=display,
                raw_words=raw_words,
            )
            result.append(new_dp)
            
            # Skip the words we consumed
            i += word_count
        else:
            # Not enough consecutive words, keep original
            result.append(dp)
            i += 1
    
    return result


async def run_discovery(
    args,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    db_exporter: DatabaseExporter = None
) -> List[PLCInfo]:
    """Run PLC discovery"""
    audit = get_audit_logger()
    
    display.print_info("Starting PLC Discovery...")
    
    ip_ranges = [args.ip_range] if args.ip_range else []
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
    if args.ip_range:
        display.print_info(f"Scanning IP range: {args.ip_range}")
        tcp_plcs = await discover_plcs(args.ip_range, config)
    else:
        display.print_info("Scanning same network segment...")
        tcp_plcs = await discover_plcs(None, config)
    
    # Merge results (deduplicate by IP)
    existing_ips = {p.ip_address for p in plcs}
    for plc in tcp_plcs:
        if plc.ip_address not in existing_ips:
            plcs.append(plc)
    
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
    audit = get_audit_logger()
    
    display.print_info(f"Starting parallel scan of {len(plcs)} PLCs...")
    
    scanner = ParallelPLCScanner(config)
    results = await scanner.scan_multiple_plcs(plcs, mode, device_ranges)
    
    # Export results for each PLC
    for ip, result in results.items():
        if result.data_points:
            # Apply data type conversion
            converted_points = apply_data_type_conversion(
                result.data_points, data_type, byte_order, type_manager
            )
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


async def run_single_scan(
    plc_info: PLCInfo,
    config: NetworkConfig,
    exporter: CSVExporter,
    display: RichProgressDisplay,
    mode: ScanMode,
    device_type: Optional[DeviceType] = None,
    start_addr: int = 0,
    end_addr: int = 999,
    interval: float = 0,
    data_type: Optional[DataType] = None,
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    type_manager: Optional[DataTypeManager] = None,
    db_exporter: DatabaseExporter = None
) -> tuple:
    """Run scan on single PLC"""
    audit = get_audit_logger()
    
    display.print_info(f"Connecting to {plc_info.ip_address}...")
    
    if data_type:
        display.print_info(f"Data type conversion: {data_type.value} ({byte_order.value})")
    
    data_points = []
    denied_addresses = set()
    
    try:
        async with PLCDataCollector(plc_info, config) as collector:
            audit.log_connect(
                plc_info.ip_address,
                plc_info.protocol.name if plc_info.protocol else "UNKNOWN",
                plc_info.port or 0,
                True
            )
            
            audit.log_scan_start(
                plc_info.ip_address,
                mode.value,
                [f"{device_type.value if device_type else 'ALL'}"]
            )
            
            if mode == ScanMode.FULL:
                display.print_info("Running full scan...")
                data_points = await collector.collect_full_scan()
            else:
                # Range mode
                display.print_info(f"Scanning {device_type.value}{start_addr}-{device_type.value}{end_addr}")
                
                if interval > 0:
                    # Continuous mode
                    try:
                        iteration = 0
                        while True:
                            iteration += 1
                            display.print_info(f"Iteration {iteration}")
                            
                            points = await collector.collect_range(
                                device_type, start_addr, end_addr
                            )
                            
                            # Apply data type conversion
                            if data_type or type_manager:
                                points = apply_data_type_conversion(
                                    points, data_type, byte_order, type_manager
                                )
                            
                            data_points = points
                            
                            if points:
                                exporter.export_plc_data(points, plc_info.ip_address)
                            
                            display.print_info(f"Waiting {interval} seconds...")
                            await asyncio.sleep(interval)
                            
                    except KeyboardInterrupt:
                        display.print_warning("Scan interrupted by user")
                else:
                    data_points = await collector.collect_range(
                        device_type, start_addr, end_addr
                    )
            
            denied_addresses = collector.get_denied_addresses()
            stats = collector.get_statistics()
            
            audit.log_scan_complete(
                plc_info.ip_address,
                stats["total_points"],
                stats["success_count"],
                stats["error_count"],
                0  # Duration would need timing
            )
    
    except Exception as e:
        audit.log_error(str(e), {"plc_ip": plc_info.ip_address})
        raise
    
    # Apply data type conversion (if not continuous mode)
    if (data_type or type_manager) and interval <= 0:
        data_points = apply_data_type_conversion(
            data_points, data_type, byte_order, type_manager
        )
    
    # Export results
    if data_points:
        filepath = exporter.export_plc_data(data_points, plc_info.ip_address)
        display.print_success(f"Data saved to: {filepath}")
        
        # Save to database if enabled
        if db_exporter and db_exporter.is_enabled:
            db_count = db_exporter.export_plc_data(data_points, plc_info.ip_address)
            display.print_info(f"Saved {db_count} records to database")
        
        # Show sample converted values if data type conversion was applied
        if data_type or type_manager:
            display.print_info("Sample converted values:")
            for dp in data_points[:5]:
                if dp.converted_value is not None:
                    display.print(f"  {dp.address}: {dp.display_value} ({dp.data_type})")
    
    if denied_addresses:
        denied_path = exporter.export_denied_addresses(denied_addresses, plc_info.ip_address)
        display.print_info(f"Denied addresses logged to: {denied_path}")
        
        # Save denied addresses to database
        if db_exporter and db_exporter.is_enabled:
            db_exporter.export_denied_addresses(denied_addresses, plc_info.ip_address)
    
    # Display statistics
    display.print_statistics(stats)
    
    return data_points, denied_addresses


async def main():
    """Main entry point"""
    args = parse_args()
    
    # Handle generate-config
    if args.generate_config:
        generate_config_template("plc_config.yaml")
        print("Configuration template saved to: plc_config.yaml")
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
    
    try:
        from datetime import datetime
        scan_start_time = datetime.now()
        
        if args.mode == "discover":
            discovered = await run_discovery(args, config, exporter, display, db_exporter)
            all_plcs = discovered if discovered else []
        
        elif args.mode in ["full", "range"]:
            # Get targets
            targets = parse_targets(args.target) if args.target else []
            
            if config_loader and not targets:
                plc_infos = config_loader.get_targets()
            else:
                if not targets:
                    display.print_error("--target is required for full/range modes")
                    sys.exit(1)
                
                # Build PLCInfo for each target
                protocol = get_protocol_from_string(args.protocol) if args.protocol else None
                port = args.port
                
                plc_infos = []
                for ip in targets:
                    if not protocol:
                        # Try to detect protocol
                        display.print_info(f"Detecting protocol for {ip}...")
                        discovery = PLCDiscovery(config)
                        detected = await discovery._probe_host(ip)
                        
                        if detected and detected.protocol:
                            plc_info = detected
                            display.print_success(f"Detected: {detected.protocol.name}")
                        else:
                            display.print_warning(f"Could not detect protocol for {ip}, defaulting to SLMP")
                            plc_info = PLCInfo(
                                ip_address=ip,
                                protocol=Protocol.SLMP,
                                port=PROTOCOL_PORTS[Protocol.SLMP]
                            )
                    else:
                        plc_info = PLCInfo(
                            ip_address=ip,
                            protocol=protocol,
                            port=port or PROTOCOL_PORTS.get(protocol)
                        )
                    plc_infos.append(plc_info)
            
            if not plc_infos:
                display.print_error("No targets specified")
                sys.exit(1)
            
            # Get device ranges for range mode
            device_ranges = None
            mode = ScanMode.FULL if args.mode == "full" else ScanMode.RANGE
            
            if args.mode == "range":
                device_type = get_device_type_from_string(args.device)
                start_addr, end_addr = parse_address_range(args.range)
                device_ranges = [DeviceRange(device_type, start_addr, end_addr)]
            
            # Run scan
            all_plcs = plc_infos
            
            if len(plc_infos) > 1 and config.max_concurrent > 1:
                # Parallel scan
                results = await run_parallel_scan(
                    plc_infos, config, exporter, display,
                    mode, device_ranges, data_type, byte_order, type_manager,
                    db_exporter
                )
                # Collect results for report
                for ip, result in results.items():
                    if result.data_points:
                        all_data_points[ip] = result.data_points
                    if result.denied_addresses:
                        all_denied_addresses[ip] = list(result.denied_addresses)
            else:
                # Single or sequential scan
                for plc_info in plc_infos:
                    device_type = get_device_type_from_string(args.device) if args.mode == "range" else None
                    start_addr, end_addr = parse_address_range(args.range) if args.mode == "range" else (0, 999)
                    
                    data_points, denied = await run_single_scan(
                        plc_info, config, exporter, display,
                        mode, device_type, start_addr, end_addr, args.interval,
                        data_type, byte_order, type_manager, db_exporter
                    )
                    # Collect results for report
                    if data_points:
                        all_data_points[plc_info.ip_address] = data_points
                    if denied:
                        all_denied_addresses[plc_info.ip_address] = list(denied)
        
        scan_end_time = datetime.now()
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
                scan_mode=args.mode,
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
        
    except KeyboardInterrupt:
        display.print_warning("Operation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        display.print_error(str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Close database
        if db_exporter:
            db_exporter.close()
        
        # Close audit logger
        if audit_file:
            get_audit_logger().log_session_end()
            close_audit_logger()


def cli():
    """Console-script entry point (``plc-scanner``)"""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
