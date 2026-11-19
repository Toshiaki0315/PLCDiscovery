"""
Command-line arguments of plc_scanner.py and how they combine with the
configuration file (CLI option, then the setting written in the file,
then the default).

Split out of plc_scanner.py; plc_scanner re-exports every name, so
existing imports keep working.
"""

import argparse
import dataclasses
from typing import List, Optional, Union

from .config import (
    DeviceRange,
    DeviceType,
    NetworkConfig,
    Protocol,
    TagRange,
    expand_tag_members,
    range_size_error,
)
from .config_loader import NETWORK_MINIMUMS, ConfigLoader, integer_error
from .data_types import DataType
from .names import BYTE_ORDER_NAMES, parse_device_type, parse_protocol
from .output import DEFAULT_OUTPUT_DIR
from .thresholds import Threshold, parse_thresholds
from .utils import target_address_error

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


# Byte order names (--byte-order choices) -> ByteOrder
BYTE_ORDER_MAP = dict(BYTE_ORDER_NAMES)


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
        """,
    )

    # Configuration file
    parser.add_argument("--config", "-c", help="Path to configuration file (YAML or JSON)")

    parser.add_argument(
        "--generate-config",
        nargs="?",
        const="plc_config.yaml",
        metavar="PATH",
        help="Write a configuration template to PATH (default: plc_config.yaml); "
        "an existing file is never overwritten",
    )

    # Mode selection
    parser.add_argument(
        "--mode",
        "-m",
        choices=["discover", "full", "range"],
        default=None,
        help="Operation mode: discover, full, or range " "(default: scan.mode from --config, otherwise discover)",
    )

    # Target specification
    parser.add_argument("--target", "-t", help="Target PLC IP address(es), comma-separated for multiple")

    parser.add_argument("--ip-range", "-r", help="IP range to scan (CIDR or hyphen notation, e.g., 192.168.1.0/24)")

    # Protocol selection
    parser.add_argument(
        "--protocol",
        "-p",
        choices=["slmp", "eip", "modbus", "s7", "fins", "fins-tcp"],
        help="Force specific protocol (auto-detected if not specified); " "fins = FINS/UDP, fins-tcp = FINS/TCP",
    )

    parser.add_argument(
        "--discover-protocols",
        help="Comma-separated protocols to probe in discover mode, e.g. slmp,modbus "
        "(default: discovery.protocols from --config, otherwise all)",
    )

    parser.add_argument("--port", type=int, help="Override default port for the protocol")

    # Device/range specification
    parser.add_argument(
        "--device",
        "-d",
        choices=["D", "M", "W", "R", "DM", "HR", "IR", "DB", "X", "Y", "B", "SM"],
        default="D",
        help="Device type to read (default: D)",
    )

    parser.add_argument(
        "--tags",
        help="EtherNet/IP tags (Logix) / variables (Omron NJ/NX) to read in range mode, "
        'comma-separated, e.g. "Temp,Speed,Recipe[0]{10},Motor.Speed,Program:Main.Step" '
        "({n} = n array elements; structures are reported per member); "
        "default: scan.tags from --config",
    )

    parser.add_argument("--range", help="Address range to read (e.g., 0-1000)")

    # Data type conversion options
    parser.add_argument(
        "--data-type", choices=list(DATA_TYPE_MAP.keys()), help="Data type for conversion (e.g., FLOAT, DWORD, INT32)"
    )

    parser.add_argument(
        "--byte-order",
        choices=["little", "big", "little_swap", "big_swap"],
        default=None,
        help="Order of multi-word values: little=CDAB (low word first), big=ABCD, "
        "little_swap=DCBA, big_swap=BADC "
        "(default: data_types.default_byte_order from --config, otherwise little)",
    )

    parser.add_argument("--type-mapping", help="Path to type mapping file (JSON/YAML) for address-specific conversions")

    # Timing parameters
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=None,
        help="Interval between scans in seconds for continuous range mode, >= 1 "
        "(default: scan.interval_seconds from --config, otherwise 0 = single scan)",
    )

    parser.add_argument(
        "--threshold",
        action="append",
        default=None,
        metavar="CONDITION",
        help='Notify (threshold_exceeded) when a value crosses a limit during a periodic scan, e.g. "D100>80"; '
        "operators: > >= < <= == !=; repeat the option or separate with commas "
        "(default: thresholds from --config)",
    )

    parser.add_argument(
        "--packet-interval",
        type=int,
        default=None,
        help="Wait time between packets in ms (default: 50, or network.packet_interval_ms from --config)",
    )

    parser.add_argument(
        "--retry-interval",
        type=int,
        default=None,
        help="Wait time before retry in ms (default: 200, or network.retry_interval_ms from --config)",
    )

    parser.add_argument(
        "--request-timeout",
        type=int,
        default=None,
        help="Request timeout in ms (default: 5000, or network.request_timeout_ms from --config)",
    )

    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=None,
        help="Maximum concurrent PLC connections (default: 1, or network.max_concurrent from --config)",
    )

    # Output options
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help=f"Output directory for CSV files "
        f"(default: output.directory from --config, otherwise {DEFAULT_OUTPUT_DIR})",
    )

    parser.add_argument(
        "--periodic-csv",
        choices=["per_cycle", "daily"],
        default=None,
        help="CSV files of periodic scans: per_cycle = one file per cycle, daily = append every "
        "cycle to one file per day and PLC (default: output.periodic_csv from --config, "
        "otherwise per_cycle)",
    )

    parser.add_argument(
        "--hex-addresses",
        action="store_true",
        default=None,
        help="Add an address_hex column to SLMP data CSVs with X/Y/B/W numbers in hexadecimal "
        "as in GX Works (X31 -> X1F); addresses stay decimal "
        "(default: output.hex_addresses from --config, otherwise off)",
    )

    parser.add_argument(
        "--encoding",
        choices=["utf-8-sig", "utf-8", "shift-jis"],
        default=None,
        help="CSV encoding: utf-8-sig = UTF-8 with BOM, opens correctly in Excel (default, "
        "or output.encoding from --config); "
        "utf-8 = without BOM; shift-jis = CP932, unrepresentable characters become '?'",
    )

    # Audit logging
    parser.add_argument("--audit-log", help="Path to audit log file")

    # Database output
    parser.add_argument("--database", help="Enable SQLite database output (specify path, e.g., ./plc_data.db)")

    parser.add_argument("--no-database", action="store_true", help="Disable database output (overrides config file)")

    parser.add_argument(
        "--db-track-history",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Track value changes in database (disable with --no-db-track-history)",
    )

    # Report generation
    parser.add_argument("--report", choices=["html", "pdf", "json"], help="Generate report in specified format")

    parser.add_argument(
        "--report-output",
        help="Report output path, used as given (default: plc_report_<timestamp> in the output directory)",
    )

    parser.add_argument("--report-title", default="PLC Discovery レポート", help="Report title")

    parser.add_argument("--report-company", default="", help="Company name for report header")

    parser.add_argument(
        "--report-theme",
        choices=["default", "dark", "light"],
        default="default",
        help="Report theme (default: default)",
    )

    # Verbosity
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")

    parser.add_argument("--no-rich", action="store_true", help="Disable rich console output")

    return parser.parse_args()


def get_protocol_from_string(protocol_str: str) -> Optional[Protocol]:
    """Convert a protocol name or alias to Protocol (see names.PROTOCOL_NAMES)"""
    return parse_protocol(protocol_str)


def get_device_type_from_string(device_str: str) -> Optional[DeviceType]:
    """Convert a device name such as "D" or "HR" to DeviceType"""
    return parse_device_type(device_str)


def parse_address_range(range_str: Optional[str]) -> tuple:
    """
    Parse address range string (e.g., '0-1000' or '100') to (start, end).

    Raises:
        ValueError: if the range is malformed, negative or start > end
    """
    if not range_str:
        return 0, 999

    parts = [p.strip() for p in range_str.split("-")]
    try:
        if len(parts) == 2:
            start, end = int(parts[0]), int(parts[1])
        elif len(parts) == 1:
            start = end = int(parts[0])
        else:
            raise ValueError
    except ValueError:
        raise ValueError(f"Invalid address range '{range_str}' (expected e.g. '0-999' or '100')") from None

    if start > end:
        raise ValueError(f"Invalid address range '{range_str}': start must be <= end")
    size_error = range_size_error(start, end)
    if size_error:
        raise ValueError(f"Invalid address range '{range_str}': {size_error}")
    return start, end


def create_network_config(args: argparse.Namespace, config_loader: Optional[ConfigLoader] = None) -> NetworkConfig:
    """
    Create NetworkConfig: defaults, then the config file's network section,
    then any timing option given explicitly on the command line.
    """
    config = config_loader.get_network_config() if config_loader else NetworkConfig()
    overrides = {
        "packet_interval_ms": args.packet_interval,
        "retry_interval_ms": args.retry_interval,
        "request_timeout_ms": args.request_timeout,
        "max_concurrent": args.max_concurrent,
    }
    return dataclasses.replace(config, **{k: v for k, v in overrides.items() if v is not None})


# Command-line timing options and the network setting each one overrides
NETWORK_OPTIONS = {
    "--packet-interval": ("packet_interval", "packet_interval_ms"),
    "--retry-interval": ("retry_interval", "retry_interval_ms"),
    "--request-timeout": ("request_timeout", "request_timeout_ms"),
    "--max-concurrent": ("max_concurrent", "max_concurrent"),
}


def network_option_errors(args: argparse.Namespace) -> List[str]:
    """Errors for timing options out of range (e.g. --request-timeout 0)"""
    errors = []
    for option, (attr, key) in NETWORK_OPTIONS.items():
        value = getattr(args, attr)
        if value is not None:
            error = integer_error(value, NETWORK_MINIMUMS[key])
            if error:
                errors.append(f"{option} {error}")
    return errors


def parse_targets(target_str: str) -> List[str]:
    """
    Parse comma-separated target IPs (empty entries such as a trailing
    comma are ignored).

    Raises:
        ValueError: if an entry is not an IPv4 address
    """
    if not target_str:
        return []
    targets = [ip.strip() for ip in target_str.split(",") if ip.strip()]
    errors = [e for e in map(target_address_error, targets) if e]
    if errors:
        raise ValueError(f"Invalid --target: {'; '.join(errors)}")
    return targets


def resolve_mode_and_interval(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> tuple:
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


def resolve_discovery_protocols(
    args: argparse.Namespace, config_loader: Optional[ConfigLoader]
) -> Optional[List[Protocol]]:
    """Protocols for discover mode: --discover-protocols, then config, then all (None)"""
    if args.discover_protocols:
        protocols = []
        for name in args.discover_protocols.split(","):
            protocol = parse_protocol(name)
            if protocol is None:
                raise ValueError(f"Unknown protocol in --discover-protocols: '{name.strip()}'")
            protocols.append(protocol)
        return protocols
    if config_loader:
        return config_loader.get_discovery_protocols()
    return None


def resolve_device_ranges(
    args: argparse.Namespace, config_loader: Optional[ConfigLoader]
) -> List[Union[DeviceRange, TagRange]]:
    """
    What range mode reads: --tags / scan.tags (EtherNet/IP Logix tags) and
    device ranges (--range, then config scan.device_ranges, then 0-999).
    With tags, device ranges are read only when given explicitly.
    """
    tags = (
        parse_tag_list(args.tags)
        if getattr(args, "tags", None)
        else (config_loader.get_tags() if config_loader else [])
    )
    if tags and config_loader:
        tags = expand_tag_members(tags, config_loader.get_tag_members())
    if tags:
        explicit = bool(args.range) or bool(config_loader and config_loader.get_device_ranges())
        ranges: List[Union[DeviceRange, TagRange]] = [TagRange(tags)]
        return ranges + (resolve_device_ranges_only(args, config_loader) if explicit else [])
    return list(resolve_device_ranges_only(args, config_loader))


def parse_tag_list(text: str) -> List[str]:
    """Comma-separated tag names; a comma inside {...} (element count) is kept"""
    tags, depth, current = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            tags.append(current.strip())
            current = ""
            continue
        depth += {"[": 1, "{": 1, "]": -1, "}": -1}.get(ch, 0)
        current += ch
    tags.append(current.strip())
    return [t for t in tags if t]


def resolve_device_ranges_only(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> List[DeviceRange]:
    """Device ranges for range mode: --range, then config scan.device_ranges, then 0-999"""
    device = get_device_type_from_string(args.device)
    if device is None:
        raise ValueError(f"Unknown device type: {args.device}")
    if args.range:
        start_addr, end_addr = parse_address_range(args.range)
        return [DeviceRange(device, start_addr, end_addr)]
    if config_loader:
        ranges = config_loader.get_device_ranges()
        if ranges:
            return ranges
    start_addr, end_addr = parse_address_range(None)
    return [DeviceRange(device, start_addr, end_addr)]


def resolve_output_settings(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> tuple:
    """
    CSV output directory and encoding: CLI option, then the setting written
    in the config file, then the default. (The loaded config always holds
    default values, so only explicitly written settings may override.)
    """
    output_dir, encoding = args.output_dir, args.encoding
    if config_loader:
        settings = config_loader.get_output_settings()
        if output_dir is None and config_loader.is_set("output", "directory"):
            output_dir = settings["directory"]
        if encoding is None and config_loader.is_set("output", "encoding"):
            encoding = settings["encoding"]
    return output_dir or DEFAULT_OUTPUT_DIR, encoding or "utf-8-sig"


def resolve_thresholds(args: argparse.Namespace, config_loader: Optional[ConfigLoader]) -> List[Threshold]:
    """--threshold conditions, else thresholds: from the config file; ValueError when malformed"""
    if getattr(args, "threshold", None):
        return parse_thresholds(args.threshold)
    return config_loader.get_thresholds() if config_loader else []
