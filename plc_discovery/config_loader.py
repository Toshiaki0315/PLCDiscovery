"""
Configuration File Loader

Supports loading configuration from YAML or JSON files.
Provides validation and default values for all settings.
"""

import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import YAML support
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.debug("PyYAML not installed, YAML config files not supported")

from .config import DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, ScanMode, range_size_error
from .data_types import ByteOrder, DataType, DataTypeManager
from .names import parse_byte_order, parse_device_type, parse_protocol
from .thresholds import Threshold, threshold_from_dict
from .utils import ip_range_error, target_address_error

# Default configuration template
DEFAULT_CONFIG = {
    "version": "1.0",
    # Network settings
    "network": {
        "discovery_timeout_ms": 1000,
        "discovery_retry_count": 3,
        "packet_interval_ms": 50,
        "retry_interval_ms": 200,
        "request_timeout_ms": 5000,
        "max_concurrent": 1,
    },
    # Discovery settings
    "discovery": {
        "enabled": True,
        "ip_ranges": [],  # List of IP ranges to scan
        "scan_same_segment": True,
        # Protocols probed during discovery (applies only when set in the file)
        "protocols": ["slmp", "ethernet_ip", "modbus", "s7", "fins", "fins_tcp"],
    },
    # Target PLCs (for direct connection without discovery)
    "targets": [
        # Example:
        # {
        #     "ip": "192.168.1.10",
        #     "protocol": "slmp",
        #     "port": 5001,
        #     "name": "Main PLC",
        # }
    ],
    # Scan settings
    "scan": {
        # "range" (production-safe), "discover", or "full" (factory downtime only:
        # reads every device range and causes much more traffic)
        "mode": "range",
        "device_ranges": [
            # Example:
            # {"device": "D", "start": 0, "end": 8191},
            # {"device": "M", "start": 0, "end": 8191},
        ],
        "interval_seconds": 0,  # 0 = single scan, >0 = continuous
    },
    # Output settings
    "output": {
        "directory": "./plc_scan_results",
        # "utf-8-sig" (UTF-8 with BOM, opens correctly in Excel), "utf-8" or "shift-jis"
        "encoding": "utf-8-sig",
        "format": "csv",  # "csv" or "json"
        "include_timestamp": True,
    },
    # Logging settings
    "logging": {
        "level": "INFO",
        "file": None,  # Log file path (optional)
        "audit_log": None,  # Audit log file path (optional)
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    },
    # Data type conversion settings
    "data_types": {
        "default_type": "WORD",
        "default_byte_order": "little",
        "mappings": [],
    },
}


# scan.mode names
_SCAN_MODES = {
    "discover": ScanMode.DISCOVER,
    "full": ScanMode.FULL,
    "range": ScanMode.RANGE,
}

# Minimum periodic interval (same as the GUI): protects the PLC and keeps
# per-cycle CSV files from colliding
MIN_INTERVAL_SECONDS = 1.0

# Protocol-specific handler options allowed in targets[].options,
# with their valid integer ranges (inclusive)
_FINS_NODE = (0, 254)
TARGET_OPTION_RANGES: Dict[Optional[Protocol], Dict[str, tuple]] = {
    Protocol.FINS: {"dest_node": _FINS_NODE, "source_node": _FINS_NODE},
    Protocol.FINS_TCP: {"dest_node": _FINS_NODE, "source_node": _FINS_NODE},
    Protocol.S7: {"rack": (0, 7), "slot": (0, 31), "db_number": (1, 65535)},
    Protocol.ETHERNET_IP: {"slot": (0, 255)},
    Protocol.MODBUS_TCP: {"unit_id": (0, 255)},
}
TARGET_OPTIONS: Dict[Optional[Protocol], set] = {
    protocol: set(ranges) for protocol, ranges in TARGET_OPTION_RANGES.items()
}


# Smallest valid value of each network setting (all integers, in ms or a count).
# A timeout of 0 made every request time out; a negative one failed every
# connection with an unrelated-looking socket error.
NETWORK_MINIMUMS: Dict[str, int] = {
    "discovery_timeout_ms": 1,
    "discovery_retry_count": 0,
    "packet_interval_ms": 0,
    "retry_interval_ms": 0,
    "request_timeout_ms": 1,
    "max_concurrent": 1,
}


def integer_error(value: Any, minimum: int) -> Optional[str]:
    """Why value is not an integer >= minimum (None when it is valid)"""
    if isinstance(value, bool) or not isinstance(value, int):
        return f"must be an integer >= {minimum}, got {value!r}"
    if value < minimum:
        return f"must be >= {minimum}, got {value}"
    return None


class ConfigLoader:
    """
    Configuration file loader and validator.

    Supports YAML and JSON configuration files.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        # Settings exactly as written in the file (without defaults), used to
        # tell an explicit setting apart from a default value
        self._file_config: Dict[str, Any] = {}
        self._load_defaults()

    def _load_defaults(self):
        """Load default configuration"""
        import copy

        self.config = copy.deepcopy(DEFAULT_CONFIG)

    def load(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file.

        Args:
            config_path: Path to configuration file (YAML or JSON)

        Returns:
            Merged configuration dictionary
        """
        given = config_path or self.config_path

        if not given:
            logger.debug("No config file specified, using defaults")
            return self.config

        path = Path(given)

        if not path.exists():
            logger.warning(f"Config file not found: {path}, using defaults")
            return self.config

        # Load based on file extension
        suffix = path.suffix.lower()

        try:
            with open(path, "r", encoding="utf-8") as f:
                if suffix in [".yaml", ".yml"]:
                    if not YAML_AVAILABLE:
                        raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml")
                    file_config = yaml.safe_load(f)
                elif suffix == ".json":
                    file_config = json.load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {suffix}")

            # Merge with defaults
            self._merge_config(file_config)
            logger.info(f"Configuration loaded from: {path}")

        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            raise

        return self.config

    def _merge_config(self, file_config: Dict[str, Any]) -> None:
        """Recursively merge file config with defaults"""
        if not file_config:
            return
        self._file_config = file_config

        def merge_dict(base: Dict, override: Dict) -> Dict:
            result = base.copy()
            for key, value in override.items():
                if value is None and key in result:
                    # An empty YAML section ("targets:" with only comments)
                    # loads as None: keep the default ([] / {}) instead
                    continue
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dict(result[key], value)
                else:
                    result[key] = value
            return result

        self.config = merge_dict(self.config, file_config)

    def is_set(self, *keys: str) -> bool:
        """
        Check whether a setting was explicitly written in the config file.

        Example:
            loader.is_set("scan", "mode")
        """
        node: Any = self._file_config
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return False
            node = node[key]
        return node is not None

    def get_scan_interval(self) -> float:
        """Get periodic scan interval in seconds (0 = single scan)"""
        return float(self.config.get("scan", {}).get("interval_seconds", 0) or 0)

    def _validate_notifications(self) -> List[str]:
        """Errors in notifications[] and notification_settings"""
        from .notifications import NOTIFICATION_TYPES, NotificationType

        errors = []
        settings = self.config.get("notification_settings") or {}
        if not isinstance(settings, dict):
            errors.append("notification_settings must be a mapping")
            settings = {}
        for key in ("report_interval_minutes", "min_interval_minutes"):
            if key in settings:
                error = number_error(settings[key], 0)
                if error:
                    errors.append(f"notification_settings.{key} {error}")

        destinations = self.config.get("notifications") or []
        if not isinstance(destinations, list):
            return errors + ["notifications must be a list"]
        known_events = {t.value for t in NotificationType}
        names = set()
        for i, item in enumerate(destinations):
            where = f"notifications[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{where} must be a mapping")
                continue
            kind = str(item.get("type", "webhook")).lower()
            if kind not in NOTIFICATION_TYPES:
                errors.append(f"{where}.type: unknown type '{kind}' (allowed: {', '.join(NOTIFICATION_TYPES)})")
            url = item.get("url") or item.get("webhook_url")
            if item.get("enabled", True) and not url:
                errors.append(f"{where}.url is required for an enabled notification")
            elif url and not str(url).lower().startswith(("http://", "https://")):
                errors.append(f"{where}.url must start with http:// or https://")
            name = item.get("name", "unnamed")
            if name in names:
                errors.append(f"{where}.name '{name}' is used twice (names must be unique)")
            names.add(name)
            if "format" in item and str(item["format"]).lower() not in ("adaptive", "messagecard"):
                errors.append(f"{where}.format: unknown format '{item['format']}' (allowed: adaptive, messagecard)")
            for event in item.get("events") or []:
                if event not in known_events:
                    errors.append(f"{where}.events: unknown event '{event}'")
            for key, minimum, exclusive in (("timeout", 0, True), ("retry_count", 1, False)):
                if key in item:
                    error = number_error(item[key], minimum, exclusive)
                    if error:
                        errors.append(f"{where}.{key} {error}")
        return errors

    def get_network_config(self) -> NetworkConfig:
        """Get NetworkConfig from loaded configuration"""
        net = self.config.get("network", {})
        return NetworkConfig(
            discovery_timeout_ms=net.get("discovery_timeout_ms", 1000),
            discovery_retry_count=net.get("discovery_retry_count", 3),
            packet_interval_ms=net.get("packet_interval_ms", 50),
            retry_interval_ms=net.get("retry_interval_ms", 200),
            request_timeout_ms=net.get("request_timeout_ms", 5000),
            max_concurrent=net.get("max_concurrent", 1),
        )

    def get_targets(self) -> List[PLCInfo]:
        """Get list of target PLCs from configuration"""
        targets = []

        for target in self.config.get("targets", []):
            protocol = self._parse_protocol(target.get("protocol"))

            plc = PLCInfo(
                ip_address=target.get("ip", ""),
                protocol=protocol,
                port=target.get("port"),
                manufacturer=target.get("manufacturer"),
                model=target.get("model"),
                options=dict(target.get("options") or {}),
            )
            targets.append(plc)

        return targets

    def get_device_ranges(self) -> List[DeviceRange]:
        """Get device ranges from configuration"""
        ranges = []

        for range_def in self.config.get("scan", {}).get("device_ranges", []):
            device_type = self._parse_device_type(range_def.get("device", "D"))

            if device_type:
                ranges.append(
                    DeviceRange(
                        device_type=device_type,
                        start_address=range_def.get("start", 0),
                        end_address=range_def.get("end", 999),
                    )
                )

        return ranges

    def get_tags(self) -> List[str]:
        """EtherNet/IP (Logix) tags to read in range mode (scan.tags)"""
        tags = self.config.get("scan", {}).get("tags") or []
        return [str(t).strip() for t in tags if str(t).strip()] if isinstance(tags, list) else []

    def get_thresholds(self) -> List[Threshold]:
        """Limits watched during periodic scans (thresholds:), see thresholds.py"""
        items = self.config.get("thresholds") or []
        if not isinstance(items, list):
            return []
        return [threshold_from_dict(item, f"thresholds[{i}]") for i, item in enumerate(items)]

    def get_tag_members(self) -> Dict[str, List[str]]:
        """Structure variable -> member names (scan.tag_members), see expand_tag_members()"""
        members = self.config.get("scan", {}).get("tag_members") or {}
        if not isinstance(members, dict):
            return {}
        return {
            str(name).strip(): [str(m).strip() for m in names if str(m).strip()]
            for name, names in members.items()
            if isinstance(names, list)
        }

    def get_scan_mode(self) -> ScanMode:
        """
        Get scan mode from configuration.

        An unknown name (rejected by validate()) falls back to DISCOVER,
        which reads no PLC data - never to a full scan of every device.
        """
        mode_str = str(self.config.get("scan", {}).get("mode", "full")).strip().lower()
        return _SCAN_MODES.get(mode_str, ScanMode.DISCOVER)

    def get_ip_ranges(self) -> List[str]:
        """Get IP ranges for discovery"""
        return list(self.config.get("discovery", {}).get("ip_ranges", []))

    def get_discovery_protocols(self) -> Optional[List[Protocol]]:
        """
        Protocols to probe during discovery, or None for all.
        Only an explicit discovery.protocols in the file restricts discovery.
        """
        if not self.is_set("discovery", "protocols"):
            return None
        return [p for p in (self._parse_protocol(n) for n in self.config["discovery"]["protocols"]) if p]

    def get_output_settings(self) -> Dict[str, Any]:
        """Get output settings"""
        return dict(self.config.get("output", {}))

    def get_logging_settings(self) -> Dict[str, Any]:
        """Get logging settings"""
        return dict(self.config.get("logging", {}))

    def _parse_protocol(self, protocol_str: Optional[str]) -> Optional[Protocol]:
        """Parse a protocol name or alias (see names.PROTOCOL_NAMES)"""
        return parse_protocol(protocol_str)

    def _parse_device_type(self, device_str: Optional[str]) -> Optional[DeviceType]:
        """Parse a device name such as D or HR"""
        return parse_device_type(device_str)

    def get_data_type_manager(self) -> Optional[DataTypeManager]:
        """
        Get DataTypeManager from configuration.

        Returns:
            DataTypeManager instance or None if not configured
        """
        dt_config = self.config.get("data_types")
        if not dt_config:
            return None

        if not dt_config.get("mappings"):
            return None

        return DataTypeManager.from_config(dt_config)

    def get_default_data_type(self) -> Optional[DataType]:
        """Get default data type from configuration"""
        dt_config = self.config.get("data_types", {})
        type_str = dt_config.get("default_type")

        if not type_str:
            return None

        try:
            return DataType(type_str.upper())
        except ValueError:
            return None

    def get_default_byte_order(self) -> ByteOrder:
        """Get default byte order from configuration (little if unknown)"""
        order = self.config.get("data_types", {}).get("default_byte_order", "little")
        return parse_byte_order(order) or ByteOrder.LITTLE_ENDIAN

    def save_template(self, file_path: str) -> None:
        """Save configuration template to file"""
        path = Path(file_path)
        suffix = path.suffix.lower()

        with open(path, "w", encoding="utf-8") as f:
            if suffix in [".yaml", ".yml"]:
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML is required for YAML files")
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
            else:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)

        logger.info(f"Configuration template saved to: {path}")

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of errors.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate network settings (a non-numeric value used to crash
        # validate() itself with a TypeError)
        net = self.config.get("network", {})
        if not isinstance(net, dict):
            errors.append("network must be a mapping")
            net = {}
        for key, minimum in NETWORK_MINIMUMS.items():
            error = integer_error(net.get(key, minimum), minimum)
            if error:
                errors.append(f"network.{key} {error}")

        # Validate targets
        for i, target in enumerate(self.config.get("targets", [])):
            if not target.get("ip"):
                errors.append(f"targets[{i}].ip is required")
            else:
                address_error = target_address_error(str(target.get("ip")))
                if address_error:
                    errors.append(f"targets[{i}].ip: {address_error}")
            protocol_str = target.get("protocol")
            protocol = self._parse_protocol(protocol_str)
            if protocol_str and protocol is None:
                errors.append(f"targets[{i}].protocol: unknown protocol '{protocol_str}' " f"(omit it to auto-detect)")
            options = target.get("options") or {}
            if not isinstance(options, dict):
                errors.append(f"targets[{i}].options must be a mapping")
            elif options:
                allowed = TARGET_OPTIONS.get(protocol, set())
                unknown = sorted(set(options) - allowed)
                if unknown:
                    errors.append(
                        f"targets[{i}].options: {', '.join(unknown)} not supported for "
                        f"{protocol.name if protocol else 'auto-detected protocol'} "
                        f"(allowed: {', '.join(sorted(allowed)) or 'none'})"
                    )
                for key, value in options.items():
                    valid = TARGET_OPTION_RANGES.get(protocol, {}).get(key)
                    if valid is None:
                        continue
                    low, high = valid
                    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                        errors.append(f"targets[{i}].options.{key} must be an integer {low}-{high}, got {value!r}")

        # Validate discovery IP ranges (syntax and size)
        for i, ip_range in enumerate(self.config.get("discovery", {}).get("ip_ranges", []) or []):
            error = ip_range_error(str(ip_range))
            if error:
                errors.append(f"discovery.ip_ranges[{i}]: {error}")

        # Validate discovery protocol filter
        for name in self.config.get("discovery", {}).get("protocols", []) or []:
            if self._parse_protocol(name) is None:
                errors.append(f"discovery.protocols: unknown protocol '{name}'")

        # Validate scan mode: a typo (e.g. "rang") must not silently become
        # a different mode such as a full scan of every device range
        if self.is_set("scan", "mode"):
            mode = self.config["scan"]["mode"]
            if str(mode).strip().lower() not in _SCAN_MODES:
                errors.append(f"scan.mode: unknown mode {mode!r} (allowed: {', '.join(_SCAN_MODES)})")

        # Validate periodic interval
        interval = self.config.get("scan", {}).get("interval_seconds", 0) or 0
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            errors.append(f"scan.interval_seconds must be a number, got {interval!r}")
        elif not math.isfinite(interval):
            # NaN slips through every comparison below and would make a
            # periodic scan run without waiting; infinity never wakes up
            errors.append(f"scan.interval_seconds must be a finite number, got {interval!r}")
        elif interval < 0 or 0 < interval < MIN_INTERVAL_SECONDS:
            errors.append(f"scan.interval_seconds must be 0 (single scan) or >= {MIN_INTERVAL_SECONDS:g}")

        tags = self.config.get("scan", {}).get("tags")
        if tags is not None and (not isinstance(tags, list) or not all(isinstance(t, str) for t in tags)):
            errors.append("scan.tags must be a list of tag names")
        members = self.config.get("scan", {}).get("tag_members")
        if members is not None and (
            not isinstance(members, dict)
            or not all(isinstance(v, list) and all(isinstance(m, str) for m in v) for v in members.values())
        ):
            errors.append("scan.tag_members must map variable names to lists of member names")

        # Validate device ranges
        for i, range_def in enumerate(self.config.get("scan", {}).get("device_ranges", []) or []):
            where = f"scan.device_ranges[{i}]"
            if not isinstance(range_def, dict):
                errors.append(f"{where} must be a mapping")
                continue
            start, end = range_def.get("start", 0), range_def.get("end", 999)
            bounds_ok = True
            for key, value in (("start", start), ("end", end)):
                error = integer_error(value, 0)
                if error:
                    errors.append(f"{where}.{key} {error}")
                    bounds_ok = False
            if bounds_ok and start > end:
                errors.append(f"{where}: start must be <= end")
            elif bounds_ok and range_size_error(start, end):
                errors.append(f"{where}: {range_size_error(start, end)}")
            if self._parse_device_type(str(range_def.get("device", "D"))) is None:
                errors.append(f"{where}: unknown device '{range_def.get('device')}'")

        periodic_csv = (self.config.get("output") or {}).get("periodic_csv", "per_cycle")
        if periodic_csv not in ("per_cycle", "daily"):
            errors.append(f"output.periodic_csv: unknown value {periodic_csv!r} (allowed: per_cycle, daily)")
        hex_addresses = (self.config.get("output") or {}).get("hex_addresses", False)
        if not isinstance(hex_addresses, bool):
            errors.append(f"output.hex_addresses must be true or false, got {hex_addresses!r}")

        # Database retention (0 = keep everything / no size limit)
        database = (self.config.get("output") or {}).get("database") or {}
        if isinstance(database, dict):
            if "max_history_days" in database:
                error = integer_error(database["max_history_days"], 0)
                if error:
                    errors.append(f"output.database.max_history_days {error}")
            for key, minimum, exclusive in (("max_size_mb", 0, False), ("cleanup_interval_hours", 0, True)):
                if key in database:
                    error = number_error(database[key], minimum, exclusive)
                    if error:
                        errors.append(f"output.database.{key} {error}")

        errors.extend(self._validate_notifications())

        thresholds = self.config.get("thresholds") or []
        if not isinstance(thresholds, list):
            errors.append("thresholds must be a list")
        else:
            for i, item in enumerate(thresholds):
                try:
                    threshold_from_dict(item, f"thresholds[{i}]")
                except ValueError as e:
                    errors.append(str(e))

        # Validate data type settings (default type/byte order and mappings)
        try:
            DataTypeManager.from_config(self.config.get("data_types"))
        except ValueError as e:
            errors.append(str(e))

        return errors


def number_error(value: Any, minimum: float, exclusive: bool = False) -> Optional[str]:
    """Why value is not a number >= (or > when exclusive) minimum"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"must be a number, got {value!r}"
    if not math.isfinite(value):
        return f"must be a finite number, got {value!r}"
    if value < minimum or (exclusive and value == minimum):
        return f"must be {'>' if exclusive else '>='} {minimum:g}, got {value:g}"
    return None


def load_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Convenience function to load configuration.

    Args:
        config_path: Path to configuration file

    Returns:
        ConfigLoader instance with loaded configuration
    """
    loader = ConfigLoader(config_path)
    loader.load()
    return loader


def generate_config_template(path: str = "plc_config.yaml", overwrite: bool = False) -> None:
    """
    Generate a configuration template file.

    Raises:
        FileExistsError: if the file exists and overwrite is False, so an
            edited configuration is never replaced by accident
    """
    if Path(path).exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists; not overwriting it. "
            f"Choose another file name or delete the existing file first."
        )
    loader = ConfigLoader()
    loader.save_template(path)
    print(f"Configuration template saved to: {path}")
