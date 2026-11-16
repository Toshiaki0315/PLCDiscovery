"""
Configuration File Loader

Supports loading configuration from YAML or JSON files.
Provides validation and default values for all settings.
"""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

logger = logging.getLogger(__name__)

# Try to import YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.debug("PyYAML not installed, YAML config files not supported")

from .config import (
    Protocol, DeviceType, DeviceRange, NetworkConfig, PLCInfo, ScanMode
)
from .data_types import DataType, ByteOrder, DataTypeManager, DataTypeMapping
from .utils import ip_range_error


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
        path = config_path or self.config_path
        
        if not path:
            logger.debug("No config file specified, using defaults")
            return self.config
        
        path = Path(path)
        
        if not path.exists():
            logger.warning(f"Config file not found: {path}, using defaults")
            return self.config
        
        # Load based on file extension
        suffix = path.suffix.lower()
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if suffix in ['.yaml', '.yml']:
                    if not YAML_AVAILABLE:
                        raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml")
                    file_config = yaml.safe_load(f)
                elif suffix == '.json':
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
    
    def _merge_config(self, file_config: Dict[str, Any]):
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
                ranges.append(DeviceRange(
                    device_type=device_type,
                    start_address=range_def.get("start", 0),
                    end_address=range_def.get("end", 999),
                ))
        
        return ranges
    
    def get_scan_mode(self) -> ScanMode:
        """Get scan mode from configuration"""
        mode_str = self.config.get("scan", {}).get("mode", "full").lower()
        
        mode_map = {
            "discover": ScanMode.DISCOVER,
            "full": ScanMode.FULL,
            "range": ScanMode.RANGE,
        }
        return mode_map.get(mode_str, ScanMode.FULL)
    
    def get_ip_ranges(self) -> List[str]:
        """Get IP ranges for discovery"""
        return self.config.get("discovery", {}).get("ip_ranges", [])
    
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
        return self.config.get("output", {})
    
    def get_logging_settings(self) -> Dict[str, Any]:
        """Get logging settings"""
        return self.config.get("logging", {})
    
    def _parse_protocol(self, protocol_str: Optional[str]) -> Optional[Protocol]:
        """Parse protocol string to Protocol enum"""
        if not protocol_str:
            return None
        
        mapping = {
            "slmp": Protocol.SLMP,
            "mc": Protocol.SLMP,
            "ethernet_ip": Protocol.ETHERNET_IP,
            "eip": Protocol.ETHERNET_IP,
            "cip": Protocol.ETHERNET_IP,
            "modbus": Protocol.MODBUS_TCP,
            "modbus_tcp": Protocol.MODBUS_TCP,
            "s7": Protocol.S7,
            "s7comm": Protocol.S7,
            "fins": Protocol.FINS,
            "fins_udp": Protocol.FINS,
            "fins_tcp": Protocol.FINS_TCP,
            "fins-tcp": Protocol.FINS_TCP,
        }
        return mapping.get(protocol_str.lower())
    
    def _parse_device_type(self, device_str: Optional[str]) -> Optional[DeviceType]:
        """Parse device type string to DeviceType enum"""
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
            "B": DeviceType.B,
            "SM": DeviceType.SM,
        }
        return mapping.get(device_str.upper())
    
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
        """Get default byte order from configuration"""
        dt_config = self.config.get("data_types", {})
        order_str = dt_config.get("default_byte_order", "little")
        
        mapping = {
            "little": ByteOrder.LITTLE_ENDIAN,
            "big": ByteOrder.BIG_ENDIAN,
            "little_swap": ByteOrder.LITTLE_ENDIAN_WORD_SWAP,
            "big_swap": ByteOrder.BIG_ENDIAN_WORD_SWAP,
        }
        return mapping.get(order_str.lower(), ByteOrder.LITTLE_ENDIAN)
    
    def save_template(self, path: str):
        """Save configuration template to file"""
        path = Path(path)
        suffix = path.suffix.lower()
        
        with open(path, 'w', encoding='utf-8') as f:
            if suffix in ['.yaml', '.yml']:
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
        
        # Validate network settings
        net = self.config.get("network", {})
        if net.get("max_concurrent", 1) < 1:
            errors.append("network.max_concurrent must be >= 1")
        if net.get("packet_interval_ms", 50) < 0:
            errors.append("network.packet_interval_ms must be >= 0")
        
        # Validate targets
        for i, target in enumerate(self.config.get("targets", [])):
            if not target.get("ip"):
                errors.append(f"targets[{i}].ip is required")
            protocol_str = target.get("protocol")
            protocol = self._parse_protocol(protocol_str)
            if protocol_str and protocol is None:
                errors.append(
                    f"targets[{i}].protocol: unknown protocol '{protocol_str}' "
                    f"(omit it to auto-detect)"
                )
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
                        errors.append(
                            f"targets[{i}].options.{key} must be an integer {low}-{high}, got {value!r}"
                        )
        
        # Validate discovery IP ranges (syntax and size)
        for i, ip_range in enumerate(self.config.get("discovery", {}).get("ip_ranges", []) or []):
            error = ip_range_error(str(ip_range))
            if error:
                errors.append(f"discovery.ip_ranges[{i}]: {error}")
        
        # Validate discovery protocol filter
        for name in self.config.get("discovery", {}).get("protocols", []) or []:
            if self._parse_protocol(name) is None:
                errors.append(f"discovery.protocols: unknown protocol '{name}'")
        
        # Validate periodic interval
        interval = self.config.get("scan", {}).get("interval_seconds", 0) or 0
        if 0 < interval < MIN_INTERVAL_SECONDS:
            errors.append(
                f"scan.interval_seconds must be 0 (single scan) or >= {MIN_INTERVAL_SECONDS:g}"
            )
        
        # Validate device ranges
        for i, range_def in enumerate(self.config.get("scan", {}).get("device_ranges", [])):
            if range_def.get("start", 0) > range_def.get("end", 0):
                errors.append(f"scan.device_ranges[{i}]: start must be <= end")
            if range_def.get("start", 0) < 0:
                errors.append(f"scan.device_ranges[{i}]: start must be >= 0")
            if self._parse_device_type(range_def.get("device", "D")) is None:
                errors.append(f"scan.device_ranges[{i}]: unknown device '{range_def.get('device')}'")

        # Validate data type settings (default type/byte order and mappings)
        try:
            DataTypeManager.from_config(self.config.get("data_types"))
        except ValueError as e:
            errors.append(str(e))

        return errors


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


def generate_config_template(path: str = "plc_config.yaml", overwrite: bool = False):
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

