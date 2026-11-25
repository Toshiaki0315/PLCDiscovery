"""
Settings file shared by the GUI and the CLI (--config).

The GUI reads and writes only the sections it edits (network timing,
output, database, notifications) and leaves every other section of an
existing configuration file (targets, scan, data_types, ...) untouched.
"""

import copy
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:  # pragma: no cover - PyYAML is a dependency
    YAML_AVAILABLE = False

from .config_loader import ConfigLoader

# Default settings file: the one the CLI documents (python plc_scanner.py -c plc_config.yaml)
DEFAULT_SETTINGS_FILE = "plc_config.yaml"

# File name endings the CLI's config loader accepts
SETTINGS_SUFFIXES = (".yaml", ".yml", ".json")

# Sections (and keys) owned by the GUI settings tabs
GUI_SECTIONS = ("network", "output", "notifications", "notification_settings")


def read_file(path: str) -> Dict[str, Any]:
    """The settings exactly as written in the file ({} if it does not exist)"""
    file = Path(path)
    if not file.is_file():
        return {}
    with open(file, encoding="utf-8-sig") as f:  # with or without a BOM, as ConfigLoader reads it
        if file.suffix.lower() == ".json":
            import json

            data = json.load(f)
        else:
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML is required for YAML settings files")
            data = yaml.safe_load(f)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the settings file must contain a mapping")
    return data


def merge(existing: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply the GUI's sections to an existing configuration.

    Mappings are merged key by key (so e.g. output.format or
    network.max_concurrent written by hand are kept); lists such as
    notifications are replaced as a whole.
    """
    result = copy.deepcopy(existing)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def validate(config: Dict[str, Any]) -> List[str]:
    """Errors the CLI would report for this configuration"""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "check.yaml")
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        loader = ConfigLoader(path)
        loader.load()
        return loader.validate()


def save(path: str, updates: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Merge the GUI's sections into the settings file and write it.

    Nothing is written when the result would be rejected by the CLI.
    Comments of an existing YAML file are not preserved (PyYAML drops them).

    Returns:
        (written configuration, validation errors)
    """
    file = Path(path)
    if file.suffix.lower() not in SETTINGS_SUFFIXES:
        # plc_scanner.py -c only reads these: a file saved under another
        # name could be written but never used
        return {}, [f"the settings file name must end in {', '.join(SETTINGS_SUFFIXES)} (got {file.name})"]
    config = merge(read_file(path), updates)
    errors = validate(config)
    if errors:
        return config, errors
    file.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temporary file first: a failure never leaves a truncated file
    tmp = file.with_name(file.name + ".tmp")
    # The file holds notification webhook URLs, which work like passwords:
    # readable by the owner only, unless the existing file says otherwise
    # (its permissions are kept instead of being reset on every save)
    try:
        mode = stat.S_IMODE(file.stat().st_mode)
    except OSError:
        mode = 0o600
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.chmod(tmp, mode)  # a leftover .tmp keeps its old mode with O_CREAT
    except OSError:
        pass
    with open(descriptor, "w", encoding="utf-8") as f:
        if file.suffix.lower() == ".json":
            import json

            json.dump(config, f, ensure_ascii=False, indent=2)
        else:
            f.write("# PLC Discovery settings (written by the GUI; also usable with plc_scanner.py -c)\n")
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    os.replace(tmp, file)
    return config, []


def load(path: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Read a settings file merged with the defaults, as the CLI sees it.

    Returns:
        (configuration with defaults, validation errors)
    """
    loader = ConfigLoader(path)
    loader.load()
    return loader.config, loader.validate()


def section(config: Dict[str, Any], *keys: str, default: Optional[Any] = None) -> Any:
    """Nested value of a configuration, or default"""
    node: Any = config
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node
