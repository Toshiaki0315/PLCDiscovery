"""
Data type conversion of collected data points (multi-word values, type
mapping files) and the data type settings of the CLI.

Split out of plc_scanner.py; plc_scanner re-exports every name.
"""

import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from .config import DataPoint, StatusCode
from .config_loader import ConfigLoader
from .cli_args import BYTE_ORDER_MAP, DATA_TYPE_MAP
from .data_types import (
    BIT_DEVICES, VARIABLE_LENGTH_TYPES, ByteOrder, DataType, DataTypeConverter, DataTypeManager,
)

logger = logging.getLogger(__name__)


def load_type_mapping(path: str, overrides: Optional[Dict[str, str]] = None) -> DataTypeManager:
    """
    Load type mapping from file.

    ``overrides`` (default_type / default_byte_order from the command line)
    replace the file's defaults before the mappings are built, so mappings
    without their own byte_order follow --byte-order.
    """
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

        if overrides and isinstance(config, dict):
            config = {**config, **overrides}
        return DataTypeManager.from_config(config, prefix=Path(path).name)
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

    Multi-word types (DWORD, FLOAT, DOUBLE, ...) combine consecutive,
    successfully read words. Values are aligned to a fixed grid so a failed
    or missing word never shifts the pairing of the following values:
    - with a type mapping: relative to the mapping's start address
    - otherwise: relative to the start of each contiguous address run
      (normally the start of the requested range)

    The combined value is stored on the first address (all words in
    raw_words). The other words stay in the output with their own raw
    value/hex and a display_value pointing to the first address, so no raw
    data is lost. Multi-word types are never applied to bit devices.

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

    # Parse addresses and find the start/end of each contiguous run
    parsed: List[Optional[tuple]] = [_split_address(dp.address) for dp in data_points]

    def continues(prev, addr) -> bool:
        return bool(addr and prev and prev[0] == addr[0] and prev[1] + 1 == addr[1])

    run_start: List[Optional[int]] = []
    for idx, addr in enumerate(parsed):
        if idx and continues(parsed[idx - 1], addr):
            run_start.append(run_start[-1])
        else:
            run_start.append(addr[1] if addr else None)
    run_end: List[Optional[int]] = [None] * len(parsed)
    for idx in range(len(parsed) - 1, -1, -1):
        addr = parsed[idx]
        if idx + 1 < len(parsed) and continues(addr, parsed[idx + 1]):
            run_end[idx] = run_end[idx + 1]
        else:
            run_end[idx] = addr[1] if addr else None

    result: List[DataPoint] = []
    i = 0
    while i < len(data_points):
        dp = data_points[i]
        addr = parsed[i]

        if addr is None or dp.value is None or dp.status != StatusCode.OK:
            result.append(dp)
            i += 1
            continue

        prefix, number = addr

        # Determine data type, value size and alignment base for this address
        align_base = run_start[i]
        mapping = type_manager.get_mapping_for_address(number, prefix) if type_manager else None
        if mapping:
            dt, bo, align_base = mapping.data_type, mapping.byte_order, mapping.start_address
            word_count = mapping.words_per_value()
        else:
            if type_manager:
                dt, bo = type_manager.default_type, type_manager.default_byte_order
            else:
                dt, bo = data_type, byte_order
            if dt in VARIABLE_LENGTH_TYPES:
                # STRING / RAW without a mapping: the whole requested range
                word_count = run_end[i] - run_start[i] + 1
            else:
                word_count = DataTypeConverter.get_word_count(dt) if dt else 1
        word_count = max(word_count or 1, 1)

        if dt is None or (word_count > 1 and prefix.upper() in BIT_DEVICES):
            result.append(dp)
            i += 1
            continue

        offset = (number - align_base) % word_count
        if offset:
            # Second/later word of a value whose first word failed or is missing
            result.append(dataclasses.replace(
                dp, data_type=dt.value,
                display_value=f"(part of {prefix}{number - offset}, incomplete)",
            ))
            i += 1
            continue

        # Collect the following consecutive, successfully read words
        group = [dp]
        for j in range(1, word_count):
            if i + j >= len(data_points):
                break
            nxt = data_points[i + j]
            if (nxt.value is None or nxt.status != StatusCode.OK
                    or parsed[i + j] != (prefix, number + j)):
                break
            group.append(nxt)

        if len(group) < word_count:
            # Not all words of this value were read: keep the raw point
            result.append(dataclasses.replace(
                dp, data_type=dt.value,
                display_value=f"(incomplete {dt.value}: {len(group)}/{word_count} words)",
            ))
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
        # Keep the remaining words of a multi-word value as their own rows
        for part in group[1:]:
            result.append(dataclasses.replace(
                part,
                data_type=dt.value,
                display_value=f"(part of {dp.address})",
            ))
        i += word_count

    return result


def resolve_data_types(args, config_loader: Optional[ConfigLoader]) -> tuple:
    """
    Data type conversion settings: (data_type, byte_order, type_manager).

    --data-type / --byte-order win over the config file. With a type mapping
    (file or config) they replace its default_type / default_byte_order:
    the type of unmapped addresses, and the byte order of mappings that do
    not set their own byte_order. An explicit mapping byte_order still wins.

    Raises:
        Exception: if the --type-mapping file cannot be loaded
    """
    data_type = DATA_TYPE_MAP.get(args.data_type) if args.data_type else None
    byte_order = BYTE_ORDER_MAP.get(args.byte_order) if args.byte_order else None
    overrides = {}
    if args.data_type:
        overrides["default_type"] = args.data_type
    if args.byte_order:
        overrides["default_byte_order"] = args.byte_order
    type_manager = None

    if args.type_mapping:
        type_manager = load_type_mapping(args.type_mapping, overrides)
    elif config_loader:
        dt_config = config_loader.config.get("data_types") or {}
        if dt_config.get("mappings"):
            type_manager = DataTypeManager.from_config({**dt_config, **overrides})
        if data_type is None and config_loader.is_set("data_types", "default_type"):
            data_type = config_loader.get_default_data_type()
        if byte_order is None and config_loader.is_set("data_types", "default_byte_order"):
            byte_order = config_loader.get_default_byte_order()

    return data_type, byte_order or ByteOrder.LITTLE_ENDIAN, type_manager
