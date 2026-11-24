"""
Regressions from the third code review (medium findings):
- type conversion never joins an unmapped value with a mapped word, and
  never treats a tag as a device address, whatever its name
- Modbus targets can be declared contiguous (edge check instead of 2N reads)
- a PLC that is off costs one reconnect attempt per scan, not one per range
- config validation of nested lists / mappings, --max-concurrent limit
- a target whose protocol could not be detected still gets its CSV rows
- audit log: error_count counts every unread point; rejected tags are listed
  as denied
- FINS simulator's denied HR range is inside the HR area
"""

import argparse
import asyncio
import csv
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.audit_log import close_audit_logger, init_audit_logger
from plc_discovery.cli_args import NETWORK_OPTIONS, network_option_errors
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
)
from plc_discovery.config_loader import MAX_CONCURRENT, ConfigLoader
from plc_discovery.conversion import apply_data_type_conversion
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, _tag_point
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.scan_runner import collect_items

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


def _ok(address, value):
    return DataPoint(address=address, status=StatusCode.OK, value=value)


# ----------------------------------------------------------------------
# Type conversion
# ----------------------------------------------------------------------


def test_unmapped_value_does_not_take_a_word_of_a_mapping():
    manager = DataTypeManager.from_config(
        {"default_type": "DWORD", "mappings": [{"start": 11, "end": 20, "type": "INT16"}]}
    )
    points = [_ok(f"D{a}", 0xFFFF) for a in range(8, 13)]  # D8-D12: D8+D9, then D10 alone before the mapping
    converted = {p.address: p for p in apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)}
    assert converted["D8"].converted_value == 0xFFFFFFFF
    assert converted["D10"].converted_value is None and "incomplete" in converted["D10"].display_value
    assert (converted["D11"].data_type, converted["D11"].converted_value) == ("INT16", -1)
    assert (converted["D12"].data_type, converted["D12"].converted_value) == ("INT16", -1)


def test_tag_named_like_a_device_address_is_not_converted():
    tags = [_tag_point("D1", StatusCode.OK, 70000, "DINT"), _tag_point("D2", StatusCode.OK, 5, "DINT")]
    assert all(point.is_tag for point in tags)
    converted = apply_data_type_conversion(tags, DataType.DWORD, ByteOrder.LITTLE_ENDIAN, None)
    assert [(p.address, p.value, p.converted_value, p.display_value) for p in converted] == [
        ("D1", 70000, None, None),
        ("D2", 5, None, None),
    ]
    # The device addresses D1 / D2 are still combined
    words = apply_data_type_conversion([_ok("D1", 1), _ok("D2", 2)], DataType.DWORD, ByteOrder.LITTLE_ENDIAN, None)
    assert words[0].converted_value == 0x00020001


# ----------------------------------------------------------------------
# Modbus: contiguous register map
# ----------------------------------------------------------------------


def test_modbus_contiguous_option_restores_the_edge_check():
    class Device(ModbusHandler):
        def __init__(self, **options):
            super().__init__("127.0.0.1", port=1, config=FAST, **options)
            self._connected = True
            self.requests = 0

        async def _ensure_fresh_connection(self):
            return True

        async def read_device_raw(self, device_type, start_address, count):
            self.requests += 1
            if start_address + count <= 100:
                return list(range(start_address, start_address + count)), StatusCode.OK
            return None, StatusCode.NG_ILLEGAL_ADDR

    sparse, contiguous = Device(), Device(contiguous=1)
    for handler in (sparse, contiguous):
        points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 499)))
        assert sum(p.status == StatusCode.OK for p in points) == 100
        assert sum(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points) == 400
    assert contiguous.requests <= 1 + 4 * 3  # the chunk and its two ends, per invalid chunk
    assert sparse.requests > 10 * contiguous.requests  # every register confirmed on its own


def test_contiguous_is_a_valid_modbus_target_option():
    def errors(value):
        loader = ConfigLoader()
        loader.config["targets"] = [{"ip": "10.0.0.1", "protocol": "modbus", "options": {"contiguous": value}}]
        return loader.validate()

    assert errors(1) == [] and errors(0) == []
    assert any("contiguous" in e for e in errors(2))


# ----------------------------------------------------------------------
# One reconnect attempt per scan
# ----------------------------------------------------------------------


def test_plc_that_is_off_costs_one_reconnect_per_scan():
    class Off(BaseProtocolHandler):
        protocol = Protocol.SLMP
        attempts = 0

        async def connect(self):
            Off.attempts += 1
            return False

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start_address, count):
            raise AssertionError("nothing is read from a PLC that is off")

    async def run():
        collector = PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), FAST)
        collector._handler = Off("10.0.0.1", 5001, FAST)
        ranges = [DeviceRange(DeviceType.D, start, start + 9) for start in (0, 100, 200, 300)]
        first = await collect_items(collector, ranges)
        after_first = Off.attempts
        await collect_items(collector, ranges)
        return first, after_first, Off.attempts

    points, after_first, after_second = asyncio.run(run())
    assert len(points) == 40 and all(p.status == StatusCode.NG_COMM_ERROR for p in points)
    assert after_first == 1  # not one connection timeout per range
    assert after_second == 2  # the next scan tries again


# ----------------------------------------------------------------------
# Configuration and CLI
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "section, key, value",
    [
        ("scan", "device_ranges", 5),
        ("discovery", "ip_ranges", "192.168.1.0/24"),  # the list dash was forgotten
        ("discovery", "protocols", "slmp"),
        ("output", "database", True),
    ],
)
def test_nested_setting_of_the_wrong_shape_is_one_clear_error(section, key, value):
    loader = ConfigLoader()
    loader.config[section][key] = value
    loader._file_config = {section: {key: value}}
    errors = loader.validate()  # no exception
    assert len(errors) == 1 and errors[0].startswith(f"{section}.{key} must be")


def test_max_concurrent_option_has_the_limit_of_the_config_file():
    def errors(value):
        args = argparse.Namespace(**{attr: None for attr, _ in NETWORK_OPTIONS.values()})
        args.max_concurrent = value
        return network_option_errors(args)

    assert errors(MAX_CONCURRENT) == []
    assert any("--max-concurrent" in e and str(MAX_CONCURRENT) in e for e in errors(500))


# ----------------------------------------------------------------------
# Output for a target whose protocol was not detected
# ----------------------------------------------------------------------


def test_undetected_target_still_gets_its_addresses_written(monkeypatch, tmp_path, capsys):
    class NothingAnswers:
        def __init__(self, config, port=None):
            pass

        async def _probe_host(self, ip):
            return None

    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--device", "HR", "--range", "0-9"]
    monkeypatch.setattr(sys, "argv", argv + ["--output-dir", str(tmp_path), "--no-rich"])
    with patch.object(plc_scanner, "PLCDiscovery", NothingAnswers):
        with pytest.raises(SystemExit) as exit_info:
            asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "no PLC protocol answered" in capsys.readouterr().out

    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1
    with open(files[0], encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [row["address"] for row in rows] == [f"HR{a}" for a in range(10)]
    assert {row["status"] for row in rows} == {"NG_COMM_ERROR"}


# ----------------------------------------------------------------------
# Audit log and denied tags
# ----------------------------------------------------------------------


def test_audit_error_count_is_every_point_that_was_not_read(tmp_path):
    points = [
        DataPoint(address="D0", status=StatusCode.OK, value=1),
        DataPoint(address="D1", status=StatusCode.NG_ILLEGAL_ADDR),
        DataPoint(address="D2", status=StatusCode.NG_ILLEGAL_ADDR),
        DataPoint(address="D3", status=StatusCode.NG_TIMEOUT),
    ]

    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = True
            self.connect_error = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def collect_range(self, device_type, start, end):
            return points

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            # error_count as the collector reports it: communication errors only
            return {"total_points": 4, "success_count": 1, "error_count": 0}

    log = tmp_path / "audit.jsonl"
    init_audit_logger(str(log))
    try:

        async def run():
            with patch.object(plc_scanner, "PLCDataCollector", Collector):
                await plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST,
                    MagicMock(hex_addresses=False),
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 3)],
                )

        asyncio.run(run())
    finally:
        close_audit_logger()

    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    complete = [e for e in events if e["event_type"] == "SCAN_COMPLETE"]
    assert len(complete) == 1 and complete[0]["data_points"] == 4
    assert (complete[0]["metadata"]["success_count"], complete[0]["metadata"]["error_count"]) == (1, 3)


def test_tags_the_controller_rejects_are_listed_as_denied():
    handler = EtherNetIPHandler("127.0.0.1")
    points = [
        _tag_point("Speed", StatusCode.OK, 5, "INT"),
        _tag_point("NoSuchTag", StatusCode.NG_ILLEGAL_ADDR),
        _tag_point("Blob", StatusCode.NG_UNSUPPORTED),
        _tag_point("Slow", StatusCode.NG_TIMEOUT),  # transient: not recorded
    ]
    assert handler._learn_denied_tags(points) is points
    assert handler.get_denied_statuses() == {
        "NoSuchTag": StatusCode.NG_ILLEGAL_ADDR,
        "Blob": StatusCode.NG_UNSUPPORTED,
    }


# ----------------------------------------------------------------------
# FINS simulator
# ----------------------------------------------------------------------


def test_fins_simulator_denied_hr_range_can_be_reached():
    from simulators.fins_simulator import FINS_AREA_HR, FINS_AREA_SIZES, INACCESSIBLE_RANGES, FINSSimulator

    # Every denied range lies inside its area (HR1000-1050 was beyond the
    # 512-word HR area and could only ever answer "address range exceeded")
    for area, start, end in INACCESSIBLE_RANGES:
        assert end < FINS_AREA_SIZES[area]
    start = next(s for area, s, _ in INACCESSIBLE_RANGES if area == FINS_AREA_HR)
    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, FINS_AREA_HR, start >> 8, start & 0xFF, 0, 0, 1])
    assert FINSSimulator().handle_frame(request, ("127.0.0.1", 9600))[12:14] == b"\x11\x03"
