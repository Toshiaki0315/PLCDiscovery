"""
Regression tests for important review findings (1-10).
"""

import argparse
import asyncio
import json
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, ScanMode, StatusCode
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager, DataTypeMapping
from plc_discovery.protocols.modbus import modbus_unit_kwargs
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.utils import get_manufacturer_from_mac


def ok(address, value):
    return DataPoint(address=address, value=value, raw_hex=f"0x{value:04X}", status=StatusCode.OK)


def make_args(**overrides):
    defaults = dict(mode=None, interval=None, range=None, device="D")
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


class SilentDisplay:
    """Stand-in for RichProgressDisplay that records messages"""

    def __init__(self):
        self.messages = []

    def __getattr__(self, name):
        return lambda *a, **k: self.messages.append((name, a))


# ---------------------------------------------------------------------------
# 1: connection failures must not be reported as success
# ---------------------------------------------------------------------------

class FakeCollector:
    def __init__(self, connected=True, denied=None, points=None):
        self.is_connected = connected
        self._denied = set(denied or [])
        self._points = points if points is not None else [ok("D0", 1)]
        self.collect_calls = 0
        self.cleared = 0
        self.exited = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.exited = True

    def clear_data(self):
        self.cleared += 1

    async def collect_range(self, *args):
        self.collect_calls += 1
        return list(self._points)

    async def collect_full_scan(self):
        return list(self._points)

    def get_denied_addresses(self):
        return set(self._denied)

    def get_denied_statuses(self):
        return {a: StatusCode.NG_ILLEGAL_ADDR for a in self._denied}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


class TestConnectionFailure:

    @pytest.mark.asyncio
    async def test_single_scan_reports_connection_failure(self, tmp_path):
        exporter = MagicMock()
        plc = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=502)
        with patch.object(plc_scanner, "PLCDataCollector", lambda *a: FakeCollector(connected=False)):
            outcome = await plc_scanner.run_single_scan(
                plc, NetworkConfig(), exporter, SilentDisplay(), ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 9)]
            )
        assert outcome.success is False
        assert "Failed to connect" in outcome.error
        exporter.export_plc_data.assert_not_called()

    def test_cli_exit_code_on_unreachable_plc(self, tmp_path, monkeypatch):
        """Connection refused -> exit code 1, other targets still attempted"""
        monkeypatch.setattr(sys, "argv", [
            "plc_scanner.py", "--mode", "range", "--protocol", "modbus",
            "--target", "127.0.0.1,127.0.0.2", "--port", "59997",
            "--range", "0-3", "--request-timeout", "300", "-q",
            "--output-dir", str(tmp_path),
        ])
        attempted = []
        real = plc_scanner.run_single_scan

        async def spy(plc_info, *args, **kwargs):
            attempted.append(plc_info.ip_address)
            return await real(plc_info, *args, **kwargs)

        monkeypatch.setattr(plc_scanner, "run_single_scan", spy)
        with pytest.raises(SystemExit) as exc:
            plc_scanner.cli()
        assert exc.value.code == 1
        assert attempted == ["127.0.0.1", "127.0.0.2"]


# ---------------------------------------------------------------------------
# 2: config file scan settings are used
# ---------------------------------------------------------------------------

class TestConfigScanSettings:

    def test_mode_and_interval_from_config(self, tmp_path):
        loader = write_config(tmp_path, {"scan": {"mode": "range", "interval_seconds": 30}})
        assert plc_scanner.resolve_mode_and_interval(make_args(), loader) == ("range", 30.0)

    def test_cli_overrides_config(self, tmp_path):
        loader = write_config(tmp_path, {"scan": {"mode": "range", "interval_seconds": 30}})
        args = make_args(mode="full", interval=0.0)
        assert plc_scanner.resolve_mode_and_interval(args, loader) == ("full", 0.0)

    def test_config_without_mode_does_not_full_scan(self, tmp_path):
        """DEFAULT_CONFIG says "full"; that default must not trigger a full scan"""
        loader = write_config(tmp_path, {"network": {"max_concurrent": 1}})
        assert plc_scanner.resolve_mode_and_interval(make_args(), loader) == ("discover", 0.0)

    def test_device_ranges_from_config(self, tmp_path):
        loader = write_config(tmp_path, {"scan": {"device_ranges": [
            {"device": "D", "start": 0, "end": 9},
            {"device": "M", "start": 100, "end": 115},
        ]}})
        ranges = plc_scanner.resolve_device_ranges(make_args(), loader)
        assert [(r.device_type, r.start_address, r.end_address) for r in ranges] == [
            (DeviceType.D, 0, 9), (DeviceType.M, 100, 115)
        ]

    def test_cli_range_overrides_config(self, tmp_path):
        loader = write_config(tmp_path, {"scan": {"device_ranges": [{"device": "M", "start": 0, "end": 1}]}})
        ranges = plc_scanner.resolve_device_ranges(make_args(range="5-6", device="W"), loader)
        assert [(r.device_type, r.start_address, r.end_address) for r in ranges] == [(DeviceType.W, 5, 6)]


# ---------------------------------------------------------------------------
# 3: type mapping multi-word conversion
# ---------------------------------------------------------------------------

class TestTypeMappingConversion:

    def manager(self):
        m = DataTypeManager()
        m.add_mapping(DataTypeMapping(0, 1, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN))
        return m

    def test_mapping_float_combines_two_words(self):
        points = [ok("D0", 0x0000), ok("D1", 0x3F80), ok("D2", 7)]
        result = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, self.manager())
        assert result[0].address == "D0"
        assert result[0].converted_value == 1.0
        assert result[0].raw_words == [0x0000, 0x3F80]
        # second word kept with its raw value
        assert result[1].address == "D1" and result[1].value == 0x3F80
        assert result[1].converted_value is None
        assert result[2].address == "D2" and result[2].converted_value == 7  # default WORD

    def test_failed_word_not_combined(self):
        points = [ok("D0", 0x0000), DataPoint(address="D1", status=StatusCode.NG_TIMEOUT)]
        result = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, self.manager())
        assert result[0].converted_value is None
        assert result[1].status == StatusCode.NG_TIMEOUT

    def test_non_consecutive_addresses_not_combined(self):
        points = [ok("D0", 0x0000), ok("D5", 0x3F80)]
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert [dp.converted_value for dp in result] == [None, None]

    def test_input_list_not_mutated(self):
        points = [ok("D0", 5)]
        plc_scanner.apply_data_type_conversion(points, DataType.INT16, ByteOrder.LITTLE_ENDIAN)
        assert points[0].converted_value is None


# ---------------------------------------------------------------------------
# 5-7: retry interval, pymodbus API, OUI
# ---------------------------------------------------------------------------

def test_retry_interval_applied():
    handler = SLMPHandler("127.0.0.1", config=NetworkConfig(retry_interval_ms=750))
    assert handler._retry_config.initial_delay_ms == 750


class TestModbusUnitKwargs:

    def test_new_api(self):
        def read(address, *, count=1, device_id=1):
            pass
        assert modbus_unit_kwargs(read, 3) == {"device_id": 3}

    def test_old_api(self):
        def read(address, count=1, slave=0, **kwargs):
            pass
        assert modbus_unit_kwargs(read, 3) == {"slave": 3}


def test_vmware_oui_not_mitsubishi():
    assert get_manufacturer_from_mac("00:50:56:12:34:56") is None


# ---------------------------------------------------------------------------
# 8-9: Ctrl+C handling and periodic-mode duplicates
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_interrupt_finalizes_and_denied_logged_once():
    collector = FakeCollector(denied={"D5"})
    exporter = MagicMock()
    exporter.export_plc_data.return_value = "data.csv"
    exporter.export_denied_addresses.return_value = "denied.csv"
    plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001)

    with patch.object(plc_scanner, "PLCDataCollector", lambda *a: collector):
        task = asyncio.ensure_future(plc_scanner.run_periodic_scan(
            [plc], NetworkConfig(), exporter, SilentDisplay(),
            [DeviceRange(DeviceType.D, 0, 9)], interval=0.01
        ))
        while collector.collect_calls < 3:
            await asyncio.sleep(0.005)
        task.cancel()  # what asyncio.run does on Ctrl+C
        (outcome,) = await task

    assert outcome.interrupted is True
    assert outcome.success is True
    assert collector.exited  # disconnected
    assert collector.cleared == collector.collect_calls  # no accumulation
    exporter.export_denied_addresses.assert_called_once_with(
        {"D5"}, "127.0.0.1", statuses={"D5": StatusCode.NG_ILLEGAL_ADDR}
    )
    # one CSV per iteration, none duplicated after the loop
    assert exporter.export_plc_data.call_count == collector.collect_calls


# ---------------------------------------------------------------------------
# 10: no sleep after the last iteration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_collect_with_interval_no_trailing_sleep():
    collector = PLCDataCollector(PLCInfo("127.0.0.1", protocol=Protocol.SLMP))

    async def fake_collect_range(*args):
        return [ok("D0", 1)]

    collector.collect_range = fake_collect_range
    started = time.monotonic()
    results = await collector.collect_with_interval(DeviceType.D, 0, 0, 10, max_iterations=1)
    assert len(results) == 1
    assert time.monotonic() - started < 1
