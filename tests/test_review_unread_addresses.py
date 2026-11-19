"""
Review fixes: every requested address appears in the output even when a
read raises or the PLC cannot be connected; NaN / infinite intervals are
rejected.
"""

import asyncio
import math
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery.collector import PLCDataCollector, comm_error_points
from plc_discovery.config import DeviceRange, DeviceType, PLCInfo, Protocol, ScanMode, StatusCode, TagRange
from plc_discovery.config_loader import ConfigLoader, number_error
from plc_discovery.output import CSVExporter


def _collector_with_failing_handler():
    collector = PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001))
    handler = MagicMock()
    handler.is_connected = True
    handler.read_device_range = AsyncMock(side_effect=RuntimeError("library bug"))
    collector._handler = handler
    return collector, handler


def test_collect_range_reports_comm_error_when_read_raises():
    collector, handler = _collector_with_failing_handler()
    points = asyncio.run(collector.collect_range(DeviceType.D, 10, 14))
    assert [p.address for p in points] == ["D10", "D11", "D12", "D13", "D14"]
    assert {p.status for p in points} == {StatusCode.NG_COMM_ERROR}
    handler.mark_needs_reconnect.assert_called_once_with()  # reconnect before the next read
    assert collector.get_statistics()["total_points"] == 5


def test_full_scan_keeps_going_and_reports_failed_range(monkeypatch):
    collector, handler = _collector_with_failing_handler()
    ok = [MagicMock(address="M0", status=StatusCode.OK)]
    handler.read_device_range = AsyncMock(side_effect=[RuntimeError("boom"), ok])
    monkeypatch.setattr(
        collector_module,
        "DEFAULT_DEVICE_RANGES",
        {Protocol.SLMP: [DeviceRange(DeviceType.D, 0, 2), DeviceRange(DeviceType.M, 0, 0)]},
    )
    points = asyncio.run(collector.collect_full_scan())
    assert [p.address for p in points] == ["D0", "D1", "D2", "M0"]
    assert [p.status for p in points[:3]] == [StatusCode.NG_COMM_ERROR] * 3


def test_comm_error_points_for_tags():
    points = comm_error_points(TagRange(["Speed", "Recipe[0]{10}"]))
    assert [(p.address, p.status) for p in points] == [
        ("Speed", StatusCode.NG_COMM_ERROR),
        ("Recipe[0]", StatusCode.NG_COMM_ERROR),
    ]


class OfflineCollector:
    def __init__(self, plc_info, config=None):
        self.is_connected = False
        self.connect_error = "connection refused"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


@pytest.mark.parametrize(
    "mode, ranges, expected",
    [
        (ScanMode.RANGE, [DeviceRange(DeviceType.D, 0, 2), TagRange(["A"])], ["D0", "D1", "D2", "A"]),
        (ScanMode.FULL, None, ["D0", "D1", "M0"]),
    ],
)
def test_single_scan_writes_requested_addresses_when_offline(monkeypatch, tmp_path, mode, ranges, expected):
    monkeypatch.setattr(plc_scanner, "PLCDataCollector", OfflineCollector)
    monkeypatch.setattr(
        collector_module,
        "DEFAULT_DEVICE_RANGES",
        {Protocol.SLMP: [DeviceRange(DeviceType.D, 0, 1), DeviceRange(DeviceType.M, 0, 0)]},
    )
    plc = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)
    outcome = asyncio.run(
        plc_scanner.run_single_scan(
            plc, MagicMock(), CSVExporter(str(tmp_path)), MagicMock(), mode, device_ranges=ranges
        )
    )
    assert not outcome.success and "connection refused" in outcome.error
    assert [p.address for p in outcome.data_points] == expected
    assert {p.status for p in outcome.data_points} == {StatusCode.NG_COMM_ERROR}
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1 and "NG_COMM_ERROR" in files[0].read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_rejected(value):
    assert "finite" in number_error(value, 0)


@pytest.mark.parametrize("text", [".nan", ".inf"])
def test_non_finite_interval_rejected_in_config(tmp_path, text):
    path = tmp_path / "c.yaml"
    path.write_text(f"scan:\n  mode: range\n  interval_seconds: {text}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("interval_seconds" in e and "finite" in e for e in loader.validate())


@pytest.mark.parametrize("value", ["nan", "inf", "-5"])
def test_non_finite_or_negative_interval_rejected_on_cli(monkeypatch, tmp_path, capsys, value):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.9",
            "--device",
            "D",
            "--range",
            "0-0",
            f"--interval={value}",
            "--output-dir",
            str(tmp_path),
        ],
    )
    with (
        patch.object(plc_scanner, "run_single_scan", AsyncMock()) as scan,
        patch.object(plc_scanner, "run_periodic_scan", AsyncMock()) as periodic,
    ):
        with pytest.raises(SystemExit) as exit_info:
            asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "--interval" in capsys.readouterr().out
    scan.assert_not_called()
    periodic.assert_not_called()


# ---------------------------------------------------------------------------
# GUI: a single read that cannot connect still saves NG_COMM_ERROR rows
# ---------------------------------------------------------------------------


class _GuiOfflineCollector:
    connect_error = None

    def __init__(self, plc, config=None):
        pass

    def set_progress_callback(self, cb):
        pass

    async def connect(self):
        return False

    async def disconnect(self):
        pass


@pytest.mark.parametrize(
    "mode, tags, expected",
    [
        ("range", None, ["D0", "D1", "D2"]),
        ("range", ["Speed", "Recipe[0]{5}"], ["Speed", "Recipe[0]"]),
        ("full", None, ["D0", "M0"]),
    ],
)
def test_gui_single_read_offline_saves_comm_errors(monkeypatch, tmp_path, mode, tags, expected):
    from plc_discovery.config import NetworkConfig
    from tests.test_review14_fixes import _import_gui

    plc_gui = _import_gui(monkeypatch)
    monkeypatch.setattr(plc_gui, "PLCDataCollector", _GuiOfflineCollector)
    monkeypatch.setattr(
        collector_module,
        "DEFAULT_DEVICE_RANGES",
        {Protocol.SLMP: [DeviceRange(DeviceType.D, 0, 0), DeviceRange(DeviceType.M, 0, 0)]},
    )
    app = MagicMock()
    posted = []
    app._post = lambda *item: posted.append(item)
    exporter = CSVExporter(str(tmp_path))
    with pytest.raises(RuntimeError) as error:
        asyncio.run(
            plc_gui.PLCScannerApp._collect_job(
                app,
                NetworkConfig(),
                "10.0.0.1",
                Protocol.SLMP,
                5001,
                mode,
                DeviceType.D,
                0,
                2,
                0,
                None,
                None,
                exporter,
                tags=tags,
            )
        )
    data = [item for item in posted if item[0] == "data"]
    assert [p.address for p in data[0][1]] == expected
    assert {p.status for p in data[0][1]} == {StatusCode.NG_COMM_ERROR}
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1 and str(files[0]) in str(error.value)
