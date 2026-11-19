"""
Regression tests for reports, found and fixed in code reviews.
"""

import asyncio
import json
import math
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.report import ReportConfig, ReportFormat, ReportGenerator, create_report


class FlakyHandler(BaseProtocolHandler):
    """Connects only while self.plc_up is True"""

    protocol = Protocol.SLMP

    def __init__(self, *a, **k):
        super().__init__("127.0.0.1", 5001, NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
        self.plc_up = True
        self.connect_calls = 0

    async def connect(self):
        self.connect_calls += 1
        self._connected = self.plc_up
        return self._connected

    async def disconnect(self):
        self._connected = False

    async def read_device_raw(self, device_type, start, count):
        if not await self._ensure_fresh_connection():
            return None, StatusCode.NG_COMM_ERROR
        return list(range(start, start + count)), StatusCode.OK


async def collector_with(handler):
    collector = PLCDataCollector(PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001))
    with patch.dict("plc_discovery.collector.PROTOCOL_HANDLERS", {Protocol.SLMP: lambda **k: handler}):
        assert await collector.connect()
    return collector


def drop_link(handler):
    """PLC goes away and the handler's reconnect fails (as after a timeout)"""
    handler.plc_up = False
    handler._connected = False
    handler._needs_reconnect = True


def _report(**config):
    plcs = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]
    points = {
        "10.0.0.1": [
            DataPoint("D0", 1, "0x0001", StatusCode.OK),
            DataPoint("D1", None, None, StatusCode.NG_ILLEGAL_ADDR),
        ]
    }
    generator, data = create_report(plcs=plcs, data_points=points, config=ReportConfig(**config))
    return generator.generate(data)


def _loader(tmp_path, text):
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


@pytest.fixture
def restore_logging():
    """main() reconfigures the root logger onto pytest's captured stdout"""
    import logging

    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def strict_loads(text):
    return json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))


def _collector_with_failing_handler():
    collector = PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001))
    handler = MagicMock()
    handler.is_connected = True
    handler.read_device_range = AsyncMock(side_effect=RuntimeError("library bug"))
    collector._handler = handler
    return collector, handler


@pytest.mark.asyncio
async def test_full_scan_reports_unreachable_ranges_then_recovers():
    handler = FlakyHandler()
    collector = await collector_with(handler)
    ranges = [DeviceRange(DeviceType.D, 0, 1), DeviceRange(DeviceType.M, 0, 0)]
    drop_link(handler)
    with patch.dict("plc_discovery.collector.DEFAULT_DEVICE_RANGES", {Protocol.SLMP: ranges}):
        down = await collector.collect_full_scan()
        assert [(p.address, p.status) for p in down] == [
            ("D0", StatusCode.NG_COMM_ERROR),
            ("D1", StatusCode.NG_COMM_ERROR),
            ("M0", StatusCode.NG_COMM_ERROR),
        ]
        handler.plc_up = True
        assert all(p.status == StatusCode.OK for p in await collector.collect_full_scan())


def test_create_report_keeps_errors():
    _, data = create_report(plcs=[], data_points={}, errors=["10.0.0.2: refused"])
    assert data.errors == ["10.0.0.2: refused"]
    _, data = create_report(plcs=[], data_points={})
    assert data.errors == []


@pytest.mark.parametrize(
    "data_types, message",
    [
        ({"mappings": [{"start": 0, "type": "FLOAT"}]}, "data_types.mappings[0].end is required"),
        ({"mappings": [{"start": 0, "end": 1, "type": "REAL"}]}, "data_types.mappings[0].type: unknown value 'REAL'"),
        (
            {"mappings": [{"start": 0, "end": 1, "type": "FLOAT", "byte_order": "BIGG"}]},
            "data_types.mappings[0].byte_order: unknown value",
        ),
        ({"mappings": [{"start": 5, "end": 1, "type": "FLOAT"}]}, "start must be <= end"),
        ({"mappings": [{"start": -1, "end": 1, "type": "FLOAT"}]}, "start must be an integer >= 0"),
        ({"mappings": [{"start": 0, "end": 9, "type": "STRING", "length": 0}]}, "length must be an integer >= 1"),
        ({"default_byte_order": "middle"}, "data_types.default_byte_order: unknown value"),
        ({"mappings": {"start": 0}}, "data_types.mappings must be a list"),
    ],
)
def test_invalid_data_types_reported_by_validate(tmp_path, data_types, message):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"targets": [{"ip": "127.0.0.1"}], "data_types": data_types}))
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any(message in e for e in errors), errors


def test_html_report_has_no_external_scripts():
    html = _report()
    assert "<script" not in html.lower()  # previously Chart.js from cdn.jsdelivr.net
    assert "cdn." not in html and "https://" not in html
    assert html.count("<svg") == 2 and "statusChart" in html and "plcChart" in html


def test_html_report_without_charts_has_no_svg():
    assert "<svg" not in _report(include_charts=False)


def test_logo_path_and_language_are_escaped(tmp_path):
    logo = tmp_path / 'logo"onerror="alert(1).png'
    logo.write_bytes(b"x")
    html = _report(logo_path=str(logo), language='ja" onload="x')
    assert 'onerror="alert(1)' not in html and 'onload="x' not in html
    assert "&quot;onerror=&quot;" in html


def test_svg_chart_escapes_labels():
    generator = ReportGenerator(ReportConfig())
    _, data = create_report(plcs=[], data_points={"<b>x</b>": [DataPoint("D0", 1, "0x0001", StatusCode.OK)]})
    assert "<b>x</b>" not in generator.generate(data).split("plcChart")[1].split("</svg>")[0]


@pytest.mark.parametrize(
    "text,fragment",
    [
        ('network:\n  max_concurrent: "3"\n', "network.max_concurrent must be an integer"),
        ("network:\n  request_timeout_ms: 0\n", "network.request_timeout_ms must be >= 1"),
        ("network:\n  retry_interval_ms: -1\n", "network.retry_interval_ms must be >= 0"),
        ("network:\n  packet_interval_ms: 1.5\n", "network.packet_interval_ms must be an integer"),
        ('scan:\n  interval_seconds: "60"\n', "scan.interval_seconds must be a number"),
        ("scan:\n  interval_seconds: -5\n", "scan.interval_seconds must be 0"),
        (
            'scan:\n  device_ranges:\n    - {device: D, start: "0", end: 9}\n',
            "scan.device_ranges[0].start must be an integer",
        ),
        (
            "scan:\n  device_ranges:\n    - {device: D, start: 10, end: 9}\n",
            "scan.device_ranges[0]: start must be <= end",
        ),
    ],
)
def test_invalid_numbers_are_reported_not_raised(tmp_path, text, fragment):
    errors = _loader(tmp_path, text).validate()
    assert any(fragment in e for e in errors), errors


def test_report_lists_denied_addresses_in_order():
    generator, data = create_report(
        plcs=[],
        data_points={},
        denied_addresses={"10.0.0.1": ["D5003", "D17", "D5000"]},
    )
    html_text = generator._generate_denied_section(data)
    assert "D17, D5000, D5003" in html_text


def test_failed_report_exits_with_1(monkeypatch, tmp_path, capsys, restore_logging):
    from plc_discovery.report import ReportGenerator

    def broken_save(self, data, output_path=None):
        raise ImportError("PDF generation requires 'weasyprint' or 'pdfkit'")

    monkeypatch.setattr(ReportGenerator, "save", broken_save)

    async def no_discovery(*args, **kwargs):
        return []

    monkeypatch.setattr(plc_scanner, "run_discovery", no_discovery)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "discover",
            "--no-rich",
            "-o",
            str(tmp_path),
            "--report",
            "pdf",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        asyncio.run(plc_scanner.main())
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Report generation failed" in out
    assert "Scan completed successfully" not in out


def test_report_output_path_used_as_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = ReportConfig(format=ReportFormat.JSON, output_path=str(tmp_path / "results"))
    generator, data = create_report([], {}, {}, "range", None, None, config)

    explicit = generator.save(data, "reports/out.json")
    assert explicit == "reports/out.json"
    assert (tmp_path / "reports" / "out.json").exists()

    auto = generator.save(data)
    assert auto.startswith(str(tmp_path / "results"))


def test_report_escapes_and_shows_mode(tmp_path):
    config = ReportConfig(format=ReportFormat.HTML, output_path=str(tmp_path))
    generator, data = create_report([], {}, {}, "range (periodic every 60s, last cycle) <b>", None, None, config)
    html = generator.generate(data)
    assert "periodic every 60s, last cycle" in html
    assert "<b>" not in html.split("periodic every 60s, last cycle")[1][:10]


def test_json_report_is_strict_json():
    dp = DataPoint(
        "D0", 0xFFFF, "0xFFFF", StatusCode.OK, data_type="FLOAT", converted_value=math.nan, display_value="nan"
    )
    generator, data = create_report(
        [PLCInfo("10.0.0.1", protocol=Protocol.SLMP)],
        {"10.0.0.1": [dp]},
        {},
        "range",
        None,
        None,
        ReportConfig(format=ReportFormat.JSON),
    )
    report = strict_loads(generator.generate(data))
    assert "NaN" not in json.dumps(report)


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
