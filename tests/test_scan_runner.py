"""
Shared scan plumbing (plc_discovery.scan_runner), handler methods the
collector uses, report stylesheets and simulator CLI helpers.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from plc_discovery.config import DataPoint, DeviceRange, DeviceType, PLCInfo, Protocol, StatusCode, TagRange
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.report import ReportConfig, ReportGenerator
from plc_discovery.scan_runner import CycleRunner, ResultWriter, collect_items, next_cycle_wait
from simulators.common import parse_denied_ranges, simulator_parser


def _ok(address):
    return DataPoint(address=address, status=StatusCode.OK, value=1)


def _collector():
    collector = MagicMock()
    collector.collect_full_scan = AsyncMock(return_value=[_ok("D0")])
    collector.collect_range = AsyncMock(return_value=[_ok("D10")])
    collector.collect_tags = AsyncMock(return_value=[_ok("Speed")])
    collector.get_denied_addresses.return_value = {"D99"}
    collector.get_denied_statuses.return_value = {"D99": StatusCode.NG_ILLEGAL_ADDR}
    return collector


def test_collect_items_full_scan_and_items_in_order():
    collector = _collector()
    assert [p.address for p in asyncio.run(collect_items(collector, None))] == ["D0"]
    points = asyncio.run(collect_items(collector, [TagRange(["Speed"]), DeviceRange(DeviceType.D, 10, 10)]))
    assert [p.address for p in points] == ["Speed", "D10"]


def test_cycle_runner_read_writes_points_and_denied_once():
    collector = _collector()
    exporter = MagicMock(hex_addresses=False)
    exporter.export_plc_data.return_value = "data.csv"
    exporter.export_denied_addresses.return_value = "denied.csv"
    writer = ResultWriter(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), exporter)

    async def run():
        runner = CycleRunner([DeviceRange(DeviceType.D, 10, 10)])
        first = await runner.read(collector, writer)
        second = await runner.read(collector, writer)
        return first, second

    first, second = asyncio.run(run())
    assert [p.address for p in first.points] == ["D10"]
    assert (first.path, first.denied_path) == ("data.csv", "denied.csv")
    assert second.denied_path is None  # already logged
    assert collector.clear_data.call_count == 2
    exporter.export_denied_addresses.assert_called_once()


def test_result_writer_without_display_never_raises():
    exporter = MagicMock(hex_addresses=True)
    exporter.export_plc_data.side_effect = PermissionError("locked")
    writer = ResultWriter(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), exporter, daily=False)
    assert writer.export_points([_ok("D0")]) is None
    assert writer.errors and "locked" in writer.errors[0]
    assert exporter.export_plc_data.call_args.kwargs["hex_addresses"] is True


def test_result_writer_daily_appends():
    exporter = MagicMock(hex_addresses=False)
    writer = ResultWriter(PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP, port=502), exporter, daily=True)
    writer.export_points([_ok("40001")])
    exporter.append_plc_data.assert_called_once()
    exporter.export_plc_data.assert_not_called()


def test_status_report_sent_only_when_due():
    sent = []

    async def notify(send):
        sent.append(send)

    async def run():
        notifier = MagicMock(report_interval_seconds=0.02)
        runner = CycleRunner(None, notifier=notifier, notify=notify)
        await runner.report_if_due({"a": [_ok("D0")]}, [], 1)
        await asyncio.sleep(0.03)
        await runner.report_if_due({"a": [_ok("D0")]}, [], 2)
        await runner.report_if_due({"a": [_ok("D0")]}, [], 3)

    asyncio.run(run())
    assert len(sent) == 1


def test_outage_notified_once_per_outage():
    sent = []

    async def notify(send):
        sent.append(send)

    async def run():
        runner = CycleRunner(None, notify=notify)
        for reachable in (False, False, True, False):
            await runner.track_outage("a", reachable, "10.0.0.1", "down")

    asyncio.run(run())
    assert len(sent) == 2


def test_next_cycle_wait_subtracts_reading_time():
    async def run():
        loop = asyncio.get_running_loop()
        return next_cycle_wait(10.0, loop.time() - 4.0), next_cycle_wait(1.0, loop.time() - 5.0)

    wait, overdue = asyncio.run(run())
    assert 5.9 < wait <= 6.0 and overdue == 0.0


def test_handler_reconnect_resets_failure_state():
    handler = SLMPHandler("127.0.0.1", 5001)
    handler._comm_failure_streak = 7
    handler.disconnect = AsyncMock()
    handler.connect = AsyncMock(return_value=True)
    assert asyncio.run(handler.reconnect()) is True
    assert handler._comm_failure_streak == 0 and not handler._needs_reconnect
    handler.connect = AsyncMock(return_value=False)
    assert asyncio.run(handler.reconnect()) is False
    handler.mark_needs_reconnect()
    assert handler._needs_reconnect


def test_uses_address_ranges():
    assert SLMPHandler("127.0.0.1", 5001).uses_address_ranges is True
    eip = EtherNetIPHandler("127.0.0.1", 44818)
    assert eip.uses_address_ranges is False  # type unknown before connecting
    eip._plc_type = "slc"
    assert eip.uses_address_ranges is True


def test_report_stylesheets_load():
    generator = ReportGenerator(ReportConfig(theme="dark"))
    default = generator._get_default_theme_css()
    assert "--primary-color: #2563eb" in default
    assert generator._get_dark_theme_css().startswith(default)
    assert "--bg-color: #0f172a" in generator._get_dark_theme_css()


def test_simulator_cli_helpers():
    assert parse_denied_ranges("5000-5100, 7000-7050,x") == [(5000, 5100), (7000, 7050)]
    assert parse_denied_ranges(None) == []
    args = simulator_parser("x", 5001, "1-2").parse_args(["--port", "6000"])
    assert (args.host, args.port, args.denied) == ("127.0.0.1", 6000, "1-2")
    assert not hasattr(simulator_parser("x", 9600).parse_args([]), "denied")
