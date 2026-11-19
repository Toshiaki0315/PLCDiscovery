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
    writer.export_points([_ok("D1")])
    assert writer.error_count == 2 and "locked" in writer.first_error
    assert writer.error_summary(" during monitoring").startswith("2 write error(s) during monitoring; first: ")
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


def test_outage_and_recovery_notified_once_each():
    notifier = MagicMock()
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def notify(send):
        await send(notifier)

    async def run():
        runner = CycleRunner(None, notify=notify)
        for reachable in (True, False, False, True, True, False):
            await runner.track_outage("PLC1", reachable, "10.0.0.1")

    asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 2  # two outages
    assert notifier.notify_recovered.await_count == 1  # first one ended
    kwargs = notifier.notify_recovered.await_args.kwargs
    assert kwargs["plc_ip"] == "10.0.0.1" and kwargs["downtime_seconds"] >= 0


def test_outage_events_reach_scan_error_subscribers():
    from plc_discovery.notifications import NotificationManager, NotificationType

    sent = []
    manager = NotificationManager()
    manager.add_custom("old", lambda event: sent.append(("old", event.type)), events=[NotificationType.SCAN_ERROR])
    manager.add_custom("new", lambda event: sent.append(("new", event.type)), events=[NotificationType.PLC_UNREACHABLE])
    manager.add_custom(
        "report", lambda event: sent.append(("report", event.type)), events=[NotificationType.STATUS_REPORT]
    )
    asyncio.run(manager.notify_unreachable("PLC1", "10.0.0.1"))
    asyncio.run(manager.notify_recovered("PLC1", "10.0.0.1", 12.0))
    assert sorted(sent, key=str) == sorted(
        [
            ("old", NotificationType.PLC_UNREACHABLE),
            ("new", NotificationType.PLC_UNREACHABLE),
            ("old", NotificationType.PLC_RECOVERED),
            ("new", NotificationType.PLC_RECOVERED),
        ],
        key=str,
    )


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


def test_parallel_scan_reports_unreached_addresses(tmp_path):
    """--max-concurrent > 1: an offline PLC still gets NG_COMM_ERROR rows and a CSV"""
    from unittest.mock import patch

    import plc_scanner
    from plc_discovery.config import NetworkConfig, ScanMode
    from plc_discovery.output import CSVExporter

    class Offline:
        is_connected = False
        connect_error = None

        def __init__(self, plc, config=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    plcs = [PLCInfo(ip, protocol=Protocol.SLMP, port=5001) for ip in ("10.0.0.1", "10.0.0.2")]
    with patch.object(plc_scanner, "PLCDataCollector", Offline):
        results = asyncio.run(
            plc_scanner.run_parallel_scan(
                plcs,
                NetworkConfig(max_concurrent=2),
                CSVExporter(str(tmp_path)),
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 1), TagRange(["A"])],
            )
        )
    for result in results.values():
        assert not result.success and "Failed to connect" in result.error
        assert [(p.address, p.status) for p in result.data_points] == [
            ("D0", StatusCode.NG_COMM_ERROR),
            ("D1", StatusCode.NG_COMM_ERROR),
            ("A", StatusCode.NG_COMM_ERROR),
        ]
    assert len(list(tmp_path.glob("plc_data_*.csv"))) == 2


def test_gui_writer_keeps_database_detail_out_of_log(caplog):
    db = MagicMock(is_enabled=True)
    db.export_plc_data.return_value = 1
    writer = ResultWriter(
        PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), MagicMock(hex_addresses=False), db_exporter=db
    )
    with caplog.at_level("INFO"):
        writer.export_points([_ok("D0")])
    assert "Saved 1 records" not in caplog.text
