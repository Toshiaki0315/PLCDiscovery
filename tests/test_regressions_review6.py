"""
Regression tests for the findings of the sixth code review.

- GUI: the scan-complete notification counted a scan with any NG point as a
  failed target (every full scan), unlike the CLI
- notifications[].retry_count: a fractional number passed validation and
  then failed every send
- an unexpected exception while reading tags ended a scan / the GUI's
  periodic monitoring
- access_denied_log.csv: two encodings in one file after the setting changed
- FINS: transport failures were reported as NG_TIMEOUT
- an undetected target sharing its IP with a detected one lost its rows in
  the report
- ParallelPLCScanner never finished with max_concurrent = 0
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import plc_gui
import plc_scanner
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DataPoint, DeviceType, NetworkConfig, PLCInfo, Protocol, ScanMode, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder
from plc_discovery.output import CSVExporter
from plc_discovery.parallel import scan_plcs_parallel
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.scan_runner import CycleResult
from plc_discovery.utils import get_timestamp


def _point(address, status=StatusCode.OK, value=1):
    ok = status == StatusCode.OK
    return DataPoint(address=address, value=value if ok else None, status=status, timestamp=get_timestamp())


# ----------------------------------------------------------------------
# GUI: scan-complete notification
# ----------------------------------------------------------------------


def _scan_complete_counts(points):
    notifier = MagicMock()
    notifier.notify_scan_complete = AsyncMock(return_value={})
    outputs = MagicMock()

    async def notify(send):
        await send(notifier)
        return True

    outputs.notify = notify
    asyncio.run(plc_gui.PLCScannerApp._notify_collect_done(outputs, "10.0.0.1", points, 1, 1.0))
    args, kwargs = notifier.notify_scan_complete.call_args
    return args[1], args[2], kwargs


def test_gui_scan_with_invalid_addresses_is_notified_as_a_successful_target():
    points = [_point("D0"), _point("R0", StatusCode.NG_ILLEGAL_ADDR)]
    success, errors, extra = _scan_complete_counts(points)
    assert (success, errors) == (1, 0)  # was (0, 1), with priority HIGH, for every full scan
    assert extra["ok_points"] == 1 and extra["ng_points"] == 1


@pytest.mark.parametrize("points", [[], [_point("D0", StatusCode.NG_TIMEOUT), _point("D1", StatusCode.NG_COMM_ERROR)]])
def test_gui_scan_the_plc_did_not_answer_is_notified_as_a_failed_target(points):
    success, errors, _ = _scan_complete_counts(points)
    assert (success, errors) == (0, 1)


# ----------------------------------------------------------------------
# notifications[].retry_count
# ----------------------------------------------------------------------


@pytest.mark.parametrize("value", [3.0, 2.5, True, "3", 0])
def test_notification_retry_count_must_be_a_whole_number(value):
    loader = ConfigLoader()
    loader._merge_config(
        {"notifications": [{"name": "n", "url": "https://example.invalid/hook", "retry_count": value}]}
    )
    assert any("notifications[0].retry_count" in error for error in loader.validate())


def test_notification_retry_count_and_fractional_timeout_are_accepted():
    loader = ConfigLoader()
    loader._merge_config(
        {"notifications": [{"name": "n", "url": "https://example.invalid/hook", "retry_count": 2, "timeout": 2.5}]}
    )
    assert loader.validate() == []


# ----------------------------------------------------------------------
# Unexpected exception while reading tags
# ----------------------------------------------------------------------


def _tag_collector(read_tags):
    collector = PLCDataCollector(PLCInfo(ip_address="10.0.0.1", protocol=Protocol.ETHERNET_IP, port=44818))
    handler = MagicMock()
    handler.is_connected = True
    handler.supports_tags = True
    handler.tag_scan_list.return_value = ["Speed", "Values[0]{3}"]
    handler.read_tags = read_tags
    collector._handler = handler
    return collector, handler


def test_tags_whose_read_raises_are_reported_as_communication_errors():
    collector, handler = _tag_collector(AsyncMock(side_effect=RuntimeError("unexpected reply")))
    points = asyncio.run(collector.collect_tags(["Speed", "Values[0]{3}"]))
    assert [(p.address, p.status, p.is_tag) for p in points] == [
        ("Speed", StatusCode.NG_COMM_ERROR, True),
        ("Values[0]", StatusCode.NG_COMM_ERROR, True),
    ]
    assert collector.get_collected_data() == points
    handler.mark_needs_reconnect.assert_called_once()


def test_full_scan_of_tags_whose_read_raises_is_reported_not_raised():
    collector, _ = _tag_collector(AsyncMock(side_effect=RuntimeError("unexpected reply")))
    points = asyncio.run(collector.collect_full_scan())
    assert [p.status for p in points] == [StatusCode.NG_COMM_ERROR] * 2


def test_stopping_a_tag_read_is_still_a_cancellation():
    collector, _ = _tag_collector(AsyncMock(side_effect=asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(collector.collect_tags(["Speed"]))


class _FakeCollector:
    connect_error = None
    is_connected = True

    def __init__(self, plc_info, config):
        pass

    def set_progress_callback(self, callback):
        pass

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "success_rate": "100.00%"}


def _gui_job(tmp_path, interval):
    app, posted = MagicMock(), []
    app._post = lambda *item: posted.append(item)
    job = plc_gui.PLCScannerApp._collect_job(
        app,
        NetworkConfig(),
        "127.0.0.1",
        Protocol.SLMP,
        5001,
        "range",
        DeviceType.D,
        0,
        0,
        interval,
        None,
        ByteOrder.LITTLE_ENDIAN,
        CSVExporter(str(tmp_path), "utf-8-sig"),
    )
    return job, posted


def test_gui_periodic_monitoring_goes_on_after_a_cycle_that_raised(tmp_path, monkeypatch):
    calls = []

    async def read(self, collector, writer):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("unexpected")
        return CycleResult([_point("D0")], None, None)

    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector)
    monkeypatch.setattr(plc_gui.CycleRunner, "read", read)

    async def run():
        coro, posted = _gui_job(tmp_path, interval=1.0)
        job = asyncio.ensure_future(coro)
        for _ in range(500):
            if len(calls) >= 2 or job.done():
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        assert not job.done()  # ended with "エラーで終了しました" after the first cycle
        job.cancel()
        with pytest.raises(asyncio.CancelledError):
            await job
        return posted

    posted = asyncio.run(run())
    shown = [item for item in posted if item[0] == "data"]
    assert len(shown) == 1 and shown[0][-1] == 2  # the second cycle; the failed one shows nothing


def test_gui_single_scan_that_raised_is_still_an_error(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector)
    monkeypatch.setattr(plc_gui.CycleRunner, "read", read)
    coro, _ = _gui_job(tmp_path, interval=0.0)
    with pytest.raises(RuntimeError, match="unexpected"):
        asyncio.run(coro)


# ----------------------------------------------------------------------
# access_denied_log.csv after the encoding setting was changed
# ----------------------------------------------------------------------


def test_denied_log_continues_in_its_own_file_after_the_encoding_was_changed(tmp_path):
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"温度"}, "10.0.0.1")
    second = CSVExporter(str(tmp_path), "shift-jis").export_denied_addresses({"圧力"}, "10.0.0.1")

    first = tmp_path / "access_denied_log.csv"
    assert second != str(first)
    # Each file is readable in one encoding (was: CP932 rows inside the UTF-8 file)
    assert "温度" in first.read_text(encoding="utf-8") and "圧力" not in first.read_text(encoding="utf-8")
    text = (tmp_path / "access_denied_log_cp932.csv").read_text(encoding="cp932")
    assert text.splitlines()[0] == "address,status,last_attempt,plc_ip" and "圧力" in text

    # ... and later rows of either encoding go to the file of that encoding
    CSVExporter(str(tmp_path), "shift-jis").export_denied_addresses({"流量"}, "10.0.0.1")
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"D9"}, "10.0.0.1")
    assert "流量" in (tmp_path / "access_denied_log_cp932.csv").read_text(encoding="cp932")
    assert "D9" in first.read_text(encoding="utf-8")
    assert len(list(tmp_path.glob("access_denied_log*.csv"))) == 2


@pytest.mark.parametrize("encodings", [("utf-8", "shift-jis"), ("shift-jis", "utf-8"), ("utf-8-sig", "utf-8-sig")])
def test_denied_log_of_plain_addresses_stays_one_file(tmp_path, encodings):
    for encoding, address in zip(encodings, ("D100", "D200")):
        CSVExporter(str(tmp_path), encoding).export_denied_addresses({address}, "10.0.0.1")
    files = list(tmp_path.glob("access_denied_log*.csv"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 3 and lines[0].startswith("address,")


def test_denied_log_with_and_without_bom_is_not_mixed(tmp_path):
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"D100"}, "10.0.0.1")
    CSVExporter(str(tmp_path), "utf-8-sig").export_denied_addresses({"D200"}, "10.0.0.1")
    assert len(list(tmp_path.glob("access_denied_log*.csv"))) == 2


# ----------------------------------------------------------------------
# FINS: timeout or transport failure
# ----------------------------------------------------------------------


def _fins_tcp(readexactly):
    handler = FINSHandler("127.0.0.1", use_tcp=True, config=NetworkConfig(request_timeout_ms=100))
    handler._connected = True
    handler._reader = MagicMock()
    handler._reader.readexactly = readexactly
    handler._writer = MagicMock()
    handler._writer.drain = AsyncMock()
    return handler


def test_fins_tcp_connection_reset_is_a_communication_error():
    handler = _fins_tcp(AsyncMock(side_effect=ConnectionResetError("reset by peer")))
    data, status = asyncio.run(handler.read_device_raw(DeviceType.DM, 0, 1))
    assert (data, status) == (None, StatusCode.NG_COMM_ERROR)  # was NG_TIMEOUT
    assert handler._needs_reconnect


def test_fins_tcp_without_an_answer_is_a_timeout():
    async def never(_size):
        await asyncio.sleep(10)

    handler = _fins_tcp(never)
    data, status = asyncio.run(handler.read_device_raw(DeviceType.DM, 0, 1))
    assert (data, status) == (None, StatusCode.NG_TIMEOUT)


def test_fins_udp_timeout_and_send_failure_have_their_own_status(caplog):
    async def never():
        await asyncio.sleep(10)

    handler = FINSHandler("127.0.0.1", config=NetworkConfig(request_timeout_ms=100))
    handler._connected = True
    handler._transport = MagicMock()
    handler._protocol_instance = MagicMock()
    handler._protocol_instance.receive = never
    with caplog.at_level("ERROR"):
        assert asyncio.run(handler.read_device_raw(DeviceType.DM, 0, 1))[1] == StatusCode.NG_TIMEOUT
    assert caplog.records == []  # one ERROR line per unanswered request before

    handler._transport.sendto.side_effect = OSError("network is unreachable")
    assert asyncio.run(handler.read_device_raw(DeviceType.DM, 0, 1))[1] == StatusCode.NG_COMM_ERROR


# ----------------------------------------------------------------------
# CLI: an undetected target on the IP of a detected one
# ----------------------------------------------------------------------


def _run_scans(tmp_path, monkeypatch, detected, undetected):
    async def resolve(args, config_loader, config, display):
        return detected, undetected

    async def scan(plc_info, config, exporter, display, mode, ranges, data_type, byte_order, manager, db, label, inst):
        return plc_scanner.ScanOutcome(plc_info.ip_address, [_point("D0")], success=True, label=label)

    monkeypatch.setattr(plc_scanner, "_resolve_targets", resolve)
    monkeypatch.setattr(plc_scanner, "scan_target", scan)
    results = plc_scanner._RunResults()
    asyncio.run(
        plc_scanner._run_scans(
            SimpleNamespace(),
            None,
            ScanMode.FULL.value,
            0.0,
            NetworkConfig(),
            CSVExporter(str(tmp_path), "utf-8-sig"),
            MagicMock(),
            None,
            None,
            (None, ByteOrder.LITTLE_ENDIAN, None),
            [],
            results,
        )
    )
    return results


def test_undetected_target_keeps_its_rows_beside_a_detected_one_on_the_same_ip(tmp_path, monkeypatch):
    detected = [PLCInfo(ip_address="10.0.0.1", protocol=Protocol.SLMP, port=5001)]
    results = _run_scans(tmp_path, monkeypatch, detected, ["10.0.0.1", "10.0.0.1", "10.0.0.2"])
    assert list(results.data_points) == [
        "10.0.0.1 (protocol not detected)",
        "10.0.0.1 (protocol not detected) #2",
        "10.0.0.2",
        "10.0.0.1",
    ]
    # was: the detected target's data under the name of the failed one
    assert results.data_points["10.0.0.1"][0].status == StatusCode.OK
    assert results.data_points["10.0.0.1 (protocol not detected)"][0].status == StatusCode.NG_COMM_ERROR
    assert results.failed_targets == list(results.data_points)[:3]


# ----------------------------------------------------------------------
# ParallelPLCScanner with max_concurrent = 0
# ----------------------------------------------------------------------


def test_parallel_scan_finishes_with_max_concurrent_zero():
    async def run():
        plcs = [PLCInfo(ip_address="10.0.0.1"), PLCInfo(ip_address="10.0.0.2")]  # no protocol: fail at once
        return await asyncio.wait_for(scan_plcs_parallel(plcs, config=NetworkConfig(max_concurrent=0)), timeout=5)

    results = asyncio.run(run())  # waited for good before
    assert len(results) == 2 and not any(r.success for r in results.values())
