"""
Regressions from the third code review (high findings):
- the search for unanswered addresses is bounded, per scan and per session,
  and also works before anything was read
- a PLC that answers nothing is "not reachable" and its scan a failure,
  whatever the transport says
- threshold notifications reach the receiver in order
- Ctrl+C in a single scan saves what was read
- --protocol on a config target does not keep the file's port and options
- encodings and log levels that worked before are still accepted
"""

import asyncio
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import scan_runner
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
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.scan_runner import CycleRunner, no_answer_error, plc_answered
from plc_discovery.thresholds import Threshold, ThresholdMonitor

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


# ----------------------------------------------------------------------
# Bounded search for unanswered addresses
# ----------------------------------------------------------------------


class _Silent(BaseProtocolHandler):
    """Answers only requests inside ``valid``; everything else times out"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, valid):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.valid = set(valid)
        self.unanswered = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        addresses = range(start_address, start_address + count)
        if all(a in self.valid for a in addresses):
            return list(addresses), StatusCode.OK
        self.unanswered += 1
        return None, StatusCode.NG_TIMEOUT


def _scan(handler, first, last):
    before = handler.unanswered
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, first, last)))
    assert [p.address for p in points] == [f"HR{a}" for a in range(first, last + 1)]
    return Counter(p.status for p in points), handler.unanswered - before


def test_wide_unanswered_range_costs_a_bounded_number_of_timeouts():
    handler = _Silent(range(100))  # HR100-399 are dropped without an answer
    budget, retries = handler.UNANSWERED_SEARCH_BUDGET, 4
    per_scan = []
    for _ in range(12):
        statuses, unanswered = _scan(handler, 0, 399)
        assert statuses[StatusCode.OK] == 100  # the readable part is never lost
        per_scan.append(unanswered)
    # One scan: the search budget plus the plain reads of the three chunks
    assert max(per_scan) <= budget + 3 * retries + 4
    # The session budget ends the searching: afterwards one request per
    # unanswered chunk (the learned addresses split the range into a few
    # chunks), the same in every cycle - not the budget again and again
    assert per_scan[-1] == per_scan[-2] < budget
    # In total: the session budget for searching, plus per scan the plain
    # reads of the unanswered chunks and their liveness checks
    assert sum(per_scan) <= handler.UNANSWERED_SESSION_BUDGET + 12 * (3 * retries + 10)


def test_readable_addresses_are_found_before_anything_was_read():
    handler = _Silent(range(10))  # fresh handler, only HR0-9 answer
    statuses, _ = _scan(handler, 0, 99)
    assert statuses[StatusCode.OK] == 10
    for _ in range(3):  # and they stay readable in the following cycles
        assert _scan(handler, 0, 99)[0][StatusCode.OK] == 10


def test_two_unanswered_addresses_in_the_first_chunk_are_isolated():
    handler = _Silent(set(range(100)) - {30, 70})
    for _ in range(3):
        statuses, unanswered = _scan(handler, 0, 99)
    assert statuses[StatusCode.OK] == 98 and unanswered == 0
    assert handler.get_denied_statuses() == {"HR30": StatusCode.NG_TIMEOUT, "HR70": StatusCode.NG_TIMEOUT}


# ----------------------------------------------------------------------
# A PLC that answers nothing
# ----------------------------------------------------------------------


def _points(status, count=3):
    return [
        DataPoint(address=f"D{i}", status=status, value=1 if status == StatusCode.OK else None) for i in range(count)
    ]


def test_plc_answered_tells_no_answer_from_address_errors():
    assert plc_answered([]) and plc_answered(_points(StatusCode.OK))
    assert plc_answered(_points(StatusCode.NG_ILLEGAL_ADDR))  # the PLC said so itself
    assert plc_answered(_points(StatusCode.NG_TIMEOUT) + _points(StatusCode.OK, 1))
    silent = _points(StatusCode.NG_TIMEOUT, 2) + _points(StatusCode.NG_COMM_ERROR, 1)
    assert not plc_answered(silent)
    assert "none of the 3 addresses" in no_answer_error(silent) and "2 NG_TIMEOUT" in no_answer_error(silent)
    assert no_answer_error(_points(StatusCode.OK)) is None


class _FakeCollector:
    """Connected collector whose reads give ``status`` for every address"""

    status = StatusCode.NG_TIMEOUT

    def __init__(self, plc_info, config=None):
        self.is_connected = True
        self.connect_error = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    def clear_data(self):
        pass

    async def collect_range(self, device_type, start, end):
        return _points(self.status)

    def get_collected_data(self):
        return _points(self.status)

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 3, "success_count": 0, "error_count": 0}


def _single_scan(collector_class):
    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", collector_class):
            return await plc_scanner.run_single_scan(
                PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                FAST,
                MagicMock(hex_addresses=False),
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 2)],
            )

    return asyncio.run(run())


def test_scan_that_nothing_answered_is_a_failure():
    outcome = _single_scan(_FakeCollector)
    assert not outcome.success and "answered none" in outcome.error
    assert len(outcome.data_points) == 3  # still written as read


def test_scan_with_address_errors_only_is_not_a_failure():
    class Illegal(_FakeCollector):
        status = StatusCode.NG_ILLEGAL_ADDR

    outcome = _single_scan(Illegal)
    assert outcome.success and outcome.error is None


def test_connected_but_silent_plc_is_reported_unreachable_and_recovers():
    """FINS/UDP has no connection to lose: is_connected stays True"""
    statuses = [StatusCode.OK, StatusCode.NG_TIMEOUT, StatusCode.NG_TIMEOUT, StatusCode.OK, StatusCode.OK]

    class Collector(_FakeCollector):
        reads = 0

        async def collect_range(self, device_type, start, end):
            status = statuses[min(Collector.reads, len(statuses) - 1)]
            Collector.reads += 1
            return _points(status)

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600)],
                    NetworkConfig(),
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.DM, 0, 2)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(400):
                if notifier.notify_recovered.await_count:
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            return await task

    outcomes = asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1  # once for the outage
    assert notifier.notify_recovered.await_count == 1
    assert outcomes[0].success  # answering again when the monitoring ended


# ----------------------------------------------------------------------
# Order of threshold notifications
# ----------------------------------------------------------------------


def test_cleared_waits_for_the_exceeded_notification_still_being_sent(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.01)
    received = []
    release = asyncio.Event

    notifier = MagicMock()

    async def run():
        gate = release()

        async def slow_exceeded(*args, **kwargs):
            await gate.wait()  # the webhook is slow for "exceeded"
            received.append("exceeded")
            return {"hook": True}

        async def cleared(*args, **kwargs):
            received.append("cleared")
            return {"hook": True}

        notifier.notify_threshold = slow_exceeded
        notifier.notify_threshold_cleared = cleared

        async def notify(send):
            return scan_runner.NotificationManager.delivered(await send(notifier))

        runner = CycleRunner(None, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))

        def point(value):
            return [DataPoint(address="D1", status=StatusCode.OK, value=value)]

        await runner.check_thresholds("PLC1", point(90), "10.0.0.1")  # exceeded: send starts
        await runner.check_thresholds("PLC1", point(5), "10.0.0.1")  # back inside while it is in flight
        assert received == []  # "cleared" must not overtake it
        gate.set()
        await runner.drain()
        await runner.check_thresholds("PLC1", point(5), "10.0.0.1")
        await runner.drain()

    asyncio.run(run())
    assert received == ["exceeded", "cleared"]


# ----------------------------------------------------------------------
# Ctrl+C in a single scan
# ----------------------------------------------------------------------


def test_interrupted_range_keeps_the_chunks_already_read():
    class Slow(_Silent):
        async def read_device_raw(self, device_type, start_address, count):
            if start_address >= 200:
                await asyncio.sleep(60)  # the scan is interrupted here
            return await super().read_device_raw(device_type, start_address, count)

    async def run():
        collector = PLCDataCollector(PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1), FAST)
        collector._handler = Slow(range(1000))
        task = asyncio.ensure_future(collector.collect_range(DeviceType.HR, 0, 499))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return collector.get_collected_data()

    points = asyncio.run(run())
    assert [p.address for p in points] == [f"HR{a}" for a in range(200)]
    assert all(p.status == StatusCode.OK for p in points)


def test_interrupted_single_scan_writes_what_was_read():
    exporter = MagicMock(hex_addresses=False)
    exporter.export_plc_data.return_value = "/tmp/out.csv"

    class Interrupted(_FakeCollector):
        status = StatusCode.OK

        async def collect_range(self, device_type, start, end):
            await asyncio.sleep(60)

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Interrupted):
            task = asyncio.ensure_future(
                plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST,
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 2)],
                )
            )
            await asyncio.sleep(0.05)
            task.cancel()
            return await task  # handled: the outcome is returned, not CancelledError

    outcome = asyncio.run(run())
    assert outcome.interrupted and len(outcome.data_points) == 3
    written = exporter.export_plc_data.call_args.args[0]
    assert [p.address for p in written] == ["D0", "D1", "D2"]


# ----------------------------------------------------------------------
# Configuration regressions
# ----------------------------------------------------------------------


def _resolve(protocol, port, target):
    seen = {}

    async def resolve_target(ip, protocol, port, config, display, base=None):
        seen.update(protocol=protocol, port=port, options=dict(base.options))
        return base

    loader = MagicMock()
    loader.get_targets.return_value = [target]
    args = MagicMock(target=None, protocol=protocol, port=port)
    with patch.object(plc_scanner, "resolve_target", resolve_target):
        asyncio.run(plc_scanner._resolve_targets(args, loader, FAST, MagicMock()))
    return seen


def test_protocol_override_does_not_keep_the_port_and_options_of_the_file():
    def target():
        return PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, options={"frame": "3E"})

    # Another protocol: its own default port (None here), no SLMP options
    assert _resolve("modbus", None, target()) == {"protocol": Protocol.MODBUS_TCP, "port": None, "options": {}}
    assert _resolve("modbus", 1502, target())["port"] == 1502
    # Same protocol, or no --protocol: the file's port and options stay
    assert _resolve("slmp", None, target()) == {"protocol": Protocol.SLMP, "port": 5001, "options": {"frame": "3E"}}
    assert _resolve(None, None, target())["port"] == 5001


@pytest.mark.parametrize("encoding", ["cp932", "sjis", "shift_jis", "utf8", "UTF8", "utf-8-sig", "utf-8-bom", "euc-jp"])
def test_encodings_the_csv_writer_can_use_are_accepted(encoding):
    loader = ConfigLoader()
    loader.config["output"]["encoding"] = encoding
    assert loader.validate() == []


@pytest.mark.parametrize("level", ["WARN", "warning", "CRITICAL", "debug"])
def test_log_levels_known_to_logging_are_accepted(level):
    loader = ConfigLoader()
    loader.config["logging"]["level"] = level
    assert loader.validate() == []


def test_unknown_encoding_and_log_level_are_still_errors():
    loader = ConfigLoader()
    loader.config["output"]["encoding"] = "no-such-encoding"
    loader.config["logging"]["level"] = "LOUD"
    errors = "\n".join(loader.validate())
    assert "output.encoding" in errors and "logging.level" in errors


# ----------------------------------------------------------------------
# Modbus reconnects after a lost connection
# ----------------------------------------------------------------------


def test_modbus_reconnects_after_a_transport_error():
    handler = ModbusHandler("127.0.0.1", port=1, config=FAST)
    handler._connected = True
    handler._client = MagicMock()
    handler._client.read_holding_registers.side_effect = ConnectionResetError("closed by the PLC")
    data, status = asyncio.run(handler.read_device_raw(DeviceType.HR, 0, 10))
    assert (data, status) == (None, StatusCode.NG_COMM_ERROR)
    assert handler._needs_reconnect  # re-established before the next request
