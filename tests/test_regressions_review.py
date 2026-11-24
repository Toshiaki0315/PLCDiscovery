"""
Regressions from the code review of the read path and notifications:
- SLMP end codes 4030H / 4031H (CPU-detected device errors) are address errors
- Modbus register maps are sparse: a readable island is never reported invalid
- a notification no destination received is offered again
- thresholds never compare the raw word of a converted value
"""

import asyncio
from collections import Counter
from unittest.mock import AsyncMock, MagicMock

from pymcprotocol.mcprotocolerror import MCProtocolError

from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from plc_discovery.conversion import apply_data_type_conversion
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.notifications import NotificationEvent, NotificationManager, NotificationType
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.scan_runner import CycleRunner
from plc_discovery.thresholds import Threshold, ThresholdMonitor, numeric_value

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


# ----------------------------------------------------------------------
# SLMP end codes
# ----------------------------------------------------------------------


def test_slmp_cpu_device_range_end_codes_are_address_errors():
    for code in (0x4030, 0x4031, 0xC056):
        status = SLMPHandler._classify_error(MCProtocolError(code), DeviceType.D, 12000)
        assert status == StatusCode.NG_ILLEGAL_ADDR, hex(code)
    # Not about the address: CPU busy / other errors stay communication errors
    assert SLMPHandler._classify_error(MCProtocolError(0x4001), DeviceType.D, 0) == StatusCode.NG_COMM_ERROR


# ----------------------------------------------------------------------
# Sparse address maps
# ----------------------------------------------------------------------


def _fake_handler(base, valid):
    class Fake(base):
        def __init__(self):
            BaseProtocolHandler.__init__(self, "127.0.0.1", 1, FAST)
            self._connected = True
            self.requests = 0

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start_address, count):
            self.requests += 1
            addresses = range(start_address, start_address + count)
            if all(a in valid for a in addresses):
                return list(addresses), StatusCode.OK
            return None, StatusCode.NG_ILLEGAL_ADDR

    return Fake()


def test_modbus_island_between_invalid_registers_is_read():
    handler = _fake_handler(ModbusHandler, set(range(40, 61)))
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99)))
    by_address = {p.address: p for p in points}
    assert len(points) == 100
    assert all(by_address[f"HR{a}"].status == StatusCode.OK for a in range(40, 61))
    assert Counter(p.status for p in points)[StatusCode.NG_ILLEGAL_ADDR] == 79
    assert handler.get_denied_addresses() == {f"HR{a}" for a in range(100) if not 40 <= a <= 60}


def test_contiguous_device_memory_keeps_the_whole_range_shortcut():
    class Contiguous(BaseProtocolHandler):
        protocol = Protocol.SLMP

    handler = _fake_handler(Contiguous, set())
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.R, 0, 899)))
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points)
    assert handler.requests == 3  # the chunk and its two end addresses


# ----------------------------------------------------------------------
# Undelivered notifications
# ----------------------------------------------------------------------


def _manager(send_ok):
    manager = NotificationManager()
    manager.min_interval_seconds = 3600
    manager.add_custom("test", lambda event: None)
    handler = manager._handlers["test"]
    handler.send = AsyncMock(side_effect=lambda event: send_ok[0])
    return manager, handler


def test_failed_send_does_not_throttle_the_next_one():
    send_ok = [False]
    manager, handler = _manager(send_ok)
    event = NotificationEvent(type=NotificationType.PLC_UNREACHABLE, title="t", message="m", throttle_key="PLC1")

    async def run():
        assert not NotificationManager.delivered(await manager.notify(event))
        assert not manager.is_suppressed(NotificationType.PLC_UNREACHABLE, "PLC1")
        send_ok[0] = True
        assert NotificationManager.delivered(await manager.notify(event))
        assert manager.is_suppressed(NotificationType.PLC_UNREACHABLE, "PLC1")

    asyncio.run(run())
    assert handler.send.await_count == 2


def test_outage_is_reported_once_the_webhook_works_again(monkeypatch):
    monkeypatch.setattr("plc_discovery.scan_runner.NOTIFY_RETRY_SECONDS", 0.0)
    notifier = MagicMock()
    results = [{"hook": False}, {"hook": False}, {"hook": True}]
    notifier.notify_unreachable = AsyncMock(side_effect=lambda *a, **k: results.pop(0))
    notifier.notify_recovered = AsyncMock(return_value={"hook": True})

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    async def run():
        runner = CycleRunner(None, notify=notify)
        for _ in range(5):  # down for five cycles; the webhook fails twice
            await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.track_outage("PLC1", True, "10.0.0.1")

    asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 3  # two failures, then delivered once
    assert notifier.notify_recovered.await_count == 1


def test_undelivered_outage_waits_before_it_is_retried():
    notifier = MagicMock()
    notifier.notify_unreachable = AsyncMock(return_value={"hook": False})

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    async def run():
        runner = CycleRunner(None, notify=notify)
        for _ in range(5):
            await runner.track_outage("PLC1", False, "10.0.0.1")

    asyncio.run(run())
    # Not once per cycle: a dead webhook must not slow down every read cycle
    assert notifier.notify_unreachable.await_count == 1


def test_undelivered_threshold_notifications_are_offered_again(monkeypatch):
    monkeypatch.setattr("plc_discovery.scan_runner.NOTIFY_RETRY_SECONDS", 0.0)
    notifier = MagicMock()
    exceeded = [{"hook": False}, {"hook": True}]
    cleared = [{"hook": False}, {"hook": True}]
    notifier.notify_threshold = AsyncMock(side_effect=lambda *a, **k: exceeded.pop(0))
    notifier.notify_threshold_cleared = AsyncMock(side_effect=lambda *a, **k: cleared.pop(0))

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    def point(value):
        return [DataPoint(address="D1", status=StatusCode.OK, value=value)]

    async def run():
        runner = CycleRunner(None, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))
        for value in (20, 20, 20, 5, 5, 5):
            await runner.check_thresholds("PLC1", point(value), "10.0.0.1")

    asyncio.run(run())
    assert notifier.notify_threshold.await_count == 2  # failed, then delivered; not sent a third time
    assert notifier.notify_threshold_cleared.await_count == 2


# ----------------------------------------------------------------------
# Thresholds on converted values
# ----------------------------------------------------------------------


def test_threshold_ignores_raw_word_of_incomplete_float():
    # D100-D101 hold a FLOAT; D101 timed out, D100's raw word is 0xC000 = 49152
    points = apply_data_type_conversion(
        [
            DataPoint(address="D100", status=StatusCode.OK, value=0xC000),
            DataPoint(address="D101", status=StatusCode.NG_TIMEOUT),
        ],
        DataType.FLOAT,
        ByteOrder.LITTLE_ENDIAN,
        None,
    )
    assert numeric_value(points[0]) is None
    monitor = ThresholdMonitor([Threshold("D100", ">", 80)])
    assert monitor.evaluate("PLC1", points).crossed == []


def test_threshold_ignores_nan_infinity_and_later_words():
    # 0x7FC0 0x1234 (NaN), +inf, and the second word of a complete FLOAT
    nan = DataPoint(address="D0", status=StatusCode.OK, value=0x1234, data_type="FLOAT", converted_value=float("nan"))
    inf = DataPoint(address="D2", status=StatusCode.OK, value=0, data_type="FLOAT", converted_value=float("inf"))
    part = DataPoint(address="D5", status=StatusCode.OK, value=0x42C8, data_type="FLOAT", display_value="(part of D4)")
    assert [numeric_value(p) for p in (nan, inf, part)] == [None, None, None]


def test_threshold_still_uses_raw_and_converted_values():
    raw = DataPoint(address="D1", status=StatusCode.OK, value=90)
    converted = DataPoint(address="D2", status=StatusCode.OK, value=0, data_type="FLOAT", converted_value=81.5)
    tag = DataPoint(address="Speed", status=StatusCode.OK, data_type="REAL", converted_value=12.5)
    assert [numeric_value(p) for p in (raw, converted, tag)] == [90.0, 81.5, 12.5]
