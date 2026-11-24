"""
Regressions from the fourth code review (high finding):
- an address the session learned as inaccessible is reported without a
  request, so it is no sign that the PLC answers: a PLC that stops answering
  is reported unreachable although such an address is in the scanned range
"""

import asyncio
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import plc_scanner
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.scan_runner import no_answer_error, plc_answered

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


def _points(status, count, cached=False, first=0):
    return [DataPoint(address=f"D{first + i}", status=status, cached=cached) for i in range(count)]


def test_learned_addresses_are_no_sign_of_an_answer():
    learned = _points(StatusCode.NG_ILLEGAL_ADDR, 2, cached=True, first=100)
    silent = _points(StatusCode.NG_TIMEOUT, 3) + _points(StatusCode.NG_COMM_ERROR, 1, first=3)
    assert not plc_answered(silent + learned)
    assert no_answer_error(silent + learned) == (
        "the PLC answered none of the 4 addresses read (3 NG_TIMEOUT, 1 NG_COMM_ERROR)"
    )
    # An address error the PLC answered in this read is an answer
    assert plc_answered(silent + _points(StatusCode.NG_ILLEGAL_ADDR, 1, first=50))
    assert plc_answered(silent + learned + _points(StatusCode.OK, 1, first=60))
    # Nothing was requested: nothing is known, as for an empty read
    assert plc_answered(learned) and no_answer_error(learned) is None
    # A learned timeout is not a request of this read either
    assert plc_answered(_points(StatusCode.NG_TIMEOUT, 1, cached=True) + _points(StatusCode.OK, 2, first=10))
    assert plc_answered(_points(StatusCode.NG_TIMEOUT, 1, cached=True) + learned)


def test_unsupported_is_no_sign_of_an_answer():
    # Mostly decided without a request: a device type the protocol lacks,
    # tags on a PLC that has none
    unsupported = _points(StatusCode.NG_UNSUPPORTED, 2, first=200)
    assert plc_answered(unsupported)
    assert not plc_answered(_points(StatusCode.NG_TIMEOUT, 3) + unsupported)


class _Udp(BaseProtocolHandler):
    """No connection to lose: stays "connected" when the PLC is switched off"""

    protocol = Protocol.FINS

    def __init__(self):
        super().__init__("127.0.0.1", 9600, FAST)
        self._connected = True
        self.power = True
        self.requests = 0

    async def connect(self):
        self._connected = True
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        if not self.power:
            return None, StatusCode.NG_TIMEOUT
        if start_address <= 5 < start_address + count:  # DM5 does not exist
            return None, StatusCode.NG_ILLEGAL_ADDR
        return list(range(start_address, start_address + count)), StatusCode.OK


def test_switched_off_plc_is_not_answering_although_an_address_was_learned():
    async def run():
        handler = _Udp()
        device_range = DeviceRange(DeviceType.DM, 0, 9)
        first = await handler.read_device_range(device_range)
        handler.power = False
        return first, [await handler.read_device_range(device_range) for _ in range(3)], handler

    first, later, handler = asyncio.run(run())
    assert Counter(p.status for p in first) == {StatusCode.OK: 9, StatusCode.NG_ILLEGAL_ADDR: 1}
    assert plc_answered(first) and not any(p.cached for p in first)  # DM5: the PLC said so itself
    assert handler.is_connected
    for points in later:
        by_address = {p.address: p for p in points}
        assert len(points) == 10
        assert (by_address["DM5"].status, by_address["DM5"].cached) == (StatusCode.NG_ILLEGAL_ADDR, True)
        assert not plc_answered(points)


def test_periodic_scan_reports_the_outage_with_a_learned_address_in_the_range():
    learned = DataPoint(address="DM5", status=StatusCode.NG_ILLEGAL_ADDR, cached=True)

    def cycle(status):
        value = 1 if status == StatusCode.OK else None
        return [DataPoint(address=f"DM{i}", status=status, value=value) for i in range(5)] + [learned]

    cycles = [cycle(StatusCode.OK), cycle(StatusCode.NG_TIMEOUT), cycle(StatusCode.NG_TIMEOUT), cycle(StatusCode.OK)]

    class Collector:
        reads = 0
        is_connected = True  # FINS/UDP: nothing to lose
        connect_error = None

        def __init__(self, plc_info, config=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def disconnect(self):
            pass

        def clear_data(self):
            pass

        def get_collected_data(self):
            return []

        async def collect_range(self, device_type, start, end):
            points = cycles[min(Collector.reads, len(cycles) - 1)]
            Collector.reads += 1
            return points

        def get_denied_addresses(self):
            return {"DM5"}

        def get_denied_statuses(self):
            return {"DM5": StatusCode.NG_ILLEGAL_ADDR}

        def get_statistics(self):
            return {"total_points": 6, "success_count": 5, "error_count": 0}

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600)],
                    FAST,
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.DM, 0, 5)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(400):
                if notifier.notify_recovered.await_count or task.done():
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            return await asyncio.wait_for(task, timeout=10)

    outcomes = asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1
    assert notifier.notify_recovered.await_count == 1
    assert outcomes[0].success
