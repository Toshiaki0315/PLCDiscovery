"""
Regression tests for the tenth review's findings.

A1: several targets sharing one IP are each scanned and reported.
A2: a collector whose reconnect failed recovers once the PLC is back,
    and reports NG_COMM_ERROR (not nothing) while it is unreachable.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import parallel
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
from plc_discovery.discovery import target_labels
from plc_discovery.protocols.base import BaseProtocolHandler

# ---------------------------------------------------------------------------
# A1: targets sharing an IP
# ---------------------------------------------------------------------------

SLMP = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001)
MODBUS = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502)
OTHER = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)


def test_target_labels():
    assert target_labels([SLMP, OTHER]) == ["127.0.0.1", "10.0.0.2"]
    assert target_labels([SLMP, MODBUS, OTHER]) == [
        "127.0.0.1 (SLMP:5001)",
        "127.0.0.1 (MODBUS_TCP:1502)",
        "10.0.0.2",
    ]
    # same IP, protocol and port (gateway with two unit IDs)
    unit2 = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502, options={"unit_id": 2})
    assert target_labels([MODBUS, unit2]) == [
        "127.0.0.1 (MODBUS_TCP:1502)",
        "127.0.0.1 (MODBUS_TCP:1502) #2",
    ]


read_by: list = []


class FakeCollector:
    is_connected = True
    connect_error = None

    def __init__(self, plc, config=None):
        self.plc = plc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *a):
        read_by.append(self.plc.protocol)
        return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.asyncio
async def test_periodic_scan_reads_every_target_sharing_an_ip():
    read_by.clear()
    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", FakeCollector):
        task = asyncio.ensure_future(
            plc_scanner.run_periodic_scan(
                [SLMP, MODBUS],
                NetworkConfig(),
                exporter,
                Display(),
                [DeviceRange(DeviceType.D, 0, 0)],
                interval=0.01,
            )
        )
        while len(read_by) < 4:
            await asyncio.sleep(0.005)
        task.cancel()
        outcomes = await task
    assert set(read_by) == {Protocol.SLMP, Protocol.MODBUS_TCP}  # previously MODBUS_TCP only
    assert [o.label for o in outcomes] == ["127.0.0.1 (SLMP:5001)", "127.0.0.1 (MODBUS_TCP:1502)"]
    assert all(o.ip_address == "127.0.0.1" and o.success for o in outcomes)
    # data files are still named by IP
    assert {c.args[1] for c in exporter.export_plc_data.call_args_list} == {"127.0.0.1"}


@pytest.mark.asyncio
async def test_parallel_scan_keeps_every_target_sharing_an_ip():
    read_by.clear()
    exporter = MagicMock()
    with patch.object(parallel, "PLCDataCollector", FakeCollector):
        results = await plc_scanner.run_parallel_scan(
            [SLMP, MODBUS, OTHER],
            NetworkConfig(max_concurrent=3),
            exporter,
            Display(),
            ScanMode.RANGE,
            [DeviceRange(DeviceType.D, 0, 0)],
        )
    assert set(results) == {"127.0.0.1 (SLMP:5001)", "127.0.0.1 (MODBUS_TCP:1502)", "10.0.0.2"}
    assert exporter.export_plc_data.call_count == 3  # previously one result (and its CSV) was lost


@pytest.mark.asyncio
async def test_parallel_scan_unique_ips_still_keyed_by_ip():
    with patch.object(parallel, "PLCDataCollector", FakeCollector):
        results = await parallel.ParallelPLCScanner(NetworkConfig(max_concurrent=2)).scan_multiple_plcs(
            [SLMP, OTHER], ScanMode.RANGE, [DeviceRange(DeviceType.D, 0, 0)]
        )
    assert set(results) == {"127.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# A2: recovery after a failed reconnect
# ---------------------------------------------------------------------------


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


@pytest.mark.asyncio
async def test_collect_range_recovers_after_failed_reconnect():
    handler = FlakyHandler()
    collector = await collector_with(handler)
    drop_link(handler)
    handler._comm_failure_streak = 10
    handler._circuit_breaker._state = handler._circuit_breaker._state.OPEN

    down = await collector.collect_range(DeviceType.D, 0, 2)
    assert [p.status for p in down] == [StatusCode.NG_COMM_ERROR] * 3  # previously []
    assert collector.get_denied_addresses() == set()  # not learned as inaccessible

    handler.plc_up = True
    up = await collector.collect_range(DeviceType.D, 0, 2)
    assert [(p.value, p.status) for p in up] == [(0, StatusCode.OK), (1, StatusCode.OK), (2, StatusCode.OK)]
    assert handler.circuit_breaker_state == "closed" and handler._comm_failure_streak == 0


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


@pytest.mark.asyncio
async def test_connected_handler_is_not_reconnected():
    handler = FlakyHandler()
    collector = await collector_with(handler)
    await collector.collect_range(DeviceType.D, 0, 0)
    await collector.collect_range(DeviceType.D, 0, 0)
    assert handler.connect_calls == 1
