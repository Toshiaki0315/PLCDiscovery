"""
Regression tests for data collection, retries and binary search, found and fixed in code reviews.
"""

import inspect
import socket
import struct
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery.collector import PROTOCOL_HANDLERS, PLCDataCollector
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.retry import RetryConfig, RetryStrategy


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


async def _scan(end, valid):
    """Read D0-end from a fake PLC where valid(address) tells readability"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    requests = []

    async def fake_read(device_type, start, count):
        requests.append((start, count))
        if all(valid(a) for a in range(start, start + count)):
            return [a & 0xFFFF for a in range(start, start + count)], StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, end))
    return handler, points, requests


def _misreported(points, valid):
    return [p.address for i, p in enumerate(points) if (p.status == StatusCode.OK) != valid(i)]


# Public coroutines a handler may offer: every PLC read goes through
# read_device_range / read_device_raw (rate limiting, address limits,
# reconnect after a timeout, binary search)
ALLOWED_PUBLIC_COROUTINES = {
    "connect",
    "disconnect",
    # disconnect + connect after a lost link, no data read
    "reconnect",
    "read_device_raw",
    "read_device_range",
    # EtherNet/IP symbolic tags: packet interval, timeout with
    # reconnect, per-tag errors (see EtherNetIPHandler.read_tags)
    "read_tags",
    # FINS CPU model for discovery: one read-only request
    # (Controller Data Read) after the packet interval, no data
    "read_controller_data",
}


def slmp_response(words):
    body = b"\x00\x00" + b"".join(struct.pack("<H", w & 0xFFFF) for w in words)
    return b"\xd0\x00\x00\xff\xff\x03\x00" + struct.pack("<H", len(body)) + body


class FakeSLMP:
    """Word reads return value = base + address. mode: normal|split|slow_first|close_after_first"""

    def __init__(self, mode="normal", base=0):
        self.mode, self.base = mode, base
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen()
        self.srv.settimeout(0.1)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.requests = 0
        self.connections = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                continue
            self.connections += 1
            with conn:
                conn.settimeout(0.1)
                while not self.stop.is_set():
                    try:
                        req = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not req:
                        break
                    self.requests += 1
                    head = struct.unpack("<I", req[15:18] + b"\x00")[0]
                    count = struct.unpack("<H", req[19:21])[0]
                    resp = slmp_response([self.base + head + i for i in range(count)])
                    if self.mode == "split":
                        conn.sendall(resp[:100])
                        time.sleep(0.05)
                        conn.sendall(resp[100:])
                    elif self.mode == "slow_first" and self.requests == 1:
                        time.sleep(1.5)
                        try:
                            conn.sendall(resp)
                        except OSError:
                            pass
                    elif self.mode == "close_after_first" and self.requests == 1:
                        conn.sendall(resp)
                        self.mode = "normal"
                        break  # drop the connection after the first reply
                    else:
                        conn.sendall(resp)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.thread.join(2)
        self.srv.close()


async def connected_handler(server, timeout_ms=1000):
    handler = SLMPHandler("127.0.0.1", server.port, config=NetworkConfig(request_timeout_ms=timeout_ms))
    assert await handler.connect()
    return handler


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
async def test_connected_handler_is_not_reconnected():
    handler = FlakyHandler()
    collector = await collector_with(handler)
    await collector.collect_range(DeviceType.D, 0, 0)
    await collector.collect_range(DeviceType.D, 0, 0)
    assert handler.connect_calls == 1


@pytest.mark.asyncio
async def test_wholly_invalid_device_costs_few_requests():
    handler, points, requests = await _scan(32767, lambda a: False)
    assert len(points) == 32768
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points)
    # 37 chunks x (chunk read + 2 edge probes); was ~65,000 requests
    assert len(requests) <= 3 * 37
    assert len(handler.get_denied_addresses()) == 32768


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "end,valid,max_requests",
    [
        (8191, lambda a: a <= 7999, 60),  # past device end
        (9999, lambda a: not (5000 <= a <= 5100 or 7000 <= a <= 7050), 160),  # gaps
        (9999, lambda a: a != 4321, 60),  # one bad word
    ],
)
async def test_mixed_ranges_still_exact(end, valid, max_requests):
    _, points, requests = await _scan(end, valid)
    assert _misreported(points, valid) == []
    assert len(requests) <= max_requests


@pytest.mark.parametrize(
    "handler_class", sorted({getattr(h, "func", h) for h in PROTOCOL_HANDLERS.values()}, key=lambda c: c.__name__)
)
def test_handlers_have_no_side_door_reads(handler_class):
    public = {
        name
        for name, member in inspect.getmembers(handler_class, inspect.iscoroutinefunction)
        if not name.startswith("_")
    }
    assert public <= ALLOWED_PUBLIC_COROUTINES, public - ALLOWED_PUBLIC_COROUTINES
    assert issubclass(handler_class, BaseProtocolHandler)


@pytest.mark.asyncio
async def test_cpu_answer_does_not_reconnect():
    handler = S7Handler("10.0.0.1", config=NetworkConfig())
    handler._connected = True
    client = MagicMock()
    client.db_read.side_effect = Exception("Read operation failed: Object does not exist (0x0a)")
    handler._client = client
    data, status = await handler.read_device_raw(DeviceType.DB, 100, 10)
    assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_transport_error_still_reconnects():
    handler = S7Handler("10.0.0.1", config=NetworkConfig())
    handler._connected = True
    client = MagicMock()
    client.db_read.side_effect = Exception("TCP : Connection reset")
    handler._client = client
    _, status = await handler.read_device_raw(DeviceType.DB, 0, 1)
    assert status == StatusCode.NG_COMM_ERROR
    assert handler._needs_reconnect is True


@pytest.mark.asyncio
async def test_r1_denied_address_mid_chunk_skipped_next_scan():
    calls = []

    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start, count):
            calls.append((start, count))
            if start <= 10 <= start + count - 1:
                return None, StatusCode.NG_ILLEGAL_ADDR
            return [start] * count, StatusCode.OK

    handler = Handler(
        "127.0.0.1",
        5001,
        NetworkConfig(packet_interval_ms=0, retry_interval_ms=0),
        retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=0, initial_delay_ms=0),
        use_circuit_breaker=False,
    )
    handler._connected = True
    rng = DeviceRange(DeviceType.D, 0, 899)

    first = await handler.read_device_range(rng)
    calls.clear()
    second = await handler.read_device_range(rng)

    assert calls == [(0, 10), (11, 889)]  # no failed read, no binary search
    assert [dp.address for dp in second] == [dp.address for dp in first]
    assert [dp.status for dp in second] == [dp.status for dp in first]
    assert second[10].status == StatusCode.NG_ILLEGAL_ADDR


def test_statistics_count_unsupported():
    collector = PLCDataCollector(PLCInfo("127.0.0.1", protocol=Protocol.SLMP))
    collector._collected_data = [
        DataPoint("D0", 1, status=StatusCode.OK),
        DataPoint("SM0", status=StatusCode.NG_UNSUPPORTED),
    ]
    stats = collector.get_statistics()
    assert stats["unsupported_count"] == 1
    assert stats["success_count"] + stats["unsupported_count"] == stats["total_points"]


@pytest.mark.asyncio
async def test_u1_split_response_read_completely():
    with FakeSLMP("split") as server:
        handler = await connected_handler(server)
        try:
            data, status = await handler.read_device_raw(DeviceType.D, 0, 900)
            assert status == StatusCode.OK
            assert data == list(range(900))
            # the stream stays in sync for the next request
            assert await handler.read_device_raw(DeviceType.D, 5, 2) == ([5, 6], StatusCode.OK)
        finally:
            await handler.disconnect()


@pytest.mark.asyncio
async def test_u2_plc_error_does_not_reconnect():
    """An end code from the PLC keeps the connection"""
    handler = SLMPHandler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()

    class MCProtocolError(Exception):
        errorcode = "0xC056"

    client.batchread_wordunits.side_effect = MCProtocolError("mc protocol error: error code 0xC056")
    handler._client, handler._connected = client, True
    assert await handler.read_device_raw(DeviceType.D, 99999, 1) == (None, StatusCode.NG_ILLEGAL_ADDR)
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "make_handler, method, device",
    [
        (lambda: S7Handler("127.0.0.1", config=NetworkConfig()), "db_read", DeviceType.DB),
    ],
)
async def test_u2_s7_transport_error_triggers_reconnect(make_handler, method, device):
    handler = make_handler()
    client = MagicMock()
    getattr(client, method).side_effect = RuntimeError(
        "ISO : An error occurred during recv TCP : Connection reset by peer"
    )
    handler._client, handler._connected = client, True
    assert (await handler.read_device_raw(device, 0, 2))[1] == StatusCode.NG_COMM_ERROR
    assert handler._needs_reconnect


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plc_type, expected",
    [
        ("slc", "_connect_slc"),
        ("generic", "_connect_generic"),
        (None, "_connect_logix_first"),
        ("logix", "_connect_logix_first"),
    ],
)
async def test_reconnect_uses_detected_driver(plc_type, expected):
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    handler._plc_type = plc_type
    mocks = {
        name: AsyncMock(return_value=True) for name in ("_connect_slc", "_connect_generic", "_connect_logix_first")
    }
    with patch.multiple(handler, **mocks):
        assert await handler.connect()
    assert mocks[expected].await_count == 1
    assert sum(m.await_count for m in mocks.values()) == 1
