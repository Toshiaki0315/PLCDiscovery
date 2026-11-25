"""
Regression tests for data collection, retries and binary search, found and fixed in code reviews.
"""

import asyncio
import inspect
import socket
import struct
import threading
import time
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pycomm3
import pytest

from plc_discovery import retry
from plc_discovery.collector import PROTOCOL_HANDLERS, PLCDataCollector
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.parallel import scan_plcs_parallel
from plc_discovery.protocols import cip_symbolic
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.retry import CircuitBreaker, RetryConfig, RetryStrategy
from plc_discovery.scan_runner import collect_items


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


FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


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


def test_contiguous_device_memory_keeps_the_whole_range_shortcut():
    class Contiguous(BaseProtocolHandler):
        protocol = Protocol.SLMP

    handler = _fake_handler(Contiguous, set())
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.R, 0, 899)))
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points)
    assert handler.requests == 3  # the chunk and its two end addresses


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


def _scan_2(handler, first, last):
    before = handler.unanswered
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, first, last)))
    assert [p.address for p in points] == [f"HR{a}" for a in range(first, last + 1)]
    return Counter(p.status for p in points), handler.unanswered - before


def test_wide_unanswered_range_costs_a_bounded_number_of_timeouts():
    handler = _Silent(range(100))  # HR100-399 are dropped without an answer
    budget, retries = handler.UNANSWERED_SEARCH_BUDGET, 4
    per_scan = []
    for _ in range(12):
        statuses, unanswered = _scan_2(handler, 0, 399)
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


def _scan_3(handler, first, last):
    before = handler.unanswered
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, first, last)))
    assert [p.address for p in points] == [f"HR{a}" for a in range(first, last + 1)]
    return Counter(p.status for p in points), handler.unanswered - before


def test_readable_addresses_are_found_before_anything_was_read():
    handler = _Silent(range(10))  # fresh handler, only HR0-9 answer
    statuses, _ = _scan_3(handler, 0, 99)
    assert statuses[StatusCode.OK] == 10
    for _ in range(3):  # and they stay readable in the following cycles
        assert _scan_3(handler, 0, 99)[0][StatusCode.OK] == 10


def _scan_4(handler, first, last):
    before = handler.unanswered
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, first, last)))
    assert [p.address for p in points] == [f"HR{a}" for a in range(first, last + 1)]
    return Counter(p.status for p in points), handler.unanswered - before


def test_two_unanswered_addresses_in_the_first_chunk_are_isolated():
    handler = _Silent(set(range(100)) - {30, 70})
    for _ in range(3):
        statuses, unanswered = _scan_4(handler, 0, 99)
    assert statuses[StatusCode.OK] == 98 and unanswered == 0
    assert handler.get_denied_statuses() == {"HR30": StatusCode.NG_TIMEOUT, "HR70": StatusCode.NG_TIMEOUT}


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


def test_plc_that_is_off_costs_one_reconnect_per_scan():
    class Off(BaseProtocolHandler):
        protocol = Protocol.SLMP
        attempts = 0

        async def connect(self):
            Off.attempts += 1
            return False

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start_address, count):
            raise AssertionError("nothing is read from a PLC that is off")

    async def run():
        collector = PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), FAST)
        collector._handler = Off("10.0.0.1", 5001, FAST)
        ranges = [DeviceRange(DeviceType.D, start, start + 9) for start in (0, 100, 200, 300)]
        first = await collect_items(collector, ranges)
        after_first = Off.attempts
        await collect_items(collector, ranges)
        return first, after_first, Off.attempts

    points, after_first, after_second = asyncio.run(run())
    assert len(points) == 40 and all(p.status == StatusCode.NG_COMM_ERROR for p in points)
    assert after_first == 1  # not one connection timeout per range
    assert after_second == 2  # the next scan tries again


FAST_2 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.SLMP

    def __init__(self, answer, config=FAST_2):
        super().__init__("10.0.0.1", 5001, config)
        self._connected = True
        self.answer = answer
        self.requests: list = []

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests.append((start_address, count))
        status = self.answer(start_address, count)
        return ([7] * count if status == StatusCode.OK else None), status


def test_dead_link_is_found_without_probing_twice_or_trying_the_next_chunk():
    alive = [True]

    async def run():
        handler = _Device(lambda start, count: StatusCode.OK if alive[0] else StatusCode.NG_TIMEOUT)
        await handler.read_device_range(DeviceRange(DeviceType.D, 0, 899))
        alive[0] = False
        handler.requests.clear()
        return handler, await handler.read_device_range(DeviceRange(DeviceType.D, 0, 2699))

    handler, points = asyncio.run(run())
    assert len(points) == 2700 and not any(p.status == StatusCode.OK for p in points)
    # The chunk and its retries (4), its halves (2), the known-good address (1);
    # was 9: that address a second time, and a request for the next chunk
    assert handler.requests == [(0, 900)] * 4 + [(0, 450), (450, 450), (0, 1)]
    assert handler.get_denied_addresses() == set()  # nothing is learned from a dead link


FAST_3 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


def test_retries_wait_for_the_packet_interval():
    outcomes = [StatusCode.NG_TIMEOUT, StatusCode.NG_TIMEOUT, StatusCode.OK]

    async def run():
        handler = _Device(lambda start, count: outcomes.pop(0))
        handler._rate_limiter.wait = AsyncMock()
        points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 9))
        return points, handler._rate_limiter.wait.await_count

    points, waits = asyncio.run(run())
    assert all(p.status == StatusCode.OK for p in points)
    assert waits == 3  # the chunk and each of its two retries (was 1: retries went out unpaced)


def test_circuit_breaker_does_not_depend_on_the_wall_clock(monkeypatch):
    breaker = CircuitBreaker()
    for _ in range(breaker.config.failure_threshold):
        breaker.record_failure()
    assert not breaker.is_available()
    # The clock is set back by an hour (NTP) while the circuit is open
    monkeypatch.setattr(retry.time, "time", lambda: 0.0)
    monotonic = time.monotonic()
    monkeypatch.setattr(retry.time, "monotonic", lambda: monotonic + breaker.config.timeout_seconds + 1)
    assert breaker.is_available()


def test_fragments_of_a_generic_array_read_wait_for_the_packet_interval(monkeypatch):
    replies = [
        (cip_symbolic.STATUS_PARTIAL, b"\xc3\x00" + struct.pack("<h", 1), None),
        (cip_symbolic.STATUS_PARTIAL, b"\xc3\x00" + struct.pack("<h", 2), None),
        (cip_symbolic.STATUS_OK, b"\xc3\x00" + struct.pack("<h", 3), None),
    ]
    sleeps = []
    monkeypatch.setattr(cip_symbolic, "_send", lambda client, service, path, data: replies.pop(0))
    monkeypatch.setattr(cip_symbolic.time, "sleep", sleeps.append)
    value, type_name = cip_symbolic.read_symbolic(object(), "Values[0]{3}", 0.05)
    assert (value, type_name) == ([1, 2, 3], "INT")
    assert sleeps == [0.05, 0.05]  # before the second and the third request


FAST_4 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device_2(BaseProtocolHandler):
    """Stays "connected"; ``answer(device_type, start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST_4)
        self._connected = True
        self.answer = answer
        self.requests: list = []

    async def connect(self):
        self._connected = True
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests.append((device_type, start_address, count))
        status = self.answer(device_type, start_address, count)
        if status == StatusCode.OK:
            return [7] * count, status
        return None, status


def test_answered_half_is_split_although_the_other_half_was_not_answered():
    # D0-49: requests are dropped. D50-99: D50-74 exist, the rest is refused.
    def answer(device_type, start, count):
        addresses = range(start, start + count)
        if any(a < 50 for a in addresses):
            return StatusCode.NG_TIMEOUT
        return StatusCode.OK if all(a < 75 for a in addresses) else StatusCode.NG_ILLEGAL_ADDR

    async def run():
        handler = _Device_2(answer)
        return await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))

    by_address = {p.address: p.status for p in asyncio.run(run())}
    assert len(by_address) == 100
    # Was reported NG_ILLEGAL_ADDR for all of HR50-99, without a request
    assert all(by_address[f"HR{a}"] == StatusCode.OK for a in range(50, 75))
    assert all(by_address[f"HR{a}"] == StatusCode.NG_ILLEGAL_ADDR for a in range(75, 100))
    assert all(by_address[f"HR{a}"] in (StatusCode.NG_TIMEOUT, StatusCode.NG_COMM_ERROR) for a in range(50))


FAST_5 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device_3(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP  # 100 registers per chunk
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST_5)
        self._connected = True
        self.answer = answer
        self.log: list = []

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        status = self.answer(start_address, count)
        self.log.append((start_address, count, status))
        return ([7] * count if status == StatusCode.OK else None), status

    def unanswered(self):
        return sum(1 for _, _, status in self.log if status == StatusCode.NG_TIMEOUT)


def _drops_above_99(start, count):
    """HR0-99 exist; a request touching anything above is dropped without an answer"""
    return StatusCode.OK if start + count <= 100 else StatusCode.NG_TIMEOUT


def test_wide_unanswered_range_costs_one_request_per_chunk_and_scan():
    async def run():
        handler = _Device_3(_drops_above_99)
        per_scan = []
        for _ in range(12):
            handler.log.clear()
            points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 1999))
            assert len(points) == 2000
            assert [p.status for p in points[:100]] == [StatusCode.OK] * 100
            assert not any(p.status == StatusCode.OK for p in points[100:])
            per_scan.append(handler.unanswered())
        return handler, per_scan

    handler, per_scan = asyncio.run(run())
    assert handler._unanswered_session_budget == 0
    # 19 chunks above HR99. While the budget lasts: the first chunk's retries,
    # the search, and one request for each chunk after it (was 84-107)
    assert max(per_scan) <= 4 + handler.UNANSWERED_SEARCH_BUDGET + 19
    # Budget spent: one request per chunk, in every cycle (was 95)
    assert per_scan[-3:] == [19, 19, 19]
    # A few addresses were confirmed; nothing the PLC answers was learned
    assert all(int(address[2:]) >= 100 for address in handler.get_denied_addresses())


FAST_6 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device_4(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP  # 100 registers per chunk
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST_6)
        self._connected = True
        self.answer = answer
        self.log: list = []

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        status = self.answer(start_address, count)
        self.log.append((start_address, count, status))
        return ([7] * count if status == StatusCode.OK else None), status

    def unanswered(self):
        return sum(1 for _, _, status in self.log if status == StatusCode.NG_TIMEOUT)


def test_chunks_after_an_unanswered_one_are_not_retried():
    async def run():
        handler = _Device_4(_drops_above_99)
        await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 999))
        return handler.log

    log = asyncio.run(run())
    whole_chunks = [start for start, count, _ in log if count == 100 and start >= 100]
    # HR100-199 with its retries; each chunk after it once (was four times each)
    assert whole_chunks.count(100) == 4
    assert all(whole_chunks.count(start) == 1 for start in range(200, 1000, 100))


FAST_7 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device_5(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP  # 100 registers per chunk
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST_7)
        self._connected = True
        self.answer = answer
        self.log: list = []

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        status = self.answer(start_address, count)
        self.log.append((start_address, count, status))
        return ([7] * count if status == StatusCode.OK else None), status

    def unanswered(self):
        return sum(1 for _, _, status in self.log if status == StatusCode.NG_TIMEOUT)


def test_link_lost_while_a_range_is_split_stops_the_requests():
    state = {"requests": 0, "dead_after": None}

    def answer(start, count):
        state["requests"] += 1
        if state["dead_after"] is not None and state["requests"] > state["dead_after"]:
            return StatusCode.NG_TIMEOUT
        # HR0-69 exist, the rest of the chunk is refused
        return StatusCode.OK if start + count <= 70 else StatusCode.NG_ILLEGAL_ADDR

    async def run(dead_after):
        state.update(requests=0, dead_after=dead_after)
        handler = _Device_5(answer)
        points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
        assert len(points) == 100
        return handler.unanswered(), handler

    # The link dies after 1, 2, ... requests of the binary search
    worst = 0
    for dead_after in range(1, 40):
        unanswered, handler = asyncio.run(run(dead_after))
        worst = max(worst, unanswered)
        # Nothing is learned from requests that were not answered
        for address, status in handler.get_denied_statuses().items():
            assert status == StatusCode.NG_ILLEGAL_ADDR and int(address[2:]) >= 70
    # Three unanswered requests make the link "down"; each waiting part of
    # the range sent one more before (up to a dozen timeouts)
    assert worst == handler.COMM_FAILURE_ABORT_THRESHOLD


def test_array_fragments_have_their_own_timeout(monkeypatch):
    import struct

    class Client:
        def open(self):
            return True

        def close(self):
            pass

    def send(client, service, path, data):
        _, offset = struct.unpack("<HI", data)
        last = offset // 4 == 7
        status = cip_symbolic.STATUS_OK if last else cip_symbolic.STATUS_PARTIAL
        return status, b"\xc4\x00" + struct.pack("<i", offset // 4), None

    monkeypatch.setattr(pycomm3, "CIPDriver", lambda path: Client())
    monkeypatch.setattr(cip_symbolic, "_send", send)

    async def run():
        # 8 fragments, 50 ms apart: 350 ms of waiting, more than the 200 ms a request may take
        handler = EtherNetIPHandler("10.0.0.3", config=NetworkConfig(packet_interval_ms=50, request_timeout_ms=200))
        handler._plc_type = "generic"
        assert await handler.connect()
        return await handler.read_tags(["Big[0]{8}"]), handler._needs_reconnect

    points, needs_reconnect = asyncio.run(run())
    assert [(p.address, p.status, p.value) for p in points] == [(f"Big[{i}]", StatusCode.OK, i) for i in range(8)]
    assert not needs_reconnect  # was NG_TIMEOUT and a reconnect, in every cycle


FAST_8 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def test_blocking_read_is_stopped_by_a_cancellation_that_arrives_with_its_result():
    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start_address, count):
            return [1] * count, StatusCode.OK

    async def run():
        handler = Handler("10.0.0.1", 5001, FAST_8)
        stopped = 0
        for ticks in range(12):  # whatever the moment of the request to stop
            task = asyncio.ensure_future(handler._run_blocking(lambda: 1))
            for _ in range(ticks):
                await asyncio.sleep(0)
            if task.done():
                break
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5)
            except asyncio.CancelledError:
                stopped += 1
        return stopped, ticks

    stopped, tried = asyncio.run(run())
    assert stopped == tried and tried > 0


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


def test_parallel_scan_finishes_with_max_concurrent_zero():
    async def run():
        plcs = [PLCInfo(ip_address="10.0.0.1"), PLCInfo(ip_address="10.0.0.2")]  # no protocol: fail at once
        return await asyncio.wait_for(scan_plcs_parallel(plcs, config=NetworkConfig(max_concurrent=0)), timeout=5)

    results = asyncio.run(run())  # waited for good before
    assert len(results) == 2 and not any(r.success for r in results.values())


class _Silent_2(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.bad = set(bad)
        self.dead_after = dead_after
        self.requests = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        addresses = range(start_address, start_address + count)
        if (self.dead_after is not None and self.requests > self.dead_after) or self.bad.intersection(addresses):
            return None, StatusCode.NG_TIMEOUT
        return list(addresses), StatusCode.OK


def test_unanswered_address_is_isolated_and_learned():
    handler = _Silent_2(bad={50})

    async def run():
        first = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
        before = handler.requests
        second = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
        return first, second, handler.requests - before

    first, second, second_requests = asyncio.run(run())
    for points in (first, second):
        assert [p.address for p in points if p.status != StatusCode.OK] == ["HR50"]
        assert Counter(p.status for p in points)[StatusCode.OK] == 99
    assert handler.get_denied_statuses() == {"HR50": StatusCode.NG_TIMEOUT}
    # Learned: the next cycle reads around it and never waits for its timeout
    assert second_requests == 2


class _Silent_3(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.bad = set(bad)
        self.dead_after = dead_after
        self.requests = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        addresses = range(start_address, start_address + count)
        if (self.dead_after is not None and self.requests > self.dead_after) or self.bad.intersection(addresses):
            return None, StatusCode.NG_TIMEOUT
        return list(addresses), StatusCode.OK


def test_unanswered_address_in_the_first_chunk_of_a_scan():
    handler = _Silent_3(bad={3})
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert [p.address for p in points if p.status != StatusCode.OK] == ["HR3"]


class _Silent_4(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.bad = set(bad)
        self.dead_after = dead_after
        self.requests = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        addresses = range(start_address, start_address + count)
        if (self.dead_after is not None and self.requests > self.dead_after) or self.bad.intersection(addresses):
            return None, StatusCode.NG_TIMEOUT
        return list(addresses), StatusCode.OK


def test_dead_link_is_not_searched_or_learned():
    handler = _Silent_4(dead_after=0)
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert len(points) == 300 and all(p.status != StatusCode.OK for p in points)
    assert handler.get_denied_addresses() == set()
    # Nothing was ever read, so the link cannot be told from the range: the
    # first chunk is searched for an address that answers with half the
    # budget (4 retries + 8), then nothing more - not 2N timeouts
    assert handler.requests <= 4 + BaseProtocolHandler.UNANSWERED_SEARCH_BUDGET // 2 + 1
    # Later scans: one request for the chunk known to be unanswered
    before = handler.requests
    asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert handler.requests - before <= 1


class _Silent_5(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.bad = set(bad)
        self.dead_after = dead_after
        self.requests = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        addresses = range(start_address, start_address + count)
        if (self.dead_after is not None and self.requests > self.dead_after) or self.bad.intersection(addresses):
            return None, StatusCode.NG_TIMEOUT
        return list(addresses), StatusCode.OK


def test_link_lost_during_a_scan_stops_the_search():
    handler = _Silent_5(dead_after=2)
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 499)))
    assert Counter(p.status for p in points)[StatusCode.OK] == 200
    assert handler.get_denied_addresses() == set()
    assert handler.requests <= 14
