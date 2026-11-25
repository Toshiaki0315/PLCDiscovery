"""
Regressions from the fifth code review (high finding):
- a chunk the PLC does not answer is not split like an address error once
  the search budget is spent: one request per chunk and scan, as documented
  (it was five to eight timeouts per chunk, in every cycle)
- the chunks after an unanswered one are asked once, without retries
- when the link is lost while a range is being split, the parts still
  waiting are not requested
"""

import asyncio

from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from plc_discovery.protocols.base import BaseProtocolHandler

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP  # 100 registers per chunk
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST)
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
        handler = _Device(_drops_above_99)
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


def test_chunks_after_an_unanswered_one_are_not_retried():
    async def run():
        handler = _Device(_drops_above_99)
        await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 999))
        return handler.log

    log = asyncio.run(run())
    whole_chunks = [start for start, count, _ in log if count == 100 and start >= 100]
    # HR100-199 with its retries; each chunk after it once (was four times each)
    assert whole_chunks.count(100) == 4
    assert all(whole_chunks.count(start) == 1 for start in range(200, 1000, 100))


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
        handler = _Device(answer)
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
