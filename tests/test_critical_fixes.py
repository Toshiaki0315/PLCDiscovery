"""
Regression tests for critical review findings (C1-C9).
"""

import asyncio
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from plc_discovery.config import DEFAULT_DEVICE_RANGES, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.retry import RetryConfig, RetryStrategy

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


FAST_RETRY = RetryConfig(strategy=RetryStrategy.FIXED, max_retries=1, initial_delay_ms=0)


def make_handler(read_fn, config, **kwargs):
    """Build a BaseProtocolHandler whose read_device_raw delegates to read_fn"""
    calls = []

    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            self._connected = True
            return True

        async def disconnect(self):
            self._connected = False

        async def read_device_raw(self, device_type, start_address, count):
            calls.append((start_address, count))
            return read_fn(start_address, count)

    handler = Handler("127.0.0.1", 5001, config, retry_config=FAST_RETRY, use_circuit_breaker=False, **kwargs)
    handler._connected = True
    return handler, calls


# ---------------------------------------------------------------------------
# C1: transient failures must not be learned as inaccessible
# ---------------------------------------------------------------------------


class TestC1TransientFailuresNotLearned:

    @pytest.mark.asyncio
    async def test_single_timeout_not_denied(self, fast_config):
        handler, _ = make_handler(lambda s, c: (None, StatusCode.NG_TIMEOUT), fast_config)
        results = await handler._binary_search_read(DeviceType.D, 0, 0)
        assert results[0].status == StatusCode.NG_TIMEOUT
        assert not handler._session_cache.is_denied("D0")

    @pytest.mark.asyncio
    async def test_single_comm_error_not_denied(self, fast_config):
        handler, _ = make_handler(lambda s, c: (None, StatusCode.NG_COMM_ERROR), fast_config)
        await handler._binary_search_read(DeviceType.D, 5, 5)
        assert handler.get_denied_addresses() == set()

    @pytest.mark.asyncio
    async def test_illegal_address_is_denied(self, fast_config):
        handler, _ = make_handler(lambda s, c: (None, StatusCode.NG_ILLEGAL_ADDR), fast_config)
        await handler._binary_search_read(DeviceType.D, 0, 0)
        assert handler._session_cache.is_denied("D0")

    @pytest.mark.asyncio
    async def test_transient_error_is_retried_next_scan(self, fast_config):
        """A timeout in scan 1 must not be reported as NG_ILLEGAL_ADDR in scan 2"""
        state = {"fail": True}

        def read(start, count):
            if state["fail"]:
                return None, StatusCode.NG_TIMEOUT
            return [7] * count, StatusCode.OK

        handler, _ = make_handler(read, fast_config)
        rng = DeviceRange(DeviceType.D, 0, 0)
        first = await handler.read_device_range(rng)
        assert first[0].status == StatusCode.NG_TIMEOUT

        state["fail"] = False
        second = await handler.read_device_range(rng)
        assert second[0].status == StatusCode.OK
        assert second[0].value == 7


# ---------------------------------------------------------------------------
# C2: binary search must stop when the link is down
# ---------------------------------------------------------------------------


class TestC2BinarySearchBounded:

    @pytest.mark.asyncio
    async def test_dead_plc_request_count_bounded(self, fast_config):
        handler, calls = make_handler(lambda s, c: (None, StatusCode.NG_TIMEOUT), fast_config)
        results = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 899))

        assert len(results) == 900
        assert all(dp.status == StatusCode.NG_TIMEOUT for dp in results)
        # Previously 2 retries + 1799 binary search requests
        assert len(calls) <= 10
        assert handler.get_denied_addresses() == set()

    @pytest.mark.asyncio
    async def test_failed_chunk_not_read_twice(self, fast_config):
        handler, calls = make_handler(
            lambda s, c: (None, StatusCode.NG_ILLEGAL_ADDR) if c > 1 else ([1], StatusCode.OK),
            fast_config,
        )
        await handler.read_device_range(DeviceRange(DeviceType.D, 0, 1))
        # one chunk read, then the two halves (no repeated full-range read)
        assert calls == [(0, 2), (0, 1), (1, 1)]

    @pytest.mark.asyncio
    async def test_unsupported_device_not_split(self, fast_config):
        handler, calls = make_handler(lambda s, c: (None, StatusCode.NG_UNSUPPORTED), fast_config)
        results = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 99))
        assert len(calls) == 1
        assert len(results) == 100
        assert all(dp.status == StatusCode.NG_UNSUPPORTED for dp in results)

    @pytest.mark.asyncio
    async def test_illegal_addresses_still_isolated(self, fast_config):
        """Address errors keep the per-address binary search"""

        def read(start, count):
            if start <= 10 <= start + count - 1:
                return None, StatusCode.NG_ILLEGAL_ADDR
            return list(range(start, start + count)), StatusCode.OK

        handler, _ = make_handler(read, fast_config)
        results = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 19))
        bad = [dp.address for dp in results if dp.status != StatusCode.OK]
        assert bad == ["D10"]
        assert handler.get_denied_addresses() == {"D10"}

    @pytest.mark.asyncio
    async def test_short_response_not_mapped(self, fast_config):
        """A response with fewer values than requested must not be labelled OK"""
        handler, _ = make_handler(lambda s, c: ([1] * (c - 1) if c > 1 else [1], StatusCode.OK), fast_config)
        results = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 3))
        assert [dp.address for dp in results] == ["D0", "D1", "D2", "D3"]
        assert all(dp.status == StatusCode.OK for dp in results)


# ---------------------------------------------------------------------------
# C3: late responses must never be taken as the current response
# ---------------------------------------------------------------------------


def fins_response(sid: int, words, end_code: int = 0) -> bytes:
    header = bytes([0xC0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, sid])
    data = b"".join(w.to_bytes(2, "big") for w in words)
    return header + bytes([0x01, 0x01]) + end_code.to_bytes(2, "big") + data


class FakeFinsUDP:
    """Minimal stand-in for FINSUDPProtocol + transport"""

    def __init__(self, on_send):
        self.queue = asyncio.Queue()
        self.on_send = on_send

    def sendto(self, frame):
        self.on_send(self, frame)

    async def receive(self):
        return await self.queue.get()

    def drain(self):
        while not self.queue.empty():
            self.queue.get_nowait()


class TestC3StaleResponses:

    @pytest.mark.asyncio
    async def test_fins_udp_discards_stale_response(self, fast_config):
        handler = FINSHandler("127.0.0.1", 9600, config=fast_config)

        def on_send(fake, frame):
            sid = frame[9]
            fake.queue.put_nowait(fins_response((sid - 1) & 0xFF, [0xDEAD]))  # late reply
            fake.queue.put_nowait(fins_response(sid, [0x1234]))

        fake = FakeFinsUDP(on_send)
        handler._transport = fake
        handler._protocol_instance = fake
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
        assert status == StatusCode.OK
        assert data == [0x1234]

    @pytest.mark.asyncio
    async def test_fins_udp_drains_queue_before_send(self, fast_config):
        handler = FINSHandler("127.0.0.1", 9600, config=fast_config)

        def on_send(fake, frame):
            fake.queue.put_nowait(fins_response(frame[9], [0x0002]))

        fake = FakeFinsUDP(on_send)
        # A late response whose SID happens to match the next request
        fake.queue.put_nowait(fins_response(1, [0x0BAD]))
        handler._transport = fake
        handler._protocol_instance = fake
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
        assert status == StatusCode.OK
        assert data == [0x0002]

    @pytest.mark.asyncio
    async def test_fins_udp_timeout_when_only_stale(self, fast_config):
        handler = FINSHandler("127.0.0.1", 9600, config=fast_config)

        def on_send(fake, frame):
            fake.queue.put_nowait(fins_response((frame[9] + 5) & 0xFF, [1]))

        fake = FakeFinsUDP(on_send)
        handler._transport = fake
        handler._protocol_instance = fake
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
        assert status == StatusCode.NG_TIMEOUT
        assert data is None

    @pytest.mark.asyncio
    async def test_blocking_timeout_forces_reconnect(self, fast_config):
        handler = SLMPHandler("127.0.0.1", 5001, config=fast_config)
        client = MagicMock()
        client.batchread_wordunits.side_effect = lambda **kw: time.sleep(0.3) or [1]
        handler._client = client
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.D, 0, 1)
        assert status == StatusCode.NG_TIMEOUT
        assert handler._needs_reconnect

        fresh = MagicMock()
        fresh.batchread_wordunits.return_value = [42]

        async def reconnect():
            handler._client = fresh
            handler._connected = True
            return True

        handler.connect = AsyncMock(side_effect=reconnect)
        handler.disconnect = AsyncMock()

        data, status = await handler.read_device_raw(DeviceType.D, 0, 1)
        handler.connect.assert_awaited_once()
        assert status == StatusCode.OK
        assert data == [42]


# ---------------------------------------------------------------------------
# C4: Modbus bit reads must be truncated to the requested count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_c4_modbus_coils_truncated(fast_config):
    handler = ModbusHandler("127.0.0.1", 502, config=fast_config)
    response = MagicMock()
    response.isError.return_value = False
    response.bits = [True, False, True, False, True, False, False, False]  # padded to 8
    client = MagicMock()
    client.read_coils.return_value = response
    handler._client = client
    handler._connected = True

    data, status = await handler.read_device_raw(DeviceType.M, 0, 5)
    assert status == StatusCode.OK
    assert data == [1, 0, 1, 0, 1]


# ---------------------------------------------------------------------------
# C5: EtherNet/IP array read tag and no mislabelled data
# ---------------------------------------------------------------------------


class TestC5EtherNetIP:

    @pytest.mark.asyncio
    async def test_slc_array_read_tag(self, fast_config):
        handler = EtherNetIPHandler("127.0.0.1", config=fast_config)
        tag = MagicMock(error=None, value=[1, 2, 3, 4, 5])
        client = MagicMock()
        client.read.return_value = tag
        handler._client = client
        handler._connected = True
        handler._plc_type = "slc"

        data, status = await handler.read_device_raw(DeviceType.D, 10, 5)
        client.read.assert_called_once_with("N7:10{5}")
        assert status == StatusCode.OK
        assert data == [1, 2, 3, 4, 5]

    @pytest.mark.asyncio
    async def test_slc_tag_error_is_illegal(self, fast_config):
        handler = EtherNetIPHandler("127.0.0.1", config=fast_config)
        client = MagicMock()
        client.read.return_value = MagicMock(error="Path destination unknown", value=None)
        handler._client = client
        handler._connected = True
        handler._plc_type = "slc"

        _, status = await handler.read_device_raw(DeviceType.D, 9000, 1)
        assert status == StatusCode.NG_ILLEGAL_ADDR

    @pytest.mark.asyncio
    @pytest.mark.parametrize("plc_type", ["logix", "generic"])
    async def test_address_read_unsupported_without_data_files(self, fast_config, plc_type):
        handler = EtherNetIPHandler("127.0.0.1", config=fast_config)
        handler._client = MagicMock()
        handler._connected = True
        handler._plc_type = plc_type

        data, status = await handler.read_device_raw(DeviceType.DM, 0, 10)
        assert status == StatusCode.NG_UNSUPPORTED
        assert data is None
        handler._client.generic_message.assert_not_called()


# ---------------------------------------------------------------------------
# C6: S7 addressing and port
# ---------------------------------------------------------------------------


class TestC6S7:

    @pytest.mark.asyncio
    async def test_db_read_uses_offset_in_configured_db(self, fast_config):
        handler = S7Handler("127.0.0.1", config=fast_config, db_number=5)
        client = MagicMock()
        client.db_read.return_value = bytearray([0x00, 0x01, 0x00, 0x02])
        handler._client = client
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.DB, 150, 2)
        client.db_read.assert_called_once_with(5, 300, 4)
        assert status == StatusCode.OK
        assert data == [1, 2]

    @pytest.mark.asyncio
    async def test_merker_read_uses_word_offset(self, fast_config):
        handler = S7Handler("127.0.0.1", config=fast_config)
        client = MagicMock()
        client.mb_read.return_value = bytearray([0x12, 0x34])
        handler._client = client
        handler._connected = True

        data, status = await handler.read_device_raw(DeviceType.M, 10, 1)
        client.mb_read.assert_called_once_with(20, 2)
        assert data == [0x1234]

    @pytest.mark.asyncio
    async def test_connect_passes_port(self, fast_config, monkeypatch):
        import snap7

        client = MagicMock()
        monkeypatch.setattr(snap7.client, "Client", lambda: client)
        handler = S7Handler("127.0.0.1", 1102, config=fast_config)
        assert await handler.connect()
        client.connect.assert_called_once_with("127.0.0.1", 0, 0, 1102)

    def test_default_full_scan_fits_one_db(self):
        (db_range,) = DEFAULT_DEVICE_RANGES[Protocol.S7]
        assert db_range.end_address * 2 + 1 < 65536


# ---------------------------------------------------------------------------
# C7: FINS end code flags and CIO word access
# ---------------------------------------------------------------------------


class TestC7FINS:

    def test_non_fatal_cpu_flag_is_ok(self):
        handler = FINSHandler("127.0.0.1")
        data, status = handler._parse_read_response(fins_response(1, [5, 6], end_code=0x0040))
        assert status == StatusCode.OK
        assert data == [5, 6]

    def test_relay_flag_masked_on_error(self):
        handler = FINSHandler("127.0.0.1")
        _, status = handler._parse_read_response(fins_response(1, [], end_code=0x9103))
        assert status == StatusCode.NG_ILLEGAL_ADDR  # 0x1103 (address range error) with relay flag

    def test_m_uses_cio_word_area(self):
        handler = FINSHandler("127.0.0.1")
        frame = handler._build_read_command(DeviceType.M, 0, 1)
        assert frame[12] == 0xB0


# ---------------------------------------------------------------------------
# C8 / C9: entry point and logging configuration
# ---------------------------------------------------------------------------


def test_c8_console_entry_point_is_sync():
    import plc_scanner

    assert not asyncio.iscoroutinefunction(plc_scanner.cli)
    assert 'plc-scanner = "plc_scanner:cli"' in (ROOT / "pyproject.toml").read_text()


def test_c9_import_does_not_configure_root_logger():
    code = "import logging, plc_discovery, plc_discovery.utils;" "print(len(logging.getLogger().handlers))"
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "0"
