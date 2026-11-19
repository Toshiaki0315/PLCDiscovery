"""
Regression tests for FINS (Omron), found and fixed in code reviews.
"""

import collections
import json
import socket
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.fins import FINS_AREA_CODES, FINSHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.protocols.slmp import SLMPHandler


def fins_error(sid, end_code):
    return bytes([0xC0, 0, 2, 0, 1, 0, 0, 1, 0, sid, 1, 1, end_code >> 8, end_code & 0xFF])


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def _connected(handler):
    handler._connected = True
    handler._client = MagicMock()
    return handler


def fins_reply(request: bytes) -> bytes:
    header = bytes(
        [0xC0, 0x00, 0x02, request[6], request[7], request[8], request[3], request[4], request[5], request[9]]
    )
    return header + request[10:12] + b"\x00\x00" + b"\x00\x2a"


class UDPServer:
    def __init__(self, respond):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.respond = respond
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                continue
            reply = self.respond(data)
            if reply:
                self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(1)
        self.sock.close()


def load(tmp_path, targets):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


@pytest.mark.parametrize(
    "end_code, status",
    [
        (0x1103, StatusCode.NG_ILLEGAL_ADDR),  # address range error
        (0x1104, StatusCode.NG_ILLEGAL_ADDR),  # address range exceeded
        (0x1101, StatusCode.NG_UNSUPPORTED),  # area classification missing
        (0x0401, StatusCode.NG_UNSUPPORTED),  # undefined command
        (0x0402, StatusCode.NG_UNSUPPORTED),  # not supported by model/version
        (0x0205, StatusCode.NG_TIMEOUT),  # response timeout (relayed)
        (0x1001, StatusCode.NG_COMM_ERROR),  # command too long: a format error, not an address
        (0x1002, StatusCode.NG_COMM_ERROR),  # command too short
    ],
)
def test_fins_end_code_classification(end_code, status):
    assert FINSHandler("127.0.0.1")._parse_read_response(fins_error(1, end_code))[1] == status


@pytest.mark.asyncio
async def test_fins_partly_valid_range_found_by_binary_search():
    """A CPU with H0-H49 only: H0-H49 are read, H50-H99 learned as inaccessible"""
    handler = FINSHandler("127.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True

    async def plc(frame, sid):
        start, count = (frame[13] << 8) | frame[14], (frame[16] << 8) | frame[17]
        if start + count > 50:
            return fins_error(sid, 0x1103)
        return fins_error(sid, 0)[:12] + b"\x00\x00" + b"\x00\x07" * count

    handler._send_udp = plc
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
    assert collections.Counter(p.status for p in points) == {
        StatusCode.OK: 50,
        StatusCode.NG_ILLEGAL_ADDR: 50,
    }  # previously 100 x NG_COMM_ERROR
    assert handler.get_denied_addresses() == {f"HR{a}" for a in range(50, 100)}
    assert handler.circuit_breaker_state == "closed"


@pytest.mark.asyncio
@pytest.mark.parametrize("device", [d for d in DeviceType if d not in FINS_AREA_CODES])
async def test_fins_unmapped_device_unsupported_without_request(fast_config, device):
    handler = FINSHandler("192.168.0.10", config=fast_config)
    handler._connected = True
    handler._send_udp = AsyncMock()
    data, status = await handler.read_device_raw(device, 0, 10)
    assert (data, status) == (None, StatusCode.NG_UNSUPPORTED)
    handler._send_udp.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory,device,start,count",
    [
        (lambda c: FINSHandler("192.168.0.10", config=c), DeviceType.DM, 65541, 1),
        (lambda c: FINSHandler("192.168.0.10", config=c), DeviceType.DM, 65530, 10),
        (lambda c: ModbusHandler("192.168.0.10", config=c), DeviceType.HR, 70000, 1),
        (lambda c: SLMPHandler("192.168.0.10", config=c), DeviceType.D, 0x1000000, 1),
    ],
)
async def test_beyond_address_limit_is_illegal_and_not_sent(fast_config, factory, device, start, count):
    handler = _connected(factory(fast_config))
    handler.read_device_raw = AsyncMock()
    handler._comm_failure_streak = 2
    data, status = await handler._tracked_read(device, start, count)
    assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
    handler.read_device_raw.assert_not_called()
    assert handler._comm_failure_streak == 2  # link state untouched


def test_fins_response_too_long_is_split():
    handler = FINSHandler("10.0.0.1")
    response = bytes(12) + bytes([0x11, 0x0B])
    assert handler._parse_read_response(response) == (None, StatusCode.NG_ILLEGAL_ADDR)


class TestFINSConnection:

    @pytest.mark.asyncio
    async def test_udp_connect_requires_fins_reply(self):
        config = NetworkConfig(request_timeout_ms=300)
        with UDPServer(lambda req: None) as silent:
            handler = FINSHandler("127.0.0.1", silent.port, config=config)
            assert await handler.connect() is False
            assert handler._transport is None
        with UDPServer(fins_reply) as server:
            handler = FINSHandler("127.0.0.1", server.port, config=config)
            assert await handler.connect() is True
            data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
            assert (data, status) == ([0x2A], StatusCode.OK)
            await handler.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_error_still_marks_disconnected(self):
        handler = FINSHandler("127.0.0.1", use_tcp=True)
        writer = MagicMock()
        writer.wait_closed = AsyncMock(side_effect=ConnectionResetError())
        handler._writer = writer
        handler._connected = True
        await handler.disconnect()
        assert handler.is_connected is False
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_tcp_handshake_failure_closes_socket(self):
        handler = FINSHandler("127.0.0.1", use_tcp=True, config=NetworkConfig(request_timeout_ms=300))
        reader = MagicMock()
        reader.readexactly = AsyncMock(return_value=b"NOPE" + b"\x00" * 20)
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        with patch("asyncio.open_connection", AsyncMock(return_value=(reader, writer))):
            assert await handler.connect() is False
        writer.close.assert_called_once()
        assert handler._writer is None


def test_read_sizes_use_safe_values():
    assert ModbusHandler("127.0.0.1").max_read_size == 100
    assert FINSHandler("127.0.0.1").max_read_size == 400


class TestFINSNodes:

    def test_dest_node_defaults_to_last_octet(self):
        assert FINSHandler("192.168.1.40").dest_node == 40
        assert FINSHandler("192.168.1.40", dest_node=3).dest_node == 3

    def test_invalid_node_rejected(self):
        with pytest.raises(ValueError):
            FINSHandler("192.168.1.40", source_node=300)

    def test_tcp_handshake_requests_explicit_client_node(self):
        assert FINSHandler("10.0.0.1", use_tcp=True)._build_tcp_handshake()[-4:] == b"\x00\x00\x00\x00"
        assert FINSHandler("10.0.0.1", use_tcp=True, source_node=7)._build_tcp_handshake()[-4:] == b"\x00\x00\x00\x07"

    @pytest.mark.asyncio
    async def test_udp_source_node_from_local_address(self):
        handler = FINSHandler("127.0.0.1", 9, config=NetworkConfig(request_timeout_ms=200))
        frames = []

        async def fake_send(frame, sid):
            frames.append(frame)
            return None  # no PLC: connect fails after building the frame

        handler._send_udp = fake_send
        assert await handler.connect() is False
        assert handler.source_node == 1  # 127.0.0.1 -> node 1
        assert frames[0][4] == 1 and frames[0][7] == 1  # DA1, SA1 in the frame


@pytest.mark.parametrize(
    "protocol, options, message",
    [
        ("fins", {"dest_node": 300}, "dest_node must be an integer 0-254"),
        ("fins_tcp", {"source_node": -1}, "source_node must be an integer 0-254"),
        ("s7", {"slot": 99}, "slot must be an integer 0-31"),
        ("s7", {"db_number": 0}, "db_number must be an integer 1-65535"),
        ("modbus", {"unit_id": "1"}, "unit_id must be an integer 0-255"),
        ("eip", {"slot": True}, "slot must be an integer 0-255"),
    ],
)
def test_validate_rejects_out_of_range_options(tmp_path, protocol, options, message):
    loader = load(tmp_path, [{"ip": "10.0.0.1", "protocol": protocol, "options": options}])
    assert any(message in e for e in loader.validate())


def test_validate_accepts_valid_options(tmp_path):
    loader = load(
        tmp_path,
        [
            {"ip": "10.0.0.1", "protocol": "fins", "options": {"dest_node": 0, "source_node": 254}},
            {"ip": "10.0.0.2", "protocol": "s7", "options": {"rack": 0, "slot": 2, "db_number": 100}},
        ],
    )
    assert loader.validate() == []


@pytest.mark.asyncio
async def test_collector_bad_option_value_returns_false():
    plc = PLCInfo("127.0.0.1", protocol=Protocol.FINS, port=9600, options={"dest_node": 300})
    collector = PLCDataCollector(plc)
    assert await collector.connect() is False  # previously raised ValueError
    assert "dest_node must be 0-254" in collector.connect_error
