"""
Regression tests for the fourth review's findings (U1-U5).

A small fake SLMP 3E server reproduces split TCP responses, a closed
connection, a late reply and values >= 0x8000.
"""

import asyncio
import json
import socket
import struct
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, DeviceType, NetworkConfig, StatusCode
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Fake SLMP 3E server
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# U1: split TCP responses are read completely
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# U2: closed connection never yields data; handler reconnects
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_u2_slmp_closed_connection_no_fake_data_and_recovers():
    with FakeSLMP("close_after_first") as server:
        handler = await connected_handler(server)
        try:
            assert await handler.read_device_raw(DeviceType.D, 10, 3) == ([10, 11, 12], StatusCode.OK)
            await asyncio.sleep(0.2)
            data, status = await handler.read_device_raw(DeviceType.D, 10, 3)
            assert data is None and status == StatusCode.NG_COMM_ERROR  # previously [0, 0, 0] / OK
            assert handler._needs_reconnect
            assert await handler.read_device_raw(DeviceType.D, 10, 3) == ([10, 11, 12], StatusCode.OK)
            assert server.connections == 2
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
async def test_u2_s7_address_error_keeps_connection():
    handler = S7Handler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.db_read.side_effect = RuntimeError("CPU : Address out of range")
    handler._client, handler._connected = client, True
    assert (await handler.read_device_raw(DeviceType.DB, 0, 2))[1] == StatusCode.NG_ILLEGAL_ADDR
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_u2_eip_comm_error_triggers_reconnect():
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.read.side_effect = ConnectionResetError("connection reset")
    handler._client, handler._connected, handler._plc_type = client, True, "slc"
    assert (await handler.read_device_raw(DeviceType.D, 0, 2))[1] == StatusCode.NG_COMM_ERROR
    assert handler._needs_reconnect


# ---------------------------------------------------------------------------
# U3: SLMP word values are unsigned like the other protocols
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_u3_slmp_values_unsigned():
    with FakeSLMP(base=0x8000) as server:
        handler = await connected_handler(server)
        try:
            assert await handler.read_device_raw(DeviceType.D, 0, 2) == ([0x8000, 0x8001], StatusCode.OK)
        finally:
            await handler.disconnect()


# ---------------------------------------------------------------------------
# U5: a late reply after a socket timeout is never used as the next answer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_u5_late_reply_not_reused():
    with FakeSLMP("slow_first") as server:
        handler = await connected_handler(server, timeout_ms=500)
        try:
            assert (await handler.read_device_raw(DeviceType.D, 100, 2))[1] == StatusCode.NG_TIMEOUT
            assert handler._needs_reconnect
            await asyncio.sleep(1.2)  # the late reply to D100 arrives on the old socket
            assert await handler.read_device_raw(DeviceType.D, 500, 2) == ([500, 501], StatusCode.OK)
        finally:
            await handler.disconnect()


def test_u5_socket_timeout_handled_explicitly():
    """socket.timeout is not asyncio.TimeoutError on Python 3.10; the handler
    must catch the builtin TimeoutError as well"""
    source = (ROOT / "plc_discovery" / "protocols" / "slmp.py").read_text(encoding="utf-8")
    assert "except (asyncio.TimeoutError, TimeoutError)" in source


# ---------------------------------------------------------------------------
# U4: STRING / RAW values span the whole field
# ---------------------------------------------------------------------------


def string_words(text, n_words):
    padded = text.ljust(n_words * 2, "\0")
    return [ord(padded[i]) | (ord(padded[i + 1]) << 8) for i in range(0, n_words * 2, 2)]


def points(start, words, prefix="D"):
    return [DataPoint(f"{prefix}{start + i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(words)]


class TestStrings:

    def test_mapping_with_length(self):
        manager = DataTypeManager.from_config(
            {
                "mappings": [
                    {"device": "D", "start": 1000, "end": 1019, "type": "STRING", "length": 10},
                ]
            }
        )
        words = string_words("PRODUCT-A1", 10) + string_words("ITEM-B2", 10)
        result = plc_scanner.apply_data_type_conversion(points(1000, words), None, ByteOrder.LITTLE_ENDIAN, manager)
        assert [(d.address, d.converted_value) for d in result if d.converted_value] == [
            ("D1000", "PRODUCT-A1"),
            ("D1010", "ITEM-B2"),
        ]
        assert len(result) == 20 and result[1].display_value == "(part of D1000)"

    def test_mapping_without_length_is_one_value(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 0, "end": 3, "type": "STRING"}]})
        result = plc_scanner.apply_data_type_conversion(
            points(0, string_words("ABCDEF", 4)), None, ByteOrder.LITTLE_ENDIAN, manager
        )
        assert result[0].converted_value == "ABCDEF"

    def test_cli_data_type_string_uses_whole_range(self):
        result = plc_scanner.apply_data_type_conversion(
            points(0, string_words("HELLO", 4)), DataType.STRING, ByteOrder.LITTLE_ENDIAN
        )
        assert result[0].converted_value == "HELLO"

    def test_failed_word_makes_string_incomplete(self):
        pts = points(0, string_words("HELLO", 4))
        pts[2] = DataPoint("D2", status=StatusCode.NG_TIMEOUT)
        result = plc_scanner.apply_data_type_conversion(pts, DataType.STRING, ByteOrder.LITTLE_ENDIAN)
        assert all(d.converted_value is None for d in result)
        assert result[0].display_value.startswith("(incomplete STRING")

    def test_raw_hex(self):
        result = plc_scanner.apply_data_type_conversion(points(0, [0x1234, 0xABCD]), DataType.RAW, ByteOrder.BIG_ENDIAN)
        assert result[0].converted_value == "1234ABCD"

    def test_example_mapping_file(self):
        manager = DataTypeManager.from_config(
            json.loads((ROOT / "type_mapping.example.json").read_text(encoding="utf-8"))
        )
        (mapping,) = [m for m in manager.mappings if m.data_type == DataType.STRING]
        assert mapping.words_per_value() == 10
