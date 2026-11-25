"""
Regression tests for S7 (Siemens), found and fixed in code reviews.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from plc_discovery.config import SAFE_READ_WORDS, DeviceType, NetworkConfig, Protocol, StatusCode
from plc_discovery.protocols.s7 import S7Handler, classify_s7_error


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def _connected(handler):
    handler._connected = True
    handler._client = MagicMock()
    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "start,count,expected",
    [
        (0xFFFFF, 1, None),  # last encodable word: sent
        (1_048_581, 1, StatusCode.NG_ILLEGAL_ADDR),  # wrapped to DBW10 before
        (0xFFFF0, 32, StatusCode.NG_ILLEGAL_ADDR),
    ],
)
async def test_s7_address_limit(fast_config, start, count, expected):
    handler = _connected(S7Handler("192.168.0.10", config=fast_config))
    handler.read_device_raw = AsyncMock(return_value=([0] * count, StatusCode.OK))
    data, status = await handler._tracked_read(DeviceType.DB, start, count)
    if expected is None:
        assert status == StatusCode.OK
        handler.read_device_raw.assert_called_once()
    else:
        assert (data, status) == (None, expected)
        handler.read_device_raw.assert_not_called()


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Read operation failed: Object does not exist (0x0a)", StatusCode.NG_ILLEGAL_ADDR),  # snap7 3.x
        ("Read operation failed: Invalid address (0x05)", StatusCode.NG_ILLEGAL_ADDR),
        ("Read operation failed: Accessing the object not allowed (0x03)", StatusCode.NG_ILLEGAL_ADDR),
        ("Read operation failed: Data type not supported (0x06)", StatusCode.NG_UNSUPPORTED),
        ("Read operation failed: Hardware error (0x01)", StatusCode.NG_COMM_ERROR),
        ("CPU : Item not available", StatusCode.NG_ILLEGAL_ADDR),  # snap7 1.x
        ("CPU : Address out of range", StatusCode.NG_ILLEGAL_ADDR),
        ("CPU : Invalid Transport size", StatusCode.NG_UNSUPPORTED),
        ("TCP : Connection reset", None),
        ("CLI : Job Timeout", None),
        ("ISO : An error occurred during recv TCP : Connection timed out", None),
    ],
)
def test_classify_s7_error(message, expected):
    assert classify_s7_error(Exception(message)) == expected


@pytest.mark.asyncio
async def test_u2_s7_address_error_keeps_connection():
    handler = S7Handler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.db_read.side_effect = RuntimeError("CPU : Address out of range")
    handler._client, handler._connected = client, True
    assert (await handler.read_device_raw(DeviceType.DB, 0, 2))[1] == StatusCode.NG_ILLEGAL_ADDR
    assert handler._needs_reconnect is False


def test_one_s7_chunk_fits_the_smallest_pdu():
    # python-snap7 splits a read at PDU - 18 bytes into several requests,
    # sent back to back outside the packet interval
    assert SAFE_READ_WORDS[Protocol.S7] * 2 <= 240 - 18
