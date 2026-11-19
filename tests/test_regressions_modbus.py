"""
Regression tests for Modbus/TCP, found and fixed in code reviews.
"""

from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, StatusCode
from plc_discovery.protocols.modbus import ModbusHandler


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def _connected(handler):
    handler._connected = True
    handler._client = MagicMock()
    return handler


class _Registers:
    def __init__(self, count):
        self.registers = list(range(count))
        self.bits = []

    def isError(self):
        return False


@pytest.mark.asyncio
async def test_last_encodable_address_still_read(fast_config):
    handler = _connected(ModbusHandler("192.168.0.10", config=fast_config))
    handler.read_device_raw = AsyncMock(return_value=([7], StatusCode.OK))
    assert await handler._tracked_read(DeviceType.HR, 65535, 1) == ([7], StatusCode.OK)


@pytest.mark.asyncio
async def test_range_across_limit_reads_valid_part(fast_config):
    """HR65500-65599: up to 65535 read, the rest NG_ILLEGAL_ADDR (not COMM_ERROR)"""
    handler = _connected(ModbusHandler("192.168.0.10", config=fast_config))

    async def fake_read(device_type, start, count):
        return [start + i for i in range(count)], StatusCode.OK

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 65500, 65599))
    assert len(points) == 100
    assert all(p.status == StatusCode.OK for p in points[:36])
    assert points[35].address == "HR65535" and points[35].value == 65535
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points[36:])
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_modbus_device_with_small_request_limit_is_fully_read():
    """A device reading at most 32 registers answers exception 03 to 100"""
    from pymodbus.pdu import ExceptionResponse

    handler = ModbusHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    client = MagicMock()
    requests = []

    def read(address, count, **kwargs):
        requests.append(count)
        return ExceptionResponse(0x03, 0x03) if count > 32 else _Registers(count)

    client.read_holding_registers = read
    handler._client = client
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 999))
    assert Counter(p.status for p in points) == {StatusCode.OK: 1000}  # was 1000 x NG_COMM_ERROR
    assert handler._needs_reconnect is False
    assert len(requests) < 200


@pytest.mark.asyncio
async def test_r4_modbus_client_without_internal_retries():
    with patch("pymodbus.client.ModbusTcpClient") as client_cls:
        client_cls.return_value.connect.return_value = True
        handler = ModbusHandler("127.0.0.1", 502, config=NetworkConfig())
        assert await handler.connect()
    assert client_cls.call_args.kwargs["retries"] == 0
