"""
ModbusHandler.read_device_raw: the status each answer of the device is
reported with.

The status decides what happens next: NG_ILLEGAL_ADDR is split by the
binary search down to single registers (about 2N requests), NG_UNSUPPORTED
is not, and NG_TIMEOUT / NG_COMM_ERROR re-establish the connection. A
device without a table answers exception 01 to every request: reported as
an address error, the whole range would be searched register by register.
"""

import time

import pytest

from plc_discovery.config import DeviceType, NetworkConfig, StatusCode
from plc_discovery.protocols.modbus import ModbusHandler

FAST_100MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Answer:
    """A pymodbus response: registers / bits, or an exception response"""

    def __init__(self, registers=(), bits=(), exception_code=None):
        self.registers = list(registers)
        self.bits = list(bits)
        if exception_code is not None:
            self.exception_code = exception_code
        self._error = exception_code is not None

    def isError(self):
        return self._error


class _ErrorWithoutCode:
    def isError(self):
        return True


class _Client:
    """pymodbus client with the 3.10+ signatures; every read gives ``answer``"""

    def __init__(self, answer=None, raises=None, delay=0.0):
        self.answer, self.raises, self.delay = answer, raises, delay
        self.calls = []

    def _read(self, name, address, count, device_id):
        self.calls.append((name, address, count, device_id))
        if self.delay:
            time.sleep(self.delay)
        if self.raises:
            raise self.raises
        return self.answer

    def read_holding_registers(self, address, count=1, device_id=1):
        return self._read("holding", address, count, device_id)

    def read_input_registers(self, address, count=1, device_id=1):
        return self._read("input", address, count, device_id)

    def read_coils(self, address, count=1, device_id=1):
        return self._read("coil", address, count, device_id)

    def read_discrete_inputs(self, address, count=1, device_id=1):
        return self._read("discrete", address, count, device_id)

    def close(self):
        pass


def _handler(client, unit_id=1):
    handler = ModbusHandler("192.168.0.10", unit_id=unit_id, config=FAST_100MS)
    handler._client = client
    handler._connected = True
    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_code, status",
    [
        (0x02, StatusCode.NG_ILLEGAL_ADDR),  # Illegal Data Address
        (0x03, StatusCode.NG_ILLEGAL_ADDR),  # Illegal Data Value (quantity)
        (0x01, StatusCode.NG_UNSUPPORTED),  # Illegal Function: no such table
        (0x04, StatusCode.NG_COMM_ERROR),  # Server Device Failure
        (0x06, StatusCode.NG_COMM_ERROR),  # Server Device Busy
        (0x0B, StatusCode.NG_COMM_ERROR),  # Gateway: target device failed to respond
    ],
)
async def test_exception_codes(exception_code, status):
    handler = _handler(_Client(_Answer(exception_code=exception_code)))
    assert await handler.read_device_raw(DeviceType.HR, 100, 10) == (None, status)
    # The device answered: the connection is fine
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_error_response_without_an_exception_code_is_a_communication_error():
    handler = _handler(_Client(_ErrorWithoutCode()))
    assert await handler.read_device_raw(DeviceType.HR, 0, 1) == (None, StatusCode.NG_COMM_ERROR)


@pytest.mark.asyncio
async def test_no_response_object_is_a_communication_error():
    handler = _handler(_Client(None))
    assert await handler.read_device_raw(DeviceType.HR, 0, 1) == (None, StatusCode.NG_COMM_ERROR)


@pytest.mark.asyncio
async def test_unanswered_request_is_a_timeout_and_reconnects():
    client = _Client(_Answer(registers=[1]), delay=0.5)  # longer than the 100 ms timeout
    handler = _handler(client)
    assert await handler.read_device_raw(DeviceType.HR, 0, 1) == (None, StatusCode.NG_TIMEOUT)
    # The late answer may still arrive on this connection: a new one is used
    assert handler._needs_reconnect is True


@pytest.mark.asyncio
async def test_connection_error_is_a_communication_error_and_reconnects():
    handler = _handler(_Client(raises=ConnectionResetError("reset by peer")))
    assert await handler.read_device_raw(DeviceType.HR, 0, 1) == (None, StatusCode.NG_COMM_ERROR)
    assert handler._needs_reconnect is True


@pytest.mark.asyncio
async def test_device_type_without_a_modbus_table_is_unsupported_without_a_request():
    client = _Client(_Answer(registers=[1]))
    handler = _handler(client)
    assert await handler.read_device_raw(DeviceType.DM, 0, 1) == (None, StatusCode.NG_UNSUPPORTED)
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "device_type, table",
    [(DeviceType.HR, "holding"), (DeviceType.D, "holding"), (DeviceType.IR, "input"), (DeviceType.R, "input")],
)
async def test_registers_are_read_from_their_table_for_the_unit(device_type, table):
    client = _Client(_Answer(registers=[0x1234, 0xFFFF]))
    handler = _handler(client, unit_id=7)
    assert await handler.read_device_raw(device_type, 40, 2) == ([0x1234, 0xFFFF], StatusCode.OK)
    assert client.calls == [(table, 40, 2, 7)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "device_type, table",
    [(DeviceType.M, "coil"), (DeviceType.Y, "coil"), (DeviceType.X, "discrete")],
)
async def test_bits_keep_only_the_requested_points(device_type, table):
    # pymodbus pads the bits to a whole byte
    client = _Client(_Answer(bits=[True, False, True, False, False, False, False, False]))
    handler = _handler(client)
    assert await handler.read_device_raw(device_type, 0, 3) == ([1, 0, 1], StatusCode.OK)
    assert client.calls == [(table, 0, 3, 1)]


@pytest.mark.asyncio
async def test_failed_reconnect_is_a_communication_error_without_a_request():
    client = _Client(_Answer(registers=[1]))
    handler = _handler(client)
    handler._needs_reconnect = True

    async def refused():
        return False

    handler.connect = refused
    assert await handler.read_device_raw(DeviceType.HR, 0, 1) == (None, StatusCode.NG_COMM_ERROR)
    assert client.calls == []
