"""
Regression tests for the sixteenth review.

1: SLMP X/Y/B/W device numbers are hexadecimal in pymcprotocol; addresses
   are sent in hex so "W100" reads W100 (not W256).
2: SLC-style EtherNet/IP reads stay within pycomm3's one-byte limits
   (at most 100 words, elements 0-255) instead of raising DataError.
3: The EtherNet/IP full scan reads data files the handler supports.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from plc_discovery.config import (
    DEFAULT_DEVICE_RANGES, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode,
)
from plc_discovery.protocols.ethernet_ip import (
    EIP_DEVICE_MAP, SLC_MAX_READ_WORDS, EtherNetIPHandler,
)
from plc_discovery.protocols.slmp import SLMPHandler, slmp_head_device


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=2000)


# ---------------------------------------------------------------------------
# 1: SLMP hexadecimal devices
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address", [0, 9, 10, 100, 160, 900, 2047])
@pytest.mark.parametrize("device", [DeviceType.X, DeviceType.Y, DeviceType.B, DeviceType.W])
def test_hex_device_number_on_the_wire(device, address):
    pymcprotocol = pytest.importorskip("pymcprotocol")
    client = pymcprotocol.Type3E()
    encoded = client._make_devicedata(slmp_head_device(device, address))
    assert int.from_bytes(encoded[:3], "little") == address


@pytest.mark.parametrize("device", [DeviceType.D, DeviceType.M, DeviceType.R, DeviceType.SM])
def test_decimal_devices_unchanged(device):
    assert slmp_head_device(device, 100) == f"{device.value}100"


@pytest.mark.asyncio
async def test_w_register_read_from_simulator(fast_config):
    pytest.importorskip("pymcprotocol")
    from simulators.slmp_simulator import SLMPDevice, SLMPProtocol

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SLMPProtocol(SLMPDevice()), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = SLMPHandler("127.0.0.1", port=port, config=fast_config)
    try:
        assert await handler.connect()
        points = await handler.read_device_range(DeviceRange(DeviceType.W, 100, 104))
        # The simulator holds W[i] = 0x5500 + i
        assert [p.value for p in points] == [0x5500 + i for i in range(100, 105)]
        assert [p.address for p in points] == [f"W{i}" for i in range(100, 105)]
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# 2: SLC read limits
# ---------------------------------------------------------------------------

def _slc_handler(config, values=None):
    handler = EtherNetIPHandler("127.0.0.1", config=config)
    client = MagicMock()
    client.read.side_effect = lambda tag: MagicMock(
        error=None, value=values if values is not None else [0] * 100
    )
    handler._client = client
    handler._connected = True
    handler._plc_type = "slc"
    return handler, client


def test_slc_chunk_fits_pycomm3_byte_size(fast_config):
    handler, _ = _slc_handler(fast_config)
    assert handler.max_read_size == SLC_MAX_READ_WORDS
    assert handler.max_read_size * 2 <= 255
    handler._plc_type = "logix"
    assert handler.max_read_size == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("start,count", [(256, 1), (250, 10), (300, 5)])
async def test_slc_element_out_of_range_is_illegal_without_request(fast_config, start, count):
    handler, client = _slc_handler(fast_config)
    data, status = await handler.read_device_raw(DeviceType.D, start, count)
    assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
    client.read.assert_not_called()
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_slc_range_past_file_end(fast_config):
    """D0-D299: 0-255 read in <=100-word requests, 256-299 illegal"""
    handler, client = _slc_handler(fast_config)
    client.read.side_effect = lambda tag: MagicMock(
        error=None, value=[1] * int(tag.split("{")[1].rstrip("}")) if "{" in tag else 1
    )
    points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 299))
    assert len(points) == 300
    assert all(p.status == StatusCode.OK for p in points[:256])
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points[256:])
    for call in client.read.call_args_list:
        tag = call.args[0]
        if "{" in tag:
            assert int(tag.split("{")[1].rstrip("}")) <= SLC_MAX_READ_WORDS
    assert handler._needs_reconnect is False


# ---------------------------------------------------------------------------
# 3: EtherNet/IP full scan ranges
# ---------------------------------------------------------------------------

def test_eip_full_scan_uses_supported_data_files():
    ranges = DEFAULT_DEVICE_RANGES[Protocol.ETHERNET_IP]
    assert ranges
    for r in ranges:
        assert r.device_type in EIP_DEVICE_MAP
        assert 0 <= r.start_address <= r.end_address <= 255
