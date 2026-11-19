"""
Regression tests for EtherNet/IP (CIP, tags), found and fixed in code reviews.
"""

import asyncio
import struct
from unittest.mock import MagicMock, patch

import pytest

from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.collector import FULL_SCAN_ADDRESS, comm_error_points, unreached_points
from plc_discovery.config import (
    DEFAULT_DEVICE_RANGES,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    Protocol,
    StatusCode,
    TagRange,
)
from plc_discovery.probes import parse_eip_identity
from plc_discovery.protocols import cip_symbolic
from plc_discovery.protocols import ethernet_ip as eip
from plc_discovery.protocols.cip_symbolic import READ_SINGLY, SymbolicReadError, encode_tag_path
from plc_discovery.protocols.ethernet_ip import EIP_DEVICE_MAP, SLC_MAX_READ_WORDS, EtherNetIPHandler, is_slc_identity


def list_identity(vendor_id, product_name, device_type=0x0E):
    name = product_name.encode()
    body = struct.pack("<HHHBBHI", vendor_id, device_type, 1, 1, 2, 0, 0x1234) + bytes([len(name)]) + name + b"\x03"
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    return (
        struct.pack("<HHII", 0x63, 2 + 4 + len(item), 0, 0)
        + b"\x00" * 8
        + struct.pack("<I", 0)
        + struct.pack("<HHH", 1, 0x0C, len(item))
        + item
    )


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=2000)


def _slc_handler(config, values=None):
    handler = EtherNetIPHandler("127.0.0.1", config=config)
    client = MagicMock()
    client.read.side_effect = lambda tag: MagicMock(error=None, value=values if values is not None else [0] * 100)
    handler._client = client
    handler._connected = True
    handler._plc_type = "slc"
    return handler, client


def _generic_handler():
    handler = eip.EtherNetIPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0))
    handler._client = MagicMock()
    handler._connected = True
    handler._plc_type = "generic"
    waits = []

    async def wait():
        waits.append(1)

    handler._rate_limiter.wait = wait
    return handler, waits


@pytest.mark.parametrize(
    "vendor_id, vendor",
    [
        (47, "Omron Corporation"),  # previously "Vendor 47"
        (367, "Keyence Corporation"),
        (1, "Rockwell Automation/Allen-Bradley"),
    ],
)
def test_broadcast_identity_uses_cip_vendor_names(vendor_id, vendor):
    plc = BroadcastDiscovery()._parse_eip_response("10.0.0.5", list_identity(vendor_id, "NJ501-1300"))
    assert plc.manufacturer == vendor
    assert plc.model == "NJ501-1300"


def test_broadcast_vendor_2_is_not_omron():
    plc = BroadcastDiscovery()._parse_eip_response("10.0.0.5", list_identity(2, "X"))
    assert "Omron" not in plc.manufacturer and "オムロン" not in plc.manufacturer


@pytest.mark.asyncio
async def test_eip_slc_words_unsigned():
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.read.return_value = MagicMock(error=None, value=[-1, -32768, 5])
    handler._client, handler._connected, handler._plc_type = client, True, "slc"
    assert await handler.read_device_raw(DeviceType.D, 0, 3) == ([0xFFFF, 0x8000, 5], StatusCode.OK)


def test_eip_identity_product_name_cleaned():
    name = b"KV\x1b[2J-8000"
    body = struct.pack("<HHHBBHI", 367, 0x0E, 1, 1, 2, 0, 1) + bytes([len(name)]) + name + b"\x03"
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    reply = (
        struct.pack("<HHII", 0x63, 2 + 4 + len(item), 0, 0)
        + b"\x00" * 8
        + struct.pack("<I", 0)
        + struct.pack("<HHH", 1, 0x0C, len(item))
        + item
    )
    assert parse_eip_identity(reply)["product_name"] == "KV[2J-8000"


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


def test_eip_full_scan_uses_supported_data_files():
    ranges = DEFAULT_DEVICE_RANGES[Protocol.ETHERNET_IP]
    assert ranges
    for r in ranges:
        assert r.device_type in EIP_DEVICE_MAP
        assert 0 <= r.start_address <= r.end_address <= 255


class TestR6SLCIdentity:

    @pytest.mark.parametrize(
        "identity, expected",
        [
            (
                {
                    "vendor": "Rockwell Automation/Allen-Bradley",
                    "product_type": "Programmable Logic Controller",
                    "product_name": "1747-L552/C C/10 - DC 3.46",
                },
                True,
            ),
            (
                {
                    "vendor": "Rockwell Automation/Allen-Bradley",
                    "product_type": "Programmable Logic Controller",
                    "product_name": "1766-L32BWA B/14.00 MicroLogix 1400",
                },
                True,
            ),
            (
                {
                    "vendor": "Rockwell Automation/Allen-Bradley",
                    "product_type": "Programmable Logic Controller",
                    "product_name": "1756-L71/B LOGIX5571",
                },
                False,
            ),
            (
                {
                    "vendor": "OMRON Corporation",
                    "product_type": "Programmable Logic Controller",
                    "product_name": "NJ501-1300",
                },
                False,
            ),
            (
                {
                    "vendor": "Rockwell Automation/Allen-Bradley",
                    "product_type": "Communications Adapter",
                    "product_name": "1756-EN2T",
                },
                False,
            ),
            (None, False),
        ],
    )
    def test_is_slc_identity(self, identity, expected):
        assert is_slc_identity(identity) is expected

    @pytest.mark.asyncio
    async def test_non_slc_device_rejected(self):
        handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
        driver = MagicMock()
        driver._list_identity.return_value = {
            "vendor": "OMRON Corporation",
            "product_type": "Programmable Logic Controller",
            "product_name": "NJ501-1300",
        }
        with patch("pycomm3.SLCDriver", return_value=driver):
            assert await handler._connect_slc() is False
        driver.close.assert_called_once()
        assert handler._plc_type is None


@pytest.mark.asyncio
async def test_u2_eip_comm_error_triggers_reconnect():
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.read.side_effect = ConnectionResetError("connection reset")
    handler._client, handler._connected, handler._plc_type = client, True, "slc"
    assert (await handler.read_device_raw(DeviceType.D, 0, 2))[1] == StatusCode.NG_COMM_ERROR
    assert handler._needs_reconnect


@pytest.mark.parametrize("name", ["A[x]", "A[1", "Motor.Speed[z]"])
def test_malformed_tag_name_is_an_illegal_address(name):
    with pytest.raises(SymbolicReadError) as error:
        encode_tag_path(name)
    assert error.value.status == StatusCode.NG_ILLEGAL_ADDR


def test_reads_singly_after_the_packet_interval(monkeypatch):
    """A batched tag whose reply did not fit is re-read as its own request, after the interval"""
    handler, waits = _generic_handler()
    calls = []

    def batch(client, names):
        calls.append(("batch", list(names)))
        return [(1, "INT"), READ_SINGLY, SymbolicReadError(StatusCode.NG_ILLEGAL_ADDR, "x")], True

    def single(client, tag):
        calls.append(("single", tag))
        return "long text", "STRING"

    monkeypatch.setattr(eip, "read_symbolic_batch", batch)
    monkeypatch.setattr(eip, "read_symbolic", single)
    points = asyncio.run(handler.read_tags(["A", "Big", "Nope"]))
    assert calls == [("batch", ["A", "Big", "Nope"]), ("single", "Big")]
    assert len(waits) == 2  # one interval per request
    assert [(p.address, p.status) for p in points] == [
        ("A", StatusCode.OK),
        ("Big", StatusCode.OK),
        ("Nope", StatusCode.NG_ILLEGAL_ADDR),
    ]


def test_rejected_multiple_service_is_remembered(monkeypatch):
    handler, waits = _generic_handler()
    calls = []

    def batch(client, names):
        calls.append(("batch", list(names)))
        return [READ_SINGLY] * len(names), False  # service not supported

    def single(client, tag):
        calls.append(("single", tag))
        return 7, "DINT"

    monkeypatch.setattr(eip, "read_symbolic_batch", batch)
    monkeypatch.setattr(eip, "read_symbolic", single)
    tags = [f"T{i}" for i in range(eip.MAX_BATCH_TAGS + 2)]  # two batches' worth
    points = asyncio.run(handler.read_tags(tags))
    assert [c for c in calls if c[0] == "batch"] == [("batch", tags[: eip.MAX_BATCH_TAGS])]  # tried once
    assert [c[1] for c in calls if c[0] == "single"] == tags
    assert len(waits) == 1 + len(tags)
    assert [p.address for p in points] == tags and {p.status for p in points} == {StatusCode.OK}
    assert handler._multiple_service_ok is False


def test_batch_reply_too_large_is_read_singly():
    data = b"\x02\x00\x06\x00\x0a\x00" + bytes([0xCC, 0, 0x06, 0]) + bytes([0xCC, 0, 0x00, 0, 0xC4, 0, 1, 0, 0, 0])
    replies = cip_symbolic._split_multiple_reply(data, 2)
    assert cip_symbolic._decode_embedded_reply("A", replies[0]) is READ_SINGLY
    assert cip_symbolic._decode_embedded_reply("B", replies[1]) == (1, "DINT")


def test_logix_batch_failure_rows_have_no_element_count():
    handler = eip.EtherNetIPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0))
    client = MagicMock()
    client.read.side_effect = RuntimeError("link lost")
    handler._client, handler._connected, handler._plc_type = client, True, "logix"
    points = asyncio.run(handler.read_tags(["Recipe[0]{10}", "Speed"]))
    assert [(p.address, p.status) for p in points] == [
        ("Recipe[0]", StatusCode.NG_COMM_ERROR),
        ("Speed", StatusCode.NG_COMM_ERROR),
    ]


def test_unreachable_ethernet_ip_full_scan_is_one_row():
    points = unreached_points(Protocol.ETHERNET_IP, None)
    assert [(p.address, p.status) for p in points] == [(FULL_SCAN_ADDRESS, StatusCode.NG_COMM_ERROR)]
    assert len(unreached_points(Protocol.FINS, None)) > 1  # data areas: one row per address


def test_comm_error_points_for_tags():
    points = comm_error_points(TagRange(["Speed", "Recipe[0]{10}"]))
    assert [(p.address, p.status) for p in points] == [
        ("Speed", StatusCode.NG_COMM_ERROR),
        ("Recipe[0]", StatusCode.NG_COMM_ERROR),
    ]
