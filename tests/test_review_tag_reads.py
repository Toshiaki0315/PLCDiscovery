"""
Review fixes for tag reads: malformed names concern one tag only; every
request of the Omron (generic CIP) path waits for the packet interval and a
rejected Multiple Service is remembered; row addresses without "{n}"; an
unreachable EtherNet/IP full scan is one "ALL" row.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from plc_discovery.collector import FULL_SCAN_ADDRESS, unreached_points
from plc_discovery.config import NetworkConfig, Protocol, StatusCode
from plc_discovery.protocols import cip_symbolic
from plc_discovery.protocols import ethernet_ip as eip
from plc_discovery.protocols.cip_symbolic import READ_SINGLY, SymbolicReadError, encode_tag_path


@pytest.mark.parametrize("name", ["A[x]", "A[1", "Motor.Speed[z]"])
def test_malformed_tag_name_is_an_illegal_address(name):
    with pytest.raises(SymbolicReadError) as error:
        encode_tag_path(name)
    assert error.value.status == StatusCode.NG_ILLEGAL_ADDR


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
