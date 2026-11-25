"""
Regression tests for EtherNet/IP (CIP, tags), found and fixed in code reviews.
"""

import asyncio
import struct
import threading
import time
from collections import Counter
from unittest.mock import MagicMock, patch

import pycomm3
import pytest
from pycomm3 import Tag
from pycomm3.exceptions import CommError, ResponseError

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
from plc_discovery.protocols.ethernet_ip import (
    EIP_DEVICE_MAP,
    SLC_MAX_READ_WORDS,
    EtherNetIPHandler,
    _is_address_error,
    _logix_batches,
    _tag_hex,
    _tag_point,
    _tag_points,
    _value_points,
    is_slc_identity,
)
from plc_discovery.scan_runner import plc_answered


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

    def single(client, tag, fragment_interval=0.0):
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

    def single(client, tag, fragment_interval=0.0):
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


@pytest.mark.parametrize(
    "value, type_name, expected",
    [(-1, "SINT", "0xFF"), (200, "USINT", "0xC8"), (0x7F, "BYTE", "0x7F"), (1, "BOOL", "0x01"), (-1, "INT", "0xFFFF")],
)
def test_eight_bit_types_are_two_hex_digits(value, type_name, expected):
    assert _tag_hex(value, type_name) == expected


DEFINITIONS = {
    "Recipe": {
        "internal_tags": {
            "Count": {"data_type_name": "DINT"},
            "Flags": {"data_type_name": "SINT"},
            "Limits": {"data_type_name": "Limit"},
            "Steps": {"data_type_name": "INT"},
        }
    },
    "Limit": {"internal_tags": {"Low": {"data_type_name": "INT"}, "High": {"data_type_name": "LINT"}}},
}


def test_structure_members_use_the_types_of_the_structure_definition():
    value = {"Count": -1, "Flags": -1, "Limits": {"Low": -2, "High": 5}, "Steps": [1, -1]}
    points = {p.address: p.raw_hex for p in _value_points("R1", value, "Recipe", DEFINITIONS)}
    assert points == {
        "R1.Count": "0xFFFFFFFF",  # DINT, not 0xFFFF
        "R1.Flags": "0xFF",
        "R1.Limits.Low": "0xFFFE",
        "R1.Limits.High": "0x0000000000000005",
        "R1.Steps[0]": "0x0001",
        "R1.Steps[1]": "0xFFFF",
    }


def test_array_of_structures_and_reply_type_with_dimension():
    reply = MagicMock(error=None, value=[{"Low": -1, "High": -1}, {"Low": 3, "High": 4}], type="Limit[2]")
    points = {p.address: p.raw_hex for p in _tag_points("Lim[0]{2}", reply, DEFINITIONS)}
    assert points["Lim[0].Low"] == "0xFFFF" and points["Lim[0].High"] == "0xFFFFFFFFFFFFFFFF"
    assert points["Lim[1].Low"] == "0x0003"


def test_members_without_a_definition_fall_back_to_the_value_width():
    for definitions in (None, {}, {"Recipe": {}}, {"Recipe": {"internal_tags": {"Count": {}}}}):
        points = _value_points("R1", {"Count": -1, "Big": 70000}, "Recipe", definitions)
        assert [(p.address, p.raw_hex) for p in points] == [("R1.Count", "0xFFFF"), ("R1.Big", "0x00011170")]


def test_tags_the_controller_rejects_are_listed_as_denied():
    handler = EtherNetIPHandler("127.0.0.1")
    points = [
        _tag_point("Speed", StatusCode.OK, 5, "INT"),
        _tag_point("NoSuchTag", StatusCode.NG_ILLEGAL_ADDR),
        _tag_point("Blob", StatusCode.NG_UNSUPPORTED),
        _tag_point("Slow", StatusCode.NG_TIMEOUT),  # transient: not recorded
    ]
    assert handler._learn_denied_tags(points) is points
    assert handler.get_denied_statuses() == {
        "NoSuchTag": StatusCode.NG_ILLEGAL_ADDR,
        "Blob": StatusCode.NG_UNSUPPORTED,
    }


def test_only_errors_about_the_address_are_address_errors():
    for text in (
        "Illegal Command or Format, Address may not exist or not enough elements in data file",
        "Addressing problem or Memory Protect Rungs",
        "Path destination unknown",
    ):
        assert _is_address_error(text), text
    for text in ("Processor is in Program mode", "Remote node cannot buffer command", "Unknown Status"):
        assert not _is_address_error(text), text


FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


def test_busy_slc_controller_is_not_learned_as_an_invalid_address():
    replies = ["Remote node cannot buffer command", "Addressing problem or Memory Protect Rungs"]

    class Client:
        def read(self, name):
            return Tag(name, None, None, replies.pop(0))

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        handler._client, handler._connected, handler._plc_type = Client(), True, "slc"
        busy = await handler.read_device_raw(DeviceType.D, 0, 1)
        return busy, await handler.read_device_raw(DeviceType.D, 0, 1), handler._needs_reconnect

    busy, invalid, needs_reconnect = asyncio.run(run())
    assert busy == (None, StatusCode.NG_COMM_ERROR)  # was NG_ILLEGAL_ADDR, learned for the session
    assert invalid == (None, StatusCode.NG_ILLEGAL_ADDR)
    assert not needs_reconnect  # the controller answered: the session is fine


def test_busy_logix_controller_does_not_make_a_tag_inaccessible():
    busy = _tag_points("Speed", Tag("Speed", None, None, "Insufficient resource"))
    missing = _tag_points("Nope", Tag("Nope", None, None, "Path segment error"))
    assert [p.status for p in busy + missing] == [StatusCode.NG_COMM_ERROR, StatusCode.NG_ILLEGAL_ADDR]


def test_logix_array_reads_are_requests_of_their_own():
    tags = [f"T{i}" for i in range(25)] + ["Big[0]{1000}", "A", "Recipe[0]{50}", "Other[0]{20}", "B"]
    batches = _logix_batches(tags)
    assert [len(b) for b in batches] == [20, 5, 1, 1, 1, 1, 1]
    assert [tag for batch in batches for tag in batch] == tags  # order kept
    assert batches[2] == ["Big[0]{1000}"] and batches[4] == ["Recipe[0]{50}"]


def test_interrupted_tag_scan_keeps_the_tags_already_read():
    reached, release = threading.Event(), threading.Event()

    class Client:
        data_types: dict = {}

        def read(self, *tags):
            if tags[0] == "T040":
                reached.set()  # the user stops the scan during this batch
                release.wait(10)
            return [Tag(tag, 1, "DINT", None) for tag in tags]

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=NetworkConfig(packet_interval_ms=0, request_timeout_ms=20000))
        handler._client, handler._connected, handler._plc_type = Client(), True, "logix"
        task = asyncio.ensure_future(handler.read_tags([f"T{i:03d}" for i in range(100)]))
        # No fixed sleeps: wait until the third batch is being read
        assert await asyncio.get_running_loop().run_in_executor(None, reached.wait, 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
        partial = list(handler.partial_points)
        release.set()  # the worker thread ends
        return partial

    partial = asyncio.run(run())
    assert [p.address for p in partial] == [f"T{i:03d}" for i in range(40)]  # was nothing


class _Logix:
    """LogixDriver stand-in driven by a shared state dict"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self._tags = {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)}
        self._data_types: dict = {}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)

    def open(self):
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        if not self.state.get("cpu_ok", True):
            # The Ethernet module registers the session, the CPU does not answer
            raise ResponseError("Failed to get PLC info")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False  # switched off during this batch
            raise CommError("failed to receive reply")
        if self.state.get("slow"):
            time.sleep(0.3)
        return [Tag(tag, 1, "DINT", None) for tag in tags]


class _Other:
    """SLCDriver / CIPDriver stand-in: opens while the device is up"""

    def __init__(self, path):
        self.path = path

    def open(self):
        if not _Logix.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def _list_identity(self):
        return {"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Communications Adapter"}

    def close(self):
        pass


@pytest.fixture
def logix(monkeypatch):
    _Logix.state = {}
    monkeypatch.setattr(pycomm3, "LogixDriver", _Logix)
    monkeypatch.setattr(pycomm3, "SLCDriver", _Other)
    monkeypatch.setattr(pycomm3, "CIPDriver", _Other)
    return _Logix.state


def test_link_lost_during_a_tag_scan_is_a_communication_error(logix):
    logix["off_at"] = "T020"

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect()
        points = await handler.read_tags(handler.tag_scan_list())
        return handler, points, await handler.read_tags(["T000", "T001"])

    handler, points, later = asyncio.run(run())
    assert Counter(p.status for p in points) == {StatusCode.OK: 20, StatusCode.NG_COMM_ERROR: 80}
    # Not "unsupported": that was learned as denied and taken for an answer
    assert handler.get_denied_addresses() == set()
    assert {p.status for p in later} == {StatusCode.NG_COMM_ERROR} and not plc_answered(later)


def test_logix_controller_stays_logix_when_a_reconnect_fails(logix):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect() and handler._plc_type == "logix"
        logix["slow"] = True  # one slow request: timeout, reconnect before the next
        timed_out = await handler.read_tags(["T000"])
        logix["slow"] = False
        logix["cpu_ok"] = False  # the CPU is still busy while the reconnect runs
        failed = await handler.read_tags(["T000"])
        kind_after_failure = handler._plc_type
        logix["cpu_ok"] = True
        recovered = await handler.read_tags(["T000"])
        await asyncio.sleep(0.4)  # the slow worker thread ends
        return handler, timed_out, failed, kind_after_failure, recovered

    handler, timed_out, failed, kind_after_failure, recovered = asyncio.run(run())
    assert timed_out[0].status == StatusCode.NG_TIMEOUT
    assert failed[0].status == StatusCode.NG_COMM_ERROR
    assert kind_after_failure == "logix"  # was "generic": tag list gone, path without the slot
    assert recovered[0].status == StatusCode.OK
    assert handler._plc_type == "logix" and len(handler.tag_scan_list()) == 100


def test_a_device_that_was_never_logix_still_falls_back_to_generic_cip(logix):
    logix["cpu_ok"] = False

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        return await handler.connect(), handler._plc_type

    assert asyncio.run(run()) == (True, "generic")


@pytest.mark.parametrize("name", ["NoSuchTag", "ConnectionStatus", "Pump1_Busy", "Cycle_Timeout"])
def test_missing_tag_is_an_address_error_whatever_it_is_called(name):
    reply = Tag(name, None, None, f"Tag doesn't exist - {name}")  # pycomm3 puts the name into the text
    assert [p.status for p in _tag_points(name, reply)] == [StatusCode.NG_ILLEGAL_ADDR]  # was NG_COMM_ERROR


def test_structure_member_that_does_not_exist_is_an_address_error():
    reply = Tag("Speed.Busy", None, None, "failed to get tag data for: Speed, ['Busy']")
    assert _tag_points("Speed.Busy", reply)[0].status == StatusCode.NG_ILLEGAL_ADDR


def test_transient_texts_are_the_ones_pycomm3_really_uses():
    for text in ("Insufficient resource", "Controller in upload or download mode", "No buffer memory"):
        assert not _is_address_error(text), text
    for text in ("Path segment error - Symbol does not exist", "Address out of range", "Privilege failure"):
        assert _is_address_error(text), text


FAST_2 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


class _Logix_2:
    """LogixDriver stand-in; ``state`` is shared by every instance"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self.state.setdefault("created", []).append(init_tags)
        self._tags = (
            {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)} if init_tags else {}
        )
        self._data_types: dict = {}
        self._cfg = {"use_instance_ids": True}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)
    info = property(lambda self: {"serial": self.state.get("serial", "A1"), "name": "Line1"})

    def open(self):
        self.state["opens"] = self.state.get("opens", 0) + 1
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False
            raise CommError("failed to receive reply")
        self.state["instance_ids"] = self._cfg["use_instance_ids"]
        return [Tag(tag, 1, "DINT", None) for tag in tags]


@pytest.fixture
def logix_2(monkeypatch):
    _Logix_2.state = {}
    for driver in ("LogixDriver", "SLCDriver", "CIPDriver"):
        monkeypatch.setattr(pycomm3, driver, _Logix_2)
    return _Logix_2.state


def test_one_reconnect_attempt_per_tag_read_after_the_link_is_lost(logix_2):
    logix_2["off_at"] = "T100"

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST_2)
        assert await handler.connect()
        opens = logix_2["opens"]
        points = await handler.read_tags([f"T{i:03d}" for i in range(2000)])
        return points, logix_2["opens"] - opens

    points, reconnects = asyncio.run(run())
    assert Counter(p.status for p in points) == {StatusCode.OK: 100, StatusCode.NG_COMM_ERROR: 1900}
    assert reconnects == 1  # was one for each of the 94 remaining batches, without the packet interval


FAST_3 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


class _Logix_3:
    """LogixDriver stand-in; ``state`` is shared by every instance"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self.state.setdefault("created", []).append(init_tags)
        self._tags = (
            {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)} if init_tags else {}
        )
        self._data_types: dict = {}
        self._cfg = {"use_instance_ids": True}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)
    info = property(lambda self: {"serial": self.state.get("serial", "A1"), "name": "Line1"})

    def open(self):
        self.state["opens"] = self.state.get("opens", 0) + 1
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False
            raise CommError("failed to receive reply")
        self.state["instance_ids"] = self._cfg["use_instance_ids"]
        return [Tag(tag, 1, "DINT", None) for tag in tags]


@pytest.fixture
def logix_3(monkeypatch):
    _Logix_3.state = {}
    for driver in ("LogixDriver", "SLCDriver", "CIPDriver"):
        monkeypatch.setattr(pycomm3, driver, _Logix_3)
    return _Logix_3.state


def test_reused_tag_definitions_are_requested_by_name(logix_3):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST_3)
        assert await handler.connect()
        await handler.read_tags(["T000"])
        first = logix_3["instance_ids"]
        assert await handler.reconnect()
        points = await handler.read_tags(["T000"])
        return first, logix_3["instance_ids"], points, len(handler.tag_scan_list())

    first, after_reconnect, points, tags = asyncio.run(run())
    assert first is True
    # The instance IDs of the reused list may belong to other tags after a
    # program download: another tag's value was recorded under the old name
    assert after_reconnect is False
    assert points[0].status == StatusCode.OK and tags == 100
    assert logix_3["created"] == [True, False]  # the tag list was not uploaded again


FAST_4 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


class _Logix_4:
    """LogixDriver stand-in; ``state`` is shared by every instance"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self.state.setdefault("created", []).append(init_tags)
        self._tags = (
            {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)} if init_tags else {}
        )
        self._data_types: dict = {}
        self._cfg = {"use_instance_ids": True}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)
    info = property(lambda self: {"serial": self.state.get("serial", "A1"), "name": "Line1"})

    def open(self):
        self.state["opens"] = self.state.get("opens", 0) + 1
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False
            raise CommError("failed to receive reply")
        self.state["instance_ids"] = self._cfg["use_instance_ids"]
        return [Tag(tag, 1, "DINT", None) for tag in tags]


@pytest.fixture
def logix_4(monkeypatch):
    _Logix_4.state = {}
    for driver in ("LogixDriver", "SLCDriver", "CIPDriver"):
        monkeypatch.setattr(pycomm3, driver, _Logix_4)
    return _Logix_4.state


def test_another_controller_on_the_address_gets_its_own_tag_list(logix_4):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST_4)
        assert await handler.connect()
        logix_4["serial"] = "B2"  # the controller was replaced
        assert await handler.reconnect()
        await handler.read_tags(["T000"])
        return logix_4["instance_ids"], len(handler.tag_scan_list())

    instance_ids, tags = asyncio.run(run())
    assert logix_4["created"] == [True, False, True]  # reconnect without tags, then the upload
    assert instance_ids is True and tags == 100


@pytest.mark.parametrize(
    "value, type_name, expected",
    [
        (-1, "DINT", "0xFFFFFFFF"),
        (-1, "INT", "0xFFFF"),
        (-1, "LINT", "0xFFFFFFFFFFFFFFFF"),
        (0x1_0000_0001, "LINT", "0x0000000100000001"),
        (2**63, "ULINT", "0x8000000000000000"),
        (5, "DINT[10]", "0x00000005"),
        (1, "BOOL", "0x01"),
        (-1, "SINT", "0xFF"),
        # Type unknown (structure member): the smallest width holding the value
        (0x1_0000_0001, None, "0x0000000100000001"),
        (-40000, None, "0xFFFF63C0"),
        (7, None, "0x0007"),
    ],
)
def test_tag_hex_keeps_the_width_of_the_type(value, type_name, expected):
    assert _tag_hex(value, type_name) == expected


def test_tag_points_use_the_reply_type():
    reply = MagicMock(error=None, value=[-1, 2], type="DINT[2]")
    assert [p.raw_hex for p in _tag_points("Arr[0]{2}", reply)] == ["0xFFFFFFFF", "0x00000002"]
    assert [p.raw_hex for p in _value_points("Big", 2**40, "LINT")] == ["0x0000010000000000"]
    # Members of a structure are not formatted with the structure's type name
    members = _value_points("Udt", {"A": -1, "B": 70000}, "MyUdt")
    assert [(p.address, p.raw_hex) for p in members] == [("Udt.A", "0xFFFF"), ("Udt.B", "0x00011170")]


FAST_5 = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


def test_logix_reconnect_reuses_the_tag_list():
    created = []

    class FakeLogixDriver:
        def __init__(self, path, init_tags=True):
            self.init_tags = init_tags
            self._tags = {}
            self._data_types = {}
            created.append(self)

        def open(self):
            if self.init_tags:  # the upload pycomm3 does on connect
                self._tags = {"Speed": {"tag_type": "atomic"}}
                self._data_types = {"MyUdt": {}}

        def close(self):
            pass

        @property
        def tags(self):  # as pycomm3: the public view of _tags
            return self._tags

    async def run():
        handler = EtherNetIPHandler("127.0.0.1", config=FAST_5)
        with patch("pycomm3.LogixDriver", FakeLogixDriver):
            assert await handler.connect()
            await handler.disconnect()
            assert await handler.connect()
        return handler

    handler = asyncio.run(run())
    assert [driver.init_tags for driver in created] == [True, False]
    assert created[1]._tags == {"Speed": {"tag_type": "atomic"}} and created[1]._data_types == {"MyUdt": {}}
    assert handler.tag_scan_list() == ["Speed"]


def test_full_scan_reads_the_first_element_of_multi_dimensional_arrays():
    handler = EtherNetIPHandler("127.0.0.1")
    handler._plc_type = "logix"
    handler._client = MagicMock(
        tags={
            "Grid": {"tag_type": "atomic", "dimensions": [4, 5, 0]},
            "Row": {"tag_type": "atomic", "dimensions": [8, 0, 0]},
            "Speed": {"tag_type": "atomic", "dimensions": [0, 0, 0]},
        }
    )
    assert handler.tag_scan_list() == ["Grid[0,0]", "Row[0]{8}", "Speed"]
