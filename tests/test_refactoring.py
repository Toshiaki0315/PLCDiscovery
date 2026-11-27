"""
Tests for helpers introduced by refactoring (behaviour kept):
names.py (one parser for protocol / device / byte order names) and the
shared statistics helpers.
"""

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, DeviceType, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder
from plc_discovery.names import parse_byte_order, parse_device_type, parse_protocol
from plc_discovery.utils import status_counts, success_rate_text


@pytest.mark.parametrize(
    "name,expected",
    [
        ("slmp", Protocol.SLMP),
        ("MC", Protocol.SLMP),
        ("eip", Protocol.ETHERNET_IP),
        ("ethernet_ip", Protocol.ETHERNET_IP),
        ("cip", Protocol.ETHERNET_IP),
        ("modbus", Protocol.MODBUS_TCP),
        ("modbus_tcp", Protocol.MODBUS_TCP),
        ("s7", Protocol.S7),
        ("s7comm", Protocol.S7),
        ("fins", Protocol.FINS),
        ("fins_udp", Protocol.FINS),
        ("fins_tcp", Protocol.FINS_TCP),
        ("FINS-TCP", Protocol.FINS_TCP),
        (" slmp ", Protocol.SLMP),
        ("", None),
        (None, None),
        ("profinet", None),
    ],
)
def test_protocol_names_same_everywhere(name, expected):
    assert parse_protocol(name) == expected
    assert plc_scanner.get_protocol_from_string(name) == expected
    assert ConfigLoader()._parse_protocol(name) == expected


@pytest.mark.parametrize("name", [d.value for d in DeviceType] + [d.value.lower() for d in DeviceType])
def test_device_names(name):
    expected = DeviceType(name.upper())
    assert parse_device_type(name) == expected
    assert plc_scanner.get_device_type_from_string(name) == expected
    assert ConfigLoader()._parse_device_type(name) == expected


def test_unknown_device_and_byte_order():
    assert parse_device_type("QQ") is None and parse_device_type("") is None
    assert parse_byte_order("middle") is None
    assert {name: parse_byte_order(name) for name in ("little", "BIG", "little_swap", "big_swap")} == {
        "little": ByteOrder.LITTLE_ENDIAN,
        "BIG": ByteOrder.BIG_ENDIAN,
        "little_swap": ByteOrder.LITTLE_ENDIAN_WORD_SWAP,
        "big_swap": ByteOrder.BIG_ENDIAN_WORD_SWAP,
    }
    assert plc_scanner.BYTE_ORDER_MAP == {o.value: o for o in ByteOrder}


def test_status_helpers():
    points = [
        DataPoint("D0", 1, None, StatusCode.OK),
        DataPoint("D1", None, None, StatusCode.NG_TIMEOUT),
        DataPoint("D2", 2, None, StatusCode.OK),
    ]
    counts = status_counts(points)
    assert counts[StatusCode.OK] == 2 and counts[StatusCode.NG_TIMEOUT] == 1
    assert counts[StatusCode.NG_UNSUPPORTED] == 0
    assert success_rate_text(2, 3) == "66.67%"
    assert success_rate_text(0, 0) == "N/A"
