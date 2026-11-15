"""
EtherNet/IP identity parsing used by discovery (ListIdentity).
"""

import logging
import struct
from unittest.mock import patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.probes import parse_eip_identity


def list_identity_reply(vendor=1, device_type=0x0E, name=b"1756-L71/B LOGIX5571", with_state=True):
    body = struct.pack("<HHH", vendor, device_type, 55) + bytes([20, 13]) + struct.pack("<HI", 0, 0x12345678)
    body += bytes([len(name)]) + name + (bytes([3]) if with_state else b"")
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    data = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(item)) + item
    return struct.pack("<HHII", 0x0063, len(data), 0, 0) + b"ctx12345" + struct.pack("<I", 0) + data


@pytest.mark.parametrize("with_state", [True, False])
def test_parse_identity_with_and_without_state(with_state):
    identity = parse_eip_identity(list_identity_reply(with_state=with_state))
    assert identity["vendor_id"] == 1
    assert identity["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert identity["product_type"] == "Programmable Logic Controller"
    assert identity["product_name"] == "1756-L71/B LOGIX5571"
    assert identity["revision"] == "20.13"
    assert identity["serial"] == "12345678"


@pytest.mark.parametrize("reply", [b"", b"\x00" * 30, list_identity_reply()[:30]])
def test_parse_identity_rejects_garbage(reply):
    assert parse_eip_identity(reply) is None


@pytest.mark.asyncio
async def test_discovery_sets_identity_without_errors(caplog):
    discovery = PLCDiscovery(NetworkConfig())
    plc = PLCInfo("127.0.0.1", protocol=Protocol.ETHERNET_IP, port=44818)
    identity = parse_eip_identity(list_identity_reply(vendor=47, device_type=0x0E, name=b"NJ501-1300"))
    with patch.object(discovery_module, "read_eip_identity", return_value=identity), \
            caplog.at_level(logging.DEBUG):
        result = await discovery._query_eip_info(plc)
    assert result.manufacturer == "Omron Corporation"
    assert result.model == "NJ501-1300"
    assert result.firmware_version == "20.13"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.asyncio
async def test_discovery_keeps_values_when_no_identity():
    discovery = PLCDiscovery(NetworkConfig())
    plc = PLCInfo("127.0.0.1", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="オムロン")
    with patch.object(discovery_module, "read_eip_identity", return_value=None):
        result = await discovery._query_eip_info(plc)
    assert result.manufacturer == "オムロン" and result.model is None
