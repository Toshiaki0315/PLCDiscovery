"""
Regression tests for the twelfth review's findings.

C1: CLI discovery stores every endpoint (IP, protocol, port) in the database.
C2: broadcast replies use the shared CIP identity parser, and TCP results
    win over broadcast results when both describe the same endpoint.
Minor: EtherNet/IP (SLC) words are reported unsigned like other protocols.
"""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.config import DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.discovery import merge_discovery_results
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler


def list_identity(vendor_id, product_name, device_type=0x0E):
    name = product_name.encode()
    body = struct.pack("<HHHBBHI", vendor_id, device_type, 1, 1, 2, 0, 0x1234) + bytes([len(name)]) + name + b"\x03"
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    return (struct.pack("<HHII", 0x63, 2 + 4 + len(item), 0, 0) + b"\x00" * 8 + struct.pack("<I", 0)
            + struct.pack("<HHH", 1, 0x0C, len(item)) + item)


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


# ---------------------------------------------------------------------------
# C1
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cli_discovery_stores_every_endpoint_in_database():
    found = [PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001),
             PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502)]
    db = MagicMock()
    db.is_enabled = True
    db.export_discovery_results.return_value = 2
    with patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=found)), \
            patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[])):
        await plc_scanner.run_discovery([], NetworkConfig(), MagicMock(), Display(), db)
    stored = db.export_discovery_results.call_args.args[0]
    assert [(p.protocol, p.port) for p in stored] == [(Protocol.SLMP, 5001), (Protocol.MODBUS_TCP, 1502)]


# ---------------------------------------------------------------------------
# C2
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vendor_id, vendor", [
    (47, "Omron Corporation"),          # previously "Vendor 47"
    (367, "Keyence Corporation"),
    (1, "Rockwell Automation/Allen-Bradley"),
])
def test_broadcast_identity_uses_cip_vendor_names(vendor_id, vendor):
    plc = BroadcastDiscovery()._parse_eip_response("10.0.0.5", list_identity(vendor_id, "NJ501-1300"))
    assert plc.manufacturer == vendor
    assert plc.model == "NJ501-1300"


def test_broadcast_vendor_2_is_not_omron():
    plc = BroadcastDiscovery()._parse_eip_response("10.0.0.5", list_identity(2, "X"))
    assert "Omron" not in plc.manufacturer and "オムロン" not in plc.manufacturer


@pytest.mark.asyncio
async def test_broadcast_keeps_both_protocols_of_one_host():
    discovery = BroadcastDiscovery()
    slmp = b"\xD0\x00" + b"\x00" * 20

    async def send(port, data, timeout):
        return {"10.0.0.7": slmp if port == 5001 else list_identity(367, "KV-8000")}

    with patch.object(discovery, "_send_broadcast", send):
        plcs = await discovery.discover_all_broadcast()
    assert sorted(p.protocol.name for p in plcs) == ["ETHERNET_IP", "SLMP"]   # previously one
    assert len(discovery.get_results()) == 2


def test_merge_prefers_primary_and_fills_gaps():
    tcp = PLCInfo("10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818,
                  manufacturer="Omron Corporation", model="NJ501-1300")
    broadcast = PLCInfo("10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818,
                        manufacturer="Vendor 47", mac_address="00:00:0a:12:34:56")
    only_broadcast = PLCInfo("10.0.0.9", protocol=Protocol.SLMP, port=5001)
    merged = merge_discovery_results([tcp], [broadcast, only_broadcast])
    assert merged == [tcp, only_broadcast]
    assert (tcp.manufacturer, tcp.model, tcp.mac_address) == (
        "Omron Corporation", "NJ501-1300", "00:00:0a:12:34:56",
    )


@pytest.mark.asyncio
async def test_cli_discovery_keeps_tcp_identity_over_broadcast():
    tcp = PLCInfo("10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818,
                  manufacturer="Omron Corporation", model="NJ501-1300")
    broadcast = PLCInfo("10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="Vendor 47")
    with patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=[tcp])), \
            patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[broadcast])):
        plcs = await plc_scanner.run_discovery([], NetworkConfig(), MagicMock(), Display())
    assert [(p.manufacturer, p.model) for p in plcs] == [("Omron Corporation", "NJ501-1300")]


# ---------------------------------------------------------------------------
# Minor: unsigned EtherNet/IP words
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_eip_slc_words_unsigned():
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    client = MagicMock()
    client.read.return_value = MagicMock(error=None, value=[-1, -32768, 5])
    handler._client, handler._connected, handler._plc_type = client, True, "slc"
    assert await handler.read_device_raw(DeviceType.D, 0, 3) == ([0xFFFF, 0x8000, 5], StatusCode.OK)
