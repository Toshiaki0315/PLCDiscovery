"""
Tests for reading MAC addresses from the OS ARP cache (no root required)
and for the ARP scan permission message.
"""

import logging
from unittest.mock import patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import ARP_SKIPPED_MESSAGE, PLCDiscovery
from plc_discovery.utils import normalize_mac, parse_arp_table

MACOS = """\
? (192.168.1.1) at 54:9b:49:3e:de:b0 on en0 ifscope [ethernet]
? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.3) at 0:24:a5:47:e3:da on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""

LINUX_ARP = """\
? (10.0.0.5) at 00:0a:dc:12:34:56 [ether] on eth0
? (10.0.0.6) at <incomplete> on eth0
"""

PROC_NET_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.7         0x1         0x2         00:1b:1b:aa:bb:cc     *        eth0
10.0.0.8         0x1         0x0         00:00:00:00:00:00     *        eth0
"""

WINDOWS = """\
インターフェイス: 192.168.10.2 --- 0x7
  インターネット アドレス 物理アドレス           種類
  192.168.10.1          00-00-1c-01-02-03     動的
  192.168.10.255        ff-ff-ff-ff-ff-ff     静的
"""


class TestParse:

    def test_macos(self):
        assert parse_arp_table(MACOS) == {
            "192.168.1.1": "54:9B:49:3E:DE:B0",
            "192.168.1.3": "00:24:A5:47:E3:DA",   # leading zeros restored
        }

    def test_linux_arp_command(self):
        assert parse_arp_table(LINUX_ARP) == {"10.0.0.5": "00:0A:DC:12:34:56"}

    def test_proc_net_arp(self):
        assert parse_arp_table(PROC_NET_ARP) == {"10.0.0.7": "00:1B:1B:AA:BB:CC"}

    def test_windows_with_japanese_headers(self):
        text = WINDOWS.encode("cp932").decode("ascii", errors="ignore")
        assert parse_arp_table(text) == {"192.168.10.1": "00:00:1C:01:02:03"}

    @pytest.mark.parametrize("mac, expected", [
        ("0:1c:42:a:b:c", "00:1C:42:0A:0B:0C"),
        ("00-1C-42-0A-0B-0C", "00:1C:42:0A:0B:0C"),
        ("ff:ff:ff:ff:ff:ff", None),
        ("00:00:00:00:00:00", None),
        ("00:1c:42:0a:0b", None),
    ])
    def test_normalize(self, mac, expected):
        assert normalize_mac(mac) == expected


@pytest.mark.asyncio
async def test_discovery_fills_mac_and_manufacturer_from_cache():
    discovery = PLCDiscovery(NetworkConfig())
    discovery.discovered_plcs = {
        "10.0.0.1": PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
        "10.0.0.2": PLCInfo("10.0.0.2", protocol=Protocol.FINS, port=9600,
                            mac_address="AA:BB:CC:DD:EE:FF", manufacturer="オムロン"),
        "172.16.0.9": PLCInfo("172.16.0.9", protocol=Protocol.S7, port=102),   # routed: not in cache
    }
    cache = {"10.0.0.1": "00:00:1C:12:34:56", "10.0.0.2": "11:22:33:44:55:66"}
    with patch.object(discovery_module, "read_arp_cache", return_value=cache):
        await discovery._fill_macs_from_arp_cache()

    plcs = discovery.discovered_plcs
    assert plcs["10.0.0.1"].mac_address == "00:00:1C:12:34:56"
    assert plcs["10.0.0.1"].manufacturer == "三菱電機"            # from OUI
    assert plcs["10.0.0.2"].mac_address == "AA:BB:CC:DD:EE:FF"   # existing value kept
    assert plcs["172.16.0.9"].mac_address is None


@pytest.mark.asyncio
async def test_permission_error_is_info_not_warning(caplog):
    if not discovery_module.SCAPY_AVAILABLE:
        pytest.skip("scapy not installed")
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100))
    error = PermissionError("Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)")
    with patch.object(discovery_module, "srp", side_effect=error), caplog.at_level(logging.INFO):
        assert await discovery._arp_scan("192.168.1.10", "255.255.255.0") == {}
    messages = [(r.levelno, r.getMessage()) for r in caplog.records if r.name == discovery_module.logger.name]
    assert (logging.INFO, ARP_SKIPPED_MESSAGE) in messages
    assert not any(level >= logging.WARNING for level, _ in messages)
