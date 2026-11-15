"""
Regression tests for the sixth review's findings (W1-W3).
"""

import asyncio
import json
import logging
import math
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery import broadcast_discovery as broadcast_module
from plc_discovery import discovery as discovery_module
from plc_discovery import utils
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.config import DataPoint, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.report import ReportConfig, ReportFormat, create_report, json_safe


# ---------------------------------------------------------------------------
# W1 / W2: every local network, also without a default gateway
# ---------------------------------------------------------------------------

MACOS_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.8 netmask 0xffffff00 broadcast 192.168.1.255
en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.10.0.5 netmask 0xffff0000 broadcast 10.10.255.255
en8: flags=8863<UP> mtu 1500
\tinet 169.254.12.34 netmask 0xffff0000 broadcast 169.254.255.255
"""

LINUX_IP = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 172.16.5.20/24 brd 172.16.5.255 scope global eth0\\       valid_lft forever
3: tun0    inet 10.8.0.2/32 scope global tun0
"""

OLD_LINUX_IFCONFIG = "eth0  Link encap:Ethernet\n      inet addr:192.168.50.3  Bcast:192.168.50.255  Mask:255.255.255.0\n"

WINDOWS_POWERSHELL = "192.168.10.2/24\r\n127.0.0.1/8\r\n169.254.3.4/16\r\n"


class TestInterfaceParsing:

    def test_macos_ifconfig(self):
        assert utils.parse_interface_listing(MACOS_IFCONFIG) == [
            ("127.0.0.1", "255.0.0.0"), ("192.168.1.8", "255.255.255.0"),
            ("10.10.0.5", "255.255.0.0"), ("169.254.12.34", "255.255.0.0"),
        ]

    def test_linux_ip_addr(self):
        assert ("172.16.5.20", "255.255.255.0") in utils.parse_interface_listing(LINUX_IP)

    def test_old_linux_ifconfig(self):
        assert utils.parse_interface_listing(OLD_LINUX_IFCONFIG) == [("192.168.50.3", "255.255.255.0")]

    def test_windows_powershell(self):
        assert ("192.168.10.2", "255.255.255.0") in utils.parse_interface_listing(WINDOWS_POWERSHELL)


def networks_with(listing):
    with patch.object(utils, "_networks_from_netifaces", return_value=None), \
            patch.object(utils, "_networks_from_os", return_value=utils.parse_interfaces(listing)):
        return utils.get_local_networks()


def test_all_networks_listed_without_loopback_link_local_or_p2p():
    assert networks_with(MACOS_IFCONFIG) == [("192.168.1.8", "255.255.255.0"), ("10.10.0.5", "255.255.0.0")]
    assert networks_with(LINUX_IP) == [("172.16.5.20", "255.255.255.0")]   # tun0 /32 skipped


def test_isolated_lan_without_default_gateway():
    """Previously fell back to 127.0.0.1/24 when 8.8.8.8 was unreachable"""
    def unreachable(*args, **kwargs):
        raise OSError(51, "Network is unreachable")

    with patch.object(utils, "_networks_from_netifaces", return_value=None), \
            patch.object(utils, "_networks_from_os", return_value=[("eth1", "10.10.0.5", "255.255.255.0")]), \
            patch.object(socket.socket, "connect", unreachable):
        assert utils.get_network_info() == ("10.10.0.5", "255.255.255.0", "10.10.0.255")


@pytest.mark.asyncio
async def test_same_segment_scans_every_network():
    discovery = PLCDiscovery(NetworkConfig())
    scanned = []

    async def fake_probe_hosts(hosts, mac_table):
        scanned.append((hosts[0], hosts[-1], len(hosts)))

    networks = [("192.168.1.8", "255.255.255.0"), ("10.10.0.5", "255.255.255.252")]
    with patch.object(discovery_module, "get_local_networks", return_value=networks), \
            patch.object(discovery_module, "SCAPY_AVAILABLE", False), \
            patch.object(discovery, "_probe_hosts", side_effect=fake_probe_hosts), \
            patch.object(discovery, "_fill_macs_from_arp_cache", AsyncMock()):
        await discovery.discover_same_segment()

    assert scanned == [("192.168.1.1", "192.168.1.254", 253), ("10.10.0.6", "10.10.0.6", 1)]


@pytest.mark.asyncio
async def test_no_network_found_warns_and_returns_empty(caplog):
    discovery = PLCDiscovery(NetworkConfig())
    with patch.object(discovery_module, "get_local_networks", return_value=[]), caplog.at_level(logging.WARNING):
        assert await discovery.discover_same_segment() == []
    assert any("No IPv4 network found" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_broadcast_sent_to_every_network():
    sent = []
    transport = MagicMock()
    transport.sendto.side_effect = lambda data, addr: sent.append(addr[0])
    loop = asyncio.get_running_loop()
    networks = [("192.168.1.8", "255.255.255.0"), ("10.10.0.5", "255.255.0.0")]
    with patch.object(broadcast_module, "get_local_networks", return_value=networks), \
            patch.object(loop, "create_datagram_endpoint", AsyncMock(return_value=(transport, None))):
        await BroadcastDiscovery()._send_broadcast(44818, b"x", 0.01)
    assert sent == ["192.168.1.255", "10.10.255.255", "255.255.255.255"]


# ---------------------------------------------------------------------------
# W3: NaN / Infinity never written as non-standard JSON
# ---------------------------------------------------------------------------

def strict_loads(text):
    return json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))


def test_json_safe():
    assert json_safe({"a": [1.5, math.nan, {"b": math.inf}], "c": "NaN"}) == {"a": [1.5, None, {"b": None}], "c": "NaN"}


def test_json_report_is_strict_json():
    dp = DataPoint("D0", 0xFFFF, "0xFFFF", StatusCode.OK, data_type="FLOAT",
                   converted_value=math.nan, display_value="nan")
    generator, data = create_report([PLCInfo("10.0.0.1", protocol=Protocol.SLMP)], {"10.0.0.1": [dp]}, {},
                                    "range", None, None, ReportConfig(format=ReportFormat.JSON))
    report = strict_loads(generator.generate(data))
    assert "NaN" not in json.dumps(report)


def test_database_stores_nan_as_null(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db")))
    db.export_plc_data([DataPoint("D0", 0xFFFF, "0xFFFF", StatusCode.OK, converted_value=math.inf)], "10.0.0.1")
    (stored,) = db._connection.execute("SELECT converted_value FROM data_points").fetchone()
    assert stored == "null"
    db.close()
