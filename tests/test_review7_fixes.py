"""
Regression tests for the seventh review's finding (X1): automatic discovery
must not spend tens of minutes on virtual or very large networks.
"""

import logging
import time
from unittest.mock import AsyncMock, patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery import utils
from plc_discovery.config import NetworkConfig, Protocol
from plc_discovery.discovery import MAX_AUTO_SCAN_PREFIX, PLCDiscovery

WINDOWS_POWERSHELL = """\
イーサネット|192.168.10.2/24
制御LAN|10.20.0.5/24
vEthernet (WSL)|172.27.48.1/20
vEthernet (Default Switch)|172.20.16.1/20
VMware Network Adapter VMnet8|192.168.80.1/24
Loopback Pseudo-Interface 1|127.0.0.1/8
"""

MACOS_IFCONFIG = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.8 netmask 0xffffff00 broadcast 192.168.1.255
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.99.0.2 netmask 0xffffff00
"""

LINUX_IP = """\
2: eth0    inet 172.16.5.20/24 brd 172.16.5.255 scope global eth0
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
4: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
"""


def networks_from(listing, **kwargs):
    with (
        patch.object(utils, "_networks_from_netifaces", return_value=None),
        patch.object(utils, "_networks_from_os", return_value=utils.parse_interfaces(listing)),
    ):
        return utils.get_local_networks(**kwargs)


class TestVirtualAdapters:

    def test_names_parsed(self):
        names = [name for name, _, _ in utils.parse_interfaces(WINDOWS_POWERSHELL)]
        assert names[:3] == ["イーサネット", "制御LAN", "vEthernet (WSL)"]
        assert [n for n, _, _ in utils.parse_interfaces(MACOS_IFCONFIG)] == ["en0", "bridge100", "utun3"]
        assert [n for n, _, _ in utils.parse_interfaces(LINUX_IP)] == ["eth0", "docker0", "virbr0"]

    def test_windows_virtual_adapters_skipped(self):
        assert networks_from(WINDOWS_POWERSHELL) == [("192.168.10.2", "255.255.255.0"), ("10.20.0.5", "255.255.255.0")]

    def test_macos_and_linux_virtual_adapters_skipped(self):
        assert networks_from(MACOS_IFCONFIG) == [("192.168.1.8", "255.255.255.0")]
        assert networks_from(LINUX_IP) == [("172.16.5.20", "255.255.255.0")]

    def test_include_virtual(self):
        assert len(networks_from(WINDOWS_POWERSHELL, include_virtual=True)) == 5

    @pytest.mark.parametrize(
        "name, virtual",
        [
            ("vEthernet (WSL)", True),
            ("VMware Network Adapter VMnet1", True),
            ("VirtualBox Host-Only Network", True),
            ("docker0", True),
            ("br-1a2b3c", True),
            ("utun0", True),
            ("tailscale0", True),
            ("イーサネット 2", False),
            ("Ethernet", False),
            ("en0", False),
            ("eth0", False),
            ("enp3s0", False),
            ("", False),
        ],
    )
    def test_is_virtual_interface(self, name, virtual):
        assert utils.is_virtual_interface(name) is virtual


@pytest.mark.asyncio
async def test_large_networks_skipped_in_auto_scan(caplog):
    discovery = PLCDiscovery(NetworkConfig())
    scanned = []
    networks = [("10.20.0.5", "255.255.255.0"), ("172.16.0.5", "255.255.240.0"), ("10.30.0.5", "255.255.252.0")]
    with (
        patch.object(discovery_module, "get_local_networks", return_value=networks),
        patch.object(discovery_module, "SCAPY_AVAILABLE", False),
        patch.object(discovery, "_probe_hosts", AsyncMock(side_effect=lambda hosts, macs: scanned.append(len(hosts)))),
        patch.object(discovery, "_fill_macs_from_arp_cache", AsyncMock()),
        caplog.at_level(logging.WARNING),
    ):
        await discovery.discover_same_segment()
    assert MAX_AUTO_SCAN_PREFIX == 22
    assert scanned == [253, 1021]  # /24 and /22 scanned, /20 skipped
    assert any("Skipping 172.16.0.0/20" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_protocols_of_a_host_probed_in_parallel():
    """A silent host costs about one timeout, not one per protocol"""

    def slow_closed_port(ip, port, timeout):
        time.sleep(0.3)
        return False

    def slow_no_reply(ip, port, protocol, timeout):
        time.sleep(0.3)
        return False

    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", side_effect=slow_closed_port),
        patch.object(discovery_module, "verify_protocol", side_effect=slow_no_reply),
    ):
        started = time.monotonic()
        assert await discovery._probe_host_all("192.0.2.77") == []
        elapsed = time.monotonic() - started
    assert elapsed < 1.0  # sequential would be 6 x 0.3 s = 1.8 s


@pytest.mark.asyncio
async def test_parallel_probing_keeps_protocol_order():
    answering = {(5001, Protocol.SLMP), (9600, Protocol.FINS), (102, Protocol.S7)}

    def delayed_verify(ip, port, protocol, timeout):
        time.sleep(0.2 if protocol == Protocol.SLMP else 0.0)  # SLMP answers last
        return (port, protocol) in answering

    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", side_effect=lambda ip, p, t: p in (5001, 102)),
        patch.object(discovery_module, "verify_protocol", side_effect=delayed_verify),
        patch.object(discovery, "_get_detailed_info", AsyncMock(side_effect=lambda plc: plc)),
    ):
        found = await discovery._probe_host_all("192.0.2.50")
        primary = await discovery._probe_host("192.0.2.50")
    assert [p.protocol for p in found] == [Protocol.SLMP, Protocol.S7, Protocol.FINS]
    assert primary.protocol == Protocol.SLMP
