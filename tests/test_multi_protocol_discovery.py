"""
Discovery lists every protocol a host answers (multi-protocol PLCs, PCs
running the simulators) and probes the simulator ports on loopback.
"""

from unittest.mock import AsyncMock, patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import PLCDiscovery, SIMULATOR_PORTS, plc_key


def fake_network(open_endpoints):
    """Patch port checks / probes so only the given (port, protocol) pairs answer"""
    ports = {port for port, _ in open_endpoints}
    return (
        patch.object(discovery_module, "is_port_open", side_effect=lambda ip, p, t: p in ports),
        patch.object(discovery_module, "verify_protocol",
                     side_effect=lambda ip, p, proto, t: (p, proto) in open_endpoints),
    )


async def probe(ip, endpoints, **kwargs):
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100), **kwargs)
    port_patch, verify_patch = fake_network(endpoints)
    with port_patch, verify_patch, patch.object(discovery, "_get_detailed_info",
                                                AsyncMock(side_effect=lambda plc: plc)):
        return await discovery._probe_host_all(ip), await discovery._probe_host(ip)


@pytest.mark.asyncio
async def test_all_verified_protocols_listed():
    endpoints = {(5001, Protocol.SLMP), (44818, Protocol.ETHERNET_IP), (9600, Protocol.FINS)}
    found, primary = await probe("192.0.2.50", endpoints)
    assert [(p.protocol, p.port) for p in found] == [
        (Protocol.SLMP, 5001), (Protocol.ETHERNET_IP, 44818), (Protocol.FINS, 9600),
    ]
    assert primary.protocol == Protocol.SLMP   # auto-detect still picks the first


@pytest.mark.asyncio
async def test_simulator_ports_probed_on_loopback_only():
    endpoints = {(1502, Protocol.MODBUS_TCP), (1102, Protocol.S7)}
    found, _ = await probe("127.0.0.1", endpoints)
    assert [(p.protocol, p.port) for p in found] == [(Protocol.MODBUS_TCP, 1502), (Protocol.S7, 1102)]

    found_lan, _ = await probe("192.0.2.50", endpoints)
    assert found_lan == []   # 1502/1102 are not tried on LAN hosts


def test_simulator_ports_constant():
    assert SIMULATOR_PORTS == {Protocol.MODBUS_TCP: [1502], Protocol.S7: [1102],
                               Protocol.ETHERNET_IP: [44819, 44820]}   # Logix / Omron modes of the EIP simulator


@pytest.mark.asyncio
async def test_probe_hosts_keeps_one_entry_per_protocol():
    discovery = PLCDiscovery(NetworkConfig())
    results = [PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001),
               PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502)]
    with patch.object(discovery, "_probe_host_all", AsyncMock(return_value=results)):
        await discovery._probe_hosts(["127.0.0.1"], {})
    assert set(discovery.discovered_plcs) == {plc_key(p) for p in results}
