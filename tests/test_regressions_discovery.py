"""
Regression tests for PLC discovery, found and fixed in code reviews.
"""

import asyncio
import concurrent.futures
import io
import json
import logging
import socket
import struct
import threading
import time
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery import broadcast_discovery as broadcast_module
from plc_discovery import discovery
from plc_discovery import discovery as discovery_module
from plc_discovery import utils
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.config import MANUFACTURER_OUI, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.discovery import (
    LARGE_SCAN_WARNING_HOSTS,
    MAX_AUTO_SCAN_PREFIX,
    PLCDiscovery,
    merge_discovery_results,
    plc_key,
    target_instances,
)
from plc_discovery.probes import probe_ethernet_ip, probe_fins_udp, probe_modbus, probe_s7, probe_slmp, verify_protocol
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.utils import get_manufacturer_from_mac, ip_range_error, parse_ip_range, target_address_error


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


EVIL = "m\x1b]0;pwned\x07\x1b[2J\x9b31m"


def _rich_display():
    from rich.console import Console

    from plc_discovery.progress import RichProgressDisplay

    display = RichProgressDisplay()
    buffer = io.StringIO()
    display.console = Console(file=buffer, force_terminal=True, width=200)
    return display, buffer


def _loader(tmp_path, config):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(config))
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


async def _scan(end, valid):
    """Read D0-end from a fake PLC where valid(address) tells readability"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    requests = []

    async def fake_read(device_type, start, count):
        requests.append((start, count))
        if all(valid(a) for a in range(start, start + count)):
            return [a & 0xFFFF for a in range(start, start + count)], StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, end))
    return handler, points, requests


@contextmanager
def tcp_server(respond):
    """One-shot-per-connection TCP server; respond(request) -> reply bytes"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    stop = threading.Event()

    def serve():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    req = conn.recv(512)
                    reply = respond(req)
                    if reply:
                        conn.sendall(reply)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        thread.join(1)
        srv.close()


def HTTP(req):
    return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"


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


OLD_LINUX_IFCONFIG = (
    "eth0  Link encap:Ethernet\n      inet addr:192.168.50.3  Bcast:192.168.50.255  Mask:255.255.255.0\n"
)


WINDOWS_POWERSHELL = "192.168.10.2/24\r\n127.0.0.1/8\r\n169.254.3.4/16\r\n"


def networks_with(listing):
    with (
        patch.object(utils, "_networks_from_netifaces", return_value=None),
        patch.object(utils, "_networks_from_os", return_value=utils.parse_interfaces(listing)),
    ):
        return utils.get_local_networks()


WINDOWS_POWERSHELL_7 = """\
イーサネット|192.168.10.2/24
制御LAN|10.20.0.5/24
vEthernet (WSL)|172.27.48.1/20
vEthernet (Default Switch)|172.20.16.1/20
VMware Network Adapter VMnet8|192.168.80.1/24
Loopback Pseudo-Interface 1|127.0.0.1/8
"""


MACOS_IFCONFIG_7 = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.8 netmask 0xffffff00 broadcast 192.168.1.255
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.99.0.2 netmask 0xffffff00
"""


LINUX_IP_7 = """\
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


def slow_closed(ip, port, timeout):
    time.sleep(0.3)
    return False


def slow_silent(ip, port, protocol, timeout):
    time.sleep(0.3)
    return False


@pytest.mark.asyncio
async def test_broadcast_keeps_both_protocols_of_one_host():
    discovery = BroadcastDiscovery()
    slmp = b"\xd0\x00" + b"\x00" * 20

    async def send(port, data, timeout):
        return {"10.0.0.7": slmp if port == 5001 else list_identity(367, "KV-8000")}

    with patch.object(discovery, "_send_broadcast", send):
        plcs = await discovery.discover_all_broadcast()
    assert sorted(p.protocol.name for p in plcs) == ["ETHERNET_IP", "SLMP_UDP"]  # previously one
    assert len(discovery.get_results()) == 2


def test_merge_prefers_primary_and_fills_gaps():
    tcp = PLCInfo(
        "10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="Omron Corporation", model="NJ501-1300"
    )
    broadcast = PLCInfo(
        "10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="Vendor 47", mac_address="00:00:0a:12:34:56"
    )
    only_broadcast = PLCInfo("10.0.0.9", protocol=Protocol.SLMP, port=5001)
    merged = merge_discovery_results([tcp], [broadcast, only_broadcast])
    assert merged == [tcp, only_broadcast]
    assert (tcp.manufacturer, tcp.model, tcp.mac_address) == (
        "Omron Corporation",
        "NJ501-1300",
        "00:00:0a:12:34:56",
    )


@pytest.mark.parametrize(
    "mac, maker",
    [
        ("00:00:0A:01:02:03", "オムロン"),
        ("00:01:FC:01:02:03", "キーエンス"),
        ("00:26:92:01:02:03", "三菱電機"),
        ("00:00:64:01:02:03", "横河電機"),
        ("00:00:BC:01:02:03", "ロックウェル"),
        ("00:0E:8C:01:02:03", "シーメンス"),  # previously "ロックウェル"
        ("00:40:1A:01:02:03", "富士電機"),
        ("00:20:B5:01:02:03", "安川電機"),
    ],
)
def test_real_vendor_ouis_are_recognised(mac, maker):
    assert get_manufacturer_from_mac(mac) == maker


@pytest.mark.parametrize(
    "mac",
    [
        "00:10:FA:01:02:03",  # Apple (was "富士電機")
        "00:0A:DC:01:02:03",  # RuggedCom switch (was "オムロン")
        "00:00:1C:01:02:03",  # Bell Technologies (was "三菱電機")
        "00:0D:7C:01:02:03",  # Codian (was "キーエンス")
        "00:30:11:01:02:03",  # HMS (was "東芝")
        "00:60:52:01:02:03",  # Peripherals Enterprise (was "安川電機")
    ],
)
def test_other_companies_ouis_are_not_named_as_plc_makers(mac):
    assert get_manufacturer_from_mac(mac) is None


def test_oui_keys_are_normalised():
    for oui in MANUFACTURER_OUI:
        assert oui == oui.upper() and len(oui) == 8 and oui.count(":") == 2


def test_oui_matches_wireshark_database():
    try:
        from scapy.all import conf
    except Exception:
        pytest.skip("scapy not installed")
    if not getattr(conf, "manufdb", None):
        pytest.skip("scapy has no manuf database")
    keywords = {
        "オムロン": "omron",
        "キーエンス": "keyence",
        "三菱電機": "mitsubishi",
        "横河電機": "yokogawa",
        "ロックウェル": "rockwell",
        "シーメンス": "siemens",
        "富士電機": "fuji electric",
        "安川電機": "yaskawa",
        "日立産機": "hitachi",
        "ジェイテクト": "jtekt",
        "IDEC": "idec",
        "デルタ電子": "delta",
        "シュナイダー": "schneider",
        "東芝": "toshiba",
        "パナソニック": "panasonic",
    }
    for oui, maker in MANUFACTURER_OUI.items():
        registered = conf.manufdb._get_manuf(oui + ":00:00:00")
        assert keywords[maker] in registered.lower(), (oui, maker, registered)


def test_discovery_table_shows_markup_literally_without_escapes():
    pytest.importorskip("rich")
    display, buffer = _rich_display()
    display.print_discovery_results(
        [
            {
                "ip_address": "10.0.0.1",
                "protocol": "EIP",
                "port": 44818,
                "manufacturer": "[link=http://evil.example]click[/link]",
                "model": EVIL,
            }
        ]
    )
    out = buffer.getvalue()
    assert "\x1b]8;" not in out  # no hyperlink (previously injected)
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x07" not in out
    assert "[link=http://evil.example]click[/link]" in out


@pytest.mark.parametrize("mode", ["range", "RANGE", " full ", "discover"])
def test_known_scan_modes_accepted(tmp_path, mode):
    assert _loader(tmp_path, {"scan": {"mode": mode}}).validate() == []


def test_slmp_broadcast_request_matches_probe_frame():
    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    request = BroadcastDiscovery()._build_slmp_discovery_request()
    assert request[:2] == b"\x50\x00"  # previously b"\x00\x50"
    # same 3E "Read Type Name" frame as the TCP probe
    assert request == bytes.fromhex("5000" "00ff" "ff03" "00" "0600" "1000" "0101" "0000")


def test_slmp_broadcast_accepts_real_reply_and_rejects_reversed_bytes():
    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    discovery = BroadcastDiscovery()
    reply = b"\xd0\x00\x00\xff\xff\x03\x00\x02\x00\x00\x00"  # 3E response, end code 0
    plc = discovery._parse_slmp_response("10.0.0.5", reply)
    assert plc is not None and plc.protocol == Protocol.SLMP_UDP  # previously None (read over UDP)
    assert discovery._parse_slmp_response("10.0.0.5", b"\x00\xd0" + reply[2:]) is None


def test_slmp_broadcast_end_to_end_with_udp_responder():
    """A UDP responder that answers only well-formed 3E requests"""
    import asyncio
    import socket
    from unittest.mock import patch

    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    responder.settimeout(3)
    port = responder.getsockname()[1]

    def serve():
        data, addr = responder.recvfrom(1024)
        if data[:2] == b"\x50\x00":
            responder.sendto(b"\xd0\x00\x00\xff\xff\x03\x00\x02\x00\x00\x00", addr)

    async def run():
        import threading

        threading.Thread(target=serve, daemon=True).start()
        from plc_discovery.config import NetworkConfig

        discovery = BroadcastDiscovery(NetworkConfig(discovery_timeout_ms=500))
        # a /32 "network": its directed broadcast address is 127.0.0.1 itself
        with (
            patch("plc_discovery.broadcast_discovery.SLMP_DISCOVERY_PORT", port),
            patch(
                "plc_discovery.broadcast_discovery.get_local_networks", return_value=[("127.0.0.1", "255.255.255.255")]
            ),
        ):
            return await discovery.discover_slmp_broadcast()

    try:
        plcs = asyncio.run(run())
    finally:
        responder.close()
    assert [p.ip_address for p in plcs] == ["127.0.0.1"]


@pytest.mark.asyncio
async def test_discovery_slmp_info_opens_no_connection():
    from unittest.mock import patch

    from plc_discovery.config import NetworkConfig
    from plc_discovery.discovery import PLCDiscovery

    plc = PLCInfo("10.0.0.5", protocol=Protocol.SLMP, port=5001)
    with (
        patch("socket.socket.connect", side_effect=AssertionError("connected")),
        patch("socket.create_connection", side_effect=AssertionError("connected")),
    ):
        result = await PLCDiscovery(NetworkConfig())._query_slmp_info(plc)
    assert (result.manufacturer, result.model) == ("三菱電機/キーエンス", "SLMP対応PLC")
    keyence = PLCInfo("10.0.0.6", protocol=Protocol.SLMP, port=5001, manufacturer="キーエンス")
    assert (await PLCDiscovery(NetworkConfig())._query_slmp_info(keyence)).manufacturer == "キーエンス"


@pytest.mark.asyncio
async def test_small_ranges_are_split_without_probes():
    """Below EDGE_PROBE_MIN_COUNT the range is split as before"""
    _, points, requests = await _scan(2, lambda a: a == 1)
    assert [p.status for p in points] == [StatusCode.NG_ILLEGAL_ADDR, StatusCode.OK, StatusCode.NG_ILLEGAL_ADDR]
    assert all(count != 1 or start in (0, 1, 2) for start, count in requests)


@pytest.mark.asyncio
async def test_transient_probe_failure_falls_back_to_splitting():
    """A timeout on an edge probe is not taken as proof of an invalid range"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    calls = []

    async def fake_read(device_type, start, count):
        calls.append((start, count))
        if (start, count) == (0, 1) and calls.count((0, 1)) == 1:
            return None, StatusCode.NG_TIMEOUT
        if start + count - 1 <= 3:
            return [0] * count, StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler._binary_search_read(DeviceType.D, 0, 7, known_failure=StatusCode.NG_ILLEGAL_ADDR)
    assert [p.status for p in points] == [StatusCode.OK] * 4 + [StatusCode.NG_ILLEGAL_ADDR] * 4


def test_modbus_identity_query_uses_discovery_timeout():
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=700, request_timeout_ms=5000))
    created = {}

    class FakeClient:
        def __init__(self, host, port=502, timeout=None, retries=None):
            created["timeout"] = timeout

        def connect(self):
            return False

    with patch("pymodbus.client.ModbusTcpClient", FakeClient):
        asyncio.run(discovery._query_modbus_info(PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP, port=502)))
    assert created["timeout"] == pytest.approx(0.7)


def test_s7_identity_query_tries_slot_2():
    pytest.importorskip("snap7")
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=1000))
    client = MagicMock()
    slots = []

    def connect(ip, rack, slot, port):
        slots.append(slot)
        if slot == 0:
            raise RuntimeError("TCP : Connection refused (slot 0)")

    client.connect.side_effect = connect
    client.read_szl.side_effect = RuntimeError("SZL not available")
    client.get_cpu_info.return_value = MagicMock(ModuleTypeName=b"CPU 315-2 PN/DP", ASName=b"S7-300")
    with patch("snap7.client.Client", return_value=client):
        plc = asyncio.run(discovery._query_s7_info(PLCInfo("10.0.0.1", protocol=Protocol.S7, port=102)))
    assert slots == [0, 2]
    assert (plc.manufacturer, plc.model, plc.cpu_type) == ("シーメンス", "CPU 315-2 PN/DP", "S7-300")


def test_s7_identity_query_is_bounded():
    pytest.importorskip("snap7")
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100))
    client = MagicMock()
    client.connect.side_effect = lambda *a: time.sleep(2)  # host that never answers

    async def run():
        # Timed inside the loop: asyncio.run() itself waits for the worker
        # thread when it shuts down, discovery does not
        started = time.monotonic()
        plc = await discovery._query_s7_info(PLCInfo("10.0.0.1", protocol=Protocol.S7, port=102))
        return plc, time.monotonic() - started

    with patch("snap7.client.Client", return_value=client):
        plc, elapsed = asyncio.run(run())
    assert elapsed < 1.0
    # The late thread does not change the result; the probe-verified
    # protocol still names the manufacturer
    assert (plc.manufacturer, plc.model) == ("シーメンス", "S7 PLC")


class TestR3Probes:

    def test_slmp_error_reply_counts(self):
        reply = b"\xd0\x00\x00\xff\xff\x03\x00\x02\x00\x59\xc0"  # end code C059
        with tcp_server(lambda req: reply) as port:
            assert probe_slmp("127.0.0.1", port, 1.0)

    def test_modbus_requires_matching_transaction(self):
        def respond(req):
            return req[:2] + b"\x00\x00\x00\x05\x01\x03\x02\x00\x2a"

        with tcp_server(respond) as port:
            assert probe_modbus("127.0.0.1", port, 1.0)
        with tcp_server(lambda req: b"\x99\x99" + respond(req)[2:]) as port:
            assert not probe_modbus("127.0.0.1", port, 1.0)

    def test_s7_connection_confirm(self):
        cc = b"\x03\x00\x00\x16\x11\xd0" + b"\x00" * 16
        with tcp_server(lambda req: cc) as port:
            assert probe_s7("127.0.0.1", port, 1.0)

    def test_eip_list_identity_context_echo(self):
        def respond(req):
            return struct.pack("<HHII", 0x0063, 0, 0, 0) + req[12:20] + b"\x00" * 4

        with tcp_server(respond) as port:
            assert probe_ethernet_ip("127.0.0.1", port, 1.0)

    @pytest.mark.parametrize("protocol", list(Protocol))
    def test_non_plc_service_rejected(self, protocol):
        with tcp_server(HTTP) as port:
            assert not verify_protocol("127.0.0.1", port, protocol, 1.0)

    @pytest.mark.asyncio
    async def test_open_port_without_protocol_not_reported(self):
        discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=200))
        with (
            patch("plc_discovery.discovery.is_port_open", side_effect=lambda ip, p, t: p == 5001),
            patch("plc_discovery.discovery.verify_protocol", return_value=False),
        ):
            assert await discovery._probe_host("192.0.2.10") is None


@pytest.mark.asyncio
async def test_discovery_protocol_filter():
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100), protocols=[Protocol.MODBUS_TCP])
    probed = []
    with (
        patch("plc_discovery.discovery.is_port_open", side_effect=lambda ip, p, t: probed.append(p) or False),
        patch("plc_discovery.discovery.verify_protocol", side_effect=AssertionError("not expected")),
    ):
        assert await discovery._probe_host("192.0.2.1") is None
    assert probed == [502]  # no SLMP/S7/EIP checks and no FINS/UDP probe


@pytest.mark.asyncio
async def test_modbus_identity_keeps_existing_manufacturer():
    discovery = PLCDiscovery(NetworkConfig())
    plc = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=502, manufacturer="横河電機")
    response = MagicMock()
    response.isError.return_value = False
    response.information = {0: b"", 1: b"FA-M3", 2: b""}
    client = MagicMock()
    client.connect.return_value = True
    client.read_device_information.return_value = response
    with patch("pymodbus.client.ModbusTcpClient", return_value=client):
        result = await discovery._query_modbus_info(plc)
    assert result.manufacturer == "横河電機"
    assert result.model == "FA-M3"


def test_fins_udp_probe_uses_ip_derived_nodes():
    received = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2)
    port = srv.getsockname()[1]

    def respond():
        data, addr = srv.recvfrom(2048)
        received.append(data)
        header = bytes([0xC0, 0, 2, data[6], data[7], data[8], data[3], data[4], data[5], data[9]])
        srv.sendto(header + data[10:12] + b"\x00\x00\x00\x00", addr)

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    try:
        assert probe_fins_udp("127.0.0.1", port, 2.0)
    finally:
        thread.join(2)
        srv.close()

    request = received[0]
    assert request[4] == 1  # DA1 = last octet of 127.0.0.1
    assert request[7] == 1  # SA1 = last octet of the local address (127.0.0.1)


class TestInterfaceParsing:

    def test_macos_ifconfig(self):
        assert utils.parse_interface_listing(MACOS_IFCONFIG) == [
            ("127.0.0.1", "255.0.0.0"),
            ("192.168.1.8", "255.255.255.0"),
            ("10.10.0.5", "255.255.0.0"),
            ("169.254.12.34", "255.255.0.0"),
        ]

    def test_linux_ip_addr(self):
        assert ("172.16.5.20", "255.255.255.0") in utils.parse_interface_listing(LINUX_IP)

    def test_old_linux_ifconfig(self):
        assert utils.parse_interface_listing(OLD_LINUX_IFCONFIG) == [("192.168.50.3", "255.255.255.0")]

    def test_windows_powershell(self):
        assert ("192.168.10.2", "255.255.255.0") in utils.parse_interface_listing(WINDOWS_POWERSHELL)


def test_all_networks_listed_without_loopback_link_local_or_p2p():
    assert networks_with(MACOS_IFCONFIG) == [("192.168.1.8", "255.255.255.0"), ("10.10.0.5", "255.255.0.0")]
    assert networks_with(LINUX_IP) == [("172.16.5.20", "255.255.255.0")]  # tun0 /32 skipped


def test_isolated_lan_without_default_gateway():
    """Previously fell back to 127.0.0.1/24 when 8.8.8.8 was unreachable"""

    def unreachable(*args, **kwargs):
        raise OSError(51, "Network is unreachable")

    with (
        patch.object(utils, "_networks_from_netifaces", return_value=None),
        patch.object(utils, "_networks_from_os", return_value=[("eth1", "10.10.0.5", "255.255.255.0")]),
        patch.object(socket.socket, "connect", unreachable),
    ):
        assert utils.get_network_info() == ("10.10.0.5", "255.255.255.0", "10.10.0.255")


@pytest.mark.asyncio
async def test_same_segment_scans_every_network():
    discovery = PLCDiscovery(NetworkConfig())
    scanned = []

    async def fake_probe_hosts(hosts, mac_table):
        scanned.append((hosts[0], hosts[-1], len(hosts)))

    networks = [("192.168.1.8", "255.255.255.0"), ("10.10.0.5", "255.255.255.252")]
    with (
        patch.object(discovery_module, "get_local_networks", return_value=networks),
        patch.object(discovery_module, "SCAPY_AVAILABLE", False),
        patch.object(discovery, "_probe_hosts", side_effect=fake_probe_hosts),
        patch.object(discovery, "_fill_macs_from_arp_cache", AsyncMock()),
    ):
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
    with (
        patch.object(broadcast_module, "get_local_networks", return_value=networks),
        patch.object(loop, "create_datagram_endpoint", AsyncMock(return_value=(transport, None))),
    ):
        await BroadcastDiscovery()._send_broadcast(44818, b"x", 0.01)
    assert sent == ["192.168.1.255", "10.10.255.255", "255.255.255.255"]


class TestVirtualAdapters:

    def test_names_parsed(self):
        names = [name for name, _, _ in utils.parse_interfaces(WINDOWS_POWERSHELL_7)]
        assert names[:3] == ["イーサネット", "制御LAN", "vEthernet (WSL)"]
        assert [n for n, _, _ in utils.parse_interfaces(MACOS_IFCONFIG_7)] == ["en0", "bridge100", "utun3"]
        assert [n for n, _, _ in utils.parse_interfaces(LINUX_IP_7)] == ["eth0", "docker0", "virbr0"]

    def test_windows_virtual_adapters_skipped(self):
        assert networks_from(WINDOWS_POWERSHELL_7) == [
            ("192.168.10.2", "255.255.255.0"),
            ("10.20.0.5", "255.255.255.0"),
        ]

    def test_macos_and_linux_virtual_adapters_skipped(self):
        assert networks_from(MACOS_IFCONFIG_7) == [("192.168.1.8", "255.255.255.0")]
        assert networks_from(LINUX_IP_7) == [("172.16.5.20", "255.255.255.0")]

    def test_include_virtual(self):
        assert len(networks_from(WINDOWS_POWERSHELL_7, include_virtual=True)) == 5

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


@pytest.mark.asyncio
async def test_batch_does_not_queue_on_small_default_pool():
    # Simulate a small PC: the shared default pool has only 2 threads
    asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=2))
    discovery = PLCDiscovery(NetworkConfig())
    hosts = [f"192.0.2.{i}" for i in range(1, 11)]
    with (
        patch.object(discovery_module, "is_port_open", side_effect=slow_closed),
        patch.object(discovery_module, "verify_protocol", side_effect=slow_silent),
    ):
        started = time.monotonic()
        await discovery._probe_hosts(hosts, {})
        elapsed = time.monotonic() - started
    # 10 hosts x 6 checks of 0.3 s: ~0.3 s in parallel, ~9 s on a 2-thread pool
    assert elapsed < 1.5


@pytest.mark.asyncio
async def test_probe_pool_is_released_after_scan():
    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", return_value=False),
        patch.object(discovery_module, "verify_protocol", return_value=False),
    ):
        await discovery._probe_hosts(["192.0.2.1", "192.0.2.2"], {})
    assert discovery._probe_executor is None
    await asyncio.sleep(0.2)
    assert not [t for t in threading.enumerate() if t.name.startswith("plc-probe") and t.is_alive()]


@pytest.mark.asyncio
async def test_single_host_probe_works_without_batch_pool():
    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", return_value=False),
        patch.object(discovery_module, "verify_protocol", return_value=False),
    ):
        assert await discovery._probe_host("192.0.2.1") is None
    assert discovery._probe_executor is None


def test_large_scan_estimate_includes_the_packet_interval(caplog):
    hosts = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(LARGE_SCAN_WARNING_HOSTS + 500)]
    config = NetworkConfig(discovery_timeout_ms=1000, packet_interval_ms=1000, max_concurrent=1)
    scanner = PLCDiscovery(config)

    async def run():
        with (
            patch.object(scanner, "_probe_host_all", AsyncMock(return_value=[])),
            patch.object(discovery.asyncio, "sleep", AsyncMock()),
        ):
            await scanner._probe_hosts(hosts, {})

    with caplog.at_level("WARNING"):
        asyncio.run(run())
    batches = len(hosts) / 10
    expected_minutes = batches * (2 * 1.0 + 1.0) / 60  # two timeouts and one interval per batch
    assert f"~{expected_minutes:.0f} minutes" in caplog.text


def test_broadcast_network_is_not_a_range_of_devices():
    assert "broadcast" in ip_range_error("255.255.255.255/32")
    assert "broadcast" in ip_range_error("255.255.255.0/24")
    assert ip_range_error("192.168.1.0/24") is None


def _unit(unit_id=None, ip="10.0.0.5"):
    options = {} if unit_id is None else {"unit_id": unit_id}
    return PLCInfo(ip, protocol=Protocol.MODBUS_TCP, port=502, options=options)


def test_target_instances_tell_targets_on_one_endpoint_apart():
    assert target_instances([_unit(1), _unit(2), _unit(ip="10.0.0.9")]) == ["unit_id1", "unit_id2", None]
    assert target_instances([_unit(), _unit(), _unit(7)]) == ["1", "2", "unit_id7"]
    assert target_instances([_unit(3), _unit(3)]) == ["unit_id3", "unit_id3_2"]
    # Another protocol or port on the same IP is told apart by those already
    slmp = PLCInfo("10.0.0.5", protocol=Protocol.SLMP, port=5001)
    assert target_instances([_unit(1), slmp]) == [None, None]


def test_arp_sweep_is_paced_and_uses_the_interface_of_the_network(monkeypatch):
    sent = {}

    def srp(packet, **options):
        sent.update(options)
        return [], []

    route = MagicMock()
    route.route.side_effect = lambda address: ("eth-control", "192.168.10.5", "0.0.0.0")
    monkeypatch.setattr(discovery, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(discovery, "srp", srp, raising=False)
    monkeypatch.setattr(discovery, "Ether", MagicMock(), raising=False)
    monkeypatch.setattr(discovery, "ARP", MagicMock(), raising=False)
    monkeypatch.setattr(discovery, "conf", MagicMock(route=route), raising=False)

    scanner = PLCDiscovery(NetworkConfig(packet_interval_ms=50, discovery_timeout_ms=1000))
    assert asyncio.run(scanner._arp_scan("192.168.10.5", "255.255.255.0")) == {}
    assert sent["inter"] == pytest.approx(0.05)  # was one burst of 254 broadcasts
    assert sent["iface"] == "eth-control"  # was scapy's default-route interface
    # Looked up for a neighbour: the PC's own address is routed through loopback
    assert route.route.call_args.args[0] != "192.168.10.5"


FAST_200MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


def test_broadcast_only_for_requested_protocols():
    async def run(protocols):
        discovery = BroadcastDiscovery(FAST_200MS)
        with patch.object(discovery, "_send_broadcast", AsyncMock(return_value={})) as send:
            await discovery.discover_all_broadcast(protocols=protocols)
        return sorted(call.kwargs["port"] for call in send.await_args_list)

    assert asyncio.run(run([Protocol.MODBUS_TCP])) == []
    assert asyncio.run(run([Protocol.ETHERNET_IP])) == [44818]
    # SLMP replies are listed as SLMP over UDP: sent for slmp-udp, not for slmp (TCP)
    assert asyncio.run(run([Protocol.SLMP_UDP])) == [5001]
    assert asyncio.run(run([Protocol.SLMP])) == []
    assert len(asyncio.run(run(None))) == 2


def test_given_port_is_probed_for_every_protocol_one_at_a_time():
    probed = []
    active = [0]
    overlaps = []  # checked after the probe: an assert in here would be swallowed by the prober

    def port_open(ip, port, timeout):
        return True

    def verify(ip, port, protocol, timeout):
        active[0] += 1
        if active[0] != 1:
            overlaps.append(protocol)
        time.sleep(0.01)
        probed.append((protocol, port))
        active[0] -= 1
        return protocol == Protocol.MODBUS_TCP

    async def run():
        with (
            patch("plc_discovery.discovery.is_port_open", port_open),
            patch("plc_discovery.discovery.verify_protocol", verify),
            patch.object(PLCDiscovery, "_get_detailed_info", AsyncMock(side_effect=lambda info: info)),
        ):
            return await PLCDiscovery(FAST_200MS, port=5007)._probe_host("192.168.1.10")

    detected = asyncio.run(run())
    assert overlaps == [], "protocols must not share the port at the same time"
    assert detected is not None and (detected.protocol, detected.port) == (Protocol.MODBUS_TCP, 5007)
    assert len(probed) > 1  # another protocol was tried on the port before Modbus answered
    assert {port for _, port in probed} == {5007}
    assert probed[-1][0] == Protocol.MODBUS_TCP  # stops at the first protocol that answers


def test_broadcast_only_slmp_result_is_read_over_udp():
    # Answered on UDP: listed (and read) as SLMP over UDP, not as a TCP port
    # nobody checked
    plc = BroadcastDiscovery()._parse_slmp_response("10.0.0.5", b"\xd0\x00" + b"\x00" * 12)
    assert plc is not None and plc.protocol == Protocol.SLMP_UDP and "UDP" in (plc.model or "")


def test_mac_maker_replaces_the_name_the_protocol_implies(monkeypatch):
    discovery = PLCDiscovery(NetworkConfig())
    implied = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, manufacturer="三菱電機/キーエンス")
    identified = PLCInfo("10.0.0.2", protocol=Protocol.MODBUS_TCP, port=502, manufacturer="Yokogawa")
    for plc in (implied, identified):
        discovery.discovered_plcs[plc_key(plc)] = plc
    monkeypatch.setattr(
        "plc_discovery.discovery.read_arp_cache",
        lambda: {"10.0.0.1": "00:01:FC:00:00:01", "10.0.0.2": "00:01:FC:00:00:02"},  # Keyence OUI
    )
    asyncio.run(discovery._fill_macs_from_arp_cache())
    assert implied.manufacturer == "キーエンス"
    assert identified.manufacturer == "Yokogawa"  # what the device itself reported stays


@pytest.mark.parametrize("text", ["224.0.0.0/30", "0.0.0.0/24", "255.255.255.255", "224.0.0.1-5", "0.0.0.0"])
def test_ranges_that_are_not_device_addresses_are_rejected(text):
    assert ip_range_error(text)  # what --ip-range and the config file report
    assert parse_ip_range(text) == []
    assert ip_range_error("192.168.1.0/24") is None and len(parse_ip_range("192.168.1.0/24")) == 254


def test_target_must_be_a_device_address():
    assert target_address_error("224.0.0.1") and target_address_error("255.255.255.255")
    assert target_address_error("192.168.1.10") is None and target_address_error("simulators") is None
