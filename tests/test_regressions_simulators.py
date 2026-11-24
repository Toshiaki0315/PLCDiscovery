"""
Regression tests for protocol simulators, found and fixed in code reviews.
"""

import ast
import asyncio
from pathlib import Path

import pytest

from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, StatusCode
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.utils import target_address_error

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=2000)


@pytest.fixture
def fast_config_17():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def test_fins_simulator_uses_address_range_error():
    from simulators.fins_simulator import INACCESSIBLE_RANGES, FINSSimulator

    area, start, _ = INACCESSIBLE_RANGES[0]
    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, area, start >> 8, start & 0xFF, 0, 0, 1])
    response = FINSSimulator().handle_frame(request, ("127.0.0.1", 9600))
    assert response[12:14] == b"\x11\x03"


@pytest.mark.parametrize("name", ["slmp", "modbus", "ethernet_ip", "s7", "fins", "run_all"])
def test_simulator_default_host_is_loopback(name):
    filename = "run_all.py" if name == "run_all" else f"{name}_simulator.py"
    source = (ROOT / "simulators" / filename).read_text(encoding="utf-8")
    if name != "run_all":
        # The protocol simulators take --host from simulators/common.py
        assert "simulator_parser(" in source and '"--host"' not in source
        source = (ROOT / "simulators" / "common.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    defaults = [
        kw.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "default"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "--host"
    ]
    assert defaults == ["127.0.0.1"]


def test_simulator_classes_default_to_loopback():
    from simulators.fins_simulator import FINSSimulator
    from simulators.run_all import SimulatorManager

    assert FINSSimulator().host == "127.0.0.1"
    assert SimulatorManager().host == "127.0.0.1"


@pytest.mark.asyncio
async def test_w_register_read_from_simulator(fast_config):
    pytest.importorskip("pymcprotocol")
    from simulators.slmp_simulator import SLMPDevice, SLMPProtocol

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: SLMPProtocol(SLMPDevice()), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = SLMPHandler("127.0.0.1", port=port, config=fast_config)
    try:
        assert await handler.connect()
        points = await handler.read_device_range(DeviceRange(DeviceType.W, 100, 104))
        # The simulator holds W[i] = 0x5500 + i
        assert [p.value for p in points] == [0x5500 + i for i in range(100, 105)]
        assert [p.address for p in points] == [f"W{i}" for i in range(100, 105)]
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_s7_wrapped_address_not_read_from_simulator(fast_config_17):
    pytest.importorskip("snap7")
    from simulators.s7_simulator import COTPProtocol, S7Device

    seen = []
    device = S7Device()
    original = device.read_db
    device.read_db = lambda db, start, size: (seen.append(start), original(db, start, size))[1]

    import asyncio

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: COTPProtocol(device), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = S7Handler("127.0.0.1", port=port, config=fast_config_17)
    try:
        assert await handler.connect()
        points = await handler.read_device_range(DeviceRange(DeviceType.DB, 1_048_581, 1_048_581))
        assert [p.status for p in points] == [StatusCode.NG_ILLEGAL_ADDR]
        assert seen == []  # nothing reached the PLC
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_denied_words_do_not_hide_readable_ones_simulator():
    """Simulator denies bytes 500-550 (words 250-275): only those are NG"""
    pytest.importorskip("snap7")
    from simulators.s7_simulator import COTPProtocol, S7Device

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: COTPProtocol(S7Device([(500, 550)])), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = S7Handler(
        "127.0.0.1", port=port, config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=2000)
    )
    reconnects = []
    original_connect = handler.connect

    async def counting_connect():
        reconnects.append(1)
        return await original_connect()

    try:
        assert await handler.connect()
        handler.connect = counting_connect
        # DB1 of the simulator is 2000 bytes = words 0-999 (a read past its end is refused)
        points = await handler.read_device_range(DeviceRange(DeviceType.DB, 0, 999))
        bad = [int(p.address[2:]) for p in points if p.status != StatusCode.OK]
        assert bad == list(range(250, 276))
        assert {p.status for p in points if p.status != StatusCode.OK} == {StatusCode.NG_ILLEGAL_ADDR}
        assert reconnects == []
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize(
    "value,ok",
    [
        ("192.168.1.10", True),
        ("simulators", True),
        ("plc-01.factory.local", True),
        ("", False),
        ("192.168.1.300", False),
        ("1.2.3", False),
        ("127.0.0.1 ;rm", False),
        ("../x", False),
        ("-bad", False),
    ],
)
def test_target_address_error(value, ok):
    assert (target_address_error(value) is None) == ok
