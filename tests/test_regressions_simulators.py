"""
Regression tests for protocol simulators, found and fixed in code reviews.
"""

import ast
import asyncio
import logging
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, StatusCode
from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.utils import target_address_error
from simulators import run_all
from simulators.fins_simulator import INACCESSIBLE_RANGES

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


def test_fins_simulator_denied_hr_range_can_be_reached():
    from simulators.fins_simulator import FINS_AREA_HR, FINS_AREA_SIZES, INACCESSIBLE_RANGES, FINSSimulator

    # Every denied range lies inside its area (HR1000-1050 was beyond the
    # 512-word HR area and could only ever answer "address range exceeded")
    for area, start, end in INACCESSIBLE_RANGES:
        assert end < FINS_AREA_SIZES[area]
    start = next(s for area, s, _ in INACCESSIBLE_RANGES if area == FINS_AREA_HR)
    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, FINS_AREA_HR, start >> 8, start & 0xFF, 0, 0, 1])
    assert FINSSimulator().handle_frame(request, ("127.0.0.1", 9600))[12:14] == b"\x11\x03"


def test_fins_simulator_picks_another_port_when_the_tcp_one_is_taken(monkeypatch):
    from simulators.control import SimulatorController

    original = asyncio.base_events.BaseEventLoop.create_server
    attempts = []

    async def create_server(self, *args, **kwargs):
        attempts.append(args[2] if len(args) > 2 else kwargs.get("port"))
        if len(attempts) == 1:
            # The UDP port was free, the same TCP number is not (CI failed on this)
            raise OSError(98, "address already in use")
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_server", create_server)
    controller = SimulatorController()
    try:
        port = controller.start("fins", "127.0.0.1", 0)
        # At least two: the second TCP number may really be taken as well
        # (the collision this is about), which is then one more attempt
        assert len(attempts) >= 2 and port == attempts[-1]
        controller.stop("fins")
        attempts.clear()
        # A port the user chose is not replaced by another one
        with pytest.raises(OSError):
            controller.start("fins", "127.0.0.1", port)
        assert len(attempts) == 1
    finally:
        controller.shutdown()


def test_run_all_reports_when_nothing_could_be_started(monkeypatch):
    from simulators import run_all

    class Manager:
        def __init__(self, host, faults=None):
            self.servers: list = []

        async def start_all(self):
            pass

        async def run_forever(self):
            pass

        async def stop_all(self):
            pass

    monkeypatch.setattr(run_all, "SimulatorManager", Manager)
    assert asyncio.run(run_all.main("127.0.0.1")) is False
    monkeypatch.setattr(sys, "argv", ["run_all.py"])
    with pytest.raises(SystemExit) as exit_info:
        run_all.run()  # ended with exit code 0: the launchers never showed their error message
    assert exit_info.value.code == 1


def test_modbus_simulator_drops_a_frame_without_a_pdu():
    from simulators.modbus_simulator import ModbusDevice, ModbusProtocol

    protocol = ModbusProtocol(ModbusDevice([]))
    protocol.transport = MagicMock()
    protocol.peer = "test"
    protocol.data_received(struct.pack(">HHHB", 1, 0, 0, 1))  # MBAP length 0
    assert protocol.buffer == b""  # the unit byte stayed and misaligned the next frame
    protocol.data_received(struct.pack(">HHHBBHH", 2, 0, 6, 1, 3, 0, 2))  # read 2 holding registers
    reply = protocol.transport.write.call_args.args[0]
    assert reply[:2] == b"\x00\x02" and reply[7] == 3


def test_eip_simulator_template_read_with_a_huge_offset_is_cheap():
    from simulators.ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol

    protocol = EtherNetIPProtocol(EtherNetIPDevice(mode="logix"))
    protocol._udt_by_template = lambda instance: ("Recipe", [])
    protocol._template_bytes = lambda name, members: b"\x01\x02\x03\x04"
    sent = []
    protocol._reply = lambda service, status=0, data=b"": sent.append(data) or b""
    started = time.monotonic()
    protocol._handle_template_read(0x4C, 1, struct.pack("<IH", 0xFFFFFFF0, 8))  # allocated 4 GB
    protocol._handle_template_read(0x4C, 1, struct.pack("<IH", 2, 4))
    assert time.monotonic() - started < 1
    assert sent == [b"\x00" * 8, b"\x03\x04\x00\x00"]


def test_simulator_stops_on_ctrl_c_while_a_client_is_connected():
    from simulators.common import serve_until_stopped

    async def run():
        loop = asyncio.get_running_loop()
        server = await loop.create_server(asyncio.Protocol, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            task = asyncio.ensure_future(serve_until_stopped(server, logging.getLogger("test")))
            await asyncio.sleep(0.1)
            started = loop.time()
            task.cancel()  # Ctrl+C
            with pytest.raises(asyncio.CancelledError):
                # "async with server: serve_forever()" never returned here on Python 3.12+
                await asyncio.wait_for(task, timeout=10)
            return loop.time() - started, server.is_serving()
        finally:
            client.close()

    elapsed, serving = asyncio.run(run())
    assert elapsed < 5 and not serving


def test_run_all_second_ctrl_c_is_not_a_failure(monkeypatch):
    from simulators import run_all

    def interrupted(coroutine):
        coroutine.close()
        raise asyncio.CancelledError  # a second Ctrl+C while the simulators were stopping

    monkeypatch.setattr(run_all.asyncio, "run", interrupted)
    monkeypatch.setattr(sys, "argv", ["run_all.py"])
    assert run_all.run() is None  # was a traceback and exit code 1: "could not be started"


def test_launcher_has_no_fins_setting_it_does_not_use():
    manager = run_all.SimulatorManager()
    assert not hasattr(manager, "fins_denied")  # [(5000, 5100), (1000, 1050)]: never passed to the simulator
    # ... and what the launcher prints is what the simulator denies
    assert [(start, end) for _, start, end in INACCESSIBLE_RANGES] == [(5000, 5100), (300, 350)]


def _printed_hint(host, monkeypatch, caplog):
    async def no_server(*args, **kwargs):
        raise OSError("not started in this test")

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_server", no_server)
        monkeypatch.setattr(loop, "create_datagram_endpoint", no_server)
        await run_all.SimulatorManager(host).start_all()

    with caplog.at_level(logging.INFO, logger="PLC-Simulator-Launcher"):
        asyncio.run(run())
    return next(r.getMessage() for r in caplog.records if "# Discover" in r.getMessage())


def test_launcher_says_which_simulators_discovery_finds(monkeypatch, caplog):
    # Simulator ports (1502, 1102, ...) are probed on loopback addresses only
    assert "finds every simulator" in _printed_hint("0.0.0.0", monkeypatch, caplog)
    caplog.clear()
    assert "standard ports" in _printed_hint("192.168.1.5", monkeypatch, caplog)


def _fins_read(area, address, count):
    from simulators.fins_simulator import FINSSimulator

    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, area, address >> 8, address & 0xFF, 0])
    response = FINSSimulator().handle_frame(request + struct.pack(">H", count), ("127.0.0.1", 9600))
    return response[12:14], response[14:]


@pytest.mark.parametrize(
    "area, address, count, end_code",
    [
        (0x82, 0, 10, b"\x00\x00"),  # DM: fine
        (0x99, 0, 1, b"\x11\x01"),  # no such memory area
        (0x82, 0, 0, b"\x11\x0c"),  # nothing requested
        (0x82, 0, 1000, b"\x11\x0b"),  # more than one response holds
        (0x82, 32760, 20, b"\x11\x04"),  # past the end of DM
        (0xB2, 510, 5, b"\x11\x04"),  # past the end of HR
    ],
)
def test_fins_simulator_end_codes(area, address, count, end_code):
    code, data = _fins_read(area, address, count)
    assert code == end_code
    assert len(data) == (2 * count if end_code == b"\x00\x00" else 0)


def test_eip_simulator_rejects_unknown_services():
    from simulators.ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol

    protocol = EtherNetIPProtocol(EtherNetIPDevice())
    reply = protocol._process_cip_request(bytes([0x4D, 0x02, 0x20, 0x6B, 0x24, 0x01]))  # Write Tag
    assert reply[0] == 0x4D | 0x80 and reply[2] == 0x08  # service not supported


def _s7_protocol():
    from simulators.s7_simulator import COTPProtocol, S7Device

    protocol = COTPProtocol(S7Device())
    protocol.transport = MagicMock()
    protocol.peer = ("127.0.0.1", 1)
    return protocol


def test_s7_simulator_survives_a_tpkt_length_below_the_header_size():
    protocol = _s7_protocol()
    finished = threading.Event()

    def feed():
        protocol.data_received(b"\x03\x00\x00\x00")
        finished.set()

    threading.Thread(target=feed, daemon=True).start()
    assert finished.wait(2), "data_received never returned (endless loop)"
    assert protocol.buffer == b""


def test_s7_simulator_failed_item_is_four_bytes_and_pdu_size_follows_the_request():
    from simulators.s7_simulator import S7_RET_OK

    protocol = _s7_protocol()
    sent = []
    protocol._make_s7_response = lambda ref, params, data: sent.append((params, data)) or b""

    protocol._make_read_response(1, [(0x0A, None), (S7_RET_OK, b"\x12\x34")])
    params, data = sent[-1]
    assert params[1] == 2
    assert data[:4] == bytes([0x0A, 0, 0, 0])  # return code, null transport size, length 0
    assert data[4:] == bytes([S7_RET_OK, 0x04]) + struct.pack(">H", 16) + b"\x12\x34"

    for requested, granted in ((120, 120), (240, 240), (480, 480), (4096, 960)):
        protocol._handle_setup_comm(1, bytes([0xF0, 0, 0, 1, 0, 1]) + struct.pack(">H", requested))
        assert struct.unpack(">H", sent[-1][0][6:8])[0] == granted


def test_run_all_starts_without_signal_handlers(monkeypatch):
    """Windows event loops raise NotImplementedError from add_signal_handler"""
    from simulators import run_all

    class Manager:
        def __init__(self, host, faults=None):
            self.stopped = False
            created.append(self)

        async def start_all(self):
            pass

        async def run_forever(self):
            pass

        async def stop_all(self):
            self.stopped = True

    created = []
    monkeypatch.setattr(run_all, "SimulatorManager", Manager)

    async def run():
        loop = asyncio.get_running_loop()

        def unsupported(*args):
            raise NotImplementedError

        monkeypatch.setattr(loop, "add_signal_handler", unsupported)
        started = time.monotonic()
        await run_all.main("127.0.0.1")
        return time.monotonic() - started

    assert asyncio.run(run()) < 2
    assert created[0].stopped


def test_simulator_tag_write_must_fit_the_tag_type():
    from simulators.control import write_value

    device = MagicMock()
    device.logix_tags = {"Counter": ("INT", 0), "Total": ("DINT", 0)}
    with pytest.raises(ValueError, match="does not fit"):
        write_value("logix", device, "", "Counter", 100000)
    write_value("logix", device, "", "Total", 100000)
    assert device.logix_tags["Total"] == ("DINT", 100000) and device.logix_tags["Counter"] == ("INT", 0)


def test_s7_simulator_refuses_reads_past_the_end_of_a_db():
    from simulators.s7_simulator import S7_RET_ADDRESS_OUT_OF_RANGE, S7_RET_OK, S7Device

    device = S7Device()
    assert device.read_db(1, 1990, 10)[1] == S7_RET_OK
    assert device.read_db(1, 1990, 12) == (None, S7_RET_ADDRESS_OUT_OF_RANGE)
    device.data_blocks[1][2500] = 1  # a value written further out extends the block
    assert device.read_db(1, 2490, 11)[1] == S7_RET_OK


def test_eip_simulator_requires_a_registered_session():
    from simulators.ethernet_ip_simulator import (
        EIP_CMD_REGISTER_SESSION,
        EIP_CMD_SEND_RR_DATA,
        EtherNetIPDevice,
        EtherNetIPProtocol,
    )

    protocol = EtherNetIPProtocol(EtherNetIPDevice())
    status = lambda reply: struct.unpack("<I", reply[8:12])[0]  # noqa: E731

    reply = protocol._process_command(EIP_CMD_SEND_RR_DATA, 0x1234, b"\x00" * 8, b"\x00" * 16)
    assert status(reply) == 0x0064  # invalid session handle

    registered = protocol._process_command(EIP_CMD_REGISTER_SESSION, 0, b"\x00" * 8, struct.pack("<HH", 1, 0))
    session = struct.unpack("<I", registered[4:8])[0]
    reply = protocol._process_command(EIP_CMD_SEND_RR_DATA, session, b"\x00" * 8, b"\x00" * 16)
    assert status(reply) != 0x0064


def test_simulator_reports_a_port_it_cannot_use(caplog):
    from simulators.common import run_simulator

    async def server():
        raise PermissionError(13, "Permission denied")

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
        run_simulator(server(), logging.getLogger("simulator-test"))
    assert exit_info.value.code == 1 and "--port" in caplog.text
