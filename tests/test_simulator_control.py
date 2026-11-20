"""
The simulator controller behind the simulator GUI (simulators/control.py):
memory access per protocol, automatic changes, starting / stopping servers
and the scanner actually reading what was written.
"""

import asyncio
import socket
import sys
import time
from unittest.mock import MagicMock

import pytest

from plc_discovery.cli_args import parse_args
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from simulators.control import (
    KINDS,
    Generator,
    SimulatorController,
    read_value,
    scanner_command,
    wave_value,
    write_value,
)
from simulators.ethernet_ip_simulator import EtherNetIPDevice
from simulators.fins_simulator import FINSSimulator
from simulators.modbus_simulator import ModbusDevice
from simulators.s7_simulator import S7Device
from simulators.slmp_simulator import SLMPDevice


@pytest.fixture
def controller():
    c = SimulatorController()
    yield c
    c.shutdown()


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_scanner_commands_are_valid_cli(monkeypatch, kind):
    command = scanner_command(kind, "0.0.0.0", 15000)
    assert "--target 127.0.0.1" in command and "--port 15000" in command
    monkeypatch.setattr(sys, "argv", command.split()[1:])
    parse_args()  # SystemExit on an unknown option or choice


@pytest.mark.parametrize(
    "kind, device, area, address, value, expected",
    [
        ("slmp", SLMPDevice(), "D", 10, 1234, 1234),
        ("slmp", SLMPDevice(), "D", 10, -1, 65535),
        ("slmp", SLMPDevice(), "M", 3, 5, 1),
        ("modbus", ModbusDevice(), "HR", 7, 42, 42),
        ("modbus", ModbusDevice(), "COIL", 2, 1, 1),
        ("eip", EtherNetIPDevice(), "N7", 4, 99, 99),
        ("logix", EtherNetIPDevice(mode="logix"), "TAG", "Temp", 81.25, 81.25),
        ("logix", EtherNetIPDevice(mode="logix"), "TAG", "Speed", 7.6, 8),
        ("logix", EtherNetIPDevice(mode="logix"), "TAG", "Running", 5, 1),
        ("omron", EtherNetIPDevice(mode="omron"), "TAG", "TotalCount", 10, 10),
        ("s7", S7Device(), "DB1", 5, 0x1234, 0x1234),
        ("s7", S7Device(), "M", 1, 300, 300),
        ("fins", FINSSimulator(), "DM", 0, 500, 500),
    ],
)
def test_write_and_read_memory(kind, device, area, address, value, expected):
    write_value(kind, device, area, address, value)
    assert read_value(kind, device, area, address) == expected


def test_memory_layout_matches_what_the_simulators_serve():
    s7 = S7Device()
    write_value("s7", s7, "DB1", 5, 0x1234)  # DB1.DBW10, big-endian
    assert s7.read_db(1, 10, 2)[0] == b"\x12\x34"
    modbus = ModbusDevice()
    write_value("modbus", modbus, "COIL", 2, 1)
    assert modbus.coils[2] is True
    logix = EtherNetIPDevice(mode="logix")
    write_value("logix", logix, "TAG", "Temp", 30)
    assert logix.logix_tags["Temp"] == ("REAL", 30.0)


@pytest.mark.parametrize(
    "kind, device, area, address, value, message",
    [
        ("slmp", SLMPDevice(), "D", 0, 70000, "16-bit word"),
        ("slmp", SLMPDevice(), "Q", 0, 1, "unknown area"),
        ("slmp", SLMPDevice(), "D", -1, 1, "0 or more"),
        ("slmp", SLMPDevice(), "D", 0, float("nan"), "finite"),
        ("logix", EtherNetIPDevice(mode="logix"), "TAG", "Nope", 1, "unknown tag"),
        ("logix", EtherNetIPDevice(mode="logix"), "TAG", "Recipe", 1, "not a number"),
        ("s7", S7Device(), "I", 0, 1, "unknown area"),
    ],
)
def test_bad_writes_are_rejected(kind, device, area, address, value, message):
    with pytest.raises(ValueError, match=message):
        write_value(kind, device, area, address, value)


def test_wave_values():
    assert wave_value("sine", 0, 100, 10, 0) == pytest.approx(0)
    assert wave_value("sine", 0, 100, 10, 5) == pytest.approx(100)
    assert wave_value("ramp", 10, 20, 4, 1) == pytest.approx(12.5)
    assert wave_value("ramp", 10, 20, 4, 5) == pytest.approx(12.5)  # repeats every period
    assert 10 <= wave_value("random", 10, 20, 4, 0) <= 20
    with pytest.raises(ValueError):
        wave_value("square", 0, 1, 1, 0)


def _read_d(port, start, end):
    async def read():
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)
        async with PLCDataCollector(plc, NetworkConfig(packet_interval_ms=0)) as collector:
            return await collector.collect_range(DeviceType.D, start, end)

    return asyncio.run(read())


def test_scanner_reads_what_the_controller_wrote(controller):
    port = controller.start("slmp", "127.0.0.1", 0)
    controller.write("slmp", "D", 0, 4321)
    points = _read_d(port, 0, 1)
    assert [(p.status, p.value) for p in points] == [(StatusCode.OK, 4321), (StatusCode.OK, 10)]


def test_denied_ranges_are_configurable(controller):
    port = controller.start("slmp", "127.0.0.1", 0, denied="0-0")
    statuses = [p.status for p in _read_d(port, 0, 1)]
    assert statuses == [StatusCode.NG_ILLEGAL_ADDR, StatusCode.OK]
    with pytest.raises(ValueError, match="denied ranges"):
        controller.start("modbus", "127.0.0.1", 0, denied="a-b")


def test_generator_changes_the_value_and_stops(controller):
    controller.start("modbus", "127.0.0.1", 0)
    controller.start_generator(Generator("modbus", "HR", 3, "ramp", 100, 200, 1.0), interval=0.02)
    seen = set()
    for _ in range(20):
        seen.add(controller.read("modbus", "HR", 3))
        time.sleep(0.03)
    assert len(seen) > 3 and all(100 <= v <= 200 for v in seen)
    assert [g.address for g in controller.generators()] == [3]
    controller.stop_generator("modbus", "HR", 3)
    time.sleep(0.05)
    frozen = controller.read("modbus", "HR", 3)
    time.sleep(0.1)
    assert controller.read("modbus", "HR", 3) == frozen and controller.generators() == []


def test_bad_generators_are_rejected_up_front(controller):
    controller.start("logix", "127.0.0.1", 0)
    for generator, message in (
        (Generator("logix", "TAG", "Nope", "sine", 0, 1, 1), "unknown tag"),
        (Generator("logix", "TAG", "Temp", "sine", 5, 1, 1), "minimum"),
        (Generator("logix", "TAG", "Temp", "sine", 0, 1, 0), "period"),
        (Generator("slmp", "D", 0, "sine", 0, 1, 1), "not running"),
    ):
        with pytest.raises(ValueError, match=message):
            controller.start_generator(generator)
    assert controller.generators() == []


def test_stop_frees_the_port_and_stops_generators(controller):
    port = controller.start("fins", "127.0.0.1", 0)
    controller.start_generator(Generator("fins", "DM", 0, "sine", 0, 10, 1))
    with pytest.raises(ValueError, match="already running"):
        controller.start("fins", "127.0.0.1", port)
    controller.stop("fins")
    assert not controller.is_running("fins") and controller.generators() == []
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):  # both FINS transports released
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind(("127.0.0.1", port))
    controller.stop("fins")  # stopping a stopped simulator is a no-op


def test_port_in_use_is_reported(controller):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        with pytest.raises(OSError):
            controller.start("slmp", "127.0.0.1", s.getsockname()[1])
    assert not controller.is_running("slmp")


def test_gui_module_imports_without_a_display(monkeypatch):
    """The Tk window itself needs a display; at least the module and its options load"""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("messagebox", "ttk", "scrolledtext"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
    monkeypatch.delitem(sys.modules, "simulators.simulator_gui", raising=False)
    from simulators import simulator_gui

    with pytest.raises(SystemExit) as exit_info:
        simulator_gui.main(["--help"])
    assert exit_info.value.code == 0


def test_stop_drops_connected_scanners(controller):
    """A periodic scan keeps its connection: stopping must still make the PLC go away"""
    port = controller.start("slmp", "127.0.0.1", 0)

    async def scan():
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)
        config = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=1000)
        async with PLCDataCollector(plc, config) as collector:
            before = await collector.collect_range(DeviceType.D, 0, 0)
            await asyncio.to_thread(controller.stop, "slmp")
            after = await collector.collect_range(DeviceType.D, 0, 0)
        return before[0].status, after[0].status

    before, after = asyncio.run(scan())
    assert before == StatusCode.OK and after != StatusCode.OK


def test_generator_limits_outside_the_area_are_rejected(controller):
    controller.start("modbus", "127.0.0.1", 0)
    with pytest.raises(ValueError, match="16-bit word"):
        controller.start_generator(Generator("modbus", "HR", 1, "ramp", 0, 70000, 1))
    assert controller.generators() == []
