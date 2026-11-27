"""
SLMP over UDP (protocol slmp-udp) and the simulator GUI's 詳細 settings
(late answers, no answer for denied addresses, connection limit, ASCII, UDP).
"""

import asyncio
import contextlib
import json
import socket
import struct
import sys
import threading
import time
from unittest.mock import patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.collector import PROTOCOL_HANDLERS, PLCDataCollector
from plc_discovery.config import DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.names import parse_protocol
from plc_discovery.probes import UDP_PROTOCOLS, identify_slmp_udp, slmp_type_name_request
from plc_discovery.protocols.slmp import SLMPHandler
from simulators.common import Faults, with_datagram_faults
from simulators.control import Extras, SavedState, SimulatorController, SimulatorSetting, apply_state
from simulators.fins_simulator import FINSSimulator, FINSUDPServerProtocol
from simulators.slmp_simulator import SLMPDevice, SLMPUDPProtocol

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500, discovery_timeout_ms=300)


@contextlib.contextmanager
def udp_serve(protocol_factory):
    """An asyncio UDP endpoint on a free loopback port, run in a thread; yields the port"""
    loop = asyncio.new_event_loop()
    endpoint, _ = loop.run_until_complete(loop.create_datagram_endpoint(protocol_factory, local_addr=("127.0.0.1", 0)))
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        yield endpoint.get_extra_info("sockname")[1]
    finally:
        loop.call_soon_threadsafe(endpoint.close)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _read(port, *reads, **options):
    async def run():
        handler = SLMPHandler("127.0.0.1", port, udp=1, config=FAST, **options)
        assert await handler.connect()
        try:
            return [await handler.read_device_raw(*read) for read in reads]
        finally:
            await handler.disconnect()

    return asyncio.run(run())


# ---------------------------------------------------------------- the protocol


def test_slmp_udp_is_a_protocol_of_its_own():
    assert parse_protocol("slmp-udp") is Protocol.SLMP_UDP and parse_protocol("slmp_udp") is Protocol.SLMP_UDP
    assert Protocol.SLMP_UDP in UDP_PROTOCOLS  # probed without a TCP port check
    handler = PROTOCOL_HANDLERS[Protocol.SLMP_UDP]("10.0.0.1", 5001)
    assert handler.protocol is Protocol.SLMP_UDP and handler.settings_text == "3E UDP"


@pytest.mark.parametrize("ascii_code", [False, True])
def test_slmp_handler_reads_words_and_bits_over_udp(ascii_code):
    device = SLMPDevice([(5000, 5100)])
    device.write_words("D", 10, [0x1234, 7])
    device.write_bits("X", 0x1F, [1])
    with udp_serve(lambda: SLMPUDPProtocol(device, ascii_code)) as port:
        words, bits, denied = _read(
            port, (DeviceType.D, 10, 2), (DeviceType.X, 0x1E, 3), (DeviceType.D, 5000, 5), ascii=int(ascii_code)
        )
    assert words == ([0x1234, 7], StatusCode.OK)
    assert bits == ([0, 1, 0], StatusCode.OK)
    assert denied == (None, StatusCode.NG_ILLEGAL_ADDR)


def test_slmp_udp_read_with_4e_frames():
    device = SLMPDevice([])
    device.write_words("D", 0, [99])
    with udp_serve(lambda: SLMPUDPProtocol(device)) as port:
        assert _read(port, (DeviceType.D, 0, 1), frame=4) == [([99], StatusCode.OK)]


def test_an_unanswered_udp_request_times_out_and_a_new_socket_is_used():
    device = SLMPDevice([])
    device.write_words("D", 0, [1])
    faults = Faults(delay_ms=800)  # longer than the 500 ms request timeout

    async def run(port):
        handler = SLMPHandler("127.0.0.1", port, udp=1, config=FAST)
        await handler.connect()
        try:
            local = handler._client._sock.getsockname()[1]
            first = await handler.read_device_raw(DeviceType.D, 0, 1)
            reconnect = handler._needs_reconnect
            await asyncio.sleep(0.5)  # the late answer arrives meanwhile, to the old socket
            second = await handler.read_device_raw(DeviceType.D, 0, 1)
            return first, reconnect, local, handler._client._sock.getsockname()[1], second
        finally:
            await handler.disconnect()

    with udp_serve(with_datagram_faults(lambda: SLMPUDPProtocol(device), faults, device)) as port:
        first, reconnect, before, after, second = asyncio.run(run(port))
    assert first == (None, StatusCode.NG_TIMEOUT) and reconnect
    # A new local port: the late answer to the first request is never read
    # as the answer to the second one (which times out again)
    assert before != after and second == (None, StatusCode.NG_TIMEOUT)


def test_nothing_listening_on_the_udp_port_is_a_communication_error():
    [result] = _read(free_udp_port(), (DeviceType.D, 0, 1))
    assert result[0] is None and result[1] in (StatusCode.NG_COMM_ERROR, StatusCode.NG_TIMEOUT)


@pytest.mark.parametrize("options, error", [({"frame": 4, "ascii": 1}, False), ({"udp": 1}, True)])
def test_slmp_udp_target_options(options, error):
    loader = ConfigLoader()
    loader._merge_config({"targets": [{"ip": "10.0.0.1", "protocol": "slmp-udp", "options": options}]})
    assert any("targets[0].options" in e for e in loader.validate()) == error
    assert loader.get_targets()[0].protocol is Protocol.SLMP_UDP


# ---------------------------------------------------------------- discovery


@pytest.mark.parametrize("ascii_code, cpu", [(False, "Q03UDVCPU"), (True, "R04CPU")])
def test_udp_probe_reads_the_model_and_the_data_code(ascii_code, cpu):
    device = SLMPDevice([], cpu=cpu)
    with udp_serve(lambda: SLMPUDPProtocol(device, ascii_code)) as port:
        identity = identify_slmp_udp("127.0.0.1", port, 0.5)
    assert (identity["frame"], identity["ascii"], identity["model"]) == ("3E", ascii_code, cpu)


def test_a_silent_udp_host_costs_about_one_timeout():
    with udp_serve(asyncio.DatagramProtocol) as port:  # receives, never answers
        started = time.monotonic()
        assert identify_slmp_udp("127.0.0.1", port, 0.3) is None
        assert time.monotonic() - started < 0.6  # not one timeout per setting


def test_udp_probe_requests_are_sent_once_each():
    received = []

    class Recorder(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            received.append(data)

    with udp_serve(Recorder) as port:
        identify_slmp_udp("127.0.0.1", port, 0.2)
        time.sleep(0.05)
    assert received == [slmp_type_name_request(f, a) for f, a in (("3E", 0), ("4E", 0), ("3E", 1), ("4E", 1))]


def test_discovery_lists_an_slmp_udp_port_with_its_settings():
    device = SLMPDevice([], cpu="R04CPU")
    with udp_serve(lambda: SLMPUDPProtocol(device, True)) as port:
        discovery = PLCDiscovery(FAST, protocols=[Protocol.SLMP_UDP], port=port)
        found = asyncio.run(discovery._probe_host_all("127.0.0.1"))
    [plc] = found
    assert (plc.protocol, plc.port, plc.model) == (Protocol.SLMP_UDP, port, "R04CPU")
    assert plc.options == {"ascii": 1} and plc.note == "SLMP 3E・ASCII・UDP"


def test_a_given_slmp_udp_target_is_read_with_the_settings_its_port_answers():
    device = SLMPDevice([])
    device.write_words("D", 0, [12])
    with udp_serve(lambda: SLMPUDPProtocol(device, True)) as port:
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP_UDP, port=port)  # no frame / ascii given

        async def run():
            collector = PLCDataCollector(plc, FAST)
            assert await collector.connect()
            try:
                return await collector._handler.read_device_raw(DeviceType.D, 0, 1)
            finally:
                await collector.disconnect()

        assert asyncio.run(run()) == ([12], StatusCode.OK)
    assert plc.options == {"frame": 3, "ascii": 1} and plc.note == "SLMP 3E・ASCII・UDP"


def test_broadcast_reply_with_a_model_name():
    reply = b"\xd0\x00\x00\xff\xff\x03\x00" + struct.pack("<H", 20) + b"\x00\x00" + b"Q06UDVCPU".ljust(16) + b"\x68\x03"
    plc = BroadcastDiscovery()._parse_slmp_response("10.0.0.5", reply)
    assert (plc.protocol, plc.model, plc.manufacturer) == (Protocol.SLMP_UDP, "Q06UDVCPU", "三菱電機/SLMP互換")


def test_udp_probe_is_faked_with_verify_protocol_in_tests():
    # conftest: while verify_protocol is replaced, the UDP probe follows it
    with patch.object(discovery_module, "verify_protocol", return_value=True):
        assert discovery_module.identify_slmp_udp("10.0.0.1", 5001, 0.1)["frame"] == "3E"


# ---------------------------------------------------------------- simulator faults over UDP


def _fins_read_request():
    header = bytes([0x80, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x01])
    return header + bytes([0x01, 0x01, 0x82, 0x13, 0x88, 0x00, 0x00, 0x0A])  # DM5000 x10 (denied)


def test_fins_udp_drops_requests_touching_denied_addresses():
    simulator = FINSSimulator()
    factory = with_datagram_faults(lambda: FINSUDPServerProtocol(simulator), Faults(drop_denied=True), simulator)
    with udp_serve(factory) as port, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.3)
        s.sendto(_fins_read_request(), ("127.0.0.1", port))
        with pytest.raises(socket.timeout):
            s.recv(512)


def test_udp_answers_come_late_with_delay():
    device = SLMPDevice([])
    factory = with_datagram_faults(lambda: SLMPUDPProtocol(device), Faults(delay_ms=300), device)
    with udp_serve(factory) as port:
        started = time.monotonic()
        assert identify_slmp_udp("127.0.0.1", port, 1.0)["model"] == device.cpu_model
        assert time.monotonic() - started >= 0.28


# ---------------------------------------------------------------- simulator GUI settings


@pytest.fixture
def controller():
    c = SimulatorController()
    yield c
    c.shutdown()


def test_controller_starts_slmp_over_udp_in_ascii(controller):
    extras = Extras(ascii=True, udp=True)
    port = controller.start("slmp", "127.0.0.1", 0, extras=extras)
    controller.write("slmp", "D", 3, 42)
    assert _read(port, (DeviceType.D, 3, 1), ascii=1) == [([42], StatusCode.OK)]
    assert controller.settings("slmp").extras == extras
    assert controller.clients("slmp") == []  # UDP: no connections


def test_controller_applies_the_faults(controller):
    port = controller.start("modbus", "127.0.0.1", 0, extras=Extras(delay_ms=300, max_connections=1))
    request = struct.pack(">HHHB", 1, 0, 6, 1) + struct.pack(">BHH", 0x03, 0, 1)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as first:
        started = time.monotonic()
        first.sendall(request)
        assert first.recv(64) and time.monotonic() - started >= 0.28
        with socket.create_connection(("127.0.0.1", port), timeout=2) as second:
            try:
                second.sendall(request)
                answer = second.recv(64)
            except ConnectionResetError:
                answer = b""
            assert answer == b""  # beyond the limit: closed


@pytest.mark.parametrize(
    "key, extras",
    [
        ("modbus", Extras(udp=True)),  # SLMP only
        ("logix", Extras(drop_denied=True)),  # no denied addresses
        ("slmp", Extras(udp=True, max_connections=1)),  # nothing to limit over UDP
        ("slmp", Extras(delay_ms=-1)),
    ],
)
def test_controller_rejects_settings_a_simulator_does_not_have(controller, key, extras):
    with pytest.raises(ValueError):
        controller.start(key, "127.0.0.1", 0, extras=extras)
    assert not controller.is_running(key)


def test_extras_are_saved_and_restored(controller):
    state = SavedState(
        simulators={
            "slmp": SimulatorSetting(0, None, False, running=True, extras=Extras(delay_ms=200, ascii=True, udp=True)),
            "fins": SimulatorSetting(0, None, False, running=False, extras=Extras(drop_denied=True)),
            "s7": SimulatorSetting(0, None, False, running=False),
        }
    )
    text = state.to_json()
    data = json.loads(text)["simulators"]
    assert data["slmp"]["delay_ms"] == 200 and data["slmp"]["udp"] is True and "max_connections" not in data["slmp"]
    assert "delay_ms" not in data["s7"]  # defaults are not written
    loaded = SavedState.from_json(text)
    assert loaded.simulators["slmp"].extras == Extras(delay_ms=200, ascii=True, udp=True)
    assert loaded.simulators["fins"].extras == Extras(drop_denied=True)
    assert apply_state(controller, loaded) == []
    assert controller.settings("slmp").extras.udp


@pytest.mark.parametrize(
    "item, fragment",
    [
        ({"delay_ms": "fast"}, "delay_ms"),
        ({"udp": 1}, "udp"),
        ({"ascii": True}, "ASCII"),  # on Modbus
    ],
)
def test_invalid_extras_in_a_state_file(item, fragment):
    text = json.dumps({"version": 1, "simulators": {"modbus": {"port": 1502, **item}}})
    with pytest.raises(ValueError, match=fragment):
        SavedState.from_json(text)


def test_extras_label():
    assert Extras().label == ""
    assert Extras(300, True, 2, True, False).label == "遅延 300 ms・読めないアドレスに応答なし・接続 2 本まで・ASCII"


def test_gui_dialog_fields_become_extras(monkeypatch):
    monkeypatch.delitem(sys.modules, "simulators.simulator_gui", raising=False)
    from simulators.control import KINDS_BY_KEY
    from simulators.simulator_gui import extras_from_fields

    slmp, modbus = KINDS_BY_KEY["slmp"], KINDS_BY_KEY["modbus"]
    assert extras_from_fields(slmp, "300", True, "0", True, True) == Extras(300, True, 0, True, True)
    # Settings a simulator does not have are left out
    assert extras_from_fields(modbus, "", False, "2", True, True) == Extras(0, False, 2, False, False)
    for delay, limit, udp in (("x", "0", False), ("-1", "0", False), ("0", "1", True), ("99999999", "0", False)):
        with pytest.raises(ValueError):
            extras_from_fields(slmp, delay, False, limit, False, udp)
