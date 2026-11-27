"""
What a survey before collecting data with a gateway (Takebishi DeviceGateway)
needs from discovery and scans:

- SLMP: the CPU model name (0101) and the frame / data code the port answers
  (3E or 4E, binary or ASCII), used again for reading the data
- devices that answer none of the supported protocols are listed, not lost
- extra discovery ports (a PLC port set to another number)
- more device types: SLMP ZR / SD / L / TN / CN, FINS AR / EM / TIM / CNT
- the scan summary: readable ranges per device and the PLC's response times
- simulators: ASCII SLMP, late / dropped answers, busy ports, silent devices
"""

import asyncio
import contextlib
import csv
import socket
import struct
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import plc_gui
import plc_scanner
from plc_discovery import discovery as discovery_module
from plc_discovery.cli_args import parse_discover_ports
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
)
from plc_discovery.config_loader import ConfigLoader, parse_port_map
from plc_discovery.data_types import ByteOrder
from plc_discovery.discovery import (
    UNIDENTIFIED_MODEL,
    PLCDiscovery,
    apply_slmp_identity,
    detect_slmp_settings,
    discover_plcs,
)
from plc_discovery.output import CSVExporter
from plc_discovery.probes import identify_slmp, parse_slmp_type_name, slmp_type_name_request
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.protocols.slmp import SLMP_BIT_DEVICES, SLMP_DEVICE_MAP, SLMPHandler
from plc_discovery.survey import address_runs, readable_text, summary_row
from simulators.common import Faults, with_faults
from simulators.fins_simulator import FINSSimulator
from simulators.modbus_simulator import ModbusDevice, ModbusProtocol
from simulators.silent_device import SilentProtocol, parse_ports
from simulators.slmp_simulator import SLMPASCIIProtocol, SLMPDevice, SLMPProtocol

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=1000, discovery_timeout_ms=500)


@contextlib.contextmanager
def serve(protocol_factory):
    """An asyncio server on a free loopback port, run in a thread; yields the port"""
    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(protocol_factory, "127.0.0.1", 0))
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        server.close()


@contextlib.contextmanager
def answering(respond):
    """A TCP server answering each request with respond(request) (None: closed without an answer)"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    stop = threading.Event()

    def run():
        srv.settimeout(0.05)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    reply = respond(conn.recv(512))
                    if reply:
                        conn.sendall(reply)
                except OSError:
                    pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        thread.join(2)
        srv.close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------- SLMP identity


@pytest.mark.parametrize(
    "protocol_class, cpu, expected",
    [
        (SLMPProtocol, "Q03UDVCPU", ("3E", False, "Q03UDVCPU", 0x0366)),
        (SLMPASCIIProtocol, "R04CPU", ("3E", True, "R04CPU", 0x4800)),
    ],
)
def test_slmp_probe_reads_the_model_and_the_data_code(protocol_class, cpu, expected):
    device = SLMPDevice([], cpu=cpu)
    with serve(lambda: protocol_class(device)) as port:
        # An ASCII port leaves the binary requests unanswered: one short timeout each
        identity = identify_slmp("127.0.0.1", port, 0.3)
    assert (identity["frame"], identity["ascii"], identity["model"], identity["model_code"]) == expected


def _answer(frame, ascii_code, end_code=0, name=b"R08CPU", code=0x4801):
    """An answer to Read CPU Model Name in the given frame / data code"""
    if ascii_code:
        payload = f"{end_code:04X}" + (name.decode().ljust(16) + f"{code:04X}" if end_code == 0 else "00FF03FF00")
        head = "D000" if frame == "3E" else "D400" + "0000" + "0000"
        return (head + "00FF03FF00" + f"{len(payload):04X}" + payload).encode()
    payload = struct.pack("<H", end_code) + (name.ljust(16) + struct.pack("<H", code) if end_code == 0 else b"")
    head = b"\xd0\x00" if frame == "3E" else b"\xd4\x00\x00\x00\x00\x00"
    return head + b"\x00\xff\xff\x03\x00" + struct.pack("<H", len(payload)) + payload


@pytest.mark.parametrize("frame, ascii_code", [("3E", False), ("4E", False), ("3E", True), ("4E", True)])
def test_slmp_answers_are_parsed_in_every_frame_and_code(frame, ascii_code):
    identity = parse_slmp_type_name(_answer(frame, ascii_code), frame, ascii_code)
    assert identity == {"frame": frame, "ascii": ascii_code, "end_code": 0, "model": "R08CPU", "model_code": 0x4801}


def test_slmp_error_answer_confirms_the_protocol_without_a_model():
    # e.g. a Keyence KV or a module that does not support 0101: C059
    identity = parse_slmp_type_name(_answer("3E", False, end_code=0xC059), "3E", False)
    assert identity["end_code"] == 0xC059 and identity["model"] is None


def test_slmp_probe_finds_a_port_that_answers_only_4e_ascii():
    def respond(request):
        if request.startswith(b"5400"):  # 4E ASCII only; everything else is ignored
            return _answer("4E", True, name=b"FX5U-32MT/ES")
        return None

    with answering(respond) as port:
        identity = identify_slmp("127.0.0.1", port, 0.3)
    assert (identity["frame"], identity["ascii"], identity["model"]) == ("4E", True, "FX5U-32MT/ES")


def test_slmp_probe_requests_are_well_formed():
    assert slmp_type_name_request("3E", True) == b"5000" + b"00FF03FF00" + b"000C" + b"001001010000"
    binary = slmp_type_name_request("4E", False)
    assert binary[:6] == b"\x54\x00\x00\x00\x00\x00" and binary[11:13] == struct.pack("<H", 6)


def test_slmp_probe_gives_up_at_once_when_the_port_is_closed():
    started = time.monotonic()
    assert identify_slmp("127.0.0.1", free_port(), 2.0) is None
    assert time.monotonic() - started < 1.0  # not one timeout per setting


@pytest.mark.parametrize(
    "identity, options, maker",
    [
        ({"frame": "3E", "ascii": False, "model": "Q03UDVCPU", "model_code": 0x366}, {}, "三菱電機"),
        (
            {"frame": "4E", "ascii": True, "model": "KV-8000", "model_code": None},
            {"frame": 4, "ascii": 1},
            "キーエンス",
        ),
        ({"frame": "3E", "ascii": True, "model": None, "model_code": None}, {"ascii": 1}, None),
    ],
)
def test_slmp_identity_fills_the_model_and_the_handler_options(identity, options, maker):
    plc = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)
    apply_slmp_identity(plc, identity)
    assert plc.options == options and plc.manufacturer == maker
    assert plc.model == identity["model"]
    assert plc.note == f"SLMP {identity['frame']}・{'ASCII' if identity['ascii'] else 'バイナリ'}"


def test_a_given_slmp_target_is_read_with_the_settings_its_port_answers():
    device = SLMPDevice([])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port, model="Line 3")
        asyncio.run(detect_slmp_settings(plc, FAST))
    assert plc.options == {"ascii": 1} and plc.model == "Line 3"  # the user's name is kept


def test_slmp_settings_given_by_the_user_are_not_probed():
    plc = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, options={"frame": 4})
    with patch.object(discovery_module, "identify_slmp", side_effect=AssertionError("not expected")):
        asyncio.run(detect_slmp_settings(plc, FAST))
    assert plc.options == {"frame": 4}


# ---------------------------------------------------------------- SLMP reads


def test_slmp_handler_reads_ascii_with_hexadecimal_x_numbers():
    device = SLMPDevice([])
    device.write_bits("X", 0x1F, [1])  # X1F
    device.write_words("D", 100, [0x1234, 0xFFFF])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:

        async def read():
            handler = SLMPHandler("127.0.0.1", port, ascii=1, config=FAST)
            assert await handler.connect()
            try:
                return (
                    await handler.read_device_raw(DeviceType.X, 0x1E, 3),
                    await handler.read_device_raw(DeviceType.D, 100, 2),
                )
            finally:
                await handler.disconnect()

        bits, words = asyncio.run(read())
    assert bits == ([0, 1, 0], StatusCode.OK)
    assert words == ([0x1234, 0xFFFF], StatusCode.OK)


def test_slmp_handler_reads_with_4e_frames():
    device = SLMPDevice([])
    device.write_words("D", 7, [42])
    with serve(lambda: SLMPProtocol(device)) as port:

        async def read():
            handler = SLMPHandler("127.0.0.1", port, frame=4, config=FAST)
            assert handler.settings_text == "4E"
            assert await handler.connect()
            try:
                return await handler.read_device_raw(DeviceType.D, 7, 1)
            finally:
                await handler.disconnect()

        assert asyncio.run(read()) == ([42], StatusCode.OK)


def test_slmp_ascii_address_errors_are_still_address_errors():
    device = SLMPDevice([(5000, 5100)])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:

        async def read():
            handler = SLMPHandler("127.0.0.1", port, ascii=1, config=FAST)
            await handler.connect()
            try:
                return await handler.read_device_raw(DeviceType.D, 5000, 10)
            finally:
                await handler.disconnect()

        assert asyncio.run(read()) == (None, StatusCode.NG_ILLEGAL_ADDR)


@pytest.mark.parametrize(
    "options, error",
    [({"frame": 4, "ascii": 1}, False), ({"frame": 5}, True), ({"ascii": 2}, True), ({"unit_id": 1}, True)],
)
def test_slmp_target_options_are_validated(options, error):
    loader = ConfigLoader()
    loader._merge_config({"targets": [{"ip": "10.0.0.1", "protocol": "slmp", "options": options}]})
    assert any("targets[0].options" in e for e in loader.validate()) == error


# ---------------------------------------------------------------- unidentified devices


def _fake_ports(open_ports, verified=()):
    return (
        patch.object(discovery_module, "is_port_open", side_effect=lambda ip, p, t: p in open_ports),
        patch.object(discovery_module, "verify_protocol", side_effect=lambda ip, p, proto, t: p in verified),
    )


def test_a_device_with_an_open_plc_port_but_no_answer_is_listed():
    discovery = PLCDiscovery(FAST)
    port_patch, verify_patch = _fake_ports({5001, 502})
    with port_patch, verify_patch:
        found = asyncio.run(discovery._probe_host_all("10.0.0.5"))
    assert found == []  # nothing to scan
    device = discovery.unidentified["10.0.0.5"]
    assert device.protocol is None and device.model == UNIDENTIFIED_MODEL
    assert "502（MODBUS_TCP）" in device.note and "5001（SLMP）" in device.note


def test_a_device_with_a_plc_makers_mac_is_listed_without_open_ports():
    discovery = PLCDiscovery(FAST)
    port_patch, verify_patch = _fake_ports(set())
    with port_patch, verify_patch:
        asyncio.run(discovery._probe_host_all("10.0.0.6", mac="00:00:64:12:34:56"))  # Yokogawa
        asyncio.run(discovery._probe_host_all("10.0.0.7", mac="AA:BB:CC:12:34:56"))  # unknown maker
    assert discovery.unidentified["10.0.0.6"].manufacturer == "横河電機"
    assert "10.0.0.7" not in discovery.unidentified


def test_a_found_plc_is_not_also_unidentified():
    discovery = PLCDiscovery(FAST)
    port_patch, verify_patch = _fake_ports({5001, 502}, verified={502})
    with port_patch, verify_patch, patch.object(discovery, "_get_detailed_info", side_effect=_same):
        found = asyncio.run(discovery._probe_host_all("10.0.0.8", mac="00:00:64:12:34:56"))
    assert [p.protocol for p in found] == [Protocol.MODBUS_TCP] and discovery.unidentified == {}


async def _same(plc):
    return plc


def test_hosts_in_the_arp_cache_with_a_plc_makers_mac_are_listed():
    discovery = PLCDiscovery(FAST)
    cache = {"10.0.0.9": "00:26:92:00:00:01", "10.0.0.10": "AA:BB:CC:00:00:01", "10.0.0.99": "00:26:92:00:00:02"}
    with patch.object(discovery_module, "read_arp_cache", return_value=cache):
        asyncio.run(discovery._note_unidentified_from_arp_cache(["10.0.0.9", "10.0.0.10"]))
    assert list(discovery.unidentified) == ["10.0.0.9"]  # in range, PLC maker
    assert discovery.unidentified["10.0.0.9"].manufacturer == "三菱電機"


def test_discover_plcs_hands_out_unidentified_devices_separately():
    async def run():
        unidentified = []
        with (patch.object(PLCDiscovery, "discover_ip_range", autospec=True) as scan,):

            async def fake(self, ip_range):
                self.unidentified["10.0.0.5"] = PLCInfo("10.0.0.5", model=UNIDENTIFIED_MODEL)
                return []

            scan.side_effect = fake
            found = await discover_plcs("10.0.0.0/30", FAST, unidentified=unidentified)
        return found, unidentified

    found, unidentified = asyncio.run(run())
    assert found == [] and [u.ip_address for u in unidentified] == ["10.0.0.5"]


def test_cli_discovery_writes_unidentified_devices_to_the_csv_only(tmp_path):
    plc = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, model="Q03UDVCPU", note="SLMP 3E・バイナリ")
    silent = PLCInfo(
        "10.0.0.2", model=UNIDENTIFIED_MODEL, note="ポートは開いているが、対応プロトコルの応答なし: 5001（SLMP）"
    )

    async def fake_discover(ip_range, config, protocols=None, extra_ports=None, unidentified=None):
        unidentified.append(silent)
        return [plc]

    db = MagicMock(is_enabled=True)
    db.export_discovery_results.return_value = 1
    with patch.object(plc_scanner, "discover_plcs", side_effect=fake_discover):
        found = asyncio.run(
            plc_scanner.run_discovery(["10.0.0.0/30"], FAST, CSVExporter(str(tmp_path)), MagicMock(), db)
        )
    assert found == [plc]
    db.export_discovery_results.assert_called_once_with([plc])  # not the unidentified device
    rows = list(csv.DictReader(open(next(tmp_path.glob("discovery_result_*.csv")), encoding="utf-8-sig")))
    assert [(r["ip_address"], r["model"], r["note"]) for r in rows] == [
        ("10.0.0.1", "Q03UDVCPU", "SLMP 3E・バイナリ"),
        ("10.0.0.2", UNIDENTIFIED_MODEL, silent.note),
    ]


def test_gui_does_not_collect_from_an_unidentified_device(monkeypatch):
    shown = []
    monkeypatch.setattr(plc_gui.messagebox, "showinfo", lambda title, text: shown.append(text))
    app = MagicMock()
    app.tree_plc.selection.return_value = ["0"]
    app.discovered = [PLCInfo("10.0.0.2", model=UNIDENTIFIED_MODEL, note="ポートは開いているが…")]
    plc_gui.PLCScannerApp._use_selected_plc(app)
    assert shown and "10.0.0.2" in shown[0]
    app.var_target.set.assert_not_called()


# ---------------------------------------------------------------- extra ports


def test_extra_ports_are_probed_after_the_standard_port():
    discovery = PLCDiscovery(FAST, extra_ports={Protocol.SLMP: [5000, 5001, 5002]})
    assert discovery._candidate_ports("10.0.0.1", Protocol.SLMP) == [5001, 5000, 5002]
    assert discovery._candidate_ports("10.0.0.1", Protocol.S7) == [102]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("slmp=5000,5002", {Protocol.SLMP: [5000, 5002]}),
        ("slmp=5000; modbus=1502;", {Protocol.SLMP: [5000], Protocol.MODBUS_TCP: [1502]}),
        ("eip=44818,44818", {Protocol.ETHERNET_IP: [44818]}),
    ],
)
def test_discover_ports_option(text, expected):
    assert parse_discover_ports(text) == expected


@pytest.mark.parametrize("text", ["slmp", "slmp=", "slmp=abc", "nope=5000", "slmp=70000"])
def test_invalid_discover_ports_option(text):
    with pytest.raises(ValueError):
        parse_discover_ports(text)


def test_discovery_ports_in_the_config_file():
    loader = ConfigLoader()
    loader._merge_config({"discovery": {"ports": {"slmp": [5000, 5002], "fins": 9601}}})
    assert loader.validate() == []
    assert loader.get_discovery_ports() == {Protocol.SLMP: [5000, 5002], Protocol.FINS: [9601]}
    assert parse_port_map({"slmp": [0]})[1] and parse_port_map(["slmp"])[1] and parse_port_map({"x": [1]})[1]


# ---------------------------------------------------------------- device types


def test_slmp_reads_the_new_device_types():
    assert {DeviceType.ZR, DeviceType.SD, DeviceType.L, DeviceType.TN, DeviceType.CN} <= set(SLMP_DEVICE_MAP)
    assert DeviceType.L in SLMP_BIT_DEVICES and DeviceType.TN not in SLMP_BIT_DEVICES


def test_slmp_simulator_answers_the_new_device_types():
    device = SLMPDevice([])
    device.write_words("TN", 3, [77])
    device.write_bits("L", 10, [1])
    with serve(lambda: SLMPProtocol(device)) as port:

        async def read():
            handler = SLMPHandler("127.0.0.1", port, config=FAST)
            await handler.connect()
            try:
                return [
                    await handler.read_device_raw(DeviceType.TN, 3, 1),
                    await handler.read_device_raw(DeviceType.L, 9, 3),
                    await handler.read_device_raw(DeviceType.ZR, 0, 2),
                ]
            finally:
                await handler.disconnect()

        tn, latch, zr = asyncio.run(read())
    assert tn == ([77], StatusCode.OK) and latch == ([0, 1, 0], StatusCode.OK) and zr[1] == StatusCode.OK


@pytest.mark.parametrize(
    "device, start, count, values",
    [
        (DeviceType.AR, 5, 2, [5, 6]),
        (DeviceType.EM, 0, 2, [1000, 1001]),
        (DeviceType.TN, 1, 2, [51, 52]),
        (DeviceType.CN, 2, 2, [6, 9]),
    ],
)
def test_fins_reads_ar_em_timers_and_counters(device, start, count, values):
    simulator = FINSSimulator()
    handler = FINSHandler("127.0.0.1")
    response = simulator.handle_frame(handler._build_read_command(device, start, count), ("127.0.0.1", 9600))
    assert handler._parse_read_response(response) == (values, StatusCode.OK)


def test_fins_counters_start_at_8000_hex_and_timers_end_before():
    handler = FINSHandler("127.0.0.1")
    frame = handler._build_read_command(DeviceType.CN, 5, 1)
    assert frame[12:15] == bytes([0x89, 0x80, 0x05])
    handler._connected = True
    handler._needs_reconnect = False
    assert asyncio.run(handler.read_device_raw(DeviceType.TN, 0x7FFF, 2)) == (None, StatusCode.NG_ILLEGAL_ADDR)


# ---------------------------------------------------------------- scan summary


def _points(*items):
    return [DataPoint(address=a, value=0, status=s, timestamp="t") for a, s in items]


OK, ILLEGAL = StatusCode.OK, StatusCode.NG_ILLEGAL_ADDR


def test_addresses_are_grouped_into_runs():
    points = _points(("D0", OK), ("D1", OK), ("D2", ILLEGAL), ("D3", ILLEGAL), ("D5", OK), ("M0", OK))
    points += _points(("Line.Speed", OK), ("Line.Count", OK), ("Line.Name", ILLEGAL))
    runs = [(r.text, r.count, r.status) for r in address_runs(points)]
    assert runs == [
        ("D0-1", 2, "OK"),
        ("D2-3", 2, "NG_ILLEGAL_ADDR"),
        ("D5", 1, "OK"),  # not joined across the gap
        ("M0", 1, "OK"),
        ("Line.Speed - Line.Count", 2, "OK"),  # tags: joined while the status stays the same
        ("Line.Name", 1, "NG_ILLEGAL_ADDR"),
    ]
    assert readable_text(address_runs(points)) == "D0-1, D5, M0, Line.Speed - Line.Count"


def test_readable_ranges_text_is_shortened():
    points = _points(*[(f"D{i * 2}", OK) for i in range(200)])
    text = readable_text(address_runs(points), limit=30)
    assert len(text) < 50 and text.endswith(")") and "…" in text


def test_summary_row_counts_and_response_times():
    plc = PLCInfo("10.0.0.1", manufacturer="三菱電機", model="R04CPU", protocol=Protocol.SLMP, port=5001)
    row = summary_row(
        "10.0.0.1",
        plc,
        _points(("D0", OK), ("D1", ILLEGAL)),
        {"requests": 3, "avg_response_ms": 1.5, "max_response_ms": 2.0, "scan_seconds": 0.4},
    )
    assert (row["ok"], row["ng_illegal_addr"], row["success_rate"], row["readable_ranges"]) == (1, 1, "50.0%", "D0")
    assert (row["requests"], row["avg_response_ms"], row["max_response_ms"], row["scan_seconds"]) == (3, 1.5, 2.0, 0.4)
    assert summary_row("x", None, [], None)["avg_response_ms"] == ""


def test_survey_summary_files(tmp_path):
    points = _points(("D0", OK), ("D1", OK), ("D2", ILLEGAL))
    summary, ranges = CSVExporter(str(tmp_path)).export_survey_summary(
        [("10.0.0.1", PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), points, {"requests": 2})]
    )
    rows = list(csv.DictReader(open(summary, encoding="utf-8-sig")))
    assert rows[0]["readable_ranges"] == "D0-1" and rows[0]["requests"] == "2"
    runs = list(csv.DictReader(open(ranges, encoding="utf-8-sig")))
    assert [(r["device"], r["start"], r["end"], r["status"]) for r in runs] == [
        ("D", "0", "1", "OK"),
        ("D", "2", "2", "NG_ILLEGAL_ADDR"),
    ]
    assert Path(summary).name.startswith("scan_summary_") and Path(ranges).name.startswith("readable_ranges_")


def test_a_scan_records_requests_response_times_and_its_duration(tmp_path):
    device = SLMPDevice([(5000, 5100)])
    with serve(lambda: SLMPProtocol(device)) as port:
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)
        outcome = asyncio.run(
            plc_scanner.scan_target(
                plc,
                FAST,
                CSVExporter(str(tmp_path)),
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 4998, 5001)],
                None,
                ByteOrder.LITTLE_ENDIAN,
                None,
                None,
                "127.0.0.1",
                None,
            )
        )
    stats = outcome.statistics
    assert stats["requests"] >= 3 and stats["avg_response_ms"] is not None and "scan_seconds" in stats
    results = plc_scanner._RunResults()
    results.add("127.0.0.1", True, None, outcome.data_points, set(), outcome.statistics)
    results.targets["127.0.0.1"] = plc
    plc_scanner._write_survey_summary(CSVExporter(str(tmp_path)), MagicMock(), results)
    row = next(csv.DictReader(open(next(tmp_path.glob("scan_summary_*.csv")), encoding="utf-8-sig")))
    assert row["readable_ranges"] == "D4998-4999" and row["ng_illegal_addr"] == "2"


def test_collector_without_a_connection_has_no_request_statistics():
    assert PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.SLMP)).request_statistics() == {}


# ---------------------------------------------------------------- simulator faults


def _exchange(port, request, timeout=1.0):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(request)
        try:
            return s.recv(512)
        except socket.timeout:
            return None


def _modbus_read(address, count=1):
    return struct.pack(">HHHB", 1, 0, 6, 1) + struct.pack(">BHH", 0x03, address, count)


def test_simulator_answers_late_with_delay():
    device = ModbusDevice([])
    with serve(with_faults(lambda: ModbusProtocol(device), Faults(delay_ms=300), device)) as port:
        started = time.monotonic()
        assert _exchange(port, _modbus_read(0))
        assert time.monotonic() - started >= 0.28


def test_simulator_drops_requests_touching_denied_addresses():
    device = ModbusDevice([(5000, 5100)])
    with serve(with_faults(lambda: ModbusProtocol(device), Faults(drop_denied=True), device)) as port:
        assert _exchange(port, _modbus_read(4990, 20), timeout=0.3) is None  # not even an exception answer
        assert _exchange(port, _modbus_read(4990, 10))[7] == 0x03  # the rest is answered


def test_simulator_closes_connections_beyond_the_limit():
    device = SLMPDevice([])
    with serve(with_faults(lambda: SLMPProtocol(device), Faults(max_connections=1), device)) as port:
        request = slmp_type_name_request("3E", False)
        with socket.create_connection(("127.0.0.1", port), timeout=1) as first:
            first.sendall(request)
            assert first.recv(64)[:2] == b"\xd0\x00"
            with socket.create_connection(("127.0.0.1", port), timeout=1) as second:
                try:
                    second.sendall(request)
                    answer = second.recv(64)
                except ConnectionResetError:
                    answer = b""
                assert answer == b""  # closed at once, nothing answered
        # Freed again once the first client left
        time.sleep(0.1)
        assert _exchange(port, request)[:2] == b"\xd0\x00"


def test_simulator_without_faults_is_unchanged():
    factory = MagicMock()
    assert with_faults(factory, None) is factory and with_faults(factory, Faults()) is factory


def test_silent_device_never_answers():
    assert parse_ports("5001, 44818") == [5001, 44818]
    with pytest.raises(ValueError):
        parse_ports("0")
    with serve(SilentProtocol) as port:
        assert _exchange(port, slmp_type_name_request("3E", False), timeout=0.3) is None
        assert identify_slmp("127.0.0.1", port, 0.2) is None


def test_slmp_ascii_simulator_answers_4e_and_rejects_other_commands():
    device = SLMPDevice([])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:
        reply = _exchange(port, slmp_type_name_request("4E", True))
        assert parse_slmp_type_name(reply, "4E", True)["model"] == device.cpu_model
        # Loopback test (0619) is not offered in ASCII: C059
        body = "0010" + "0619" + "0000" + "0002" + "AB"
        reply = _exchange(port, ("5000" + "00FF03FF00" + f"{len(body):04X}" + body).encode())
        assert reply[18:22] == b"C059"


# ---------------------------------------------------------------- review fixes


def test_tag_names_ending_in_digits_are_kept_in_the_summary():
    points = _points(("Motor1", OK), ("Motor2", OK), ("Tank3", ILLEGAL), ("D1", OK), ("D2", OK))
    assert [(r.text, r.status) for r in address_runs(points)] == [
        ("Motor1 - Motor2", "OK"),  # previously "MOTOR1-2"
        ("Tank3", "NG_ILLEGAL_ADDR"),
        ("D1-2", "OK"),
    ]


def test_slmp_handler_detects_the_setting_of_its_port_itself():
    device = SLMPDevice([])
    device.write_words("D", 5, [55])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:

        async def read():
            handler = SLMPHandler("127.0.0.1", port, config=FAST)  # no frame / ascii given
            assert await handler.connect()
            try:
                return handler.settings_text, await handler.read_device_raw(DeviceType.D, 5, 1)
            finally:
                await handler.disconnect()

        assert asyncio.run(read()) == ("3E ASCII", ([55], StatusCode.OK))


def test_slmp_handler_detects_again_once_the_plc_is_back():
    port = free_port()
    device = SLMPDevice([])
    device.write_words("D", 0, [7])

    async def run():
        handler = SLMPHandler("127.0.0.1", port, config=FAST)
        assert not await handler.connect()  # PLC off: nothing detected, not connected
        assert handler._detect
        loop = asyncio.get_running_loop()
        server = await loop.create_server(lambda: SLMPASCIIProtocol(device), "127.0.0.1", port)
        try:
            assert await handler.connect()  # back: detected now
            try:
                return handler.settings_text, await handler.read_device_raw(DeviceType.D, 0, 1)
            finally:
                await handler.disconnect()
        finally:
            server.close()

    assert asyncio.run(run()) == ("3E ASCII", ([7], StatusCode.OK))


def test_slmp_settings_given_are_not_detected(monkeypatch):
    from plc_discovery import probes
    from plc_discovery.protocols.slmp import SLMPBinaryHandler

    monkeypatch.setattr(probes, "identify_slmp", MagicMock(side_effect=AssertionError("not expected")))
    device = SLMPDevice([])
    with serve(lambda: SLMPProtocol(device)) as port:

        async def connect():
            handler = SLMPHandler("127.0.0.1", port, frame=3, config=FAST)
            ok = await handler.connect()
            await handler.disconnect()
            return ok

        assert asyncio.run(connect())
    assert SLMPBinaryHandler("127.0.0.1").settings_text == "4E" and not SLMPBinaryHandler("127.0.0.1")._detect


def test_unsupported_answers_decided_without_a_request_are_not_timed():
    from plc_discovery.protocols.modbus import ModbusHandler

    handler = ModbusHandler("10.0.0.1", config=FAST)
    handler._connected, handler._client = True, MagicMock()
    assert asyncio.run(handler._tracked_read(DeviceType.DM, 0, 1))[1] == StatusCode.NG_UNSUPPORTED
    assert (handler.request_count, handler.answered_count) == (0, 0)


def test_periodic_scans_report_requests_and_response_times(tmp_path):
    device = SLMPDevice([])
    with serve(lambda: SLMPProtocol(device)) as port:

        async def run():
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port, options={"frame": 3})],
                    FAST,
                    CSVExporter(str(tmp_path)),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 0, 9)],
                    interval=60,
                )
            )
            await asyncio.sleep(0.5)  # one cycle, then waiting for the next
            task.cancel()
            return await task

        (outcome,) = asyncio.run(run())
    assert outcome.statistics["requests"] >= 1 and outcome.statistics["avg_response_ms"] is not None


def test_statistics_without_answers_show_a_dash(capsys):
    from plc_discovery.progress import RichProgressDisplay

    RichProgressDisplay(use_rich=False).print_statistics({"requests": 0, "avg_response_ms": None})
    assert "avg_response_ms: -" in capsys.readouterr().out


def test_probe_threads_include_the_extra_ports():
    discovery = PLCDiscovery(FAST, protocols=[Protocol.SLMP], extra_ports={Protocol.SLMP: [5002]})
    with patch.object(discovery_module.concurrent.futures, "ThreadPoolExecutor") as pool:
        pool.return_value.shutdown = MagicMock()
        with patch.object(discovery, "_probe_host_all", side_effect=_no_plcs):
            asyncio.run(discovery._probe_hosts(["10.0.0.1"], {}))
    # A batch of 10 hosts x (SLMP + 1 extra port + the 4 simulator ports)
    assert pool.call_args.kwargs["max_workers"] == 10 * (1 + 1 + 4)


async def _no_plcs(host, mac=None):
    return []


def test_collector_counts_requests_across_reconnects_and_keeps_detected_settings():
    device = SLMPDevice([])
    with serve(lambda: SLMPASCIIProtocol(device)) as port:

        async def run():
            plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)
            collector = PLCDataCollector(plc, FAST)
            for _ in range(2):  # a reconnect creates a new handler
                assert await collector.connect()
                await collector._handler.read_device_range(DeviceRange(DeviceType.D, 0, 9))
                await collector.disconnect()
            return plc, collector.request_statistics()

        plc, stats = asyncio.run(run())
    assert stats["requests"] == 2 and stats["avg_response_ms"] is not None
    # Detected on the first connection and kept: the second one is not probed again
    assert plc.options == {"frame": 3, "ascii": 1}


class _IgnoresModelName(SLMPProtocol):
    """Reads like a PLC, but leaves Read CPU Model Name (0101) unanswered"""

    def _process_frame(self, frame):
        if frame[-6:-4] == b"\x01\x01":  # command 0101 (little-endian), subcommand 0000
            return b""
        return super()._process_frame(frame)


def test_a_device_ignoring_the_model_name_is_not_probed_on_every_reconnect(monkeypatch):
    from plc_discovery import probes

    calls = []
    real = probes.identify_slmp
    monkeypatch.setattr(probes, "identify_slmp", lambda *a: calls.append(a) or real(*a))
    device = SLMPDevice([])
    device.write_words("D", 0, [3])
    config = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=1000, discovery_timeout_ms=100)
    with serve(lambda: _IgnoresModelName(device)) as port:

        async def run():
            handler = SLMPHandler("127.0.0.1", port, config=config)
            assert await handler.connect()  # nothing detected: 3E binary
            first = await handler.read_device_raw(DeviceType.D, 0, 1)
            handler._needs_reconnect = True  # e.g. after a timeout
            second = await handler.read_device_raw(DeviceType.D, 0, 1)
            await handler.disconnect()
            return first, second, handler.detected_options

        first, second, kept = asyncio.run(run())
    assert first == second == ([3], StatusCode.OK)
    assert len(calls) == 1  # the answered read settled it: no probe on the reconnect
    assert kept == {"frame": 3, "ascii": 0}


def test_the_collector_fills_in_the_model_and_settings_the_handler_found():
    device = SLMPDevice([], cpu="R04CPU")
    with serve(lambda: SLMPASCIIProtocol(device)) as port:
        plc = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)  # given without options (--protocol slmp)
        named = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port, model="Line 3")

        async def run():
            for target in (plc, named):
                collector = PLCDataCollector(target, FAST)
                assert await collector.connect()
                await collector.disconnect()

        asyncio.run(run())
    assert (plc.model, plc.note, plc.options) == ("R04CPU", "SLMP 3E・ASCII", {"frame": 3, "ascii": 1})
    assert named.model == "Line 3"  # the user's name wins


def test_cli_targets_are_not_probed_before_connecting():
    # The handler detects the settings when it connects: no second probe first
    with patch.object(discovery_module, "identify_slmp", side_effect=AssertionError("not expected")):
        plc = asyncio.run(plc_scanner.resolve_target("127.0.0.1", Protocol.SLMP, 5001, FAST, MagicMock()))
    assert plc.options == {}
