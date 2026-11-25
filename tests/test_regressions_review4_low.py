"""
Regressions from the fourth code review (low findings):
- read path: a dead link is found with fewer requests, retries are paced,
  one S7 chunk is one request, the circuit breaker uses the monotonic clock,
  EtherNet/IP: a busy controller is not an invalid address, array reads are
  not sent as a burst, an interrupted tag scan keeps what it read
- scan control: numbers are shown in full, duplicated limits, alignment of
  the default type behind a mapping, the period does not drift, status
  reports, counts after an interrupted scan
- configuration and output: encoding names, 64-bit values in the database,
  --port, config files with a BOM, broadcast networks, a bad output directory
- GUI, simulators and the project's own tooling
"""

import asyncio
import json
import struct
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from pycomm3 import Tag

import plc_gui_settings
import plc_scanner
from plc_discovery import retry, scan_runner
from plc_discovery.cli_args import parse_args
from plc_discovery.config import (
    SAFE_READ_WORDS,
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    Protocol,
    StatusCode,
)
from plc_discovery.config_loader import ConfigLoader, is_known_encoding
from plc_discovery.conversion import apply_data_type_conversion
from plc_discovery.data_types import ByteOrder, DataTypeManager
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.notifications import NotificationType
from plc_discovery.output import CSVExporter, normalize_csv_encoding
from plc_discovery.protocols import cip_symbolic
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, _is_address_error, _logix_batches, _tag_points
from plc_discovery.retry import CircuitBreaker
from plc_discovery.scan_runner import CycleRunner, cycle_start
from plc_discovery.thresholds import Threshold, ThresholdMonitor, parse_thresholds
from plc_discovery.utils import ip_range_error, number_text

ROOT = Path(__file__).resolve().parent.parent
FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


# ----------------------------------------------------------------------
# Read path
# ----------------------------------------------------------------------


class _Device(BaseProtocolHandler):
    """Stays "connected"; ``answer(start, count)`` decides each request"""

    protocol = Protocol.SLMP

    def __init__(self, answer, config=FAST):
        super().__init__("10.0.0.1", 5001, config)
        self._connected = True
        self.answer = answer
        self.requests: list = []

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests.append((start_address, count))
        status = self.answer(start_address, count)
        return ([7] * count if status == StatusCode.OK else None), status


def test_dead_link_is_found_without_probing_twice_or_trying_the_next_chunk():
    alive = [True]

    async def run():
        handler = _Device(lambda start, count: StatusCode.OK if alive[0] else StatusCode.NG_TIMEOUT)
        await handler.read_device_range(DeviceRange(DeviceType.D, 0, 899))
        alive[0] = False
        handler.requests.clear()
        return handler, await handler.read_device_range(DeviceRange(DeviceType.D, 0, 2699))

    handler, points = asyncio.run(run())
    assert len(points) == 2700 and not any(p.status == StatusCode.OK for p in points)
    # The chunk and its retries (4), its halves (2), the known-good address (1);
    # was 9: that address a second time, and a request for the next chunk
    assert handler.requests == [(0, 900)] * 4 + [(0, 450), (450, 450), (0, 1)]
    assert handler.get_denied_addresses() == set()  # nothing is learned from a dead link


def test_retries_wait_for_the_packet_interval():
    outcomes = [StatusCode.NG_TIMEOUT, StatusCode.NG_TIMEOUT, StatusCode.OK]

    async def run():
        handler = _Device(lambda start, count: outcomes.pop(0))
        handler._rate_limiter.wait = AsyncMock()
        points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, 9))
        return points, handler._rate_limiter.wait.await_count

    points, waits = asyncio.run(run())
    assert all(p.status == StatusCode.OK for p in points)
    assert waits == 3  # the chunk and each of its two retries (was 1: retries went out unpaced)


def test_one_s7_chunk_fits_the_smallest_pdu():
    # python-snap7 splits a read at PDU - 18 bytes into several requests,
    # sent back to back outside the packet interval
    assert SAFE_READ_WORDS[Protocol.S7] * 2 <= 240 - 18


def test_circuit_breaker_does_not_depend_on_the_wall_clock(monkeypatch):
    breaker = CircuitBreaker()
    for _ in range(breaker.config.failure_threshold):
        breaker.record_failure()
    assert not breaker.is_available()
    # The clock is set back by an hour (NTP) while the circuit is open
    monkeypatch.setattr(retry.time, "time", lambda: 0.0)
    monotonic = time.monotonic()
    monkeypatch.setattr(retry.time, "monotonic", lambda: monotonic + breaker.config.timeout_seconds + 1)
    assert breaker.is_available()


def test_only_errors_about_the_address_are_address_errors():
    for text in (
        "Illegal Command or Format, Address may not exist or not enough elements in data file",
        "Addressing problem or Memory Protect Rungs",
        "Path destination unknown",
    ):
        assert _is_address_error(text), text
    for text in ("Processor is in Program mode", "Remote node cannot buffer command", "Unknown Status"):
        assert not _is_address_error(text), text


def test_busy_slc_controller_is_not_learned_as_an_invalid_address():
    replies = ["Remote node cannot buffer command", "Addressing problem or Memory Protect Rungs"]

    class Client:
        def read(self, name):
            return Tag(name, None, None, replies.pop(0))

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        handler._client, handler._connected, handler._plc_type = Client(), True, "slc"
        busy = await handler.read_device_raw(DeviceType.D, 0, 1)
        return busy, await handler.read_device_raw(DeviceType.D, 0, 1), handler._needs_reconnect

    busy, invalid, needs_reconnect = asyncio.run(run())
    assert busy == (None, StatusCode.NG_COMM_ERROR)  # was NG_ILLEGAL_ADDR, learned for the session
    assert invalid == (None, StatusCode.NG_ILLEGAL_ADDR)
    assert not needs_reconnect  # the controller answered: the session is fine


def test_busy_logix_controller_does_not_make_a_tag_inaccessible():
    busy = _tag_points("Speed", Tag("Speed", None, None, "Resource unavailable"))
    missing = _tag_points("Nope", Tag("Nope", None, None, "Path segment error"))
    assert [p.status for p in busy + missing] == [StatusCode.NG_COMM_ERROR, StatusCode.NG_ILLEGAL_ADDR]


def test_logix_array_reads_are_requests_of_their_own():
    tags = [f"T{i}" for i in range(25)] + ["Big[0]{1000}", "A", "Recipe[0]{50}", "Other[0]{20}", "B"]
    batches = _logix_batches(tags)
    assert [len(b) for b in batches] == [20, 5, 1, 1, 1, 1, 1]
    assert [tag for batch in batches for tag in batch] == tags  # order kept
    assert batches[2] == ["Big[0]{1000}"] and batches[4] == ["Recipe[0]{50}"]


def test_fragments_of_a_generic_array_read_wait_for_the_packet_interval(monkeypatch):
    replies = [
        (cip_symbolic.STATUS_PARTIAL, b"\xc3\x00" + struct.pack("<h", 1), None),
        (cip_symbolic.STATUS_PARTIAL, b"\xc3\x00" + struct.pack("<h", 2), None),
        (cip_symbolic.STATUS_OK, b"\xc3\x00" + struct.pack("<h", 3), None),
    ]
    sleeps = []
    monkeypatch.setattr(cip_symbolic, "_send", lambda client, service, path, data: replies.pop(0))
    monkeypatch.setattr(cip_symbolic.time, "sleep", sleeps.append)
    value, type_name = cip_symbolic.read_symbolic(object(), "Values[0]{3}", 0.05)
    assert (value, type_name) == ([1, 2, 3], "INT")
    assert sleeps == [0.05, 0.05]  # before the second and the third request


def test_interrupted_tag_scan_keeps_the_tags_already_read():
    class Client:
        data_types: dict = {}

        def read(self, *tags):
            if tags[0] == "T040":
                time.sleep(0.5)  # the user stops the scan during this batch
            return [Tag(tag, 1, "DINT", None) for tag in tags]

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=NetworkConfig(packet_interval_ms=0, request_timeout_ms=5000))
        handler._client, handler._connected, handler._plc_type = Client(), True, "logix"
        task = asyncio.ensure_future(handler.read_tags([f"T{i:03d}" for i in range(100)]))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
        partial = list(handler.partial_points)
        await asyncio.sleep(0.5)  # the worker thread ends
        return partial

    partial = asyncio.run(run())
    assert [p.address for p in partial] == [f"T{i:03d}" for i in range(40)]  # was nothing


# ----------------------------------------------------------------------
# Scan control
# ----------------------------------------------------------------------


def test_numbers_are_shown_in_full():
    assert [number_text(v) for v in (1234567, 81.5, 0.1 + 0.2, 80, -3.0)] == ["1234567", "81.5", "0.3", "80", "-3"]
    first, second = parse_thresholds(["D100>1234567", "D100>1234568"])
    # Both were "D100 > 1.23457e+06": one label, one notification key
    assert (first.label, second.label) == ("D100 > 1234567", "D100 > 1234568")


def test_a_limit_listed_twice_counts_its_cycles_once():
    limit = Threshold("D1", ">", 5, for_cycles=2)
    monitor = ThresholdMonitor([limit, limit])
    assert monitor.thresholds == [limit]
    point = [DataPoint(address="D1", status=StatusCode.OK, value=9)]
    assert monitor.evaluate("PLC1", point).crossed == []  # first cycle outside: not yet (was exceeded)
    assert len(monitor.evaluate("PLC1", point).crossed) == 1


def test_default_type_is_aligned_again_behind_a_mapping():
    manager = DataTypeManager.from_config(
        {"default_type": "DWORD", "mappings": [{"start": 3, "end": 4, "type": "FLOAT"}]}
    )
    points = [DataPoint(address=f"D{a}", status=StatusCode.OK, value=a) for a in range(10)]
    converted = {p.address: p for p in apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)}
    assert converted["D0"].converted_value == 0x00010000
    assert "incomplete" in converted["D2"].display_value  # one word left before the mapping
    assert converted["D3"].data_type == "FLOAT"
    # Was "(part of D4, incomplete)": D4 belongs to the FLOAT, and D5 was never converted
    assert converted["D5"].converted_value == 0x00060005
    assert converted["D7"].converted_value == 0x00080007
    assert "incomplete" in converted["D9"].display_value


def test_cycle_start_keeps_the_schedule_and_restarts_it_when_late():
    async def run():
        now = asyncio.get_running_loop().time()
        first = cycle_start(1.0, None)
        on_time = cycle_start(1.0, now - 1.003)  # the sleep overshot by 3 ms
        late = cycle_start(1.0, now - 2.0)  # the read took a whole interval too long
        return now, first, on_time, late, cycle_start(None, now - 5)

    now, first, on_time, late, single = asyncio.run(run())
    assert first == pytest.approx(now, abs=0.05)
    assert on_time == pytest.approx(now - 0.003, abs=1e-6)  # the scheduled time, not "now": no drift
    assert late == pytest.approx(now, abs=0.05)
    assert single == pytest.approx(now, abs=0.05)


def test_status_report_is_not_sent_twice_at_once(monkeypatch, caplog):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.01)
    sends = []

    async def run():
        gate = asyncio.Event()

        async def notify(send):
            sends.append(1)
            await gate.wait()
            return False  # the webhook finally fails

        runner = CycleRunner(None, notifier=MagicMock(report_interval_seconds=0.001), notify=notify)
        for iteration in (1, 2, 3):
            await runner.report_if_due({"PLC1": []}, [], iteration)
            await asyncio.sleep(0.01)
        in_flight = len(runner._in_flight)
        gate.set()
        await runner.drain()
        return in_flight, dict(runner._in_flight)

    with caplog.at_level("WARNING"):
        in_flight, after = asyncio.run(run())
    assert sends == [1]  # was one more for every due report, and drain() lost track of them
    assert in_flight == 1 and after == {}
    assert NotificationType.STATUS_REPORT.value in caplog.text
    assert "it will be retried" not in caplog.text  # nothing retries a status report


def test_interrupted_scan_does_not_count_unscanned_targets_as_successful():
    notifier = MagicMock()
    notifier.notify_scan_complete = AsyncMock(return_value={"hook": True})
    results = plc_scanner._RunResults(plcs=[MagicMock(), MagicMock(), MagicMock()], interrupted=True)
    results.add("10.0.0.1", True, None, [], set())  # Ctrl+C during the first of three

    asyncio.run(plc_scanner._notify_scan_end(notifier, "range", results, 1.0))
    assert notifier.notify_scan_complete.await_args.args[:3] == (1, 1, 0)  # was (3, 3, 0)

    results.interrupted = False
    asyncio.run(plc_scanner._notify_scan_end(notifier, "range", results, 1.0))
    assert notifier.notify_scan_complete.await_args.args[:3] == (3, 3, 0)


# ----------------------------------------------------------------------
# Configuration and output
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, codec",
    [("shiftjis", "cp932"), (" cp932 ", "cp932"), (932, "cp932"), ("mskanji", "cp932"), ("UTF8", "utf-8")],
)
def test_any_spelling_of_an_encoding_is_understood(name, codec):
    assert normalize_csv_encoding(name) == codec and is_known_encoding(name)


def test_encodings_that_cannot_write_a_csv_are_rejected():
    assert not is_known_encoding("base64") and not is_known_encoding("no-such-codec")
    assert is_known_encoding("euc-jp")


def test_character_missing_from_the_encoding_does_not_fail_the_file(tmp_path):
    exporter = CSVExporter(str(tmp_path), "euc-jp")
    point = DataPoint(address="Motor①ü", value=1, raw_hex="0001", status=StatusCode.OK)
    path = exporter.export_plc_data([point], "10.0.0.1")  # raised UnicodeEncodeError, leaving a truncated file
    text = Path(path).read_text(encoding="euc-jp")
    assert "Motor" in text and "?" in text


def test_unsigned_64_bit_value_is_stored_without_the_number(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "plc.db")))
    try:
        big = DataPoint(address="Big", value=2**64 - 1, raw_hex="0xFFFFFFFFFFFFFFFF")
        small = DataPoint(address="Small", value=-(2**63), raw_hex="0x8000000000000000")
        assert db.export_plc_data([big, small], "10.0.0.1", protocol="ETHERNET_IP", port=44818) == 2  # was 1
        rows = {r["address"]: (r["value"], r["raw_hex"]) for r in db._db.execute("SELECT * FROM data_points")}
        indexes = {r[0] for r in db._db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    finally:
        db.close()
    assert rows == {"Big": (None, "0xFFFFFFFFFFFFFFFF"), "Small": (-(2**63), "0x8000000000000000")}
    # The indexes scripts/setup_database.sh creates (retention deletes by changed_at)
    assert {"idx_history_plc_ip", "idx_history_address", "idx_history_changed_at"} <= indexes


@pytest.mark.parametrize("port", ["70000", "0", "-1", "abc"])
def test_port_option_is_range_checked(monkeypatch, capsys, port):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--mode", "discover", f"--port={port}"])
    with pytest.raises(SystemExit) as exit_info:
        parse_args()
    assert exit_info.value.code == 2 and "1-65535" in capsys.readouterr().err


def test_json_config_with_a_bom_loads(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"network": {"packet_interval_ms": 75}}), encoding="utf-8-sig")
    assert ConfigLoader().load(str(path))["network"]["packet_interval_ms"] == 75


def test_config_file_that_is_a_list_is_a_clear_error(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- ip: 10.0.0.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at the top level"):
        ConfigLoader().load(str(path))


def test_broadcast_network_is_not_a_range_of_devices():
    assert "broadcast" in ip_range_error("255.255.255.255/32")
    assert "broadcast" in ip_range_error("255.255.255.0/24")
    assert ip_range_error("192.168.1.0/24") is None


def test_unusable_output_directory_is_an_error_message(monkeypatch, tmp_path, capsys):
    occupied = tmp_path / "afile"
    occupied.write_text("x")
    audit = tmp_path / "audit.jsonl"
    argv = ["plc_scanner.py", "--mode", "discover", "--ip-range", "127.0.0.1", "-o", str(occupied)]
    monkeypatch.setattr(sys, "argv", argv + ["--no-rich", "--audit-log", str(audit)])
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())  # was a FileExistsError traceback
    assert exit_info.value.code == 1
    assert "Cannot use the output directory" in capsys.readouterr().out
    events = [json.loads(line)["event_type"] for line in audit.read_text(encoding="utf-8").splitlines()]
    assert events[0] == "SESSION_START" and events[-1] == "SESSION_END"  # the session is closed


# ----------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------


class _Var:
    def __init__(self, value):
        self.value = value

    def set(self, value):
        self.value = value

    def get(self):
        return self.value


def _settings_tabs():
    class App(plc_gui_settings.SettingsTabsMixin):
        def __init__(self):
            names = "packet_interval retry_interval timeout output_dir encoding hex_addresses periodic_csv".split()
            names += "report_interval min_interval db_enabled db_path db_history db_days db_size db_interval".split()
            for name in names:
                setattr(self, f"var_{name}", _Var("utf-8-sig" if name == "encoding" else "0"))
            self.notify_destinations: list = []

        def _refresh_notify_tree(self):
            pass

    return App()


@pytest.mark.parametrize("name, shown", [("cp932", "shift-jis"), ("sjis", "shift-jis"), ("UTF8", "utf-8")])
def test_gui_understands_the_encoding_names_the_cli_accepts(name, shown):
    app = _settings_tabs()
    app._apply_settings({"output": {"encoding": name}})
    assert app.var_encoding.get() == shown  # stayed utf-8-sig: other CSVs than the CLI's, and "save" changed the file


def test_gui_discovery_uses_the_timeout_of_the_settings_file():
    app = _settings_tabs()
    assert app._discovery_settings == {}
    app._apply_settings({"network": {"discovery_timeout_ms": 3000, "discovery_retry_count": 2, "max_concurrent": 4}})
    assert app._discovery_settings == {"discovery_timeout_ms": 3000, "discovery_retry_count": 2}
    assert NetworkConfig(**app._discovery_settings).discovery_timeout_ms == 3000
    app._apply_settings({"network": {"discovery_timeout_ms": "soon"}})
    assert app._discovery_settings == {}


# ----------------------------------------------------------------------
# Simulators
# ----------------------------------------------------------------------


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
        assert len(attempts) == 2 and port == attempts[1]
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
        def __init__(self, host):
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


# ----------------------------------------------------------------------
# The project's own tooling
# ----------------------------------------------------------------------


def test_lint_tools_are_pinned_to_the_versions_ci_uses():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pins = ("black==26.5.1", "isort==6.0.1", "flake8==7.3.0", "mypy==1.18.1")
    for name in ("requirements-dev.txt", "pyproject.toml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for pin in pins:
            assert pin in ci and pin in text, f"{pin} in {name}"


def test_pytest_is_configured_once_with_a_time_limit():
    assert "timeout = 120" in (ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "[tool.pytest.ini_options]" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "pytest-timeout" in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")


def test_every_ci_job_has_a_time_limit():
    lines = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines()
    jobs = [i for i, line in enumerate(lines) if line.strip() == "runs-on: ubuntu-latest"]
    assert len(jobs) >= 6
    for index in jobs:
        assert any("timeout-minutes:" in line for line in lines[index + 1 : index + 4]), lines[index - 1]
