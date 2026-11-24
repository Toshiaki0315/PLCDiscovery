"""
Regressions from the second code review (medium findings):
- a device that drops requests instead of answering an error is narrowed down
- tag values keep the hex width of their CIP type
- data type conversion leaves tag names alone and stays inside a mapping
- discovery: broadcasts only where asked, paced connections, --port probing
- config validation never ends in a traceback; CLI options win over targets
- a locked database fails an export at once and is reported
- the GUI worker stays busy until a stopped job has cleaned up
- every read request is in the audit log
- a Logix reconnect does not upload the tag list again
"""

import asyncio
import json
import sqlite3
import sys
import threading
import time
from collections import Counter
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.audit_log import close_audit_logger, get_audit_logger, init_audit_logger
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.conversion import apply_data_type_conversion
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager, DataTypeMapping
from plc_discovery.database import DatabaseExporter
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, _tag_hex, _tag_points, _value_points
from plc_discovery.scan_runner import ResultWriter

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


# ----------------------------------------------------------------------
# Devices that do not answer requests touching an invalid address
# ----------------------------------------------------------------------


class _Silent(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST)
        self._connected = True
        self.bad = set(bad)
        self.dead_after = dead_after
        self.requests = 0

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        addresses = range(start_address, start_address + count)
        if (self.dead_after is not None and self.requests > self.dead_after) or self.bad.intersection(addresses):
            return None, StatusCode.NG_TIMEOUT
        return list(addresses), StatusCode.OK


def test_unanswered_address_is_isolated_and_learned():
    handler = _Silent(bad={50})

    async def run():
        first = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
        before = handler.requests
        second = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
        return first, second, handler.requests - before

    first, second, second_requests = asyncio.run(run())
    for points in (first, second):
        assert [p.address for p in points if p.status != StatusCode.OK] == ["HR50"]
        assert Counter(p.status for p in points)[StatusCode.OK] == 99
    assert handler.get_denied_statuses() == {"HR50": StatusCode.NG_TIMEOUT}
    # Learned: the next cycle reads around it and never waits for its timeout
    assert second_requests == 2


def test_unanswered_address_in_the_first_chunk_of_a_scan():
    handler = _Silent(bad={3})
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert [p.address for p in points if p.status != StatusCode.OK] == ["HR3"]


def test_dead_link_is_not_searched_or_learned():
    handler = _Silent(dead_after=0)
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert len(points) == 300 and all(p.status != StatusCode.OK for p in points)
    assert handler.get_denied_addresses() == set()
    # Nothing was ever read, so the link cannot be told from the range: the
    # first chunk is searched for an address that answers with half the
    # budget (4 retries + 8), then nothing more - not 2N timeouts
    assert handler.requests <= 4 + BaseProtocolHandler.UNANSWERED_SEARCH_BUDGET // 2 + 1
    # Later scans: one request for the chunk known to be unanswered
    before = handler.requests
    asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299)))
    assert handler.requests - before <= 1


def test_link_lost_during_a_scan_stops_the_search():
    handler = _Silent(dead_after=2)
    points = asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 499)))
    assert Counter(p.status for p in points)[StatusCode.OK] == 200
    assert handler.get_denied_addresses() == set()
    assert handler.requests <= 14


# ----------------------------------------------------------------------
# Hex of tag values
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, type_name, expected",
    [
        (-1, "DINT", "0xFFFFFFFF"),
        (-1, "INT", "0xFFFF"),
        (-1, "LINT", "0xFFFFFFFFFFFFFFFF"),
        (0x1_0000_0001, "LINT", "0x0000000100000001"),
        (2**63, "ULINT", "0x8000000000000000"),
        (5, "DINT[10]", "0x00000005"),
        (1, "BOOL", "0x0001"),
        # Type unknown (structure member): the smallest width holding the value
        (0x1_0000_0001, None, "0x0000000100000001"),
        (-40000, None, "0xFFFF63C0"),
        (7, None, "0x0007"),
    ],
)
def test_tag_hex_keeps_the_width_of_the_type(value, type_name, expected):
    assert _tag_hex(value, type_name) == expected


def test_tag_points_use_the_reply_type():
    reply = MagicMock(error=None, value=[-1, 2], type="DINT[2]")
    assert [p.raw_hex for p in _tag_points("Arr[0]{2}", reply)] == ["0xFFFFFFFF", "0x00000002"]
    assert [p.raw_hex for p in _value_points("Big", 2**40, "LINT")] == ["0x0000010000000000"]
    # Members of a structure are not formatted with the structure's type name
    members = _value_points("Udt", {"A": -1, "B": 70000}, "MyUdt")
    assert [(p.address, p.raw_hex) for p in members] == [("Udt.A", "0xFFFF"), ("Udt.B", "0x00011170")]


# ----------------------------------------------------------------------
# Data type conversion
# ----------------------------------------------------------------------


def _ok(address, value):
    return DataPoint(address=address, status=StatusCode.OK, value=value)


def test_conversion_never_combines_tags():
    tags = [_ok("Count1", 100000), _ok("Count2", 7)]
    converted = apply_data_type_conversion(tags, DataType.DWORD, ByteOrder.LITTLE_ENDIAN, None)
    assert [(p.address, p.value, p.converted_value, p.display_value) for p in converted] == [
        ("Count1", 100000, None, None),
        ("Count2", 7, None, None),
    ]
    # Device addresses are still converted
    words = apply_data_type_conversion([_ok("D0", 1), _ok("D1", 2)], DataType.DWORD, ByteOrder.LITTLE_ENDIAN, None)
    assert words[0].converted_value == 0x00020001


def test_values_never_take_words_from_beyond_their_mapping():
    manager = DataTypeManager()
    manager.add_mapping(DataTypeMapping(100, 102, DataType.FLOAT))  # 3 words: the last value is cut short
    manager.add_mapping(DataTypeMapping(103, 103, DataType.INT16))
    points = [_ok(f"D{a}", 0xFFFF) for a in range(100, 104)]
    converted = apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)
    by_address = {p.address: p for p in converted}
    assert by_address["D102"].converted_value is None and "incomplete" in by_address["D102"].display_value
    assert by_address["D103"].data_type == "INT16" and by_address["D103"].converted_value == -1


def test_mapping_config_rejects_cut_and_overlapping_ranges():
    with pytest.raises(ValueError, match="not a multiple"):
        DataTypeManager.from_config({"mappings": [{"start": 100, "end": 102, "type": "FLOAT"}]})
    with pytest.raises(ValueError, match="overlaps"):
        DataTypeManager.from_config(
            {
                "mappings": [
                    {"start": 100, "end": 199, "type": "WORD"},
                    {"start": 110, "end": 111, "type": "FLOAT"},
                ]
            }
        )
    # Different devices may use the same numbers
    DataTypeManager.from_config(
        {
            "mappings": [
                {"start": 100, "end": 101, "type": "FLOAT", "device": "D"},
                {"start": 100, "end": 101, "type": "DWORD", "device": "W"},
            ]
        }
    )


def test_int16_of_a_wider_value_is_masked():
    point = apply_data_type_conversion([_ok("D0", 100000)], DataType.INT16, ByteOrder.LITTLE_ENDIAN, None)[0]
    assert point.converted_value == -31072  # low 16 bits 0x86A0, signed


# ----------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------


def test_broadcast_only_for_requested_protocols():
    async def run(protocols):
        discovery = BroadcastDiscovery(FAST)
        with patch.object(discovery, "_send_broadcast", AsyncMock(return_value={})) as send:
            await discovery.discover_all_broadcast(protocols=protocols)
        return sorted(call.kwargs["port"] for call in send.await_args_list)

    assert asyncio.run(run([Protocol.MODBUS_TCP])) == []
    assert asyncio.run(run([Protocol.ETHERNET_IP])) == [44818]
    assert len(asyncio.run(run(None))) == 2


def test_no_broadcast_when_the_search_is_limited_to_ip_ranges():
    async def run(ip_ranges):
        with (
            patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[])) as broadcast,
            patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=[])),
        ):
            await plc_scanner.run_discovery(ip_ranges, FAST, MagicMock(), MagicMock())
        return broadcast.await_count

    assert asyncio.run(run(["192.168.10.0/24"])) == 0
    assert asyncio.run(run([])) == 1


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
            return await PLCDiscovery(FAST, port=5007)._probe_host("192.168.1.10")

    detected = asyncio.run(run())
    assert overlaps == [], "protocols must not share the port at the same time"
    assert detected is not None and (detected.protocol, detected.port) == (Protocol.MODBUS_TCP, 5007)
    assert len(probed) > 1  # another protocol was tried on the port before Modbus answered
    assert {port for _, port in probed} == {5007}
    assert probed[-1][0] == Protocol.MODBUS_TCP  # stops at the first protocol that answers


def test_resolve_target_detects_on_the_given_port():
    seen = {}

    class Discovery:
        def __init__(self, config, port=None):
            seen["port"] = port

        async def _probe_host(self, ip):
            return PLCInfo(ip, protocol=Protocol.SLMP, port=seen["port"])

    async def run():
        with patch.object(plc_scanner, "PLCDiscovery", Discovery):
            return await plc_scanner.resolve_target("10.0.0.1", None, 5007, FAST, MagicMock())

    resolved = asyncio.run(run())
    assert seen["port"] == 5007 and resolved.port == 5007


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "section, value, fragment",
    [
        ("scan", "range", "scan must be a mapping"),
        ("discovery", ["192.168.1.0/24"], "discovery must be a mapping"),
        ("targets", {"ip": "10.0.0.1"}, "targets must be a list"),
        ("targets", ["10.0.0.1"], "targets[0] must be a mapping"),
    ],
)
def test_wrongly_typed_sections_are_errors_not_tracebacks(section, value, fragment):
    loader = ConfigLoader()
    loader.config[section] = value
    assert any(fragment in error for error in loader.validate())


def test_unknown_network_key_and_bad_port_are_rejected():
    loader = ConfigLoader()
    loader.config["network"]["packet_interval"] = 500  # meant packet_interval_ms
    loader.config["targets"] = [{"ip": "10.0.0.1", "port": "abc"}, {"ip": "10.0.0.2", "port": 99999}]
    errors = loader.validate()
    assert any("unknown key(s) packet_interval" in e for e in errors)
    assert any("targets[0].port" in e for e in errors) and any("targets[1].port" in e for e in errors)
    assert ConfigLoader().validate() == []


def test_command_line_protocol_and_port_win_over_config_targets():
    args = MagicMock(target=None, protocol="modbus", port=1502)
    loader = MagicMock()
    loader.get_targets.return_value = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]

    async def run():
        return await plc_scanner._resolve_targets(args, loader, FAST, MagicMock())

    plc_infos, undetected = asyncio.run(run())
    assert undetected == []
    assert (plc_infos[0].protocol, plc_infos[0].port) == (Protocol.MODBUS_TCP, 1502)


# ----------------------------------------------------------------------
# Locked database
# ----------------------------------------------------------------------


def test_locked_database_fails_the_export_at_once_and_is_reported(tmp_path):
    path = str(tmp_path / "plc.db")
    db = DatabaseExporter.create(path)
    db._db.execute("PRAGMA busy_timeout = 100")
    blocker = sqlite3.connect(path)
    blocker.execute("BEGIN EXCLUSIVE")
    points = [DataPoint(address=f"D{i}", value=i, status=StatusCode.OK) for i in range(20)]
    try:
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError):
            db.export_plc_data(points, "10.0.0.1", protocol="SLMP", port=5001)
        assert time.monotonic() - started < 2  # one busy timeout, not one per row

        writer = ResultWriter(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), MagicMock(), None, db)
        writer.export_points(points)
        assert writer.error_count == 1 and "database" in (writer.first_error or "")
    finally:
        blocker.rollback()
        blocker.close()

    # Usable again once the lock is gone; nothing of the failed exports was kept
    assert db.export_plc_data(points, "10.0.0.1", protocol="SLMP", port=5001) == 20
    assert db._db.execute("SELECT COUNT(*) FROM data_points").fetchone()[0] == 20
    db.close()


# ----------------------------------------------------------------------
# GUI worker
# ----------------------------------------------------------------------


def _import_async_worker(monkeypatch):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "messagebox", "ttk"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
        monkeypatch.delitem(sys.modules, "plc_gui", raising=False)
    from plc_gui import AsyncWorker

    return AsyncWorker


def _wait(condition, seconds=2.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


def test_gui_worker_is_busy_until_a_stopped_job_has_cleaned_up(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    state = {"started": False, "cleaning": False, "cleaned": False}
    release = threading.Event()  # lets the cleanup finish (no wall-clock assumptions)
    done = []

    async def job():
        state["started"] = True
        try:
            await asyncio.sleep(60)
        finally:
            state["cleaning"] = True  # final notification, PLC disconnect
            while not release.is_set():
                await asyncio.sleep(0.005)
            state["cleaned"] = True

    try:
        worker.submit(job(), done.append)
        assert _wait(lambda: state["started"])
        worker.cancel()
        assert _wait(lambda: state["cleaning"])
        # Still disconnecting: a second job must not be allowed to start
        assert worker.busy and not state["cleaned"] and not done
        release.set()
        assert _wait(lambda: not worker.busy)
        assert state["cleaned"] and isinstance(done[0], asyncio.CancelledError)
    finally:
        release.set()
        worker.shutdown(timeout=2)


def test_gui_worker_reports_result_and_exception(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    done = []

    async def ok():
        return 1

    async def fails():
        raise ValueError("boom")

    try:
        worker.submit(ok(), done.append)
        assert _wait(lambda: len(done) == 1) and done[0] is None and not worker.busy
        worker.submit(fails(), done.append)
        assert _wait(lambda: len(done) == 2) and isinstance(done[1], ValueError)
    finally:
        worker.shutdown(timeout=2)


# ----------------------------------------------------------------------
# Audit log
# ----------------------------------------------------------------------


def test_every_read_request_is_in_the_audit_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    init_audit_logger(str(log))
    try:

        class Handler(_Silent):
            async def read_device_raw(self, device_type, start_address, count):
                self.requests += 1
                if start_address + count > 150:
                    return None, StatusCode.NG_ILLEGAL_ADDR
                return [0] * count, StatusCode.OK

        handler = Handler()
        asyncio.run(handler.read_device_range(DeviceRange(DeviceType.HR, 0, 199)))
    finally:
        close_audit_logger()

    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    reads = [e for e in events if e["event_type"] in ("READ_SUCCESS", "READ_ERROR")]
    assert len(reads) == handler.requests
    first = reads[0]
    assert (first["plc_ip"], first["protocol"], first["device"]) == ("127.0.0.1", "MODBUS_TCP", "HR")
    assert (first["address_start"], first["address_end"], first["status"]) == (0, 99, "SUCCESS")
    assert any(e["event_type"] == "READ_ERROR" and e["error_message"] == "NG_ILLEGAL_ADDR" for e in reads)


def test_audit_event_that_is_not_json_is_still_recorded(tmp_path):
    log = tmp_path / "audit.jsonl"
    init_audit_logger(str(log))
    try:
        get_audit_logger().log_error("scan failed", {"values": {7}, "path": tmp_path})  # a set, a Path: not JSON
    finally:
        close_audit_logger()
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    errors = [e for e in events if e["event_type"] == "ERROR"]
    # Written as text, not dropped: an audit log must not lose a record
    assert len(errors) == 1 and errors[0]["error_message"] == "scan failed"
    assert errors[0]["metadata"] == {"values": "{7}", "path": str(tmp_path)}


# ----------------------------------------------------------------------
# Logix reconnect
# ----------------------------------------------------------------------


def test_logix_reconnect_reuses_the_tag_list():
    created = []

    class FakeLogixDriver:
        def __init__(self, path, init_tags=True):
            self.init_tags = init_tags
            self._tags = {}
            self._data_types = {}
            created.append(self)

        def open(self):
            if self.init_tags:  # the upload pycomm3 does on connect
                self._tags = {"Speed": {"tag_type": "atomic"}}
                self._data_types = {"MyUdt": {}}

        def close(self):
            pass

        @property
        def tags(self):  # as pycomm3: the public view of _tags
            return self._tags

    async def run():
        handler = EtherNetIPHandler("127.0.0.1", config=FAST)
        with patch("pycomm3.LogixDriver", FakeLogixDriver):
            assert await handler.connect()
            await handler.disconnect()
            assert await handler.connect()
        return handler

    handler = asyncio.run(run())
    assert [driver.init_tags for driver in created] == [True, False]
    assert created[1]._tags == {"Speed": {"tag_type": "atomic"}} and created[1]._data_types == {"MyUdt": {}}
    assert handler.tag_scan_list() == ["Speed"]
