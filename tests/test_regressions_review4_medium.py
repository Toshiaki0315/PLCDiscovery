"""
Regressions from the fourth code review (medium findings):
- EtherNet/IP: a link lost during a tag scan is a communication error, not
  "unsupported"; a Logix controller stays Logix when a reconnect fails
- nothing read yet and one range unanswered: the next range is still asked;
  a half the PLC answered is split although the other half was unanswered
- Ctrl+C during a parallel scan: what was read is written and reported
- targets with the same IP, protocol and port keep separate files and
  database rows
- --database keeps the config file's retention settings
- the ARP sweep is paced and sent on the scanned network's interface
- GUI: one wrong value in the settings file does not empty the rest; a
  stopped single scan keeps what it read
- simulators stop on Ctrl+C while a client is connected
"""

import argparse
import asyncio
import logging
import socket
import sqlite3
import time
from collections import Counter
from unittest.mock import MagicMock, patch

import pycomm3
import pytest
from pycomm3 import Tag
from pycomm3.exceptions import CommError, ResponseError

import plc_gui
import plc_gui_settings
import plc_scanner
from plc_discovery import discovery, settings_file
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
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.discovery import PLCDiscovery, target_instances, target_labels
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.scan_runner import ResultWriter, plc_answered
from plc_discovery.utils import get_timestamp

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


# ----------------------------------------------------------------------
# EtherNet/IP
# ----------------------------------------------------------------------


class _Logix:
    """LogixDriver stand-in driven by a shared state dict"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self._tags = {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)}
        self._data_types: dict = {}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)

    def open(self):
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        if not self.state.get("cpu_ok", True):
            # The Ethernet module registers the session, the CPU does not answer
            raise ResponseError("Failed to get PLC info")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False  # switched off during this batch
            raise CommError("failed to receive reply")
        if self.state.get("slow"):
            time.sleep(0.3)
        return [Tag(tag, 1, "DINT", None) for tag in tags]


class _Other:
    """SLCDriver / CIPDriver stand-in: opens while the device is up"""

    def __init__(self, path):
        self.path = path

    def open(self):
        if not _Logix.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def _list_identity(self):
        return {"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Communications Adapter"}

    def close(self):
        pass


@pytest.fixture
def logix(monkeypatch):
    _Logix.state = {}
    monkeypatch.setattr(pycomm3, "LogixDriver", _Logix)
    monkeypatch.setattr(pycomm3, "SLCDriver", _Other)
    monkeypatch.setattr(pycomm3, "CIPDriver", _Other)
    return _Logix.state


def test_link_lost_during_a_tag_scan_is_a_communication_error(logix):
    logix["off_at"] = "T020"

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect()
        points = await handler.read_tags(handler.tag_scan_list())
        return handler, points, await handler.read_tags(["T000", "T001"])

    handler, points, later = asyncio.run(run())
    assert Counter(p.status for p in points) == {StatusCode.OK: 20, StatusCode.NG_COMM_ERROR: 80}
    # Not "unsupported": that was learned as denied and taken for an answer
    assert handler.get_denied_addresses() == set()
    assert {p.status for p in later} == {StatusCode.NG_COMM_ERROR} and not plc_answered(later)


def test_logix_controller_stays_logix_when_a_reconnect_fails(logix):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect() and handler._plc_type == "logix"
        logix["slow"] = True  # one slow request: timeout, reconnect before the next
        timed_out = await handler.read_tags(["T000"])
        logix["slow"] = False
        logix["cpu_ok"] = False  # the CPU is still busy while the reconnect runs
        failed = await handler.read_tags(["T000"])
        kind_after_failure = handler._plc_type
        logix["cpu_ok"] = True
        recovered = await handler.read_tags(["T000"])
        await asyncio.sleep(0.4)  # the slow worker thread ends
        return handler, timed_out, failed, kind_after_failure, recovered

    handler, timed_out, failed, kind_after_failure, recovered = asyncio.run(run())
    assert timed_out[0].status == StatusCode.NG_TIMEOUT
    assert failed[0].status == StatusCode.NG_COMM_ERROR
    assert kind_after_failure == "logix"  # was "generic": tag list gone, path without the slot
    assert recovered[0].status == StatusCode.OK
    assert handler._plc_type == "logix" and len(handler.tag_scan_list()) == 100


def test_a_device_that_was_never_logix_still_falls_back_to_generic_cip(logix):
    logix["cpu_ok"] = False

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        return await handler.connect(), handler._plc_type

    assert asyncio.run(run()) == (True, "generic")


# ----------------------------------------------------------------------
# Nothing read yet, and a range that is not answered
# ----------------------------------------------------------------------


class _Device(BaseProtocolHandler):
    """Stays "connected"; ``answer(device_type, start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST)
        self._connected = True
        self.answer = answer
        self.requests: list = []

    async def connect(self):
        self._connected = True
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests.append((device_type, start_address, count))
        status = self.answer(device_type, start_address, count)
        if status == StatusCode.OK:
            return [7] * count, status
        return None, status


def test_other_ranges_are_still_read_after_the_first_one_went_unanswered():
    # A gateway that drops requests touching a missing holding register
    # looks like a dead link until something answers: the input registers do
    valid_hr = set(range(40, 61))

    def answer(device_type, start, count):
        if device_type == DeviceType.HR and any(a not in valid_hr for a in range(start, start + count)):
            return StatusCode.NG_TIMEOUT
        return StatusCode.OK

    async def run():
        handler = _Device(answer)
        hr = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299))
        ir = await handler.read_device_range(DeviceRange(DeviceType.IR, 0, 99))
        return handler, hr, ir

    handler, hr, ir = asyncio.run(run())
    assert len(hr) == 300 and len(ir) == 100
    assert all(p.status == StatusCode.OK for p in ir)  # was never requested: 100 x NG_COMM_ERROR
    assert plc_answered(hr + ir)
    assert handler.circuit_breaker_state == "closed"


def test_plc_that_never_answers_costs_a_bounded_number_of_requests():
    async def run():
        handler = _Device(lambda *request: StatusCode.NG_TIMEOUT)
        per_cycle = []
        for _ in range(60):
            before = len(handler.requests)
            for device_type in (DeviceType.HR, DeviceType.IR, DeviceType.D):
                points = await handler.read_device_range(DeviceRange(device_type, 0, 999))
                assert len(points) == 1000 and plc_answered(points) is False
            per_cycle.append(len(handler.requests) - before)
        return handler, per_cycle

    handler, per_cycle = asyncio.run(run())
    # One request per range and cycle while the session budget lasts, then none
    assert max(per_cycle[1:]) <= 3
    assert sum(per_cycle) <= 13 + handler.UNANSWERED_SESSION_BUDGET + 60  # search, probes, breaker retries
    assert per_cycle[-1] <= 1


def test_answered_half_is_split_although_the_other_half_was_not_answered():
    # D0-49: requests are dropped. D50-99: D50-74 exist, the rest is refused.
    def answer(device_type, start, count):
        addresses = range(start, start + count)
        if any(a < 50 for a in addresses):
            return StatusCode.NG_TIMEOUT
        return StatusCode.OK if all(a < 75 for a in addresses) else StatusCode.NG_ILLEGAL_ADDR

    async def run():
        handler = _Device(answer)
        return await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))

    by_address = {p.address: p.status for p in asyncio.run(run())}
    assert len(by_address) == 100
    # Was reported NG_ILLEGAL_ADDR for all of HR50-99, without a request
    assert all(by_address[f"HR{a}"] == StatusCode.OK for a in range(50, 75))
    assert all(by_address[f"HR{a}"] == StatusCode.NG_ILLEGAL_ADDR for a in range(75, 100))
    assert all(by_address[f"HR{a}"] in (StatusCode.NG_TIMEOUT, StatusCode.NG_COMM_ERROR) for a in range(50))


# ----------------------------------------------------------------------
# Ctrl+C during a parallel scan
# ----------------------------------------------------------------------


def test_interrupted_parallel_scan_writes_and_reports_what_was_read():
    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = False
            self.connect_error = None
            self.skip_reconnect = False
            self.data: list = []

        async def __aenter__(self):
            self.is_connected = True
            return self

        async def __aexit__(self, *exc):
            await asyncio.sleep(0.05)  # closing the connection takes a moment
            self.is_connected = False

        async def collect_range(self, device_type, start, end):
            for address in range(start, end + 1):
                self.data.append(DataPoint(address=f"D{address}", value=1, raw_hex="0001", timestamp=get_timestamp()))
                await asyncio.sleep(0.02)
            return self.data

        def get_collected_data(self):
            return self.data

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": len(self.data), "success_count": len(self.data), "error_count": 0}

    exporter = MagicMock(hex_addresses=False)
    plcs = [PLCInfo(f"10.0.0.{i}", protocol=Protocol.SLMP, port=5001) for i in (1, 2, 3)]

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_parallel_scan(
                    plcs,
                    NetworkConfig(max_concurrent=2),
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 999)],
                )
            )
            await asyncio.sleep(0.2)
            task.cancel()  # Ctrl+C
            return await asyncio.wait_for(task, timeout=10)

    results = asyncio.run(run())
    # The third target was still waiting for its turn: not scanned, not reported
    assert sorted(results) == ["10.0.0.1", "10.0.0.2"]
    for outcome in results.values():
        assert outcome.interrupted and len(outcome.data_points) >= 3
    # Was 0: the scanning targets were cancelled again before they had written
    assert exporter.export_plc_data.call_count == 2


# ----------------------------------------------------------------------
# Targets with the same IP, protocol and port
# ----------------------------------------------------------------------


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


def test_two_units_behind_a_gateway_keep_separate_files_and_history(tmp_path):
    plcs = [_unit(1), _unit(2)]
    exporter = CSVExporter(str(tmp_path), "utf-8-sig")
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "plc.db")))
    try:
        writers = [
            ResultWriter(plc, exporter, db_exporter=db, label=label, daily=True, instance=instance)
            for plc, label, instance in zip(plcs, target_labels(plcs), target_instances(plcs))
        ]
        for _ in range(3):  # three cycles; the values never change
            for writer, value in zip(writers, (100, 200)):
                point = DataPoint(address="HR0", value=value, raw_hex=f"{value:04X}", timestamp=get_timestamp())
                assert writer.export_points([point]) is not None
                assert writer.error_count == 0
    finally:
        db.close()

    files = sorted(p.name for p in tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 2 and "unit_id1" in files[0] and "unit_id2" in files[1]
    for name, value in zip(files, ("100", "200")):
        rows = (tmp_path / name).read_text(encoding="utf-8-sig").splitlines()[1:]
        assert len(rows) == 3 and all(f"HR0,{value}," in row for row in rows)

    with sqlite3.connect(tmp_path / "plc.db") as connection:
        stored = connection.execute("SELECT protocol, value, COUNT(*) FROM data_points GROUP BY 1, 2").fetchall()
        changes = connection.execute("SELECT COUNT(*) FROM data_history").fetchone()[0]
    assert sorted(stored) == [("MODBUS_TCP/unit_id1", 100, 3), ("MODBUS_TCP/unit_id2", 200, 3)]
    assert changes == 0  # was one false change per cycle: unit 1 compared with unit 2


def test_single_target_on_an_endpoint_keeps_its_file_name_and_protocol(tmp_path):
    exporter = MagicMock(hex_addresses=False)
    db = MagicMock(is_enabled=True)
    writer = ResultWriter(_unit(1), exporter, db_exporter=db, label="10.0.0.5 (MODBUS_TCP:502)")
    writer.export_points([DataPoint(address="HR0", value=1)])
    assert exporter.export_plc_data.call_args.kwargs["target_tag"] == "MODBUS_TCP_502"
    assert db.export_plc_data.call_args.kwargs["protocol"] == "MODBUS_TCP"


# ----------------------------------------------------------------------
# --database and the config file
# ----------------------------------------------------------------------


def _db_config(tmp_path, database_section, **cli):
    loader = ConfigLoader()
    loader.config["output"]["database"] = database_section
    args = argparse.Namespace(no_database=False, database=None, db_track_history=None)
    vars(args).update(cli)
    exporter = plc_scanner._create_db_exporter(args, loader, MagicMock())
    if exporter is None:
        return None
    try:
        return exporter.config
    finally:
        exporter.close()


def test_database_option_keeps_the_retention_of_the_config_file(tmp_path):
    section = {"enabled": False, "path": str(tmp_path / "file.db"), "max_history_days": 0, "max_size_mb": 50}
    config = _db_config(tmp_path, section, database=str(tmp_path / "cli.db"))
    assert config.enabled and config.path == str(tmp_path / "cli.db")
    # Was 30 days: one run with --database deleted the history the file kept
    assert (config.max_history_days, config.max_size_mb, config.track_history) == (0, 50, True)


def test_track_history_option_applies_to_a_database_from_the_config_file(tmp_path):
    section = {"enabled": True, "path": str(tmp_path / "file.db"), "track_history": True}
    assert _db_config(tmp_path, section).track_history is True
    assert _db_config(tmp_path, section, db_track_history=False).track_history is False
    section["track_history"] = False
    assert _db_config(tmp_path, section).track_history is False
    assert _db_config(tmp_path, section, database=str(tmp_path / "cli.db")).track_history is False


def test_empty_database_section_does_not_crash(tmp_path):
    assert _db_config(tmp_path, None) is None  # "database:" with every line commented out
    assert _db_config(tmp_path, None, database=str(tmp_path / "cli.db")).enabled


# ----------------------------------------------------------------------
# ARP sweep
# ----------------------------------------------------------------------


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
            for name, value in dict(
                var_packet_interval="50",
                var_retry_interval="200",
                var_timeout="5000",
                var_output_dir="out",
                var_encoding="utf-8-sig",
                var_hex_addresses=False,
                var_periodic_csv="per_cycle",
                var_report_interval="0",
                var_min_interval="0",
                var_db_enabled=False,
                var_db_path="plc_data.db",
                var_db_history=True,
                var_db_days="30",
                var_db_size="0",
                var_db_interval="24",
            ).items():
                setattr(self, name, _Var(value))
            self.notify_destinations: list = []

        def _refresh_notify_tree(self):
            pass

        def _int_field(self, var, label, minimum=0):
            return int(var.get())

        def _network_config(self):
            return NetworkConfig()

    return App()


def test_one_wrong_value_in_the_settings_file_does_not_empty_the_rest(tmp_path):
    path = tmp_path / "plc_config.yaml"
    path.write_text(
        "output:\n"
        "  database:\n"
        "    enabled: true\n"
        "    max_size_mb:\n"  # left empty
        "notification_settings:\n"
        "  report_interval_minutes: 30\n"
        "notifications:\n"
        "  - name: teams\n"
        "    type: teams\n"
        "    url: https://example.com/hook\n",
        encoding="utf-8",
    )
    config, errors = settings_file.load(str(path))
    assert errors  # the wrong value is reported
    app = _settings_tabs()
    app._apply_settings(config)  # raised, leaving everything below at its default
    assert app.var_db_size.get() == "0"
    assert app.var_report_interval.get() == "30"
    assert [d["name"] for d in app.notify_destinations] == ["teams"]

    # "Save" no longer writes an empty destination list over the file
    _, save_errors = settings_file.save(str(path), app._settings_dict())
    assert save_errors == []
    saved, _ = settings_file.load(str(path))
    assert [d["url"] for d in saved["notifications"]] == ["https://example.com/hook"]
    assert saved["notification_settings"]["report_interval_minutes"] == 30


def test_stopped_single_scan_keeps_what_it_read(tmp_path):
    from simulators.slmp_simulator import SLMPDevice, SLMPProtocol

    async def run():
        loop = asyncio.get_running_loop()
        server = await loop.create_server(lambda: SLMPProtocol(SLMPDevice([])), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        app, posted = MagicMock(), []
        app._post = lambda *item: posted.append(item)
        job = asyncio.ensure_future(
            plc_gui.PLCScannerApp._collect_job(
                app,
                NetworkConfig(packet_interval_ms=100),
                "127.0.0.1",
                Protocol.SLMP,
                port,
                "full",
                DeviceType.D,
                0,
                0,
                0.0,
                None,
                ByteOrder.LITTLE_ENDIAN,
                CSVExporter(str(tmp_path), "utf-8-sig"),
            )
        )
        await asyncio.sleep(0.7)
        job.cancel()  # the Stop button
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(job, timeout=10)
        server.close()
        return posted

    posted = asyncio.run(run())
    shown = [item[1] for item in posted if item[0] == "data"]
    assert len(shown) == 1 and len(shown[0]) > 0  # was nothing: the table stayed empty
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1  # was no file at all
    assert len(files[0].read_text(encoding="utf-8-sig").splitlines()) == len(shown[0]) + 1


# ----------------------------------------------------------------------
# Simulators
# ----------------------------------------------------------------------


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
