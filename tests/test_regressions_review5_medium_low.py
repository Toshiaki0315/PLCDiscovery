"""
Regressions from the fifth code review (medium and low findings):
- EtherNet/IP: a missing tag is an address error whatever it is called; one
  reconnect attempt per tag read; reused tag definitions are requested by
  name and only on the same controller; array fragments have their own
  timeout; after an outage a Logix full scan reads tags again
- interruptions: a scan that is complete is written although Ctrl+C / Stop
  arrives while the PLC is being disconnected; while connecting, the targets
  already scanned are still reported
- daily CSV after the encoding was changed; keys inside targets / ranges
- scan control: points decided without a request are no answer; one
  target's unexpected error stays its own; thresholds; STRING default type;
  arguments are checked before anything is opened
- configuration and output: encodings, BOM, a locked database, "~"
- GUI settings that cannot be shown are not overwritten silently
"""

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pycomm3
import pytest
from pycomm3 import Tag
from pycomm3.exceptions import CommError

import plc_gui
import plc_gui_settings
import plc_scanner
from plc_discovery import settings_file
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
from plc_discovery.config_loader import ConfigLoader, generate_config_template, is_known_encoding
from plc_discovery.conversion import apply_data_type_conversion, load_type_mapping
from plc_discovery.data_types import ByteOrder, DataTypeManager
from plc_discovery.output import CSVExporter
from plc_discovery.protocols import cip_symbolic
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, _is_address_error, _tag_points
from plc_discovery.scan_runner import plc_answered
from plc_discovery.thresholds import parse_thresholds
from plc_discovery.utils import get_timestamp, number_text

FAST = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


# ----------------------------------------------------------------------
# EtherNet/IP
# ----------------------------------------------------------------------


@pytest.mark.parametrize("name", ["NoSuchTag", "ConnectionStatus", "Pump1_Busy", "Cycle_Timeout"])
def test_missing_tag_is_an_address_error_whatever_it_is_called(name):
    reply = Tag(name, None, None, f"Tag doesn't exist - {name}")  # pycomm3 puts the name into the text
    assert [p.status for p in _tag_points(name, reply)] == [StatusCode.NG_ILLEGAL_ADDR]  # was NG_COMM_ERROR


def test_structure_member_that_does_not_exist_is_an_address_error():
    reply = Tag("Speed.Busy", None, None, "failed to get tag data for: Speed, ['Busy']")
    assert _tag_points("Speed.Busy", reply)[0].status == StatusCode.NG_ILLEGAL_ADDR


def test_transient_texts_are_the_ones_pycomm3_really_uses():
    for text in ("Insufficient resource", "Controller in upload or download mode", "No buffer memory"):
        assert not _is_address_error(text), text
    for text in ("Path segment error - Symbol does not exist", "Address out of range", "Privilege failure"):
        assert _is_address_error(text), text


class _Logix:
    """LogixDriver stand-in; ``state`` is shared by every instance"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self.state.setdefault("created", []).append(init_tags)
        self._tags = (
            {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)} if init_tags else {}
        )
        self._data_types: dict = {}
        self._cfg = {"use_instance_ids": True}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)
    info = property(lambda self: {"serial": self.state.get("serial", "A1"), "name": "Line1"})

    def open(self):
        self.state["opens"] = self.state.get("opens", 0) + 1
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False
            raise CommError("failed to receive reply")
        self.state["instance_ids"] = self._cfg["use_instance_ids"]
        return [Tag(tag, 1, "DINT", None) for tag in tags]


@pytest.fixture
def logix(monkeypatch):
    _Logix.state = {}
    for driver in ("LogixDriver", "SLCDriver", "CIPDriver"):
        monkeypatch.setattr(pycomm3, driver, _Logix)
    return _Logix.state


def test_one_reconnect_attempt_per_tag_read_after_the_link_is_lost(logix):
    logix["off_at"] = "T100"

    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect()
        opens = logix["opens"]
        points = await handler.read_tags([f"T{i:03d}" for i in range(2000)])
        return points, logix["opens"] - opens

    points, reconnects = asyncio.run(run())
    assert Counter(p.status for p in points) == {StatusCode.OK: 100, StatusCode.NG_COMM_ERROR: 1900}
    assert reconnects == 1  # was one for each of the 94 remaining batches, without the packet interval


def test_reused_tag_definitions_are_requested_by_name(logix):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect()
        await handler.read_tags(["T000"])
        first = logix["instance_ids"]
        assert await handler.reconnect()
        points = await handler.read_tags(["T000"])
        return first, logix["instance_ids"], points, len(handler.tag_scan_list())

    first, after_reconnect, points, tags = asyncio.run(run())
    assert first is True
    # The instance IDs of the reused list may belong to other tags after a
    # program download: another tag's value was recorded under the old name
    assert after_reconnect is False
    assert points[0].status == StatusCode.OK and tags == 100
    assert logix["created"] == [True, False]  # the tag list was not uploaded again


def test_another_controller_on_the_address_gets_its_own_tag_list(logix):
    async def run():
        handler = EtherNetIPHandler("10.0.0.2", config=FAST)
        assert await handler.connect()
        logix["serial"] = "B2"  # the controller was replaced
        assert await handler.reconnect()
        await handler.read_tags(["T000"])
        return logix["instance_ids"], len(handler.tag_scan_list())

    instance_ids, tags = asyncio.run(run())
    assert logix["created"] == [True, False, True]  # reconnect without tags, then the upload
    assert instance_ids is True and tags == 100


def test_array_fragments_have_their_own_timeout(monkeypatch):
    import struct

    class Client:
        def open(self):
            return True

        def close(self):
            pass

    def send(client, service, path, data):
        _, offset = struct.unpack("<HI", data)
        last = offset // 4 == 7
        status = cip_symbolic.STATUS_OK if last else cip_symbolic.STATUS_PARTIAL
        return status, b"\xc4\x00" + struct.pack("<i", offset // 4), None

    monkeypatch.setattr(pycomm3, "CIPDriver", lambda path: Client())
    monkeypatch.setattr(cip_symbolic, "_send", send)

    async def run():
        # 8 fragments, 50 ms apart: 350 ms of waiting, more than the 200 ms a request may take
        handler = EtherNetIPHandler("10.0.0.3", config=NetworkConfig(packet_interval_ms=50, request_timeout_ms=200))
        handler._plc_type = "generic"
        assert await handler.connect()
        return await handler.read_tags(["Big[0]{8}"]), handler._needs_reconnect

    points, needs_reconnect = asyncio.run(run())
    assert [(p.address, p.status, p.value) for p in points] == [(f"Big[{i}]", StatusCode.OK, i) for i in range(8)]
    assert not needs_reconnect  # was NG_TIMEOUT and a reconnect, in every cycle


def test_logix_full_scan_reads_tags_again_after_an_outage(logix):
    async def run():
        collector = PLCDataCollector(PLCInfo("10.0.0.2", port=44818, protocol=Protocol.ETHERNET_IP), FAST)
        assert await collector.connect()
        cycles = [await collector.collect_full_scan()]
        for up in (False, False, True, True):
            logix["up"] = up
            cycles.append(await collector.collect_full_scan())
        return cycles, collector.get_denied_addresses()

    cycles, denied = asyncio.run(run())
    assert [len(points) for points in cycles] == [100, 100, 1, 100, 100]
    # Back on: tags, not 512 rows of the SLC data files as NG_UNSUPPORTED
    assert all(p.is_tag and p.status == StatusCode.OK for p in cycles[3])
    assert denied == set()
    assert not plc_answered(cycles[1]) and not plc_answered(cycles[2])


# ----------------------------------------------------------------------
# Interruptions while connecting / disconnecting
# ----------------------------------------------------------------------


def _collector_class(connect_seconds=0.0, disconnect_seconds=0.0, read_seconds=0.0):
    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = False
            self.connect_error = None
            self.skip_reconnect = False
            self.data: list = []

        async def __aenter__(self):
            await asyncio.sleep(connect_seconds)
            self.is_connected = True
            return self

        async def __aexit__(self, *exc):
            await asyncio.sleep(disconnect_seconds)
            self.is_connected = False

        async def disconnect(self):
            self.is_connected = False

        async def collect_range(self, device_type, start, end):
            await asyncio.sleep(read_seconds)
            self.data = [
                DataPoint(address=f"D{a}", value=1, raw_hex="0001", timestamp=get_timestamp())
                for a in range(start, end + 1)
            ]
            return self.data

        def get_collected_data(self):
            return self.data

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": len(self.data), "success_count": len(self.data), "error_count": 0}

    return Collector


def _interrupted_scan(collector_class, cancel_after):
    exporter = MagicMock(hex_addresses=False)

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", collector_class):
            task = asyncio.ensure_future(
                plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST,
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 9)],
                )
            )
            await asyncio.sleep(cancel_after)
            task.cancel()  # Ctrl+C
            return await asyncio.wait_for(task, timeout=10)

    return asyncio.run(run()), exporter


def test_complete_scan_is_written_although_interrupted_while_disconnecting():
    outcome, exporter = _interrupted_scan(_collector_class(disconnect_seconds=5), cancel_after=0.2)
    # Was CancelledError out of run_single_scan: nothing written, no report
    assert outcome.interrupted and outcome.success and len(outcome.data_points) == 10
    assert exporter.export_plc_data.call_count == 1


def test_interruption_while_connecting_is_reported_not_raised():
    outcome, exporter = _interrupted_scan(_collector_class(connect_seconds=5), cancel_after=0.2)
    # The run goes on to its report with the targets already scanned
    assert outcome.interrupted and not outcome.success and outcome.data_points == []
    assert "interrupted" in outcome.error
    assert exporter.export_plc_data.call_count == 0


def test_gui_second_stop_while_disconnecting_keeps_the_partial_scan(tmp_path, monkeypatch):
    from plc_discovery.protocols.slmp import SLMPHandler
    from simulators.slmp_simulator import SLMPDevice, SLMPProtocol

    original = SLMPHandler.disconnect

    async def slow_disconnect(self):
        await asyncio.sleep(1.0)  # a PLC that is slow to answer the close
        await original(self)

    monkeypatch.setattr(SLMPHandler, "disconnect", slow_disconnect)

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
        # 3rd progress call: the first range is read ("Starting" and the
        # first "Scanning" come before anything was read)
        for _ in range(2000):
            if app._progress_cb.call_count >= 3 or job.done():
                break
            await asyncio.sleep(0.01)
        job.cancel()  # Stop
        await asyncio.sleep(0.3)
        job.cancel()  # Stop again, while "停止しています..." is shown
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(job, timeout=10)
        server.close()
        return posted

    posted = asyncio.run(run())
    shown = [item[1] for item in posted if item[0] == "data"]
    assert len(shown) == 1 and len(shown[0]) > 0  # was nothing, with "saved" in the status line
    assert len(list(tmp_path.glob("plc_data_*.csv"))) == 1


# ----------------------------------------------------------------------
# Daily CSV, and keys inside targets / device ranges
# ----------------------------------------------------------------------


def test_daily_csv_continues_in_its_own_file_after_the_encoding_was_changed(tmp_path):
    def append(encoding, address):
        exporter = CSVExporter(str(tmp_path), encoding)
        point = DataPoint(address=address, value=1, raw_hex="0001", status=StatusCode.OK, timestamp="t")
        return Path(exporter.append_plc_data([point], "10.0.0.1"))

    first = append("utf-8-sig", "D0")
    assert append("utf-8-sig", "D1") == first
    second = append("shift-jis", "D2")
    assert append("shift-jis", "D3") == second
    assert second != first and second.name.endswith("_cp932.csv")
    # Was one file: the BOM made its header unreadable in CP932, and D2 / D3
    # were written with an empty address column
    assert [line.split(",")[0] for line in first.read_text(encoding="utf-8-sig").splitlines()] == [
        "address",
        "D0",
        "D1",
    ]
    assert [line.split(",")[0] for line in second.read_text(encoding="cp932").splitlines()] == ["address", "D2", "D3"]


def test_misplaced_and_misspelt_keys_of_targets_and_ranges_are_errors():
    loader = ConfigLoader()
    loader.config["targets"] = [{"ip": "10.0.0.5", "protocol": "modbus", "unit_id": 2, "name": "meter"}]
    loader.config["scan"]["device_ranges"] = [{"device": "HR", "start": 100, "stop": 200}]
    errors = loader.validate()  # was []: unit 1 was read, and HR100-999 instead of HR100-200
    assert any("targets[0]" in e and "unit_id" in e and "options" in e for e in errors)
    assert any("scan.device_ranges[0]" in e and "stop" in e for e in errors)

    loader.config["targets"] = [{"ip": "10.0.0.5", "protocol": "modbus", "options": {"unit_id": 2}, "model": 1500}]
    loader.config["scan"]["device_ranges"] = [{"device": "HR", "start": 100, "end": 200, "comment": "meter"}]
    assert loader.validate() == []
    assert loader.get_targets()[0].model == "1500"  # text: the HTML report failed on a number


# ----------------------------------------------------------------------
# Scan control
# ----------------------------------------------------------------------


class _Modbus(BaseProtocolHandler):
    protocol = Protocol.MODBUS_TCP
    EDGE_PROBE_SHORTCUT = False
    MAX_ADDRESS = 0xFFFF

    def __init__(self, status):
        super().__init__("10.0.0.1", 502, FAST)
        self._connected = True
        self.status = status

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        return ([7] * count if self.status == StatusCode.OK else None), self.status


def test_addresses_beyond_the_protocol_limit_are_no_answer_of_the_plc():
    crossing = DeviceRange(DeviceType.HR, 65500, 65600)
    silent = asyncio.run(_Modbus(StatusCode.NG_TIMEOUT).read_device_range(crossing))
    assert len(silent) == 101 and not plc_answered(silent)  # was "answered": success, never "down"

    answering = asyncio.run(_Modbus(StatusCode.OK).read_device_range(crossing))
    by_address = {p.address: p for p in answering}
    assert by_address["HR65535"].status == StatusCode.OK
    assert (by_address["HR65536"].status, by_address["HR65536"].cached) == (StatusCode.NG_ILLEGAL_ADDR, True)
    assert plc_answered(answering)


def test_unexpected_error_of_one_target_is_its_own_failure():
    async def run_single_scan(plc_info, *args, **kwargs):
        raise RuntimeError("driver bug")

    exporter = MagicMock(hex_addresses=False)

    async def run():
        with patch.object(plc_scanner, "run_single_scan", run_single_scan):
            return await plc_scanner.scan_target(
                PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                FAST,
                exporter,
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 3)],
                None,
                ByteOrder.LITTLE_ENDIAN,
                None,
                None,
                "10.0.0.1",
                None,
            )

    outcome = asyncio.run(run())  # raised in a sequential scan: the other targets were never scanned
    assert not outcome.success and outcome.error == "driver bug"
    assert [p.status for p in outcome.data_points] == [StatusCode.NG_COMM_ERROR] * 4
    assert exporter.export_plc_data.call_count == 1


def test_periodic_scan_goes_on_after_an_unexpected_error_of_a_read():
    class Collector(_collector_class()):
        reads = 0

        def __init__(self, plc_info, config=None):
            super().__init__(plc_info, config)
            self.is_connected = True

        def clear_data(self):
            pass

        async def collect_range(self, device_type, start, end):
            Collector.reads += 1
            if Collector.reads == 2:
                raise RuntimeError("driver bug")
            return await super().collect_range(device_type, start, end)

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)],
                    FAST,
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 0, 2)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(1000):
                if notifier.notify_recovered.await_count or task.done():
                    break
                await asyncio.sleep(0.005)
            assert not task.done()  # the monitoring ended with the exception
            task.cancel()
            return await asyncio.wait_for(task, timeout=10)

    asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1 and notifier.notify_recovered.await_count == 1


def test_thresholds_on_array_elements_and_large_numbers():
    limits = parse_thresholds(["Matrix[0,0]>5, D1>=2", "D100>1234567890123", "D100>1234567890124"])
    assert [t.address for t in limits] == ["Matrix[0,0]", "D1", "D100", "D100"]  # was "invalid threshold 'Matrix[0'"
    assert (limits[2].label, limits[3].label) == ("D100 > 1234567890123", "D100 > 1234567890124")
    assert number_text(0.1 + 0.2) == "0.3" and number_text(2**62) == str(2**62)


def test_string_default_type_before_a_mapping_is_converted():
    manager = DataTypeManager.from_config(
        {"default_type": "STRING", "mappings": [{"start": 4, "end": 5, "type": "DWORD"}]}
    )
    points = [DataPoint(address=f"D{a}", status=StatusCode.OK, value=0x4241) for a in range(10)]
    converted = {p.address: p for p in apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)}
    # Was "(incomplete STRING: 4/10 words)": the length ran to the end of the range
    assert converted["D0"].converted_value == "ABABABAB"
    assert converted["D4"].data_type == "DWORD"
    assert converted["D6"].converted_value == "ABABABAB"


def test_arguments_are_checked_before_the_audit_log_and_database_are_opened(monkeypatch, tmp_path, capsys):
    audit, database = tmp_path / "audit.jsonl", tmp_path / "plc.db"
    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--device", "D", "--range", "0-1"]
    argv += ["--threshold", "D0>>x", "--audit-log", str(audit), "--database", str(database), "--no-rich"]
    monkeypatch.setattr(sys, "argv", argv + ["--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    # Was a session left open in the audit log, and a database already cleaned up
    assert not audit.exists() and not database.exists()


# ----------------------------------------------------------------------
# Configuration and output
# ----------------------------------------------------------------------


def test_encodings_that_scramble_or_fail_a_csv_are_rejected():
    for name in ("idna", "punycode", "cp500", "utf-7", "unicode_escape"):
        assert not is_known_encoding(name), name
    for name in ("utf-16", "euc-jp", "latin-1", "cp932", "utf-8-sig", "ascii"):
        assert is_known_encoding(name), name


def test_files_with_a_bom_load_everywhere(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"network": {"packet_interval_ms": 75}}), encoding="utf-8-sig")
    assert settings_file.read_file(str(settings)) == {"network": {"packet_interval_ms": 75}}  # JSONDecodeError

    mapping = tmp_path / "types.json"
    mapping.write_text(json.dumps({"default_type": "INT16", "mappings": []}), encoding="utf-8-sig")
    assert load_type_mapping(str(mapping)).default_type.value == "INT16"


def test_locked_database_does_not_stop_the_scan(monkeypatch, tmp_path, capsys):
    database = MagicMock(is_enabled=True)
    database.begin_session.side_effect = RuntimeError("database is locked")
    monkeypatch.setattr(plc_scanner, "_create_db_exporter", lambda *args: database)
    monkeypatch.setattr(plc_scanner, "PLCDataCollector", _collector_class())
    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--protocol", "slmp"]
    argv += ["--device", "D", "--range", "0-3", "--no-rich", "--output-dir", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", argv)
    asyncio.run(plc_scanner.main())  # exit 1 "database is locked", and no PLC was scanned
    assert "Database session could not be started" in capsys.readouterr().out
    assert len(list(tmp_path.glob("plc_data_*.csv"))) == 1


def test_generated_config_must_be_a_format_that_can_be_loaded(tmp_path):
    with pytest.raises(ValueError, match="yaml"):
        generate_config_template(str(tmp_path / "plc_config.txt"))  # wrote JSON that --config then refused
    assert not (tmp_path / "plc_config.txt").exists()
    generate_config_template(str(tmp_path / "plc_config.yaml"))
    assert ConfigLoader().load(str(tmp_path / "plc_config.yaml"))


def test_home_directory_in_paths_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    exporter = CSVExporter("~/plc_results", "utf-8")  # created a directory called "~"
    assert exporter.output_dir == tmp_path / "plc_results"


# ----------------------------------------------------------------------
# GUI settings
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
            values = dict(
                packet_interval="50",
                retry_interval="200",
                timeout="5000",
                output_dir="out",
                encoding="utf-8-sig",
                hex_addresses=False,
                periodic_csv="per_cycle",
                report_interval="0",
                min_interval="0",
                db_enabled=False,
                db_path="plc_data.db",
                db_history=True,
                db_days="30",
                db_size="0",
                db_interval="24",
            )
            for name, value in values.items():
                setattr(self, f"var_{name}", _Var(value))
            self.notify_destinations: list = []

        def _refresh_notify_tree(self):
            pass

        def _int_field(self, var, label, minimum=0):
            return int(var.get())

        def _network_config(self):
            return NetworkConfig()

    return App()


def test_gui_notes_what_it_could_not_show():
    app = _settings_tabs()
    app._apply_settings(
        {
            "notifications": {"teams": {"type": "teams", "url": "https://example.com/secret"}},  # not a list
            "output": {"hex_addresses": "false", "database": {"enabled": "no", "max_history_days": 1000000}},
        }
    )
    # Shown as defaults; "save" would write them over the file, so it asks first
    assert {"notifications", "output.hex_addresses", "output.database.enabled"} <= set(app._settings_dropped)
    assert app.var_hex_addresses.get() is False and app.var_db_enabled.get() is False  # bool("false") is True
    assert app.var_db_days.get() == "1000000"  # was "1e+06", refused on every save

    app._apply_settings({"output": {"hex_addresses": True}, "notifications": [{"name": "a", "url": "https://x"}]})
    assert list(app._settings_dropped) == [] and app.var_hex_addresses.get() is True


def test_gui_keeps_an_encoding_it_cannot_show():
    app = _settings_tabs()
    app._apply_settings({"output": {"encoding": "euc-jp"}})
    assert list(app._settings_dropped) == []
    assert app.var_encoding.get() == "utf-8-sig"  # the radio button stays where it was
    assert app._csv_encoding() == "euc_jp"  # used for the CSV files ...
    assert app._settings_dict()["output"]["encoding"] == "euc_jp"  # ... and written back (was utf-8-sig)
    app.var_encoding.set("shift-jis")  # the user chooses another one
    assert app._csv_encoding() == "shift-jis"


# ----------------------------------------------------------------------
# Simulators
# ----------------------------------------------------------------------


def test_run_all_second_ctrl_c_is_not_a_failure(monkeypatch):
    from simulators import run_all

    def interrupted(coroutine):
        coroutine.close()
        raise asyncio.CancelledError  # a second Ctrl+C while the simulators were stopping

    monkeypatch.setattr(run_all.asyncio, "run", interrupted)
    monkeypatch.setattr(sys, "argv", ["run_all.py"])
    assert run_all.run() is None  # was a traceback and exit code 1: "could not be started"


# ----------------------------------------------------------------------
# A request to stop is never lost (Python 3.10 / 3.11)
# ----------------------------------------------------------------------


def test_wait_for_keeps_a_cancellation_that_arrives_as_the_result_does():
    from plc_discovery.utils import wait_for

    async def body():
        future = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_soon(future.set_result, "answer")
        await wait_for(future, 2)
        return "went on"  # asyncio.wait_for of Python 3.10 / 3.11 returned here: the stop was ignored

    async def run():
        task = asyncio.ensure_future(body())
        await asyncio.sleep(0)  # body is waiting
        await asyncio.sleep(0)  # the result is there, body's wake-up is scheduled
        task.cancel()
        try:
            return await task
        except asyncio.CancelledError:
            return "stopped"

    assert asyncio.run(run()) == "stopped"


def test_wait_for_times_out_and_returns_results_like_asyncio():
    from plc_discovery.utils import wait_for

    async def run():
        cleaned = []

        async def slow():
            try:
                await asyncio.sleep(10)
            finally:
                cleaned.append(True)

        async def quick():
            return 7

        async def failing():
            raise ValueError("bad frame")

        with pytest.raises(asyncio.TimeoutError):
            await wait_for(slow(), 0.05)
        with pytest.raises(ValueError, match="bad frame"):
            await wait_for(failing(), 1)
        return await wait_for(quick(), 1), cleaned

    assert asyncio.run(run()) == (7, [True])  # the timed-out coroutine was cancelled and ran its cleanup


def test_blocking_read_is_stopped_by_a_cancellation_that_arrives_with_its_result():
    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start_address, count):
            return [1] * count, StatusCode.OK

    async def run():
        handler = Handler("10.0.0.1", 5001, FAST)
        stopped = 0
        for ticks in range(12):  # whatever the moment of the request to stop
            task = asyncio.ensure_future(handler._run_blocking(lambda: 1))
            for _ in range(ticks):
                await asyncio.sleep(0)
            if task.done():
                break
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5)
            except asyncio.CancelledError:
                stopped += 1
        return stopped, ticks

    stopped, tried = asyncio.run(run())
    assert stopped == tried and tried > 0
