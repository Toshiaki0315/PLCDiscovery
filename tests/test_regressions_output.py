"""
Regression tests for CSV output, found and fixed in code reviews.
"""

import asyncio
import csv
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import progress
from plc_discovery.audit_log import AuditLogger, close_audit_logger, get_audit_logger, init_audit_logger
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import DEFAULT_CONFIG
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.output import CSVExporter, csv_safe, load_denied_addresses, normalize_csv_encoding
from plc_discovery.progress import RichProgressDisplay, create_progress_callback
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.retry import RetryConfig, RetryStrategy

EVIL = "m\x1b]0;pwned\x07\x1b[2J\x9b31m"


def _rich_display():
    from rich.console import Console

    from plc_discovery.progress import RichProgressDisplay

    display = RichProgressDisplay()
    buffer = io.StringIO()
    display.console = Console(file=buffer, force_terminal=True, width=200)
    return display, buffer


def _async_return(value):
    async def fn(*args, **kwargs):
        return value

    return fn


def cp932_stream(errors="strict"):
    return io.TextIOWrapper(io.BytesIO(), encoding="cp932", errors=errors)


def test_plcinfo_strips_control_characters_however_set():
    plc = PLCInfo("10.0.0.1", model=EVIL, manufacturer="A\x1bB")
    plc.cpu_type = "C\x07PU"
    plc.firmware_version = "1.0\x00"
    assert (plc.model, plc.manufacturer, plc.cpu_type, plc.firmware_version) == ("m]0;pwned[2J31m", "AB", "CPU", "1.0")
    assert "\x1b" not in json.dumps(plc.to_dict())


def test_messages_strip_control_characters():
    pytest.importorskip("rich")
    display, buffer = _rich_display()
    display.print_error(f"Detected {EVIL}")
    display.print(f"value {EVIL}")
    out = buffer.getvalue()
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x9b" not in out


def test_plain_output_strips_control_characters(capsys):
    from plc_discovery.progress import RichProgressDisplay

    display = RichProgressDisplay(use_rich=False)
    display.print_discovery_results([{"ip_address": "10.0.0.1", "protocol": "EIP", "manufacturer": EVIL}])
    display.print_warning(EVIL)
    assert "\x1b" not in capsys.readouterr().out


def test_r2_csv_keeps_second_word(tmp_path):
    points = [
        DataPoint("D0", 0x0000, "0x0000", StatusCode.OK),
        DataPoint("D1", 0x3F80, "0x3F80", StatusCode.OK),
    ]
    converted = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
    path = CSVExporter(str(tmp_path)).export_plc_data(converted, "1.2.3.4")
    lines = open(path, encoding="utf-8").read().splitlines()

    assert len(lines) == 3  # header + D0 + D1
    assert lines[1].startswith("D0,0,0x0000,FLOAT,1.0,")
    assert lines[2].startswith("D1,16256,0x3F80,FLOAT,,(part of D0),OK")


@pytest.mark.asyncio
async def test_unsupported_status_kept_in_cache_and_csv(tmp_path):
    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            self._connected = True
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start, count):
            return None, StatusCode.NG_UNSUPPORTED

    handler = Handler(
        "127.0.0.1",
        1,
        NetworkConfig(packet_interval_ms=0, retry_interval_ms=0),
        retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=0, initial_delay_ms=0),
        use_circuit_breaker=False,
    )
    handler._connected = True
    rng = DeviceRange(DeviceType.SM, 0, 2)
    await handler.read_device_range(rng)
    second = await handler.read_device_range(rng)  # served from cache

    assert {dp.status for dp in second} == {StatusCode.NG_UNSUPPORTED}
    statuses = handler.get_denied_statuses()
    assert statuses == {f"SM{i}": StatusCode.NG_UNSUPPORTED for i in range(3)}

    path = CSVExporter(str(tmp_path)).export_denied_addresses(set(statuses), "1.2.3.4", statuses=statuses)
    assert "SM0,NG_UNSUPPORTED," in open(path, encoding="utf-8").read()


class TestCSVSafe:

    @pytest.mark.parametrize(
        "value, expected",
        [
            ('=HYPERLINK("http://x")', '\'=HYPERLINK("http://x")'),
            ("+cmd", "'+cmd"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("-2+3", "'-2+3"),
            ("-12.500000", "-12.500000"),  # negative number stays numeric
            ("0x3F80", "0x3F80"),
            ("Omron", "Omron"),
            (-5, -5),
            (None, None),
        ],
    )
    def test_csv_safe(self, value, expected):
        assert csv_safe(value) == expected

    def test_discovery_csv_neutralizes_device_strings(self, tmp_path):
        plc = PLCInfo(
            "10.0.0.5", manufacturer='=HYPERLINK("http://x","click")', model="@cmd", protocol=Protocol.MODBUS_TCP
        )
        path = CSVExporter(str(tmp_path)).export_discovery_results([plc])
        row = next(csv.DictReader(open(path, encoding="utf-8")))
        assert row["manufacturer"].startswith("'=")
        assert row["model"] == "'@cmd"
        assert row["ip_address"] == "10.0.0.5"

    def test_data_csv_keeps_negative_numbers(self, tmp_path):
        dp = DataPoint("D0", 0xFFFF, "0xFFFF", StatusCode.OK, data_type="INT16", converted_value=-1, display_value="-1")
        path = CSVExporter(str(tmp_path)).export_plc_data([dp], "1.2.3.4")
        row = next(csv.DictReader(open(path, encoding="utf-8")))
        assert row["converted_value"] == "-1" and row["display_value"] == "-1"


def test_same_second_exports_do_not_overwrite(tmp_path):
    exporter = CSVExporter(str(tmp_path))
    points = [DataPoint("D0", 1, "0x0001", StatusCode.OK)]
    with patch("plc_discovery.output.get_file_timestamp", return_value="20260101_000000"):
        paths = [exporter.export_plc_data(points, "10.0.0.1") for _ in range(3)]
    assert len(set(paths)) == 3
    assert paths[1].endswith("plc_data_10_0_0_1_20260101_000000_1.csv")


class TestShiftJIS:

    @pytest.mark.parametrize("name", ["shift-jis", "shift_jis", "SJIS", "cp932"])
    def test_aliases_map_to_cp932(self, name):
        assert normalize_csv_encoding(name) == "cp932"

    def test_unrepresentable_vendor_name_does_not_fail(self, tmp_path):
        plcs = [
            PLCInfo("10.0.0.9", manufacturer="Dürr Somac GmbH", protocol=Protocol.ETHERNET_IP),
            PLCInfo("10.0.0.1", manufacturer="三菱電機", model="①号機 ㈱テスト～", protocol=Protocol.SLMP),
        ]
        path = CSVExporter(str(tmp_path), "shift-jis").export_discovery_results(plcs)
        rows = list(csv.DictReader(open(path, encoding="cp932")))
        assert rows[0]["manufacturer"] == "D?rr Somac GmbH"
        assert rows[1]["manufacturer"] == "三菱電機"
        assert rows[1]["model"] == "①号機 ㈱テスト～"  # CP932-only characters kept

    @pytest.mark.asyncio
    async def test_discovery_results_shown_when_csv_fails(self):
        plcs = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]
        exporter = MagicMock()
        exporter.export_discovery_results.side_effect = PermissionError("locked")
        display = MagicMock()
        errors = []
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(plc_scanner.BroadcastDiscovery, "discover_all_broadcast", _async_return([]))
            mp.setattr(plc_scanner, "discover_plcs", _async_return(plcs))
            result = await plc_scanner.run_discovery([], NetworkConfig(), exporter, display, errors=errors)
        assert result == plcs
        display.print_discovery_results.assert_called_once()  # list still shown
        assert errors and "locked" in errors[0]


class TestUTF8BOM:

    def test_cli_default_is_utf8_with_bom(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["plc_scanner.py"])
        args = plc_scanner.parse_args()
        assert plc_scanner.resolve_output_settings(args, None)[1] == "utf-8-sig"
        assert DEFAULT_CONFIG["output"]["encoding"] == "utf-8-sig"

    def test_data_csv_starts_with_bom(self, tmp_path):
        path = CSVExporter(str(tmp_path), "utf-8-sig").export_discovery_results(
            [PLCInfo("10.0.0.1", manufacturer="三菱電機", protocol=Protocol.SLMP)]
        )
        raw = Path(path).read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")
        assert "三菱電機" in raw.decode("utf-8-sig")

    def test_denied_log_append_writes_bom_once(self, tmp_path):
        exporter = CSVExporter(str(tmp_path), "utf-8-sig")
        exporter.export_denied_addresses({"D10"}, "10.0.0.1")
        path = exporter.export_denied_addresses({"D20"}, "10.0.0.1")
        raw = Path(path).read_bytes()
        assert raw.count(b"\xef\xbb\xbf") == 1
        assert load_denied_addresses(path) == {"D10", "D20"}  # BOM stripped when reading

    def test_plain_utf8_has_no_bom(self, tmp_path):
        path = CSVExporter(str(tmp_path), "utf-8").export_plc_data(
            [DataPoint("D0", 1, "0x0001", StatusCode.OK)], "10.0.0.1"
        )
        assert not Path(path).read_bytes().startswith(b"\xef\xbb\xbf")


def test_ascii_markers_when_symbols_not_encodable(monkeypatch):
    stream = cp932_stream()
    monkeypatch.setattr(sys, "stdout", stream)
    display = RichProgressDisplay(use_rich=False)
    display.print_info("接続中")
    display.print_error("失敗")
    display.print_success("完了")
    stream.flush()
    text = stream.buffer.getvalue().decode("cp932")
    assert "[INFO] 接続中" in text and "[ERROR] 失敗" in text and "[OK] 完了" in text


def test_symbols_kept_when_encodable(monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", stream)
    RichProgressDisplay(use_rich=False).print_info("x")
    stream.flush()
    assert stream.buffer.getvalue().decode("utf-8").startswith("ℹ x")


def test_no_rich_disables_console():
    assert RichProgressDisplay(use_rich=False).console is None
    if progress.RICH_AVAILABLE:
        assert RichProgressDisplay().console is not None


def test_rich_markup_in_messages_is_escaped():
    if not progress.RICH_AVAILABLE:
        pytest.skip("rich not installed")
    display = RichProgressDisplay()
    with display.console.capture() as captured:
        display.print_info("value [bold]x[/bold] and [/unbalanced]")
    assert "[bold]x[/bold] and [/unbalanced]" in captured.get()


def test_audit_console_output_failure_does_not_reach_the_caller(tmp_path):
    log = tmp_path / "audit.jsonl"
    audit = AuditLogger(str(log), console_output=True)
    try:
        with patch("builtins.print", side_effect=UnicodeEncodeError("cp932", "タグ", 0, 1, "illegal")):
            audit.log_tag_read("10.0.0.1", "ETHERNET_IP", ["温度"], "OK", 1.0)  # must not raise
    finally:
        audit.close()
    assert "温度" in log.read_text(encoding="utf-8")  # the file record is written all the same


def test_character_missing_from_the_encoding_does_not_fail_the_file(tmp_path):
    exporter = CSVExporter(str(tmp_path), "euc-jp")
    point = DataPoint(address="Motor①ü", value=1, raw_hex="0001", status=StatusCode.OK)
    path = exporter.export_plc_data([point], "10.0.0.1")  # raised UnicodeEncodeError, leaving a truncated file
    text = Path(path).read_text(encoding="euc-jp")
    assert "Motor" in text and "?" in text


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


def test_home_directory_in_paths_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    exporter = CSVExporter("~/plc_results", "utf-8")  # created a directory called "~"
    assert exporter.output_dir == tmp_path / "plc_results"


def test_denied_log_continues_in_its_own_file_after_the_encoding_was_changed(tmp_path):
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"温度"}, "10.0.0.1")
    second = CSVExporter(str(tmp_path), "shift-jis").export_denied_addresses({"圧力"}, "10.0.0.1")

    first = tmp_path / "access_denied_log.csv"
    assert second != str(first)
    # Each file is readable in one encoding (was: CP932 rows inside the UTF-8 file)
    assert "温度" in first.read_text(encoding="utf-8") and "圧力" not in first.read_text(encoding="utf-8")
    text = (tmp_path / "access_denied_log_cp932.csv").read_text(encoding="cp932")
    assert text.splitlines()[0] == "address,status,last_attempt,plc_ip" and "圧力" in text

    # ... and later rows of either encoding go to the file of that encoding
    CSVExporter(str(tmp_path), "shift-jis").export_denied_addresses({"流量"}, "10.0.0.1")
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"D9"}, "10.0.0.1")
    assert "流量" in (tmp_path / "access_denied_log_cp932.csv").read_text(encoding="cp932")
    assert "D9" in first.read_text(encoding="utf-8")
    assert len(list(tmp_path.glob("access_denied_log*.csv"))) == 2


@pytest.mark.parametrize("encodings", [("utf-8", "shift-jis"), ("shift-jis", "utf-8"), ("utf-8-sig", "utf-8-sig")])
def test_denied_log_of_plain_addresses_stays_one_file(tmp_path, encodings):
    for encoding, address in zip(encodings, ("D100", "D200")):
        CSVExporter(str(tmp_path), encoding).export_denied_addresses({address}, "10.0.0.1")
    files = list(tmp_path.glob("access_denied_log*.csv"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 3 and lines[0].startswith("address,")


def test_denied_log_with_and_without_bom_is_not_mixed(tmp_path):
    CSVExporter(str(tmp_path), "utf-8").export_denied_addresses({"D100"}, "10.0.0.1")
    CSVExporter(str(tmp_path), "utf-8-sig").export_denied_addresses({"D200"}, "10.0.0.1")
    assert len(list(tmp_path.glob("access_denied_log*.csv"))) == 2


FAST_200MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


class _Silent(BaseProtocolHandler):
    """Times out when a request touches ``bad``; never answers after ``dead_after`` requests"""

    protocol = Protocol.MODBUS_TCP

    def __init__(self, bad=(), dead_after=None):
        super().__init__("127.0.0.1", 1, FAST_200MS)
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


def test_empty_denied_log_gets_its_header(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8")
    (tmp_path / "access_denied_log.csv").write_bytes(b"")
    path = exporter.export_denied_addresses({"D100"}, "10.0.0.1")
    lines = open(path, encoding="utf-8").read().splitlines()
    assert lines[0].startswith("address") and "D100" in lines[1]


def test_progress_callback_updates_the_first_task():
    display = MagicMock()
    create_progress_callback(display, 0)("reading", 3, 10)  # rich's first task id is 0
    display._progress.update.assert_called_once_with(0, completed=3, total=10, description="reading")
