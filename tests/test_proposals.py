"""
Tests for the proposal items: Teams Adaptive Card, MELSEC hex address
column, daily CSV for periodic scans, EtherNet/IP Logix tag reading and
the simulator's PCCC (SLC data file) reads.
"""

import asyncio
import csv
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.collector import PLCDataCollector, collect_item
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode, TagRange,
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.notifications import (
    NotificationConfig, NotificationEvent, NotificationManager, NotificationPriority,
    NotificationType, TeamsHandler,
)
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, MAX_TAG_ARRAY_ELEMENTS
from plc_discovery.utils import melsec_address

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# 4: Teams Adaptive Card
# ---------------------------------------------------------------------------

def _teams(**kwargs):
    return TeamsHandler(NotificationConfig(name="t", type="teams", url="https://x", **kwargs))


def _event():
    return NotificationEvent(type=NotificationType.SCAN_ERROR, title="PLC Scan Error", message="10.0.0.1 down",
                             priority=NotificationPriority.HIGH, timestamp="ts", data={"plc_ip": "10.0.0.1"})


def test_teams_sends_adaptive_card_by_default():
    payload = _teams().build_payload(_event())
    assert payload["type"] == "message"
    attachment = payload["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    texts = [b.get("text") for b in card["body"] if b["type"] == "TextBlock"]
    assert texts[0] == "PLC Scan Error" and "10.0.0.1 down" in texts
    assert card["body"][0]["color"] == "warning"
    facts = {f["title"]: f["value"] for f in card["body"][-1]["facts"]}
    assert facts == {"Type": "scan_error", "Timestamp": "ts", "plc_ip": "10.0.0.1"}


def test_teams_legacy_message_card_on_request():
    payload = _teams(card_format="messagecard").build_payload(_event())
    assert payload["@type"] == "MessageCard"
    manager = NotificationManager.from_config({"notifications": [
        {"name": "t", "type": "teams", "url": "https://x", "format": "MessageCard"}]})
    assert manager._handlers["t"].config.card_format == "messagecard"


def test_teams_format_validated(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("notifications:\n  - {name: t, type: teams, url: 'https://x', format: html}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("notifications[0].format" in e for e in loader.validate())


# ---------------------------------------------------------------------------
# 6: MELSEC hex addresses
# ---------------------------------------------------------------------------

def test_melsec_address():
    assert [melsec_address(a) for a in ("X31", "Y0", "B255", "W2047", "D100", "M31", "SM400", "HR5")] == \
        ["X1F", "Y0", "BFF", "W7FF", "D100", "M31", "SM400", "HR5"]


def _points(*addresses):
    return [DataPoint(a, 1, "0x0001", StatusCode.OK, "2026-11-17 10:00:00.000") for a in addresses]


def test_csv_address_hex_column(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8", hex_addresses=True)
    path = exporter.export_plc_data(_points("X31", "D5"), "10.0.0.1", hex_addresses=True)
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    assert [(r["address"], r["address_hex"]) for r in rows] == [("X31", "X1F"), ("D5", "D5")]
    plain = exporter.export_plc_data(_points("X31"), "10.0.0.2")
    assert "address_hex" not in open(plain, encoding="utf-8").readline()


class _Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.parametrize("protocol,expected", [(Protocol.SLMP, True), (Protocol.MODBUS_TCP, False)])
def test_hex_column_only_for_slmp(tmp_path, protocol, expected):
    """Modbus X/Y are coils / discrete inputs numbered in decimal"""
    exporter = CSVExporter(str(tmp_path), "utf-8", hex_addresses=True)
    writer = plc_scanner._ResultWriter(PLCInfo("10.0.0.1", protocol=protocol, port=1), exporter, _Display())
    path = writer.export_points(_points("X31"))
    assert ("address_hex" in open(path, encoding="utf-8").readline()) is expected


def test_cli_and_config_hex_option(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--hex-addresses", "--periodic-csv", "daily"])
    args = plc_scanner.parse_args()
    assert args.hex_addresses is True and args.periodic_csv == "daily"
    path = tmp_path / "c.yaml"
    path.write_text("output:\n  hex_addresses: 'yes'\n  periodic_csv: hourly\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any("output.hex_addresses" in e for e in errors)
    assert any("output.periodic_csv" in e for e in errors)


# ---------------------------------------------------------------------------
# 5: one CSV per day for periodic scans
# ---------------------------------------------------------------------------

def test_daily_csv_appends_cycles(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8-sig")
    first = exporter.append_plc_data(_points("D0", "D1"), "10.0.0.1")
    second = exporter.append_plc_data(_points("D0", "D1"), "10.0.0.1")
    assert first == second and Path(first).name.startswith("plc_data_10_0_0_1_2")
    raw = Path(first).read_bytes()
    assert raw.count(b"\xef\xbb\xbf") == 1                    # BOM once
    rows = list(csv.DictReader(open(first, encoding="utf-8-sig")))
    assert [r["address"] for r in rows] == ["D0", "D1", "D0", "D1"]
    assert "converted_value" in rows[0]                       # fixed extended columns


def test_daily_csv_keeps_existing_columns(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8")
    path = exporter.append_plc_data(_points("X31"), "10.0.0.1")
    exporter.append_plc_data(_points("X31"), "10.0.0.1", hex_addresses=True)   # switched on later
    header = open(path, encoding="utf-8").readline()
    assert "address_hex" not in header                        # same columns for the whole day


def test_periodic_writer_uses_daily_file(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8")
    exporter.periodic_csv = "daily"
    writer = plc_scanner._ResultWriter(PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), exporter, _Display())
    writer.daily = True
    paths = {writer.export_points(_points("D0")) for _ in range(3)}
    assert len(paths) == 1 and len(list(tmp_path.glob("plc_data_*.csv"))) == 1


# ---------------------------------------------------------------------------
# 3: EtherNet/IP Logix tags
# ---------------------------------------------------------------------------

class _Tag:
    def __init__(self, tag, value, error=None):
        self.tag, self.value, self.error = tag, value, error


def _logix(tags_info=None, reply=None):
    handler = EtherNetIPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0))
    client = MagicMock()
    client.tags = tags_info or {}
    client.read.side_effect = reply
    handler._client = client
    handler._connected = True
    handler._plc_type = "logix"
    return handler, client


def test_tag_values_become_data_points():
    replies = {
        "Speed": _Tag("Speed", 1500), "Temp": _Tag("Temp", 23.5), "Run": _Tag("Run", True),
        "Recipe[2]{3}": _Tag("Recipe", [7, 8, 9]), "Missing": _Tag("Missing", None, "Tag doesn't exist"),
        "Udt": _Tag("Udt", {"a": 1}), "Total": _Tag("Total", 100000),
    }
    handler, client = _logix(reply=lambda *tags: [replies[t] for t in tags])
    points = asyncio.run(handler.read_tags(list(replies)))
    by_address = {p.address: p for p in points}
    assert (by_address["Speed"].value, by_address["Speed"].raw_hex) == (1500, "0x05DC")
    assert by_address["Temp"].display_value == "23.5" and by_address["Temp"].data_type == "REAL"
    assert by_address["Run"].value == 1
    assert [by_address[f"Recipe[{i}]"].value for i in (2, 3, 4)] == [7, 8, 9]
    assert by_address["Missing"].status == StatusCode.NG_ILLEGAL_ADDR
    assert by_address["Udt.a"].value == 1           # structures are reported per member
    assert by_address["Total"].raw_hex == "0x000186A0"


def test_tags_on_non_logix_device_unsupported():
    handler, client = _logix()
    handler._plc_type = "slc"
    points = asyncio.run(handler.read_tags(["A", "B"]))
    assert [p.status for p in points] == [StatusCode.NG_UNSUPPORTED] * 2
    client.read.assert_not_called()


def test_tag_read_timeout_reconnects(monkeypatch):
    handler, client = _logix()

    async def slow(func, timeout=None):
        handler._needs_reconnect = True
        raise asyncio.TimeoutError()

    monkeypatch.setattr(handler, "_run_blocking", slow)
    points = asyncio.run(handler.read_tags(["A"]))
    assert points[0].status == StatusCode.NG_TIMEOUT and handler._needs_reconnect


def test_tag_scan_list_atomic_controller_tags():
    handler, _ = _logix(tags_info={
        "Speed": {"tag_type": "atomic", "dimensions": [0, 0, 0]},
        "Big": {"tag_type": "atomic", "dimensions": [5000, 0, 0]},
        "Arr": {"tag_type": "atomic", "dimensions": [10, 0, 0]},
        "Udt": {"tag_type": "struct", "dimensions": [0, 0, 0]},
        "Program:Main.Step": {"tag_type": "atomic", "dimensions": [0, 0, 0]},
        "Odd": {"tag_type": "other"},
    })
    assert handler.tag_scan_list() == ["Arr[0]{10}", f"Big[0]{{{MAX_TAG_ARRAY_ELEMENTS}}}",
                                       "Program:Main.Step", "Speed", "Udt"]


def test_nested_struct_values_flattened():
    from plc_discovery.protocols.ethernet_ip import _value_points
    value = [{"a": 1, "sub": {"b": 2.5}, "arr": [3, 4]}, {"a": 5, "sub": {"b": 0.5}, "arr": [6, 7]}]
    points = _value_points("U[1]{2}", value)
    assert [p.address for p in points] == [
        "U[1].a", "U[1].sub.b", "U[1].arr[0]", "U[1].arr[1]",
        "U[2].a", "U[2].sub.b", "U[2].arr[0]", "U[2].arr[1]"]
    assert points[1].display_value == "2.5" and points[7].value == 7


def test_generic_cip_tag_list_empty_and_full_scan_falls_back():
    handler, _ = _logix(tags_info={"Speed": {"tag_type": "atomic", "dimensions": []}})
    handler._plc_type = "generic"
    assert handler.supports_tags and handler.tag_scan_list() == []


def test_symbolic_read_decoding():
    from plc_discovery.protocols import cip_symbolic as cs
    assert cs.split_element_count("V[2]{5}") == ("V[2]", 5)
    assert cs.split_element_count(" V ") == ("V", 1)
    assert cs.decode_values("V", 0xC8, (123456).to_bytes(4, "little"), 1) == (123456, "UDINT")
    assert cs.decode_values("B{2}", 0xC1, b"\x01\x00\x00\x00", 2) == ([1, 0], "BOOL")  # Omron 2-byte BOOL
    with pytest.raises(cs.SymbolicReadError) as err:
        cs.decode_values("S", cs.STRUCTURE_TYPE, b"\x00" * 8, 1)
    assert err.value.status == StatusCode.NG_UNSUPPORTED
    with pytest.raises(cs.SymbolicReadError) as err:
        cs.decode_values("V{4}", 0xC3, b"\x00\x00", 4)
    assert err.value.status == StatusCode.NG_COMM_ERROR
    assert cs.status_for_cip_error(0x05) == StatusCode.NG_ILLEGAL_ADDR
    assert cs.status_for_cip_error(0x08) == StatusCode.NG_UNSUPPORTED
    assert cs.status_for_cip_error(0x01) == StatusCode.NG_COMM_ERROR


def test_full_scan_of_logix_reads_tags():
    handler, _ = _logix(tags_info={"Speed": {"tag_type": "atomic", "dimensions": []}},
                        reply=lambda *tags: [_Tag(t, 1) for t in tags])
    collector = PLCDataCollector(PLCInfo("10.0.0.1", protocol=Protocol.ETHERNET_IP, port=44818))
    collector._handler = handler
    points = asyncio.run(collector.collect_full_scan())
    assert [(p.address, p.status) for p in points] == [("Speed", StatusCode.OK)]


def test_tag_range_from_cli_and_config(monkeypatch, tmp_path):
    assert plc_scanner.parse_tag_list("A, B[0]{10},C.Member, ") == ["A", "B[0]{10}", "C.Member"]
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--tags", "Speed,Temp"])
    ranges = plc_scanner.resolve_device_ranges(plc_scanner.parse_args(), None)
    assert len(ranges) == 1 and isinstance(ranges[0], TagRange) and ranges[0].tags == ["Speed", "Temp"]
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--tags", "Speed", "--range", "0-9"])
    ranges = plc_scanner.resolve_device_ranges(plc_scanner.parse_args(), None)
    assert isinstance(ranges[0], TagRange) and isinstance(ranges[1], DeviceRange)
    path = tmp_path / "c.yaml"
    path.write_text("scan:\n  tags: [Speed, 'Recipe[0]{5}']\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.get_tags() == ["Speed", "Recipe[0]{5}"] and loader.validate() == []


def test_collect_item_dispatch():
    collector = MagicMock()

    async def tags(t):
        return ["tags"]

    async def rng(*a):
        return ["range"]

    collector.collect_tags = tags
    collector.collect_range = rng
    assert asyncio.run(collect_item(collector, TagRange(["A"]))) == ["tags"]
    assert asyncio.run(collect_item(collector, DeviceRange(DeviceType.D, 0, 1))) == ["range"]


# ---------------------------------------------------------------------------
# 8: simulator PCCC reads through pycomm3's SLCDriver
# ---------------------------------------------------------------------------

def test_simulator_serves_slc_data_files():
    pytest.importorskip("pycomm3")
    import threading
    from pycomm3 import SLCDriver
    from simulators.ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(
        lambda: EtherNetIPProtocol(EtherNetIPDevice([(100, 150)])), "127.0.0.1", 0))
    port = server.sockets[0].getsockname()[1]
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        with SLCDriver(f"127.0.0.1:{port}") as plc:
            assert plc.read("N7:2{3}").value == [20, 30, 40]
            assert plc.read("B3:5{2}").value == [5, 6]
            assert plc.read("N7:99{3}").error             # 100 is denied
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        server.close()
