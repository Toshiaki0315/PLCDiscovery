"""
Regression tests for the eighteenth review.

1: A range that fails with NG_ILLEGAL_ADDR and whose two end addresses are
   invalid on their own is reported as a whole instead of being split
   down to single addresses (~2N requests).
2: A user-specified address range is limited to MAX_RANGE_POINTS.
"""


import pytest

import plc_scanner
from plc_discovery.config import (
    MAX_RANGE_POINTS, DeviceRange, DeviceType, NetworkConfig, StatusCode, range_size_error,
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.slmp import SLMPHandler


async def _scan(end, valid):
    """Read D0-end from a fake PLC where valid(address) tells readability"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    requests = []

    async def fake_read(device_type, start, count):
        requests.append((start, count))
        if all(valid(a) for a in range(start, start + count)):
            return [a & 0xFFFF for a in range(start, start + count)], StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, end))
    return handler, points, requests


def _misreported(points, valid):
    return [p.address for i, p in enumerate(points) if (p.status == StatusCode.OK) != valid(i)]


@pytest.mark.asyncio
async def test_wholly_invalid_device_costs_few_requests():
    handler, points, requests = await _scan(32767, lambda a: False)
    assert len(points) == 32768
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points)
    # 37 chunks x (chunk read + 2 edge probes); was ~65,000 requests
    assert len(requests) <= 3 * 37
    assert len(handler.get_denied_addresses()) == 32768


@pytest.mark.asyncio
@pytest.mark.parametrize("end,valid,max_requests", [
    (8191, lambda a: a <= 7999, 60),                                        # past device end
    (9999, lambda a: not (5000 <= a <= 5100 or 7000 <= a <= 7050), 160),   # gaps
    (9999, lambda a: a != 4321, 60),                                        # one bad word
])
async def test_mixed_ranges_still_exact(end, valid, max_requests):
    _, points, requests = await _scan(end, valid)
    assert _misreported(points, valid) == []
    assert len(requests) <= max_requests


@pytest.mark.asyncio
async def test_small_ranges_are_split_without_probes():
    """Below EDGE_PROBE_MIN_COUNT the range is split as before"""
    _, points, requests = await _scan(2, lambda a: a == 1)
    assert [p.status for p in points] == [
        StatusCode.NG_ILLEGAL_ADDR, StatusCode.OK, StatusCode.NG_ILLEGAL_ADDR
    ]
    assert all(count != 1 or start in (0, 1, 2) for start, count in requests)


@pytest.mark.asyncio
async def test_transient_probe_failure_falls_back_to_splitting():
    """A timeout on an edge probe is not taken as proof of an invalid range"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    calls = []

    async def fake_read(device_type, start, count):
        calls.append((start, count))
        if (start, count) == (0, 1) and calls.count((0, 1)) == 1:
            return None, StatusCode.NG_TIMEOUT
        if start + count - 1 <= 3:
            return [0] * count, StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler._binary_search_read(
        DeviceType.D, 0, 7, known_failure=StatusCode.NG_ILLEGAL_ADDR
    )
    assert [p.status for p in points] == [StatusCode.OK] * 4 + [StatusCode.NG_ILLEGAL_ADDR] * 4


# ---------------------------------------------------------------------------
# 2: range size limit
# ---------------------------------------------------------------------------

def test_range_size_error():
    assert range_size_error(0, MAX_RANGE_POINTS - 1) is None
    assert "at most" in range_size_error(0, MAX_RANGE_POINTS)


def test_cli_rejects_huge_range():
    assert plc_scanner.parse_address_range(f"0-{MAX_RANGE_POINTS - 1}") == (0, MAX_RANGE_POINTS - 1)
    with pytest.raises(ValueError, match="at most"):
        plc_scanner.parse_address_range("0-16000000")


def test_config_rejects_huge_range(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text("scan:\n  device_ranges:\n    - {device: D, start: 0, end: 16000000}\n",
                    encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("scan.device_ranges[0]" in e and "at most" in e for e in loader.validate())


def test_gui_checks_range_size():
    source = (plc_scanner.Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "MAX_RANGE_POINTS" in source and "end - start + 1 > MAX_RANGE_POINTS" in source


# ---------------------------------------------------------------------------
# Third pass: handlers expose no PLC access outside the safe read path
# ---------------------------------------------------------------------------

import inspect
from pathlib import Path

from plc_discovery.collector import PROTOCOL_HANDLERS
from plc_discovery.protocols.base import BaseProtocolHandler

# Public coroutines a handler may offer: every PLC read goes through
# read_device_range / read_device_raw (rate limiting, address limits,
# reconnect after a timeout, binary search)
ALLOWED_PUBLIC_COROUTINES = {"connect", "disconnect", "read_device_raw", "read_device_range"}


@pytest.mark.parametrize("handler_class", sorted(
    {getattr(h, "func", h) for h in PROTOCOL_HANDLERS.values()}, key=lambda c: c.__name__
))
def test_handlers_have_no_side_door_reads(handler_class):
    public = {
        name for name, member in inspect.getmembers(handler_class, inspect.iscoroutinefunction)
        if not name.startswith("_")
    }
    assert public <= ALLOWED_PUBLIC_COROUTINES, public - ALLOWED_PUBLIC_COROUTINES
    assert issubclass(handler_class, BaseProtocolHandler)


# ---------------------------------------------------------------------------
# Fourth pass: targets sharing an IP stay apart in CSV and the database
# ---------------------------------------------------------------------------

import sqlite3

from plc_discovery.config import DataPoint, PLCInfo, Protocol
from plc_discovery.database import SCHEMA_VERSION, DatabaseConfig, DatabaseExporter
from plc_discovery.output import CSVExporter


class _Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


def _points(values):
    return [DataPoint(address=f"D{i}", value=v, status=StatusCode.OK) for i, v in enumerate(values)]


def test_shared_ip_targets_have_separate_history(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "t.db")))
    try:
        for _ in range(2):   # two cycles, values unchanged per target
            db.export_plc_data(_points([0, 10]), "127.0.0.1", protocol="SLMP", port=5001)
            db.export_plc_data(_points([182, 197]), "127.0.0.1", protocol="FINS", port=9600)
        assert db.get_changes(days=1) == []   # was a "change" per address and target
        db.export_plc_data(_points([1, 10]), "127.0.0.1", protocol="SLMP", port=5001)
        changes = db.get_changes(days=1)
        assert [(c["protocol"], c["port"], c["address"], c["old_value"], c["new_value"]) for c in changes] \
            == [("SLMP", 5001, "D0", 0, 1)]
        latest = db.get_latest_data("127.0.0.1")
        assert {(r["protocol"], r["address"]): r["value"] for r in latest} == {
            ("FINS", "D0"): 182, ("FINS", "D1"): 197, ("SLMP", "D0"): 1, ("SLMP", "D1"): 10,
        }
    finally:
        db.close()


def test_v2_database_gets_target_columns(tmp_path):
    path = tmp_path / "v2.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE schema_info (version INTEGER PRIMARY KEY, created_at TEXT NOT NULL);
        INSERT INTO schema_info VALUES (2, '2026-01-01');
        CREATE TABLE data_points (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
            plc_ip TEXT NOT NULL, address TEXT NOT NULL, value INTEGER, raw_hex TEXT,
            data_type TEXT, converted_value TEXT, display_value TEXT, status TEXT NOT NULL,
            timestamp TEXT NOT NULL);
        INSERT INTO data_points (plc_ip, address, value, status, timestamp)
            VALUES ('10.0.0.1', 'D0', 5, 'OK', '2026-01-01 00:00:00');
        CREATE TABLE denied_addresses (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
            plc_ip TEXT NOT NULL, address TEXT NOT NULL, status TEXT NOT NULL, timestamp TEXT NOT NULL);
        CREATE TABLE data_history (id INTEGER PRIMARY KEY AUTOINCREMENT, plc_ip TEXT NOT NULL,
            address TEXT NOT NULL, old_value INTEGER, new_value INTEGER, changed_at TEXT NOT NULL);
    """)
    conn.commit()
    conn.close()
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path)))
    try:
        for table in ("data_points", "denied_addresses", "data_history"):
            columns = {r[1] for r in db._connection.execute(f"PRAGMA table_info({table})")}
            assert {"protocol", "port"} <= columns
        assert db._connection.execute("SELECT MAX(version) FROM schema_info").fetchone()[0] == SCHEMA_VERSION
        # Old rows are kept; they have no target and never pair with new rows
        db.export_plc_data(_points([9]), "10.0.0.1", protocol="SLMP", port=5001)
        assert db.get_changes(days=3650) == []
        assert db._connection.execute("SELECT COUNT(*) FROM data_points").fetchone()[0] == 2
    finally:
        db.close()
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path))).close()   # reopen: no-op


def test_writer_names_shared_ip_outputs(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8")
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "t.db")))
    try:
        slmp = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001)
        fins = PLCInfo("127.0.0.1", protocol=Protocol.FINS, port=9600)
        alone = PLCInfo("10.0.0.5", protocol=Protocol.SLMP, port=5001)
        labels = dict(zip(("slmp", "fins", "alone"), plc_scanner.target_labels([slmp, fins, alone])))
        paths = {}
        for key, plc in (("slmp", slmp), ("fins", fins), ("alone", alone)):
            writer = plc_scanner._ResultWriter(plc, exporter, _Display(), db, label=labels[key])
            paths[key] = Path(writer.export_points(_points([1])))
            writer.export_new_denied({"D9"}, {"D9": StatusCode.NG_ILLEGAL_ADDR})
        assert paths["slmp"].name.startswith("plc_data_127_0_0_1_SLMP_5001_")
        assert paths["fins"].name.startswith("plc_data_127_0_0_1_FINS_9600_")
        assert paths["alone"].name.startswith("plc_data_10_0_0_5_2")   # unchanged naming
        log = (tmp_path / "access_denied_log.csv").read_text(encoding="utf-8")
        assert "127.0.0.1 (SLMP:5001)" in log and "127.0.0.1 (FINS:9600)" in log
        assert ",10.0.0.5\n" in log.replace("\r\n", "\n")
        rows = db._connection.execute(
            "SELECT plc_ip, protocol, port FROM denied_addresses ORDER BY id").fetchall()
        assert [tuple(r) for r in rows] == [
            ("127.0.0.1", "SLMP", 5001), ("127.0.0.1", "FINS", 9600), ("10.0.0.5", "SLMP", 5001)]
    finally:
        db.close()


def test_shell_setup_script_matches_schema_version():
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_database.sh").read_text(encoding="utf-8")
    assert f"VALUES ({SCHEMA_VERSION}," in text
    assert "UNIQUE(ip_address)" not in text
    assert text.count("    protocol TEXT,\n    port INTEGER,") >= 3
