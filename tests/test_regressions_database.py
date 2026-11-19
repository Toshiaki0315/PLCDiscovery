"""
Regression tests for database output, found and fixed in code reviews.
"""

import math
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

import plc_scanner
from plc_discovery import database
from plc_discovery.config import DataPoint, PLCInfo, Protocol, StatusCode
from plc_discovery.database import SCHEMA_VERSION, DatabaseConfig, DatabaseExporter
from plc_discovery.output import CSVExporter
from plc_discovery.scan_runner import ResultWriter
from plc_discovery.utils import get_timestamp

V1_PLCS = """
CREATE TABLE schema_info (version INTEGER PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE plcs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT, manufacturer TEXT, model TEXT, protocol TEXT, port INTEGER,
    cpu_type TEXT, firmware_version TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(ip_address)
);
CREATE INDEX idx_plcs_ip ON plcs(ip_address);
INSERT INTO schema_info VALUES (1, '2026-01-01');
INSERT INTO plcs (ip_address, manufacturer, protocol, port, first_seen, last_seen)
    VALUES ('10.0.0.1', 'Mitsubishi', 'SLMP', 5001, '2026-01-01', '2026-01-01');
"""


def rows(db):
    return sorted((p["ip_address"], p["protocol"], p["port"], p["model"]) for p in db.get_plcs())


ROOT = Path(__file__).resolve().parent.parent


class _Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


def _points(values):
    return [DataPoint(address=f"D{i}", value=v, status=StatusCode.OK) for i, v in enumerate(values)]


def _point(value):
    return [
        DataPoint(address="D0", value=value, raw_hex=f"0x{value:04X}", status=StatusCode.OK, timestamp=get_timestamp())
    ]


def _old_database(path, rows=3):
    """Database with `rows` exports of D0, all dated 2000-01-01"""
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=0, track_history=False))
    for value in range(rows):
        db.export_plc_data(_point(value), "10.0.0.1", protocol="SLMP", port=5001)
    db._connection.execute("UPDATE data_points SET timestamp = '2000-01-01 00:00:00'")
    db._connection.execute(
        "INSERT INTO data_history (plc_ip, address, old_value, new_value, changed_at) "
        "VALUES ('10.0.0.1', 'D0', 0, 1, '2000-01-01T00:00:00')"
    )
    db._connection.commit()
    db.close()


def _count(path, table):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def points(value):
    return [DataPoint("D0", value, f"0x{value:04X}", StatusCode.OK, "2026-01-01 00:00:00.000")]


def test_database_keeps_each_protocol_of_one_ip(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    plcs = [
        PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001),
        PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502),
    ]
    assert db.export_discovery_results(plcs) == 2
    assert db.export_discovery_results(plcs) == 2  # second run updates, no duplicates
    assert rows(db) == [("127.0.0.1", "MODBUS_TCP", 1502, None), ("127.0.0.1", "SLMP", 5001, None)]


def test_database_rows_without_protocol_are_not_duplicated(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    db.export_discovery_results([PLCInfo("10.0.0.9")])
    db.export_discovery_results([PLCInfo("10.0.0.9", model="X")])
    assert rows(db) == [("10.0.0.9", None, None, "X")]


def test_v1_database_is_migrated(tmp_path):
    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    conn.executescript(V1_PLCS)
    conn.close()

    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path)))
    db.export_discovery_results(
        [
            PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, model="Q03UDE"),
            PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP, port=502),
        ]
    )
    assert rows(db) == [("10.0.0.1", "MODBUS_TCP", 502, None), ("10.0.0.1", "SLMP", 5001, "Q03UDE")]
    old = [p for p in db.get_plcs() if p["protocol"] == "SLMP"][0]
    assert old["manufacturer"] == "Mitsubishi" and old["first_seen"] == "2026-01-01"  # existing data kept
    assert (
        db._connection.execute("SELECT MAX(version) FROM schema_info").fetchone()[0] == SCHEMA_VERSION
    )  # migrated to the current version
    db.close()
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path))).close()  # reopening is a no-op


def test_setup_script_uses_scanner_schema():
    from plc_discovery import database
    from scripts import setup_database

    assert setup_database.CREATE_TABLES_SQL is database.CREATE_TABLES_SQL


def test_cleanup_old_data_vacuums(tmp_path):
    from plc_discovery.database import DatabaseConfig, DatabaseExporter

    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    db.export_plc_data([DataPoint("D0", 1, "0x0001", StatusCode.OK)], "10.0.0.1")
    db._connection.execute("UPDATE data_points SET timestamp = '2000-01-01T00:00:00'")
    db.export_plc_data([DataPoint("D0", 2, "0x0002", StatusCode.OK)], "10.0.0.1")
    db._connection.commit()
    db.cleanup_old_data(30)  # previously OperationalError: cannot VACUUM from within a transaction
    rows = db._connection.execute("SELECT value FROM data_points").fetchall()
    assert [r[0] for r in rows] == [2]
    db.close()


def test_cleanup_window_uses_local_time(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "t.db")))
    try:
        conn = db._connection
        now = datetime.now()
        # One row just inside a 1-day window, one just outside (local time)
        for minutes, address in ((-(24 * 60 - 30), "D1"), (-(24 * 60 + 30), "D2")):
            stamp = (now + timedelta(minutes=minutes)).isoformat()
            conn.execute(
                "INSERT INTO data_history (plc_ip, address, old_value, new_value, changed_at) "
                "VALUES (?, ?, 0, 1, ?)",
                ("10.0.0.1", address, stamp),
            )
        conn.commit()
        assert [r["address"] for r in db.get_changes(days=1)] == ["D1"]
        db._cleanup_old_data(days=1)
        rows = conn.execute("SELECT address FROM data_history").fetchall()
        assert [r[0] for r in rows] == ["D1"]
    finally:
        db.close()


def test_no_utc_comparison_left():
    for path in ("plc_discovery/database.py", "scripts/manage_database.sh"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "datetime('now', ?)" not in text
        assert "datetime('now', '-" not in text


@pytest.mark.skipif(
    subprocess.run(["which", "sqlite3"], capture_output=True).returncode != 0, reason="sqlite3 command not available"
)
@pytest.mark.parametrize("days", ["abc", "1'); DELETE FROM plcs; --", "0", ""])
def test_cleanup_script_rejects_bad_days(tmp_path, days):
    db_path = tmp_path / "t.db"
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(db_path))).close()
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "manage_database.sh"), "cleanup", str(db_path), days],
        capture_output=True,
        text=True,
    )
    if days == "":
        # Empty argument falls back to the default 30 days
        assert result.returncode == 0
    else:
        assert result.returncode == 1
        assert "positive integer" in result.stdout


def test_shared_ip_targets_have_separate_history(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "t.db")))
    try:
        for _ in range(2):  # two cycles, values unchanged per target
            db.export_plc_data(_points([0, 10]), "127.0.0.1", protocol="SLMP", port=5001)
            db.export_plc_data(_points([182, 197]), "127.0.0.1", protocol="FINS", port=9600)
        assert db.get_changes(days=1) == []  # was a "change" per address and target
        db.export_plc_data(_points([1, 10]), "127.0.0.1", protocol="SLMP", port=5001)
        changes = db.get_changes(days=1)
        assert [(c["protocol"], c["port"], c["address"], c["old_value"], c["new_value"]) for c in changes] == [
            ("SLMP", 5001, "D0", 0, 1)
        ]
        latest = db.get_latest_data("127.0.0.1")
        assert {(r["protocol"], r["address"]): r["value"] for r in latest} == {
            ("FINS", "D0"): 182,
            ("FINS", "D1"): 197,
            ("SLMP", "D0"): 1,
            ("SLMP", "D1"): 10,
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
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path))).close()  # reopen: no-op


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
            writer = ResultWriter(plc, exporter, _Display(), db, label=labels[key])
            paths[key] = Path(writer.export_points(_points([1])))
            writer.export_new_denied({"D9"}, {"D9": StatusCode.NG_ILLEGAL_ADDR})
        assert paths["slmp"].name.startswith("plc_data_127_0_0_1_SLMP_5001_")
        assert paths["fins"].name.startswith("plc_data_127_0_0_1_FINS_9600_")
        assert paths["alone"].name.startswith("plc_data_10_0_0_5_2")  # unchanged naming
        log = (tmp_path / "access_denied_log.csv").read_text(encoding="utf-8")
        assert "127.0.0.1 (SLMP:5001)" in log and "127.0.0.1 (FINS:9600)" in log
        assert ",10.0.0.5\n" in log.replace("\r\n", "\n")
        rows = db._connection.execute("SELECT plc_ip, protocol, port FROM denied_addresses ORDER BY id").fetchall()
        assert [tuple(r) for r in rows] == [
            ("127.0.0.1", "SLMP", 5001),
            ("127.0.0.1", "FINS", 9600),
            ("10.0.0.5", "SLMP", 5001),
        ]
    finally:
        db.close()


def test_shell_setup_script_matches_schema_version():
    text = (Path(__file__).resolve().parent.parent / "scripts" / "setup_database.sh").read_text(encoding="utf-8")
    assert f"VALUES ({SCHEMA_VERSION}," in text
    assert "UNIQUE(ip_address)" not in text
    assert text.count("    protocol TEXT,\n    port INTEGER,") >= 3


def test_retention_applied_when_opened(tmp_path):
    path = tmp_path / "d.db"
    _old_database(path)
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=30)).close()
    assert _count(path, "data_points") == 1  # latest value per address kept
    assert _count(path, "data_history") == 0


def test_zero_days_keeps_everything(tmp_path):
    path = tmp_path / "d.db"
    _old_database(path)
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=0)).close()
    assert _count(path, "data_points") == 3
    assert _count(path, "data_history") == 1


def test_retention_applied_daily_during_long_runs(tmp_path, monkeypatch):
    path = tmp_path / "d.db"
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=30))
    try:
        for value in range(3):
            db.export_plc_data(_point(value), "10.0.0.1", protocol="SLMP", port=5001)
        db._connection.execute("UPDATE data_points SET timestamp = '2000-01-01 00:00:00'")
        db._connection.commit()
        db.export_plc_data(_point(9), "10.0.0.1", protocol="SLMP", port=5001)
        assert _count(path, "data_points") == 4  # not yet a day
        # +1 s: (t + interval) - t can round to just below interval
        clock = [db._last_cleanup + database.CLEANUP_INTERVAL_SECONDS + 1]
        monkeypatch.setattr(database.time, "monotonic", lambda: clock[0])
        db.export_plc_data(_point(10), "10.0.0.1", protocol="SLMP", port=5001)
        assert _count(path, "data_points") == 2  # old rows gone, newest kept
    finally:
        db.close()


class TestDatabase:

    def test_latest_values_loaded_once_and_history_kept(self, tmp_path):
        db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db"), track_history=True))
        with patch.object(db, "_get_latest_values", wraps=db._get_latest_values) as spy:
            db.export_plc_data(points(1), "10.0.0.1")
            db.export_plc_data(points(2), "10.0.0.1")
            db.export_plc_data(points(3), "10.0.0.1")
        assert spy.call_count == 1
        rows = db._connection.execute("SELECT old_value, new_value FROM data_history ORDER BY id").fetchall()
        assert [tuple(r) for r in rows] == [(1, 2), (2, 3)]
        db.close()

    def test_composite_index_exists(self, tmp_path):
        db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db")))
        names = {r[0] for r in db._connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_data_points_plc_addr_id" in names
        db.close()

    def test_cli_records_scan_session(self, tmp_path, monkeypatch):
        db_path = tmp_path / "scan.db"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "plc_scanner.py",
                "--mode",
                "range",
                "--protocol",
                "modbus",
                "--target",
                "127.0.0.1",
                "--port",
                "59997",
                "--range",
                "0-1",
                "--request-timeout",
                "300",
                "-q",
                "--database",
                str(db_path),
                "--output-dir",
                str(tmp_path),
            ],
        )
        with pytest.raises(SystemExit):
            plc_scanner.cli()
        rows = sqlite3.connect(db_path).execute("SELECT mode, status FROM scan_sessions").fetchall()
        assert rows == [("range", "completed with errors")]


def test_database_stores_nan_as_null(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db")))
    db.export_plc_data([DataPoint("D0", 0xFFFF, "0xFFFF", StatusCode.OK, converted_value=math.inf)], "10.0.0.1")
    (stored,) = db._connection.execute("SELECT converted_value FROM data_points").fetchone()
    assert stored == "null"
    db.close()
