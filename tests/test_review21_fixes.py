"""
Regression tests for the twenty-first review.

1: max_history_days is applied automatically (when the database is
   opened and once a day during long runs); 0 keeps everything.
2: A target whose protocol cannot be detected is reported as failed
   instead of being scanned as SLMP.
"""

import asyncio
import sqlite3
import sys
from unittest.mock import AsyncMock, patch

import pytest

import plc_scanner
from plc_discovery import database
from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.utils import get_timestamp


def _point(value):
    return [DataPoint(address="D0", value=value, raw_hex=f"0x{value:04X}", status=StatusCode.OK,
                      timestamp=get_timestamp())]


def _old_database(path, rows=3):
    """Database with `rows` exports of D0, all dated 2000-01-01"""
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=0,
                                         track_history=False))
    for value in range(rows):
        db.export_plc_data(_point(value), "10.0.0.1", protocol="SLMP", port=5001)
    db._connection.execute("UPDATE data_points SET timestamp = '2000-01-01 00:00:00'")
    db._connection.execute(
        "INSERT INTO data_history (plc_ip, address, old_value, new_value, changed_at) "
        "VALUES ('10.0.0.1', 'D0', 0, 1, '2000-01-01T00:00:00')")
    db._connection.commit()
    db.close()


def _count(path, table):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_retention_applied_when_opened(tmp_path):
    path = tmp_path / "d.db"
    _old_database(path)
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=30)).close()
    assert _count(path, "data_points") == 1      # latest value per address kept
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
        assert _count(path, "data_points") == 4             # not yet a day
        clock = [db._last_cleanup + database.CLEANUP_INTERVAL_SECONDS]
        monkeypatch.setattr(database.time, "monotonic", lambda: clock[0])
        db.export_plc_data(_point(10), "10.0.0.1", protocol="SLMP", port=5001)
        assert _count(path, "data_points") == 2             # old rows gone, newest kept
    finally:
        db.close()


def test_config_validates_max_history_days(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("output:\n  database:\n    max_history_days: -1\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("output.database.max_history_days" in e for e in loader.validate())


@pytest.fixture
def restore_logging():
    import logging
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def test_undetected_target_is_failed_not_slmp(monkeypatch, tmp_path, capsys, restore_logging):
    scanned = []

    async def fake_single_scan(plc_info, *args, **kwargs):
        scanned.append(plc_info)
        return plc_scanner.ScanOutcome(plc_info.ip_address, success=True)

    monkeypatch.setattr(plc_scanner, "run_single_scan", fake_single_scan)
    monkeypatch.setattr(sys, "argv", [
        "plc_scanner.py", "--mode", "range", "--target", "10.0.0.9", "--device", "D",
        "--range", "0-1", "--no-rich", "-o", str(tmp_path),
    ])
    with patch("plc_discovery.discovery.PLCDiscovery._probe_host", AsyncMock(return_value=None)), \
            pytest.raises(SystemExit) as exc:
        asyncio.run(plc_scanner.main())
    assert exc.value.code == 1
    assert scanned == []                       # was scanned as SLMP
    out = capsys.readouterr().out
    assert "no PLC protocol answered" in out
    assert "SLMP" not in out
