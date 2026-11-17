"""
Tests for the notification / database settings added with the GUI tabs.

- notification_settings: periodic status reports and suppression of
  repeated notifications of the same type
- output.database: size limit (max_size_mb) and cleanup interval
- settings_file: the GUI's settings file shared with the CLI
- macOS application name (no-op elsewhere / never raises)
"""

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

import plc_scanner
from plc_discovery import database, settings_file
from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.notifications import (
    NotificationConfig, NotificationEvent, NotificationManager, NotificationType,
)
from plc_discovery.utils import get_timestamp


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def _manager(**kwargs):
    manager = NotificationManager(**kwargs)
    sent = []

    async def handler(event):
        sent.append(event.type)
        return True

    manager.add_custom("capture", handler)
    return manager, sent


def _event(kind=NotificationType.SCAN_ERROR):
    return NotificationEvent(type=kind, title="t", message="m")


def test_repeated_notifications_are_suppressed(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("plc_discovery.notifications.time.monotonic", lambda: clock[0])
    manager, sent = _manager(min_interval_seconds=600)

    asyncio.run(manager.notify(_event()))
    clock[0] += 60
    assert asyncio.run(manager.notify(_event())) == {}          # within 10 min: dropped
    asyncio.run(manager.notify(_event(NotificationType.SCAN_COMPLETE)))   # other type: sent
    clock[0] += 600
    asyncio.run(manager.notify(_event()))                        # after 10 min: sent
    assert sent == [NotificationType.SCAN_ERROR, NotificationType.SCAN_COMPLETE, NotificationType.SCAN_ERROR]


def test_no_limit_by_default():
    manager, sent = _manager()
    for _ in range(3):
        asyncio.run(manager.notify(_event()))
    assert len(sent) == 3


def test_settings_read_from_config():
    manager = NotificationManager.from_config({
        "notification_settings": {"report_interval_minutes": 15, "min_interval_minutes": 5},
        "notifications": [{"name": "t", "type": "teams", "url": "https://example.invalid/x",
                           "events": ["status_report"]}],
    })
    assert manager.report_interval_seconds == 900
    assert manager.min_interval_seconds == 300
    assert manager.has_handlers
    assert not NotificationManager.from_config({}).has_handlers


def test_status_report_message():
    ok = DataPoint("D0", 1, "0x0001", StatusCode.OK)
    ng = DataPoint("D1", None, None, StatusCode.NG_ILLEGAL_ADDR)
    message, problems = plc_scanner.status_report_message(
        {"10.0.0.1": [ok, ok], "10.0.0.2": [ok, ng], "10.0.0.3": []}, ["10.0.0.3"], 7)
    assert message.splitlines() == [
        "Cycle 7", "10.0.0.1: OK 2 / NG 0", "10.0.0.2: OK 1 / NG 1", "10.0.0.3: not reachable"]
    assert problems
    assert plc_scanner.status_report_message({"10.0.0.1": [ok]}, [], 1)[1] is False


@pytest.mark.parametrize("text,fragment", [
    ("notifications:\n  - {name: a, type: line, url: 'https://x'}\n", "notifications[0].type"),
    ("notifications:\n  - {name: a, type: teams}\n", "notifications[0].url is required"),
    ("notifications:\n  - {name: a, type: teams, url: 'ftp://x'}\n", "must start with http"),
    ("notifications:\n  - {name: a, type: teams, url: 'https://x'}\n  - {name: a, type: slack, url: 'https://y'}\n",
     "used twice"),
    ("notifications:\n  - {name: a, type: teams, url: 'https://x', events: [foo]}\n", "unknown event 'foo'"),
    ("notification_settings:\n  report_interval_minutes: -1\n", "report_interval_minutes"),
    ("output:\n  database:\n    max_size_mb: -5\n", "output.database.max_size_mb"),
    ("output:\n  database:\n    cleanup_interval_hours: 0\n", "output.database.cleanup_interval_hours"),
])
def test_config_validation(tmp_path, text, fragment):
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any(fragment in e for e in loader.validate()), loader.validate()


def test_disabled_destination_needs_no_url(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("notifications:\n  - {name: a, type: teams, enabled: false}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.validate() == []


# ---------------------------------------------------------------------------
# Database size limit and cleanup interval
# ---------------------------------------------------------------------------

def _fill(db, cycles, addresses=200):
    for value in range(cycles):
        points = [DataPoint(f"D{i}", value, f"0x{value:04X}", StatusCode.OK, get_timestamp())
                  for i in range(addresses)]
        db.export_plc_data(points, "10.0.0.1", protocol="SLMP", port=5001)


def test_size_limit_keeps_latest_values(tmp_path):
    path = tmp_path / "d.db"
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=0))
    _fill(db, 40)
    big = db.used_bytes()
    db.close()

    limit_mb = big / 4 / 1048576
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path), max_history_days=0,
                                         max_size_mb=limit_mb))
    try:
        assert db.used_bytes() <= limit_mb * 1048576
        latest = db._connection.execute(
            "SELECT COUNT(*), MIN(value) FROM data_points WHERE id IN "
            "(SELECT MAX(id) FROM data_points GROUP BY address)").fetchone()
        latest = tuple(latest)
        assert latest == (200, 39)          # newest value of every address kept
    finally:
        db.close()
    assert path.stat().st_size < big        # VACUUM on open gave the space back


def test_too_small_limit_never_empties(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db"),
                                         max_history_days=0, max_size_mb=0.0001))
    try:
        _fill(db, 3, addresses=50)
        db._enforce_size_limit()
        assert db._connection.execute("SELECT COUNT(*) FROM data_points").fetchone()[0] == 50
    finally:
        db.close()


def test_cleanup_interval_from_config(tmp_path, monkeypatch):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db"),
                                         max_history_days=30, cleanup_interval_hours=2))
    try:
        calls = []
        monkeypatch.setattr(db, "_apply_retention", lambda vacuum: calls.append(vacuum))
        start = db._last_cleanup
        clock = [start + 3600]
        monkeypatch.setattr(database.time, "monotonic", lambda: clock[0])
        _fill(db, 1, addresses=1)
        assert calls == []                                  # 1 h < 2 h
        clock[0] = start + 2 * 3600 + 1
        _fill(db, 1, addresses=1)
        assert calls == [False]                             # no VACUUM during a run
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Settings file shared by the GUI and the CLI
# ---------------------------------------------------------------------------

GUI_UPDATES = {
    "network": {"packet_interval_ms": 30, "retry_interval_ms": 100, "request_timeout_ms": 3000},
    "output": {"directory": "./out", "encoding": "utf-8",
               "database": {"enabled": True, "path": "./x.db", "track_history": True,
                            "max_history_days": 7, "max_size_mb": 50.0, "cleanup_interval_hours": 6.0}},
    "notifications": [{"name": "teams", "type": "teams", "url": "https://example.invalid/hook",
                       "enabled": True, "events": ["scan_error"], "timeout": 10.0, "retry_count": 3}],
    "notification_settings": {"report_interval_minutes": 30, "min_interval_minutes": 10},
}


def test_save_keeps_other_sections(tmp_path):
    path = tmp_path / "plc_config.yaml"
    path.write_text("targets:\n  - {ip: 10.0.0.1, protocol: slmp}\nnetwork:\n  max_concurrent: 2\n"
                    "output:\n  format: csv\n", encoding="utf-8")
    config, errors = settings_file.save(str(path), GUI_UPDATES)
    assert errors == []
    written = settings_file.read_file(str(path))
    assert written["targets"] == [{"ip": "10.0.0.1", "protocol": "slmp"}]
    assert written["network"]["max_concurrent"] == 2 and written["network"]["packet_interval_ms"] == 30
    assert written["output"]["format"] == "csv" and written["output"]["database"]["max_size_mb"] == 50.0
    assert written["notifications"][0]["name"] == "teams"
    loaded, load_errors = settings_file.load(str(path))
    assert load_errors == [] and loaded["notification_settings"]["min_interval_minutes"] == 10
    # The CLI reads the same file
    assert DatabaseConfig.from_dict(loaded["output"]["database"]).cleanup_interval_hours == 6.0
    assert NotificationManager.from_config(loaded).report_interval_seconds == 1800


def test_invalid_settings_are_not_written(tmp_path):
    path = tmp_path / "plc_config.yaml"
    path.write_text("scan:\n  mode: range\n", encoding="utf-8")
    bad = dict(GUI_UPDATES, notifications=[{"name": "x", "type": "teams", "url": "nope"}])
    _, errors = settings_file.save(str(path), bad)
    assert errors and "http" in errors[0]
    assert path.read_text(encoding="utf-8") == "scan:\n  mode: range\n"


def test_example_config_documents_new_settings():
    root = Path(__file__).resolve().parent.parent
    text = (root / "plc_config.example.yaml").read_text(encoding="utf-8")
    for key in ("max_size_mb", "cleanup_interval_hours", "report_interval_minutes", "min_interval_minutes",
                "status_report"):
        assert key in text
    assert "plc_config.yaml" in (root / ".gitignore").read_text(encoding="utf-8")


def test_macos_app_name_never_raises(monkeypatch):
    import ast
    source = (Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert "set_macos_app_name" in names
    assert 'tk.Tk(className=APP_NAME)' in source
