"""
Regression tests for the findings of the eighth code review.

- database: scan_sessions.plc_count counted targets sharing an IP as one
- simulators/run_all.py: an unused FINS setting that differed from what the
  simulator denies, and a discovery hint that named too few simulators
"""

import asyncio
import logging

from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.database import DatabaseExporter
from plc_discovery.utils import get_timestamp
from simulators import run_all
from simulators.fins_simulator import INACCESSIBLE_RANGES


def _points(count):
    return [DataPoint(address=f"D{i}", value=i, status=StatusCode.OK, timestamp=get_timestamp()) for i in range(count)]


def test_session_counts_targets_sharing_an_ip_separately(tmp_path):
    db = DatabaseExporter.create(str(tmp_path / "plc.db"))
    try:
        db.begin_session("range")
        db.export_plc_data(_points(2), "10.0.0.1", protocol="SLMP", port=5001)
        db.export_plc_data(_points(2), "10.0.0.1", protocol="MODBUS_TCP/1", port=502)
        db.export_plc_data(_points(2), "10.0.0.1", protocol="MODBUS_TCP/unit_id2", port=502)
        db.export_plc_data(_points(2), "10.0.0.2", protocol="SLMP", port=5001)
        db.export_plc_data(_points(2), "10.0.0.3")  # protocol not detected
        db.export_plc_data(_points(2), "10.0.0.1", protocol="SLMP", port=5001)  # a second cycle
        db.end_session()
        session = db.get_scan_sessions()[0]
    finally:
        db.close()
    assert session["plc_count"] == 5  # was 3: one per IP
    assert (session["success_count"], session["error_count"]) == (12, 0)


def test_session_without_data_counts_no_plc(tmp_path):
    db = DatabaseExporter.create(str(tmp_path / "plc.db"))
    try:
        db.begin_session("discover")
        db.end_session()
        session = db.get_scan_sessions()[0]
    finally:
        db.close()
    assert (session["plc_count"], session["success_count"], session["error_count"]) == (0, 0, 0)


def test_launcher_has_no_fins_setting_it_does_not_use():
    manager = run_all.SimulatorManager()
    assert not hasattr(manager, "fins_denied")  # [(5000, 5100), (1000, 1050)]: never passed to the simulator
    # ... and what the launcher prints is what the simulator denies
    assert [(start, end) for _, start, end in INACCESSIBLE_RANGES] == [(5000, 5100), (300, 350)]


def _printed_hint(host, monkeypatch, caplog):
    async def no_server(*args, **kwargs):
        raise OSError("not started in this test")

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_server", no_server)
        monkeypatch.setattr(loop, "create_datagram_endpoint", no_server)
        await run_all.SimulatorManager(host).start_all()

    with caplog.at_level(logging.INFO, logger="PLC-Simulator-Launcher"):
        asyncio.run(run())
    return next(r.getMessage() for r in caplog.records if "# Discover" in r.getMessage())


def test_launcher_says_which_simulators_discovery_finds(monkeypatch, caplog):
    # Simulator ports (1502, 1102, ...) are probed on loopback addresses only
    assert "finds every simulator" in _printed_hint("0.0.0.0", monkeypatch, caplog)
    caplog.clear()
    assert "standard ports" in _printed_hint("192.168.1.5", monkeypatch, caplog)
