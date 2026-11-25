"""
Regression tests for the findings of the ninth code review.

- scripts/check.bat ran the checks a second time (with "python") whenever
  the run with "py" failed: "where py && (py ...) || (python ...)".
- A periodic scan stopped while it waited for the next cycle saved the rest
  of a cycle that had failed (CLI and GUI): only a read that is under way
  is saved.
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import plc_gui
import plc_scanner
from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol
from plc_discovery.data_types import ByteOrder
from plc_discovery.output import CSVExporter
from plc_discovery.scan_runner import CycleResult, CycleRunner
from simulators.control import SimulatorController

ROOT = Path(__file__).resolve().parent.parent


def test_check_bat_does_not_run_the_checks_again_after_a_failure():
    lines = (ROOT / "scripts" / "check.bat").read_text(encoding="utf-8").splitlines()
    commands = [line for line in lines if "check.py" in line and not line.lower().startswith("rem")]
    assert len(commands) == 3  # .venv, py, python: one each
    for line in commands:
        # "a && (run) || (run)" runs the second one when the first run fails
        assert "||" not in line and "&&" not in line
    # Each run is followed by the exit with its result
    for i, line in enumerate(lines):
        if line in commands:
            assert lines[i + 1].strip().lower() == "exit /b %errorlevel%"


def _spy_save_partial(monkeypatch):
    saved = []
    original = CycleRunner.save_partial

    def save_partial(self, collector, writer):
        saved.append(collector)
        return original(self, collector, writer)

    monkeypatch.setattr(CycleRunner, "save_partial", save_partial)
    return saved


def _run_cli_periodic(tmp_path, monkeypatch, read, stop_after):
    monkeypatch.setattr(CycleRunner, "read", read)
    saved = _spy_save_partial(monkeypatch)
    controller = SimulatorController()
    try:
        port = controller.start("slmp", "127.0.0.1", 0)

        async def run():
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)],
                    NetworkConfig(packet_interval_ms=0, retry_interval_ms=0),
                    CSVExporter(str(tmp_path)),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 0, 9)],
                    interval=60,
                )
            )
            await asyncio.sleep(stop_after)
            task.cancel()
            return await task

        (outcome,) = asyncio.run(run())
    finally:
        controller.shutdown()
    return outcome, saved


def test_cli_stop_while_waiting_after_a_failed_cycle_saves_nothing(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        raise RuntimeError("unexpected")

    outcome, saved = _run_cli_periodic(tmp_path, monkeypatch, read, 0.3)
    assert outcome.interrupted
    assert saved == []
    assert list(tmp_path.glob("plc_data_*.csv")) == []


def test_cli_stop_during_the_first_read_is_still_saved(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        await asyncio.sleep(30)

    outcome, saved = _run_cli_periodic(tmp_path, monkeypatch, read, 0.3)
    assert outcome.interrupted
    assert len(saved) == 1


class _FakeCollector:
    connect_error = None
    is_connected = True

    def __init__(self, plc_info, config):
        pass

    def set_progress_callback(self, callback):
        pass

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    def get_collected_data(self):
        return []

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 0, "success_count": 0, "success_rate": "0.00%"}


def _run_gui_periodic(tmp_path, monkeypatch, read):
    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector)
    monkeypatch.setattr(CycleRunner, "read", read)
    saved = _spy_save_partial(monkeypatch)
    app = MagicMock()
    app._post = lambda *item: None

    async def run():
        job = asyncio.ensure_future(
            plc_gui.PLCScannerApp._collect_job(
                app,
                NetworkConfig(),
                "127.0.0.1",
                Protocol.SLMP,
                5001,
                "range",
                DeviceType.D,
                0,
                0,
                60.0,
                None,
                ByteOrder.LITTLE_ENDIAN,
                CSVExporter(str(tmp_path), "utf-8-sig"),
            )
        )
        await asyncio.sleep(0.3)
        assert not job.done()
        job.cancel()
        with pytest.raises(asyncio.CancelledError):
            await job

    asyncio.run(run())
    return saved


def test_gui_stop_while_waiting_after_a_failed_first_cycle_saves_nothing(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        raise RuntimeError("unexpected")

    assert _run_gui_periodic(tmp_path, monkeypatch, read) == []


def test_gui_stop_during_the_first_read_is_still_saved(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        await asyncio.sleep(30)
        return CycleResult([], None, None)

    assert len(_run_gui_periodic(tmp_path, monkeypatch, read)) == 1
