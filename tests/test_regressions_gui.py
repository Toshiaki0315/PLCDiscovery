"""
Regression tests for GUI (plc_gui.py), found and fixed in code reviews.
"""

import asyncio
import sys
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, Protocol, StatusCode
from plc_discovery.output import CSVExporter


def _import_gui(monkeypatch):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "messagebox", "ttk"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
        monkeypatch.delitem(sys.modules, "plc_gui", raising=False)
    import plc_gui

    return plc_gui


class OfflineCollector:
    """Offline when connecting; answers from the second cycle"""

    instances = []

    def __init__(self, plc, config=None):
        self.cycles = 0
        self.disconnected = False
        self.connect_error = OfflineCollector.connect_error
        OfflineCollector.instances.append(self)

    def set_progress_callback(self, cb):
        pass

    async def connect(self):
        return False

    async def disconnect(self):
        self.disconnected = True

    def clear_data(self):
        pass

    @property
    def is_connected(self):
        # Like PLCDataCollector.is_connected: offline in cycle 1, then answering
        return self.cycles > 1

    async def collect_range(self, device_type, start, end):
        self.cycles += 1
        status = StatusCode.OK if self.cycles > 1 else StatusCode.NG_COMM_ERROR
        return [DataPoint("D0", 1 if status == StatusCode.OK else None, None, status)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {}


def _run_collect(plc_gui, monkeypatch, interval, connect_error=None):
    from plc_discovery.config import DeviceType, NetworkConfig, Protocol

    OfflineCollector.instances.clear()
    OfflineCollector.connect_error = connect_error
    monkeypatch.setattr(plc_gui, "PLCDataCollector", OfflineCollector)
    app = MagicMock()
    posted = []
    app._post = lambda *item: posted.append(item)

    async def run():
        job = asyncio.ensure_future(
            plc_gui.PLCScannerApp._collect_job(
                app,
                NetworkConfig(),
                "10.0.0.1",
                Protocol.SLMP,
                5001,
                "range",
                DeviceType.D,
                0,
                0,
                interval,
                None,
                None,
                MagicMock(),
            )
        )
        if interval:
            while not job.done() and (not OfflineCollector.instances or OfflineCollector.instances[0].cycles < 2):
                await asyncio.sleep(0.005)
            job.cancel()
        try:
            await job
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    return [item[1] for item in posted if item[0] == "data"]


class _GuiOfflineCollector:
    connect_error = None

    def __init__(self, plc, config=None):
        pass

    def set_progress_callback(self, cb):
        pass

    async def connect(self):
        return False

    async def disconnect(self):
        pass


def test_gui_periodic_monitoring_starts_while_plc_offline(monkeypatch):
    plc_gui = _import_gui(monkeypatch)
    cycles = _run_collect(plc_gui, monkeypatch, interval=0.01)
    assert [pts[0].status for pts in cycles[:2]] == [StatusCode.NG_COMM_ERROR, StatusCode.OK]  # previously aborted
    assert OfflineCollector.instances[0].disconnected


def test_gui_single_read_still_fails_when_offline(monkeypatch):
    plc_gui = _import_gui(monkeypatch)
    with pytest.raises(RuntimeError):
        _run_collect(plc_gui, monkeypatch, interval=0)


def test_gui_periodic_with_invalid_options_fails(monkeypatch):
    plc_gui = _import_gui(monkeypatch)
    with pytest.raises(RuntimeError):
        _run_collect(plc_gui, monkeypatch, interval=0.01, connect_error="invalid options")


def test_gui_collect_job_reads_tags(monkeypatch):
    """Range mode with the tag field filled in reads the tags instead of the device range"""
    from plc_discovery.config import DataPoint, DeviceType, NetworkConfig, Protocol

    plc_gui = _import_gui(monkeypatch)
    requested = []

    class TagCollector:
        connect_error = None
        is_connected = True

        def __init__(self, plc, config):
            pass

        def set_progress_callback(self, cb):
            pass

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        def clear_data(self):
            pass

        async def collect_tags(self, tags):
            requested.append(tags)
            return [DataPoint(address=t, status=StatusCode.OK, value=1) for t in tags]

        async def collect_range(self, *a):
            raise AssertionError("device range must not be read when tags are given")

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {}

    monkeypatch.setattr(plc_gui, "PLCDataCollector", TagCollector)
    app = MagicMock()
    posted = []
    app._post = lambda *item: posted.append(item)
    asyncio.run(
        plc_gui.PLCScannerApp._collect_job(
            app,
            NetworkConfig(),
            "10.0.0.1",
            Protocol.ETHERNET_IP,
            44818,
            "range",
            DeviceType.D,
            0,
            0,
            0,
            None,
            None,
            MagicMock(),
            tags=["Temp", "Motor.Speed"],
        )
    )
    assert requested == [["Temp", "Motor.Speed"]]
    assert [p.address for p in posted[-1][1]] == ["Temp", "Motor.Speed"]


def test_gui_checks_range_size():
    source = (plc_scanner.Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "MAX_RANGE_POINTS" in source and "end - start + 1 > MAX_RANGE_POINTS" in source


def test_gui_validates_target_address():
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "target_address_error(ip)" in source


def test_gui_explains_decimal_addresses():
    """X/Y/B/W are hexadecimal in GX Works but decimal in this tool"""
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "X1F → 31" in source


@pytest.mark.parametrize(
    "mode, tags, expected",
    [
        ("range", None, ["D0", "D1", "D2"]),
        ("range", ["Speed", "Recipe[0]{5}"], ["Speed", "Recipe[0]"]),
        ("full", None, ["D0", "M0"]),
    ],
)
def test_gui_single_read_offline_saves_comm_errors(monkeypatch, tmp_path, mode, tags, expected):
    from plc_discovery.config import NetworkConfig
    from tests.test_regressions_gui import _import_gui

    plc_gui = _import_gui(monkeypatch)
    monkeypatch.setattr(plc_gui, "PLCDataCollector", _GuiOfflineCollector)
    monkeypatch.setattr(
        collector_module,
        "DEFAULT_DEVICE_RANGES",
        {Protocol.SLMP: [DeviceRange(DeviceType.D, 0, 0), DeviceRange(DeviceType.M, 0, 0)]},
    )
    app = MagicMock()
    posted = []
    app._post = lambda *item: posted.append(item)
    exporter = CSVExporter(str(tmp_path))
    with pytest.raises(RuntimeError) as error:
        asyncio.run(
            plc_gui.PLCScannerApp._collect_job(
                app,
                NetworkConfig(),
                "10.0.0.1",
                Protocol.SLMP,
                5001,
                mode,
                DeviceType.D,
                0,
                2,
                0,
                None,
                None,
                exporter,
                tags=tags,
            )
        )
    data = [item for item in posted if item[0] == "data"]
    assert [p.address for p in data[0][1]] == expected
    assert {p.status for p in data[0][1]} == {StatusCode.NG_COMM_ERROR}
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1 and str(files[0]) in str(error.value)
