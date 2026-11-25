"""
Regression tests for GUI (plc_gui.py), found and fixed in code reviews.
"""

import asyncio
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import plc_gui
import plc_gui_settings
import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery import settings_file
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from plc_discovery.data_types import ByteOrder
from plc_discovery.output import DEFAULT_OUTPUT_DIR, CSVExporter
from plc_discovery.scan_runner import CycleResult, CycleRunner
from plc_discovery.utils import get_timestamp


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


def _import_async_worker(monkeypatch):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "messagebox", "ttk"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
        monkeypatch.delitem(sys.modules, "plc_gui", raising=False)
    from plc_gui import AsyncWorker

    return AsyncWorker


def _wait(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


def test_gui_worker_stays_busy_until_the_result_is_acknowledged(monkeypatch):
    worker = _import_async_worker(monkeypatch)(acknowledge=True)
    done = []

    async def job():
        return None

    try:
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 1)
        # Ended, but the GUI has not handled the result yet: no new job
        assert worker.busy
        worker.acknowledge()
        assert not worker.busy
        # The next job follows the same rule
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 2) and worker.busy
        worker.acknowledge()
        assert not worker.busy
    finally:
        worker.shutdown(timeout=2)


def test_gui_worker_without_acknowledge_is_free_when_the_job_ends(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    done = []

    async def job():
        return None

    try:
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 1) and _wait(lambda: not worker.busy)
    finally:
        worker.shutdown(timeout=2)


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
            names = "packet_interval retry_interval timeout output_dir encoding hex_addresses periodic_csv".split()
            names += "report_interval min_interval db_enabled db_path db_history db_days db_size db_interval".split()
            for name in names:
                setattr(self, f"var_{name}", _Var("utf-8-sig" if name == "encoding" else "0"))
            self.notify_destinations: list = []

        def _refresh_notify_tree(self):
            pass

    return App()


@pytest.mark.parametrize("name, shown", [("cp932", "shift-jis"), ("sjis", "shift-jis"), ("UTF8", "utf-8")])
def test_gui_understands_the_encoding_names_the_cli_accepts(name, shown):
    app = _settings_tabs()
    app._apply_settings({"output": {"encoding": name}})
    assert app.var_encoding.get() == shown  # stayed utf-8-sig: other CSVs than the CLI's, and "save" changed the file


def test_gui_discovery_uses_the_timeout_of_the_settings_file():
    app = _settings_tabs()
    assert app._discovery_settings == {}
    app._apply_settings({"network": {"discovery_timeout_ms": 3000, "discovery_retry_count": 2, "max_concurrent": 4}})
    assert app._discovery_settings == {"discovery_timeout_ms": 3000, "discovery_retry_count": 2}
    assert NetworkConfig(**app._discovery_settings).discovery_timeout_ms == 3000
    app._apply_settings({"network": {"discovery_timeout_ms": "soon"}})
    assert app._discovery_settings == {}


def _settings_tabs_2():
    class App(plc_gui_settings.SettingsTabsMixin):
        def __init__(self):
            for name, value in dict(
                var_packet_interval="50",
                var_retry_interval="200",
                var_timeout="5000",
                var_output_dir="out",
                var_encoding="utf-8-sig",
                var_hex_addresses=False,
                var_periodic_csv="per_cycle",
                var_report_interval="0",
                var_min_interval="0",
                var_db_enabled=False,
                var_db_path="plc_data.db",
                var_db_history=True,
                var_db_days="30",
                var_db_size="0",
                var_db_interval="24",
            ).items():
                setattr(self, name, _Var(value))
            self.notify_destinations: list = []

        def _refresh_notify_tree(self):
            pass

        def _int_field(self, var, label, minimum=0):
            return int(var.get())

        def _network_config(self):
            return NetworkConfig()

    return App()


def test_one_wrong_value_in_the_settings_file_does_not_empty_the_rest(tmp_path):
    path = tmp_path / "plc_config.yaml"
    path.write_text(
        "output:\n"
        "  database:\n"
        "    enabled: true\n"
        "    max_size_mb:\n"  # left empty
        "notification_settings:\n"
        "  report_interval_minutes: 30\n"
        "notifications:\n"
        "  - name: teams\n"
        "    type: teams\n"
        "    url: https://example.com/hook\n",
        encoding="utf-8",
    )
    config, errors = settings_file.load(str(path))
    assert errors  # the wrong value is reported
    app = _settings_tabs_2()
    app._apply_settings(config)  # raised, leaving everything below at its default
    assert app.var_db_size.get() == "0"
    assert app.var_report_interval.get() == "30"
    assert [d["name"] for d in app.notify_destinations] == ["teams"]

    # "Save" no longer writes an empty destination list over the file
    _, save_errors = settings_file.save(str(path), app._settings_dict())
    assert save_errors == []
    saved, _ = settings_file.load(str(path))
    assert [d["url"] for d in saved["notifications"]] == ["https://example.com/hook"]
    assert saved["notification_settings"]["report_interval_minutes"] == 30


def test_stopped_single_scan_keeps_what_it_read(tmp_path):
    from simulators.slmp_simulator import SLMPDevice, SLMPProtocol

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
        # Not a fixed sleep: wait until the scan has moved on to its second
        # range, so something was read whatever the speed of the machine.
        # The full scan reports "Starting" (1st call), then each range just
        # before reading it: the 2nd call comes before anything was read,
        # the 3rd once the first range is complete
        for _ in range(2000):
            if app._progress_cb.call_count >= 3 or job.done():
                break
            await asyncio.sleep(0.01)
        assert not job.done()
        job.cancel()  # the Stop button
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(job, timeout=10)
        server.close()
        return posted

    posted = asyncio.run(run())
    shown = [item[1] for item in posted if item[0] == "data"]
    assert len(shown) == 1 and len(shown[0]) > 0  # was nothing: the table stayed empty
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1  # was no file at all
    assert len(files[0].read_text(encoding="utf-8-sig").splitlines()) == len(shown[0]) + 1


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


def _settings_tabs_3():
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
    app = _settings_tabs_3()
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


def _settings_tabs_4():
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


def test_gui_keeps_an_encoding_it_cannot_show():
    app = _settings_tabs_4()
    app._apply_settings({"output": {"encoding": "euc-jp"}})
    assert list(app._settings_dropped) == []
    assert app.var_encoding.get() == "utf-8-sig"  # the radio button stays where it was
    assert app._csv_encoding() == "euc_jp"  # used for the CSV files ...
    assert app._settings_dict()["output"]["encoding"] == "euc_jp"  # ... and written back (was utf-8-sig)
    app.var_encoding.set("shift-jis")  # the user chooses another one
    assert app._csv_encoding() == "shift-jis"


def _point(address, status=StatusCode.OK, value=1):
    ok = status == StatusCode.OK
    return DataPoint(address=address, value=value if ok else None, status=status, timestamp=get_timestamp())


def _scan_complete_counts(points):
    notifier = MagicMock()
    notifier.notify_scan_complete = AsyncMock(return_value={})
    outputs = MagicMock()

    async def notify(send):
        await send(notifier)
        return True

    outputs.notify = notify
    asyncio.run(plc_gui.PLCScannerApp._notify_collect_done(outputs, "10.0.0.1", points, 1, 1.0))
    args, kwargs = notifier.notify_scan_complete.call_args
    return args[1], args[2], kwargs


def test_gui_scan_with_invalid_addresses_is_notified_as_a_successful_target():
    points = [_point("D0"), _point("R0", StatusCode.NG_ILLEGAL_ADDR)]
    success, errors, extra = _scan_complete_counts(points)
    assert (success, errors) == (1, 0)  # was (0, 1), with priority HIGH, for every full scan
    assert extra["ok_points"] == 1 and extra["ng_points"] == 1


@pytest.mark.parametrize("points", [[], [_point("D0", StatusCode.NG_TIMEOUT), _point("D1", StatusCode.NG_COMM_ERROR)]])
def test_gui_scan_the_plc_did_not_answer_is_notified_as_a_failed_target(points):
    success, errors, _ = _scan_complete_counts(points)
    assert (success, errors) == (0, 1)


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

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "success_rate": "100.00%"}


def _gui_job(tmp_path, interval):
    app, posted = MagicMock(), []
    app._post = lambda *item: posted.append(item)
    job = plc_gui.PLCScannerApp._collect_job(
        app,
        NetworkConfig(),
        "127.0.0.1",
        Protocol.SLMP,
        5001,
        "range",
        DeviceType.D,
        0,
        0,
        interval,
        None,
        ByteOrder.LITTLE_ENDIAN,
        CSVExporter(str(tmp_path), "utf-8-sig"),
    )
    return job, posted


def test_gui_periodic_monitoring_goes_on_after_a_cycle_that_raised(tmp_path, monkeypatch):
    calls = []

    async def read(self, collector, writer):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("unexpected")
        return CycleResult([_point("D0")], None, None)

    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector)
    monkeypatch.setattr(plc_gui.CycleRunner, "read", read)

    async def run():
        coro, posted = _gui_job(tmp_path, interval=1.0)
        job = asyncio.ensure_future(coro)
        for _ in range(500):
            if len(calls) >= 2 or job.done():
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        assert not job.done()  # ended with "エラーで終了しました" after the first cycle
        job.cancel()
        with pytest.raises(asyncio.CancelledError):
            await job
        return posted

    posted = asyncio.run(run())
    shown = [item for item in posted if item[0] == "data"]
    assert len(shown) == 1 and shown[0][-1] == 2  # the second cycle; the failed one shows nothing


def test_gui_single_scan_that_raised_is_still_an_error(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector)
    monkeypatch.setattr(plc_gui.CycleRunner, "read", read)
    coro, _ = _gui_job(tmp_path, interval=0.0)
    with pytest.raises(RuntimeError, match="unexpected"):
        asyncio.run(coro)


class _Var_2:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home folder and a separate folder the GUI was started in"""
    home = tmp_path / "home"
    start = tmp_path / "start"
    home.mkdir()
    start.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(start)
    return home


def _opened_folder(monkeypatch, text):
    opened = []
    monkeypatch.setattr(plc_gui.sys, "platform", "darwin")
    monkeypatch.setattr(plc_gui.subprocess, "Popen", lambda command: opened.append(command[-1]))
    app = MagicMock()
    app.var_output_dir = _Var_2(text)
    plc_gui.PLCScannerApp._open_output_dir(app)
    return Path(opened[0])


def test_gui_opens_the_output_folder_in_the_home_folder(home, monkeypatch):
    opened = _opened_folder(monkeypatch, "~/plc_results")
    assert opened == home / "plc_results" and opened.is_dir()
    assert not Path("~").exists()  # was created where the GUI was started, and opened empty


class _Var_3:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


@pytest.mark.parametrize("text", ["", "   "])
def test_gui_opens_the_default_output_folder_for_an_empty_field(home, monkeypatch, text):
    opened = _opened_folder(monkeypatch, text)
    assert opened.resolve() == Path(DEFAULT_OUTPUT_DIR).resolve()  # was the folder the GUI was started in


class _Var_4:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def _settings_app(path_text):
    class App(plc_gui_settings.SettingsTabsMixin):
        var_settings_path = _Var_4(path_text)
        var_status = _Var_4("")
        worker = None

        def _settings_dict(self):
            return {"network": {"packet_interval_ms": 70}}

        def _apply_settings(self, config):
            self.applied = config

        def _start_audit_log(self, config):
            pass

    return App()


def test_gui_saves_and_loads_the_settings_file_in_the_home_folder(home, monkeypatch):
    monkeypatch.setattr(plc_gui_settings.messagebox, "showinfo", MagicMock())
    monkeypatch.setattr(plc_gui_settings.messagebox, "showerror", MagicMock())
    app = _settings_app("~/plc_config.json")
    app._save_settings()
    saved = home / "plc_config.json"
    assert json.loads(saved.read_text(encoding="utf-8"))["network"]["packet_interval_ms"] == 70
    assert not Path("~").exists()  # was ./~/plc_config.json

    app._load_settings()
    assert app.applied["network"]["packet_interval_ms"] == 70  # was "設定ファイルがありません"
    plc_gui_settings.messagebox.showinfo.assert_not_called()


def _spy_save_partial(monkeypatch):
    saved = []
    original = CycleRunner.save_partial

    def save_partial(self, collector, writer):
        saved.append(collector)
        return original(self, collector, writer)

    monkeypatch.setattr(CycleRunner, "save_partial", save_partial)
    return saved


class _FakeCollector_2:
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
    monkeypatch.setattr(plc_gui, "PLCDataCollector", _FakeCollector_2)
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


class _FakeCollector_3:
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


def test_gui_stop_during_the_first_read_is_still_saved(tmp_path, monkeypatch):
    async def read(self, collector, writer):
        await asyncio.sleep(30)
        return CycleResult([], None, None)

    assert len(_run_gui_periodic(tmp_path, monkeypatch, read)) == 1


def _wait_2(condition, seconds=2.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


def test_gui_worker_is_busy_until_a_stopped_job_has_cleaned_up(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    state = {"started": False, "cleaning": False, "cleaned": False}
    release = threading.Event()  # lets the cleanup finish (no wall-clock assumptions)
    done = []

    async def job():
        state["started"] = True
        try:
            await asyncio.sleep(60)
        finally:
            state["cleaning"] = True  # final notification, PLC disconnect
            while not release.is_set():
                await asyncio.sleep(0.005)
            state["cleaned"] = True

    try:
        worker.submit(job(), done.append)
        assert _wait_2(lambda: state["started"])
        worker.cancel()
        assert _wait_2(lambda: state["cleaning"])
        # Still disconnecting: a second job must not be allowed to start
        assert worker.busy and not state["cleaned"] and not done
        release.set()
        assert _wait_2(lambda: not worker.busy)
        assert state["cleaned"] and isinstance(done[0], asyncio.CancelledError)
    finally:
        release.set()
        worker.shutdown(timeout=2)


def _wait_3(condition, seconds=2.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


def test_gui_worker_reports_result_and_exception(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    done = []

    async def ok():
        return 1

    async def fails():
        raise ValueError("boom")

    try:
        worker.submit(ok(), done.append)
        assert _wait_3(lambda: len(done) == 1) and done[0] is None and not worker.busy
        worker.submit(fails(), done.append)
        assert _wait_3(lambda: len(done) == 2) and isinstance(done[1], ValueError)
    finally:
        worker.shutdown(timeout=2)
