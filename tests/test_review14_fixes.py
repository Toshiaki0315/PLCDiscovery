"""
Regression tests for the fourteenth review's findings.

E1: STRING values follow the byte order (high byte first for "big").
E2: a type mapping without byte_order uses default_byte_order.
E3: invalid data_types settings are reported as config errors, and type
    and byte order names are case-insensitive.
E4: GUI periodic monitoring keeps going when the PLC is offline at start.
"""

import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder, DataType, DataTypeConverter, DataTypeManager

# ---------------------------------------------------------------------------
# E1: STRING byte order
# ---------------------------------------------------------------------------

WORDS = [0x4142, 0x4344]  # bytes 41 42 43 44 as Siemens/Omron store "ABCD"


@pytest.mark.parametrize(
    "byte_order, text",
    [
        (ByteOrder.LITTLE_ENDIAN, "BADC"),  # low byte first (Mitsubishi, Keyence): unchanged
        (ByteOrder.BIG_ENDIAN, "ABCD"),  # previously "BADC"
        (ByteOrder.LITTLE_ENDIAN_WORD_SWAP, "ABCD"),
        (ByteOrder.BIG_ENDIAN_WORD_SWAP, "BADC"),
    ],
)
def test_string_follows_byte_order(byte_order, text):
    assert DataTypeConverter.convert(WORDS, DataType.STRING, byte_order) == text


def test_big_endian_string_stops_at_nul():
    assert DataTypeConverter.convert([0x4142, 0x4300, 0x4445], DataType.STRING, ByteOrder.BIG_ENDIAN) == "ABC"


def test_cli_conversion_reads_big_endian_string():
    points = [DataPoint(f"D{i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(WORDS)]
    first, _ = plc_scanner.apply_data_type_conversion(points, DataType.STRING, ByteOrder.BIG_ENDIAN)
    assert first.converted_value == "ABCD"


# ---------------------------------------------------------------------------
# E2: mapping inherits default byte order
# ---------------------------------------------------------------------------


def test_mapping_without_byte_order_uses_default():
    manager = DataTypeManager.from_config(
        {
            "default_byte_order": "big",
            "mappings": [
                {"start": 0, "end": 1, "type": "FLOAT"},
                {"start": 2, "end": 3, "type": "FLOAT", "byte_order": "little"},
            ],
        }
    )
    assert [m.byte_order for m in manager.mappings] == [ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN]


def test_big_endian_float_mapping_value():
    manager = DataTypeManager.from_config(
        {
            "default_byte_order": "big",
            "mappings": [{"start": 0, "end": 1, "type": "FLOAT"}],
        }
    )
    words = [0x3F80, 0x0000]  # 1.0 high word first
    points = [DataPoint(f"D{i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(words)]
    first = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)[0]
    assert first.converted_value == 1.0  # previously 2.3e-41 (read as little)


# ---------------------------------------------------------------------------
# E3: validation and case-insensitive names
# ---------------------------------------------------------------------------


def test_names_are_case_insensitive():
    manager = DataTypeManager.from_config(
        {
            "default_type": "dword",
            "default_byte_order": "BIG",
            "mappings": [{"start": 0, "end": 1, "type": "float", "byte_order": "Little_Swap", "device": "d"}],
        }
    )
    assert manager.default_type == DataType.DWORD and manager.default_byte_order == ByteOrder.BIG_ENDIAN
    (mapping,) = manager.mappings
    assert (mapping.data_type, mapping.byte_order, mapping.device) == (
        DataType.FLOAT,
        ByteOrder.LITTLE_ENDIAN_WORD_SWAP,
        "D",
    )


@pytest.mark.parametrize(
    "data_types, message",
    [
        ({"mappings": [{"start": 0, "type": "FLOAT"}]}, "data_types.mappings[0].end is required"),
        ({"mappings": [{"start": 0, "end": 1, "type": "REAL"}]}, "data_types.mappings[0].type: unknown value 'REAL'"),
        (
            {"mappings": [{"start": 0, "end": 1, "type": "FLOAT", "byte_order": "BIGG"}]},
            "data_types.mappings[0].byte_order: unknown value",
        ),
        ({"mappings": [{"start": 5, "end": 1, "type": "FLOAT"}]}, "start must be <= end"),
        ({"mappings": [{"start": -1, "end": 1, "type": "FLOAT"}]}, "start must be an integer >= 0"),
        ({"mappings": [{"start": 0, "end": 9, "type": "STRING", "length": 0}]}, "length must be an integer >= 1"),
        ({"default_byte_order": "middle"}, "data_types.default_byte_order: unknown value"),
        ({"mappings": {"start": 0}}, "data_types.mappings must be a list"),
    ],
)
def test_invalid_data_types_reported_by_validate(tmp_path, data_types, message):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"targets": [{"ip": "127.0.0.1"}], "data_types": data_types}))
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any(message in e for e in errors), errors


def test_cli_invalid_mapping_is_config_error(tmp_path, monkeypatch, capsys):
    path = tmp_path / "c.json"
    path.write_text(
        json.dumps(
            {
                "targets": [{"ip": "127.0.0.1", "protocol": "slmp"}],
                "data_types": {"mappings": [{"start": 0, "type": "FLOAT"}]},
            }
        )
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "plc_scanner.py",
            "--config",
            str(path),
            "--mode",
            "range",
            "--device",
            "D",
            "--range",
            "0-0",
            "-o",
            str(tmp_path),
        ],
    )
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "Config error: data_types.mappings[0].end is required" in capsys.readouterr().out  # previously a traceback


def test_type_mapping_file_error_names_the_file(tmp_path):
    path = tmp_path / "types.json"
    path.write_text(json.dumps({"mappings": [{"start": 0, "end": 1, "type": "REAL"}]}))
    with pytest.raises(ValueError, match=r"types\.json\.mappings\[0\]\.type"):
        plc_scanner.load_type_mapping(str(path))


# ---------------------------------------------------------------------------
# E4: GUI periodic monitoring with the PLC offline at start
# ---------------------------------------------------------------------------


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
