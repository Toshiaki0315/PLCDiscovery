"""
Regression tests for the command line (plc_scanner.py), found and fixed in code reviews.
"""

import argparse
import asyncio
import csv
import io
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pycomm3
import pytest
from pycomm3 import Tag
from pycomm3.exceptions import CommError

import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery import parallel, scan_runner
from plc_discovery.audit_log import close_audit_logger, init_audit_logger
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.cli_args import NETWORK_OPTIONS, network_option_errors, parse_args, resolve_device_ranges_only
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    MAX_RANGE_POINTS,
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    ScanMode,
    StatusCode,
    TagRange,
)
from plc_discovery.config_loader import MAX_CONCURRENT, ConfigLoader
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.discovery import target_labels
from plc_discovery.notifications import NotificationManager, NotificationType
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.scan_runner import CycleRunner, ResultWriter, cycle_start, no_answer_error, plc_answered
from plc_discovery.utils import get_timestamp
from simulators.control import SimulatorController

SLMP = PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001)


MODBUS = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502)


OTHER = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)


read_by: list = []


class FakeCollector:
    is_connected = True
    connect_error = None

    def __init__(self, plc, config=None):
        self.plc = plc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *a):
        read_by.append(self.plc.protocol)
        return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


class LateCollector:
    """Unreachable for the first two cycles, then answers"""

    instances = []

    def __init__(self, plc, config=None):
        self.plc = plc
        self.cycles = 0
        self.valid = plc.options.get("valid", True)
        self.connect_error = None if self.valid else "invalid options"
        LateCollector.instances.append(self)

    @property
    def is_connected(self):
        return self.valid and self.cycles > 2

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *a):
        self.cycles += 1
        status = StatusCode.OK if self.is_connected else StatusCode.NG_COMM_ERROR
        return [DataPoint("D0", 1 if status == StatusCode.OK else None, None, status)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


async def run_periodic(plcs, cycles):
    LateCollector.instances.clear()
    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", LateCollector):
        task = asyncio.ensure_future(
            plc_scanner.run_periodic_scan(
                plcs,
                NetworkConfig(),
                exporter,
                Display(),
                [DeviceRange(DeviceType.D, 0, 0)],
                interval=0.01,
            )
        )
        while not LateCollector.instances or max(c.cycles for c in LateCollector.instances) < cycles:
            await asyncio.sleep(0.005)
        task.cancel()
        return await task, exporter


WORDS = [0x4142, 0x4344]  # bytes 41 42 43 44 as Siemens/Omron store "ABCD"


ROOT = Path(__file__).resolve().parent.parent


def _args(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", *argv])
    return plc_scanner.parse_args()


def _loader(tmp_path, text):
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


MAPPED = (
    "data_types:\n  default_type: WORD\n  default_byte_order: big\n"
    "  mappings:\n    - {start: 500, end: 501, type: DWORD}\n"
)


BYTE_ORDER_MAPPINGS = (
    "data_types:\n  default_byte_order: big\n  mappings:\n"
    "    - {start: 0, end: 1, type: FLOAT}\n"
    "    - {start: 10, end: 11, type: FLOAT, byte_order: big_swap}\n"
)


def plc_scanner_default_output():
    from plc_discovery.output import DEFAULT_OUTPUT_DIR

    return DEFAULT_OUTPUT_DIR


@pytest.fixture
def restore_logging():
    import logging

    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


class FakeCollector_2:
    def __init__(self, ip, connected=True):
        self.ip = ip
        self.is_connected = connected
        self.collect_calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *args):
        self.collect_calls += 1
        return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


def make_args(**kw):
    base = dict(packet_interval=None, retry_interval=None, request_timeout=None, max_concurrent=None)
    base.update(kw)
    return argparse.Namespace(**base)


def ok(address, value):
    return DataPoint(address, value, f"0x{value:04X}", StatusCode.OK)


class FakeCollector_3:
    is_connected = True

    def __init__(self):
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *a):
        self.calls += 1
        return [ok("D0", 1)]

    async def collect_full_scan(self):
        return [ok("D0", 1)]

    def get_denied_addresses(self):
        return {"D9"}

    def get_denied_statuses(self):
        return {"D9": StatusCode.NG_ILLEGAL_ADDR}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


def load(tmp_path, data):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


def cp932_stream(errors="strict"):
    return io.TextIOWrapper(io.BytesIO(), encoding="cp932", errors=errors)


class OfflineCollector:
    def __init__(self, plc_info, config=None):
        self.is_connected = False
        self.connect_error = "connection refused"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


def test_target_labels():
    assert target_labels([SLMP, OTHER]) == ["127.0.0.1", "10.0.0.2"]
    assert target_labels([SLMP, MODBUS, OTHER]) == [
        "127.0.0.1 (SLMP:5001)",
        "127.0.0.1 (MODBUS_TCP:1502)",
        "10.0.0.2",
    ]
    # same IP, protocol and port (gateway with two unit IDs)
    unit2 = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502, options={"unit_id": 2})
    assert target_labels([MODBUS, unit2]) == [
        "127.0.0.1 (MODBUS_TCP:1502)",
        "127.0.0.1 (MODBUS_TCP:1502) #2",
    ]


@pytest.mark.asyncio
async def test_periodic_scan_reads_every_target_sharing_an_ip():
    read_by.clear()
    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", FakeCollector):
        task = asyncio.ensure_future(
            plc_scanner.run_periodic_scan(
                [SLMP, MODBUS],
                NetworkConfig(),
                exporter,
                Display(),
                [DeviceRange(DeviceType.D, 0, 0)],
                interval=0.01,
            )
        )
        while len(read_by) < 4:
            await asyncio.sleep(0.005)
        task.cancel()
        outcomes = await task
    assert set(read_by) == {Protocol.SLMP, Protocol.MODBUS_TCP}  # previously MODBUS_TCP only
    assert [o.label for o in outcomes] == ["127.0.0.1 (SLMP:5001)", "127.0.0.1 (MODBUS_TCP:1502)"]
    assert all(o.ip_address == "127.0.0.1" and o.success for o in outcomes)
    # data files are still named by IP
    assert {c.args[1] for c in exporter.export_plc_data.call_args_list} == {"127.0.0.1"}


@pytest.mark.asyncio
async def test_parallel_scan_keeps_every_target_sharing_an_ip():
    read_by.clear()
    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", FakeCollector):
        results = await plc_scanner.run_parallel_scan(
            [SLMP, MODBUS, OTHER],
            NetworkConfig(max_concurrent=3),
            exporter,
            Display(),
            ScanMode.RANGE,
            [DeviceRange(DeviceType.D, 0, 0)],
        )
    assert set(results) == {"127.0.0.1 (SLMP:5001)", "127.0.0.1 (MODBUS_TCP:1502)", "10.0.0.2"}
    assert exporter.export_plc_data.call_count == 3  # previously one result (and its CSV) was lost


@pytest.mark.asyncio
async def test_parallel_scan_unique_ips_still_keyed_by_ip():
    with patch.object(parallel, "PLCDataCollector", FakeCollector):
        results = await parallel.ParallelPLCScanner(NetworkConfig(max_concurrent=2)).scan_multiple_plcs(
            [SLMP, OTHER], ScanMode.RANGE, [DeviceRange(DeviceType.D, 0, 0)]
        )
    assert set(results) == {"127.0.0.1", "10.0.0.2"}


@pytest.mark.asyncio
async def test_periodic_scan_picks_up_target_that_comes_online():
    (outcome,), exporter = await run_periodic([PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)], 4)
    statuses = [c.args[0][0].status for c in exporter.export_plc_data.call_args_list]
    assert statuses[:2] == [StatusCode.NG_COMM_ERROR] * 2  # offline cycles are logged
    assert StatusCode.OK in statuses[2:]  # previously never read at all
    assert outcome.success and outcome.error is None


@pytest.mark.asyncio
async def test_periodic_scan_target_never_reached_is_reported_failed():
    (outcome,), _ = await run_periodic([PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)], 2)
    assert outcome.success is False and "Failed to connect" in outcome.error


@pytest.mark.asyncio
async def test_periodic_scan_skips_target_with_invalid_options():
    good = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)
    bad = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001, options={"valid": False})
    outcomes, _ = await run_periodic([good, bad], 4)
    by_ip = {o.ip_address: o for o in outcomes}
    assert by_ip["10.0.0.2"].success is False
    assert [c for c in LateCollector.instances if c.plc is bad][0].cycles == 0  # never polled


@pytest.mark.asyncio
async def test_cli_discovery_stores_every_endpoint_in_database():
    found = [
        PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001),
        PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502),
    ]
    db = MagicMock()
    db.is_enabled = True
    db.export_discovery_results.return_value = 2
    with (
        patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=found)),
        patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[])),
    ):
        await plc_scanner.run_discovery([], NetworkConfig(), MagicMock(), Display(), db)
    stored = db.export_discovery_results.call_args.args[0]
    assert [(p.protocol, p.port) for p in stored] == [(Protocol.SLMP, 5001), (Protocol.MODBUS_TCP, 1502)]


@pytest.mark.asyncio
async def test_cli_discovery_keeps_tcp_identity_over_broadcast():
    tcp = PLCInfo(
        "10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="Omron Corporation", model="NJ501-1300"
    )
    broadcast = PLCInfo("10.0.0.5", protocol=Protocol.ETHERNET_IP, port=44818, manufacturer="Vendor 47")
    with (
        patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=[tcp])),
        patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[broadcast])),
    ):
        plcs = await plc_scanner.run_discovery([], NetworkConfig(), MagicMock(), Display())
    assert [(p.manufacturer, p.model) for p in plcs] == [("Omron Corporation", "NJ501-1300")]


@pytest.mark.asyncio
async def test_cli_discovery_lists_an_unidentified_host_once_for_overlapping_ranges():
    async def discover(ip_range, config, unidentified=None, **kwargs):
        unidentified.append(PLCInfo("10.0.0.7", model="未対応・要確認", note="ポートは開いているが…"))
        return []

    exporter = MagicMock()
    with patch.object(plc_scanner, "discover_plcs", discover):
        await plc_scanner.run_discovery(["10.0.0.0/29", "10.0.0.4/30"], NetworkConfig(), exporter, Display())
    written = exporter.export_discovery_results.call_args.args[0]
    assert [p.ip_address for p in written] == ["10.0.0.7"]  # was listed once per range


@pytest.mark.asyncio
async def test_cli_report_lists_failed_targets(tmp_path, monkeypatch):
    async def scan(plc_info, *a, **k):
        if plc_info.ip_address == "10.0.0.2":
            return plc_scanner.ScanOutcome("10.0.0.2", error="Failed to connect to 10.0.0.2:5001 (SLMP): refused")
        return plc_scanner.ScanOutcome(
            plc_info.ip_address, success=True, data_points=[DataPoint("D0", 1, "0x0001", StatusCode.OK)]
        )

    monkeypatch.setattr(
        "sys.argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.1,10.0.0.2",
            "--protocol",
            "slmp",
            "--device",
            "D",
            "--range",
            "0-0",
            "--output-dir",
            str(tmp_path),
            "--report",
            "json",
            "--report-output",
            str(tmp_path / "report.json"),
        ],
    )
    with patch.object(plc_scanner, "run_single_scan", AsyncMock(side_effect=scan)):
        with pytest.raises(SystemExit) as exit_info:
            await plc_scanner.main()
    assert exit_info.value.code == 1

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["errors"] == ["10.0.0.2: Failed to connect to 10.0.0.2:5001 (SLMP): refused"]


def test_target_error_without_reason():
    assert plc_scanner._target_error("10.0.0.3", None) == "10.0.0.3: scan failed"


def test_cli_conversion_reads_big_endian_string():
    points = [DataPoint(f"D{i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(WORDS)]
    first, _ = plc_scanner.apply_data_type_conversion(points, DataType.STRING, ByteOrder.BIG_ENDIAN)
    assert first.converted_value == "ABCD"


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


def test_cli_rejects_huge_range_before_scanning(tmp_path, monkeypatch, capsys):
    import asyncio
    from unittest.mock import AsyncMock, patch

    monkeypatch.setattr(
        "sys.argv", ["plc_scanner.py", "--mode", "discover", "--ip-range", "10.0.0.0/8", "-o", str(tmp_path)]
    )
    probe = AsyncMock(return_value=[])
    with patch.object(plc_scanner, "discover_plcs", probe), pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    probe.assert_not_called()
    assert "16,777,214 hosts" in capsys.readouterr().out


def test_docker_simulators_listen_in_container_published_on_loopback():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "simulators/run_all.py", "--host", "0.0.0.0"]' in dockerfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"5001:5001"' not in compose and '"127.0.0.1:5001:5001"' in compose


def test_cli_scan_mode_typo_exits_without_scanning(tmp_path, monkeypatch, capsys):
    import asyncio
    from unittest.mock import AsyncMock, patch

    path = tmp_path / "c.json"
    path.write_text(json.dumps({"scan": {"mode": "rang"}, "targets": [{"ip": "127.0.0.1", "protocol": "slmp"}]}))
    monkeypatch.setattr("sys.argv", ["plc_scanner.py", "--config", str(path), "-o", str(tmp_path)])
    scan = AsyncMock()
    with patch.object(plc_scanner, "run_single_scan", scan), pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    scan.assert_not_called()
    assert "scan.mode: unknown mode 'rang'" in capsys.readouterr().out


def test_cli_data_type_applies_to_unmapped_addresses(monkeypatch, tmp_path):
    args = _args(monkeypatch, "--data-type", "FLOAT", "--byte-order", "little")
    data_type, byte_order, manager = plc_scanner.resolve_data_types(args, _loader(tmp_path, MAPPED))
    assert (data_type, byte_order) == (DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
    assert manager.default_type == DataType.FLOAT
    assert manager.default_byte_order == ByteOrder.LITTLE_ENDIAN

    points = [DataPoint(address=f"D{i}", value=v, status=StatusCode.OK) for i, v in enumerate([0x0000, 0x4120])]
    converted = plc_scanner.apply_data_type_conversion(points, data_type, byte_order, manager)
    assert converted[0].data_type == "FLOAT"
    assert converted[0].converted_value == pytest.approx(10.0)


def test_config_data_types_used_without_cli_options(monkeypatch, tmp_path):
    data_type, byte_order, manager = plc_scanner.resolve_data_types(_args(monkeypatch), _loader(tmp_path, MAPPED))
    assert (data_type, byte_order) == (DataType.WORD, ByteOrder.BIG_ENDIAN)
    assert manager.default_type == DataType.WORD


@pytest.mark.parametrize(
    "argv,fragment",
    [
        (["--request-timeout", "0"], "--request-timeout must be >= 1"),
        (["--max-concurrent", "0"], "--max-concurrent must be >= 1"),
        (["--packet-interval", "-1"], "--packet-interval must be >= 0"),
        (["--retry-interval", "-200"], "--retry-interval must be >= 0"),
    ],
)
def test_cli_network_options_checked(monkeypatch, argv, fragment):
    errors = plc_scanner.network_option_errors(_args(monkeypatch, *argv))
    assert len(errors) == 1 and errors[0].startswith(fragment)


def test_cli_network_options_valid(monkeypatch):
    args = _args(monkeypatch, "--request-timeout", "1", "--packet-interval", "0")
    assert plc_scanner.network_option_errors(args) == []


def test_cli_rejects_zero_timeout_before_scanning(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--request-timeout", "0", "--no-rich"])
    with pytest.raises(SystemExit) as exc:
        asyncio.run(plc_scanner.main())
    assert exc.value.code == 1
    assert "--request-timeout must be >= 1" in capsys.readouterr().out


def test_cli_byte_order_applies_to_mappings_without_own_order(monkeypatch, tmp_path):
    args = _args(monkeypatch, "--byte-order", "little")
    _, byte_order, manager = plc_scanner.resolve_data_types(args, _loader(tmp_path, BYTE_ORDER_MAPPINGS))
    assert byte_order == ByteOrder.LITTLE_ENDIAN
    assert manager.default_byte_order == ByteOrder.LITTLE_ENDIAN
    assert manager.get_mapping_for_address(0, "D").byte_order == ByteOrder.LITTLE_ENDIAN
    # An explicit byte_order on a mapping still wins
    assert manager.get_mapping_for_address(10, "D").byte_order == ByteOrder.BIG_ENDIAN_WORD_SWAP


def test_config_byte_order_kept_without_cli_option(monkeypatch, tmp_path):
    _, byte_order, manager = plc_scanner.resolve_data_types(_args(monkeypatch), _loader(tmp_path, BYTE_ORDER_MAPPINGS))
    assert byte_order == ByteOrder.BIG_ENDIAN
    assert manager.get_mapping_for_address(0, "D").byte_order == ByteOrder.BIG_ENDIAN


def test_type_mapping_file_follows_cli_byte_order(monkeypatch, tmp_path):
    path = tmp_path / "types.json"
    path.write_text(
        '{"default_byte_order": "big", "mappings": [{"start": 0, "end": 1, "type": "FLOAT"}]}',
        encoding="utf-8",
    )
    args = _args(monkeypatch, "--type-mapping", str(path), "--byte-order", "little")
    _, _, manager = plc_scanner.resolve_data_types(args, None)
    assert manager.get_mapping_for_address(0, "D").byte_order == ByteOrder.LITTLE_ENDIAN


def test_docker_default_output_is_the_mounted_directory():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    production = dockerfile.split("FROM base as production", 1)[1].split("FROM base as", 1)[0]
    assert "ln -s /app/output /app/plc_scan_results" in production
    assert plc_scanner_default_output() == "./plc_scan_results"
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./plc_scan_results:/app/output" in compose


def test_cli_rejects_huge_range():
    assert plc_scanner.parse_address_range(f"0-{MAX_RANGE_POINTS - 1}") == (0, MAX_RANGE_POINTS - 1)
    with pytest.raises(ValueError, match="at most"):
        plc_scanner.parse_address_range("0-16000000")


def test_cli_targets_skip_empty_and_reject_invalid():
    assert plc_scanner.parse_targets("127.0.0.1,,10.0.0.2, ") == ["127.0.0.1", "10.0.0.2"]
    with pytest.raises(ValueError, match="192.168.1.300"):
        plc_scanner.parse_targets("127.0.0.1,192.168.1.300")


def test_undetected_target_is_failed_not_slmp(monkeypatch, tmp_path, capsys, restore_logging):
    scanned = []

    async def fake_single_scan(plc_info, *args, **kwargs):
        scanned.append(plc_info)
        return plc_scanner.ScanOutcome(plc_info.ip_address, success=True)

    monkeypatch.setattr(plc_scanner, "run_single_scan", fake_single_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.9",
            "--device",
            "D",
            "--range",
            "0-1",
            "--no-rich",
            "-o",
            str(tmp_path),
        ],
    )
    with (
        patch("plc_discovery.discovery.PLCDiscovery._probe_host", AsyncMock(return_value=None)),
        pytest.raises(SystemExit) as exc,
    ):
        asyncio.run(plc_scanner.main())
    assert exc.value.code == 1
    assert scanned == []  # was scanned as SLMP
    out = capsys.readouterr().out
    assert "no PLC protocol answered" in out
    assert "SLMP" not in out


@pytest.mark.asyncio
async def test_r5_periodic_scan_round_robin():
    collectors = {
        "10.0.0.1": FakeCollector_2("10.0.0.1"),
        "10.0.0.2": FakeCollector_2("10.0.0.2", connected=False),
        "10.0.0.3": FakeCollector_2("10.0.0.3"),
    }
    plcs = [PLCInfo(ip, protocol=Protocol.SLMP, port=5001) for ip in collectors]
    exporter = MagicMock()

    with patch.object(plc_scanner, "PLCDataCollector", lambda plc, cfg: collectors[plc.ip_address]):
        task = asyncio.ensure_future(
            plc_scanner.run_periodic_scan(
                plcs, NetworkConfig(), exporter, Display(), [DeviceRange(DeviceType.D, 0, 0)], interval=0.01
            )
        )
        while collectors["10.0.0.3"].collect_calls < 3:
            await asyncio.sleep(0.005)
        task.cancel()
        outcomes = {o.ip_address: o for o in await task}

    assert collectors["10.0.0.1"].collect_calls >= 3
    # unreachable at the start: still polled every cycle (reconnect is retried)
    assert collectors["10.0.0.2"].collect_calls >= 2
    assert outcomes["10.0.0.1"].success and outcomes["10.0.0.3"].success
    assert not outcomes["10.0.0.2"].success
    assert "Failed to connect" in outcomes["10.0.0.2"].error
    exported_ips = {c.args[1] for c in exporter.export_plc_data.call_args_list}
    assert exported_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_cli_timing_overrides_config(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"network": {"packet_interval_ms": 300, "request_timeout_ms": 9000}}))
    loader = ConfigLoader(str(path))
    loader.load()
    config = plc_scanner.create_network_config(make_args(packet_interval=80), loader)
    assert config.packet_interval_ms == 80  # CLI wins
    assert config.request_timeout_ms == 9000  # from config file
    assert plc_scanner.create_network_config(make_args(), None) == NetworkConfig()


@pytest.mark.asyncio
async def test_periodic_scan_survives_locked_csv():
    collector = FakeCollector_3()
    exporter = MagicMock()
    exporter.export_plc_data.side_effect = PermissionError("locked by Excel")
    exporter.export_denied_addresses.side_effect = [PermissionError("locked"), "denied.csv"]

    with patch.object(plc_scanner, "PLCDataCollector", lambda *a: collector):
        task = asyncio.ensure_future(
            plc_scanner.run_periodic_scan(
                [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)],
                NetworkConfig(),
                exporter,
                Display(),
                [DeviceRange(DeviceType.D, 0, 0)],
                interval=0.01,
            )
        )
        while collector.calls < 4:
            await asyncio.sleep(0.005)
        task.cancel()
        (outcome,) = await task

    assert collector.calls >= 4  # monitoring kept running
    assert exporter.export_denied_addresses.call_count == 2  # failed write retried once, then done
    assert outcome.success is False and "write error" in outcome.error


@pytest.mark.asyncio
async def test_single_scan_reports_write_failure():
    exporter = MagicMock()
    exporter.export_plc_data.side_effect = OSError("disk full")
    with patch.object(plc_scanner, "PLCDataCollector", lambda *a: FakeCollector_3()):
        outcome = await plc_scanner.run_single_scan(
            PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
            NetworkConfig(),
            exporter,
            Display(),
            ScanMode.RANGE,
            [DeviceRange(DeviceType.D, 0, 0)],
        )
    assert outcome.success is False
    assert "disk full" in outcome.error
    assert outcome.data_points  # data was still collected


def test_docker_compose_ports_match_run_all():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    run_all = (ROOT / "simulators" / "run_all.py").read_text(encoding="utf-8")
    for port in ("5001", "1502", "44818", "1102"):
        assert f"self.host, {port}" in run_all
        assert f'"127.0.0.1:{port}:{port}"' in compose
    assert '"127.0.0.1:9600:9600/udp"' in compose and '"127.0.0.1:9600:9600/tcp"' in compose


def test_cli_rejects_sub_second_interval(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "127.0.0.1",
            "--interval",
            "0.5",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        plc_scanner.cli()
    assert exc.value.code == 1
    assert ">= 1 seconds" in capsys.readouterr().out


def test_discovery_protocols_from_cli_and_config(tmp_path, monkeypatch):
    args = MagicMock(discover_protocols="eip, fins-tcp")
    assert plc_scanner.resolve_discovery_protocols(args, None) == [Protocol.ETHERNET_IP, Protocol.FINS_TCP]
    args = MagicMock(discover_protocols=None)
    assert plc_scanner.resolve_discovery_protocols(args, load(tmp_path, {})) is None  # default: all
    loader = load(tmp_path, {"discovery": {"protocols": ["slmp", "fins_tcp"]}})
    assert plc_scanner.resolve_discovery_protocols(args, loader) == [Protocol.SLMP, Protocol.FINS_TCP]
    with pytest.raises(ValueError):
        plc_scanner.resolve_discovery_protocols(MagicMock(discover_protocols="bogus"), None)


@pytest.mark.asyncio
async def test_bad_target_does_not_stop_other_targets(tmp_path):
    """Sequential CLI scan: the invalid target fails, the next one is still scanned"""
    good = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)
    bad = PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600, options={"dest_node": 300})

    class GoodCollector:
        is_connected = True
        connect_error = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def collect_range(self, *a):
            return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": 1, "success_count": 1, "error_count": 0}

    def make(plc, config):
        return GoodCollector() if plc is good else PLCDataCollector(plc, config)

    class Display:
        def __getattr__(self, name):
            return lambda *a, **k: None

    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", make):
        outcomes = [
            await plc_scanner.run_single_scan(
                plc,
                NetworkConfig(),
                exporter,
                Display(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 0)],
            )
            for plc in (bad, good)
        ]

    assert outcomes[0].success is False
    assert "invalid options" in outcomes[0].error and "dest_node" in outcomes[0].error
    assert outcomes[1].success is True


def test_make_streams_safe_replaces_unencodable(monkeypatch):
    out, err = cp932_stream(), cp932_stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    plc_scanner.make_streams_safe()
    print("Dürr ✓ 三菱電機")  # would raise UnicodeEncodeError before
    out.flush()
    assert out.buffer.getvalue().decode("cp932").strip() == "D?rr ? 三菱電機"


def test_third_party_loggers_quiet_unless_verbose():
    plc_scanner.quiet_third_party_loggers(verbose=False)
    assert logging.getLogger("pycomm3").level == logging.CRITICAL
    assert logging.getLogger("pymodbus").level == logging.CRITICAL
    plc_scanner.quiet_third_party_loggers(verbose=True)
    assert logging.getLogger("pycomm3").level == logging.DEBUG
    plc_scanner.quiet_third_party_loggers(verbose=False)


@pytest.mark.parametrize(
    "mode, ranges, expected",
    [
        (ScanMode.RANGE, [DeviceRange(DeviceType.D, 0, 2), TagRange(["A"])], ["D0", "D1", "D2", "A"]),
        (ScanMode.FULL, None, ["D0", "D1", "M0"]),
    ],
)
def test_single_scan_writes_requested_addresses_when_offline(monkeypatch, tmp_path, mode, ranges, expected):
    monkeypatch.setattr(plc_scanner, "PLCDataCollector", OfflineCollector)
    monkeypatch.setattr(
        collector_module,
        "DEFAULT_DEVICE_RANGES",
        {Protocol.SLMP: [DeviceRange(DeviceType.D, 0, 1), DeviceRange(DeviceType.M, 0, 0)]},
    )
    plc = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)
    outcome = asyncio.run(
        plc_scanner.run_single_scan(
            plc, MagicMock(), CSVExporter(str(tmp_path)), MagicMock(), mode, device_ranges=ranges
        )
    )
    assert not outcome.success and "connection refused" in outcome.error
    assert [p.address for p in outcome.data_points] == expected
    assert {p.status for p in outcome.data_points} == {StatusCode.NG_COMM_ERROR}
    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1 and "NG_COMM_ERROR" in files[0].read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("value", ["nan", "inf", "-5"])
def test_non_finite_or_negative_interval_rejected_on_cli(monkeypatch, tmp_path, capsys, value):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.9",
            "--device",
            "D",
            "--range",
            "0-0",
            f"--interval={value}",
            "--output-dir",
            str(tmp_path),
        ],
    )
    with (
        patch.object(plc_scanner, "run_single_scan", AsyncMock()) as scan,
        patch.object(plc_scanner, "run_periodic_scan", AsyncMock()) as periodic,
    ):
        with pytest.raises(SystemExit) as exit_info:
            asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "--interval" in capsys.readouterr().out
    scan.assert_not_called()
    periodic.assert_not_called()


def test_outage_is_reported_once_the_webhook_works_again(monkeypatch):
    monkeypatch.setattr("plc_discovery.scan_runner.NOTIFY_RETRY_SECONDS", 0.0)
    notifier = MagicMock()
    results = [{"hook": False}, {"hook": False}, {"hook": True}]
    notifier.notify_unreachable = AsyncMock(side_effect=lambda *a, **k: results.pop(0))
    notifier.notify_recovered = AsyncMock(return_value={"hook": True})

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    async def run():
        runner = CycleRunner(None, notify=notify)
        for _ in range(5):  # down for five cycles; the webhook fails twice
            await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.track_outage("PLC1", True, "10.0.0.1")

    asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 3  # two failures, then delivered once
    assert notifier.notify_recovered.await_count == 1


def test_undelivered_outage_waits_before_it_is_retried():
    notifier = MagicMock()
    notifier.notify_unreachable = AsyncMock(return_value={"hook": False})

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    async def run():
        runner = CycleRunner(None, notify=notify)
        for _ in range(5):
            await runner.track_outage("PLC1", False, "10.0.0.1")

    asyncio.run(run())
    # Not once per cycle: a dead webhook must not slow down every read cycle
    assert notifier.notify_unreachable.await_count == 1


def _points(status, count=3):
    return [
        DataPoint(address=f"D{i}", status=status, value=1 if status == StatusCode.OK else None) for i in range(count)
    ]


def test_plc_answered_tells_no_answer_from_address_errors():
    assert plc_answered([]) and plc_answered(_points(StatusCode.OK))
    assert plc_answered(_points(StatusCode.NG_ILLEGAL_ADDR))  # the PLC said so itself
    assert plc_answered(_points(StatusCode.NG_TIMEOUT) + _points(StatusCode.OK, 1))
    silent = _points(StatusCode.NG_TIMEOUT, 2) + _points(StatusCode.NG_COMM_ERROR, 1)
    assert not plc_answered(silent)
    assert "none of the 3 addresses" in no_answer_error(silent) and "2 NG_TIMEOUT" in no_answer_error(silent)
    assert no_answer_error(_points(StatusCode.OK)) is None


FAST_200MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=1, request_timeout_ms=200)


class _FakeCollector:
    """Connected collector whose reads give ``status`` for every address"""

    status = StatusCode.NG_TIMEOUT

    def __init__(self, plc_info, config=None):
        self.is_connected = True
        self.connect_error = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    def clear_data(self):
        pass

    async def collect_range(self, device_type, start, end):
        return _points(self.status)

    def get_collected_data(self):
        return _points(self.status)

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 3, "success_count": 0, "error_count": 0}


def _single_scan(collector_class):
    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", collector_class):
            return await plc_scanner.run_single_scan(
                PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                FAST_200MS,
                MagicMock(hex_addresses=False),
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 2)],
            )

    return asyncio.run(run())


def test_scan_that_nothing_answered_is_a_failure():
    outcome = _single_scan(_FakeCollector)
    assert not outcome.success and "answered none" in outcome.error
    assert len(outcome.data_points) == 3  # still written as read


def test_scan_with_address_errors_only_is_not_a_failure():
    class Illegal(_FakeCollector):
        status = StatusCode.NG_ILLEGAL_ADDR

    outcome = _single_scan(Illegal)
    assert outcome.success and outcome.error is None


def test_connected_but_silent_plc_is_reported_unreachable_and_recovers():
    """FINS/UDP has no connection to lose: is_connected stays True"""
    statuses = [StatusCode.OK, StatusCode.NG_TIMEOUT, StatusCode.NG_TIMEOUT, StatusCode.OK, StatusCode.OK]

    class Collector(_FakeCollector):
        reads = 0

        async def collect_range(self, device_type, start, end):
            status = statuses[min(Collector.reads, len(statuses) - 1)]
            Collector.reads += 1
            return _points(status)

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600)],
                    NetworkConfig(),
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.DM, 0, 2)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(400):
                if notifier.notify_recovered.await_count:
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            return await task

    outcomes = asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1  # once for the outage
    assert notifier.notify_recovered.await_count == 1
    assert outcomes[0].success  # answering again when the monitoring ended


def test_interrupted_single_scan_writes_what_was_read():
    exporter = MagicMock(hex_addresses=False)
    exporter.export_plc_data.return_value = "/tmp/out.csv"

    class Interrupted(_FakeCollector):
        status = StatusCode.OK

        async def collect_range(self, device_type, start, end):
            await asyncio.sleep(60)

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Interrupted):
            task = asyncio.ensure_future(
                plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST_200MS,
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 2)],
                )
            )
            await asyncio.sleep(0.05)
            task.cancel()
            return await task  # handled: the outcome is returned, not CancelledError

    outcome = asyncio.run(run())
    assert outcome.interrupted and len(outcome.data_points) == 3
    written = exporter.export_plc_data.call_args.args[0]
    assert [p.address for p in written] == ["D0", "D1", "D2"]


def _resolve(protocol, port, target):
    seen = {}

    async def resolve_target(ip, protocol, port, config, display, base=None):
        seen.update(protocol=protocol, port=port, options=dict(base.options))
        return base

    loader = MagicMock()
    loader.get_targets.return_value = [target]
    args = MagicMock(target=None, protocol=protocol, port=port)
    with patch.object(plc_scanner, "resolve_target", resolve_target):
        asyncio.run(plc_scanner._resolve_targets(args, loader, FAST_200MS, MagicMock()))
    return seen


def test_protocol_override_does_not_keep_the_port_and_options_of_the_file():
    def target():
        return PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, options={"frame": "3E"})

    # Another protocol: its own default port (None here), no SLMP options
    assert _resolve("modbus", None, target()) == {"protocol": Protocol.MODBUS_TCP, "port": None, "options": {}}
    assert _resolve("modbus", 1502, target())["port"] == 1502
    # Same protocol, or no --protocol: the file's port and options stay
    assert _resolve("slmp", None, target()) == {"protocol": Protocol.SLMP, "port": 5001, "options": {"frame": "3E"}}
    assert _resolve(None, None, target())["port"] == 5001


def test_stop_request_is_not_lost_while_a_notification_finishes():
    """
    asyncio.wait_for of Python 3.10 / 3.11 drops a cancellation that arrives
    when the awaited notification has just finished: the periodic scan went
    on reading after it was told to stop (and CI hung on that test).
    """

    async def notify(send):
        return True

    async def stopped_after(ticks):
        runner = CycleRunner(None, notify=notify)

        async def cycle():
            await runner.track_outage("PLC1", False, "10.0.0.1")
            await asyncio.sleep(3600)  # the rest of the read cycle

        task = asyncio.ensure_future(cycle())
        for _ in range(ticks):
            await asyncio.sleep(0)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5)
        except asyncio.CancelledError:
            return True
        except asyncio.TimeoutError:
            return False
        return False

    async def run():
        # Whatever the moment of the request: before, while and after the send
        return [await stopped_after(ticks) for ticks in range(8)]

    assert asyncio.run(run()) == [True] * 8


def test_max_concurrent_option_has_the_limit_of_the_config_file():
    def errors(value):
        args = argparse.Namespace(**{attr: None for attr, _ in NETWORK_OPTIONS.values()})
        args.max_concurrent = value
        return network_option_errors(args)

    assert errors(MAX_CONCURRENT) == []
    assert any("--max-concurrent" in e and str(MAX_CONCURRENT) in e for e in errors(500))


def test_undetected_target_still_gets_its_addresses_written(monkeypatch, tmp_path, capsys):
    class NothingAnswers:
        def __init__(self, config, port=None):
            pass

        async def _probe_host(self, ip):
            return None

    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--device", "HR", "--range", "0-9"]
    monkeypatch.setattr(sys, "argv", argv + ["--output-dir", str(tmp_path), "--no-rich"])
    with patch.object(plc_scanner, "PLCDiscovery", NothingAnswers):
        with pytest.raises(SystemExit) as exit_info:
            asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "no PLC protocol answered" in capsys.readouterr().out

    files = list(tmp_path.glob("plc_data_*.csv"))
    assert len(files) == 1
    with open(files[0], encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [row["address"] for row in rows] == [f"HR{a}" for a in range(10)]
    assert {row["status"] for row in rows} == {"NG_COMM_ERROR"}


def test_audit_error_count_is_every_point_that_was_not_read(tmp_path):
    points = [
        DataPoint(address="D0", status=StatusCode.OK, value=1),
        DataPoint(address="D1", status=StatusCode.NG_ILLEGAL_ADDR),
        DataPoint(address="D2", status=StatusCode.NG_ILLEGAL_ADDR),
        DataPoint(address="D3", status=StatusCode.NG_TIMEOUT),
    ]

    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = True
            self.connect_error = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def collect_range(self, device_type, start, end):
            return points

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            # error_count as the collector reports it: communication errors only
            return {"total_points": 4, "success_count": 1, "error_count": 0}

    log = tmp_path / "audit.jsonl"
    init_audit_logger(str(log))
    try:

        async def run():
            with patch.object(plc_scanner, "PLCDataCollector", Collector):
                await plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST_200MS,
                    MagicMock(hex_addresses=False),
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 3)],
                )

        asyncio.run(run())
    finally:
        close_audit_logger()

    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    complete = [e for e in events if e["event_type"] == "SCAN_COMPLETE"]
    assert len(complete) == 1 and complete[0]["data_points"] == 4
    assert (complete[0]["metadata"]["success_count"], complete[0]["metadata"]["error_count"]) == (1, 3)


def _points_2(status, count, cached=False, first=0):
    return [DataPoint(address=f"D{first + i}", status=status, cached=cached) for i in range(count)]


def test_learned_addresses_are_no_sign_of_an_answer():
    learned = _points_2(StatusCode.NG_ILLEGAL_ADDR, 2, cached=True, first=100)
    silent = _points_2(StatusCode.NG_TIMEOUT, 3) + _points_2(StatusCode.NG_COMM_ERROR, 1, first=3)
    assert not plc_answered(silent + learned)
    assert no_answer_error(silent + learned) == (
        "the PLC answered none of the 4 addresses read (3 NG_TIMEOUT, 1 NG_COMM_ERROR)"
    )
    # An address error the PLC answered in this read is an answer
    assert plc_answered(silent + _points_2(StatusCode.NG_ILLEGAL_ADDR, 1, first=50))
    assert plc_answered(silent + learned + _points_2(StatusCode.OK, 1, first=60))
    # Nothing was requested: nothing is known, as for an empty read
    assert plc_answered(learned) and no_answer_error(learned) is None
    # A learned timeout is not a request of this read either
    assert plc_answered(_points_2(StatusCode.NG_TIMEOUT, 1, cached=True) + _points_2(StatusCode.OK, 2, first=10))
    assert plc_answered(_points_2(StatusCode.NG_TIMEOUT, 1, cached=True) + learned)


def _points_3(status, count, cached=False, first=0):
    return [DataPoint(address=f"D{first + i}", status=status, cached=cached) for i in range(count)]


def test_unsupported_is_no_sign_of_an_answer():
    # Mostly decided without a request: a device type the protocol lacks,
    # tags on a PLC that has none
    unsupported = _points_3(StatusCode.NG_UNSUPPORTED, 2, first=200)
    assert plc_answered(unsupported)
    assert not plc_answered(_points_3(StatusCode.NG_TIMEOUT, 3) + unsupported)


class _Udp(BaseProtocolHandler):
    """No connection to lose: stays "connected" when the PLC is switched off"""

    protocol = Protocol.FINS

    def __init__(self):
        super().__init__("127.0.0.1", 9600, FAST_200MS)
        self._connected = True
        self.power = True
        self.requests = 0

    async def connect(self):
        self._connected = True
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests += 1
        if not self.power:
            return None, StatusCode.NG_TIMEOUT
        if start_address <= 5 < start_address + count:  # DM5 does not exist
            return None, StatusCode.NG_ILLEGAL_ADDR
        return list(range(start_address, start_address + count)), StatusCode.OK


def test_switched_off_plc_is_not_answering_although_an_address_was_learned():
    async def run():
        handler = _Udp()
        device_range = DeviceRange(DeviceType.DM, 0, 9)
        first = await handler.read_device_range(device_range)
        handler.power = False
        return first, [await handler.read_device_range(device_range) for _ in range(3)], handler

    first, later, handler = asyncio.run(run())
    assert Counter(p.status for p in first) == {StatusCode.OK: 9, StatusCode.NG_ILLEGAL_ADDR: 1}
    assert plc_answered(first) and not any(p.cached for p in first)  # DM5: the PLC said so itself
    assert handler.is_connected
    for points in later:
        by_address = {p.address: p for p in points}
        assert len(points) == 10
        assert (by_address["DM5"].status, by_address["DM5"].cached) == (StatusCode.NG_ILLEGAL_ADDR, True)
        assert not plc_answered(points)


def test_periodic_scan_reports_the_outage_with_a_learned_address_in_the_range():
    learned = DataPoint(address="DM5", status=StatusCode.NG_ILLEGAL_ADDR, cached=True)

    def cycle(status):
        value = 1 if status == StatusCode.OK else None
        return [DataPoint(address=f"DM{i}", status=status, value=value) for i in range(5)] + [learned]

    cycles = [cycle(StatusCode.OK), cycle(StatusCode.NG_TIMEOUT), cycle(StatusCode.NG_TIMEOUT), cycle(StatusCode.OK)]

    class Collector:
        reads = 0
        is_connected = True  # FINS/UDP: nothing to lose
        connect_error = None

        def __init__(self, plc_info, config=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def disconnect(self):
            pass

        def clear_data(self):
            pass

        def get_collected_data(self):
            return []

        async def collect_range(self, device_type, start, end):
            points = cycles[min(Collector.reads, len(cycles) - 1)]
            Collector.reads += 1
            return points

        def get_denied_addresses(self):
            return {"DM5"}

        def get_denied_statuses(self):
            return {"DM5": StatusCode.NG_ILLEGAL_ADDR}

        def get_statistics(self):
            return {"total_points": 6, "success_count": 5, "error_count": 0}

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600)],
                    FAST_200MS,
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.DM, 0, 5)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(400):
                if notifier.notify_recovered.await_count or task.done():
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            return await asyncio.wait_for(task, timeout=10)

    outcomes = asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1
    assert notifier.notify_recovered.await_count == 1
    assert outcomes[0].success


def test_cycle_start_keeps_the_schedule_and_restarts_it_when_late():
    async def run():
        now = asyncio.get_running_loop().time()
        first = cycle_start(1.0, None)
        on_time = cycle_start(1.0, now - 1.003)  # the sleep overshot by 3 ms
        late = cycle_start(1.0, now - 2.0)  # the read took a whole interval too long
        return now, first, on_time, late, cycle_start(None, now - 5)

    now, first, on_time, late, single = asyncio.run(run())
    assert first == pytest.approx(now, abs=0.05)
    assert on_time == pytest.approx(now - 0.003, abs=1e-6)  # the scheduled time, not "now": no drift
    assert late == pytest.approx(now, abs=0.05)
    assert single == pytest.approx(now, abs=0.05)


def test_status_report_is_not_sent_twice_at_once(monkeypatch, caplog):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.01)
    sends = []

    async def run():
        gate = asyncio.Event()

        async def notify(send):
            sends.append(1)
            await gate.wait()
            return False  # the webhook finally fails

        runner = CycleRunner(None, notifier=MagicMock(report_interval_seconds=0.001), notify=notify)
        for iteration in (1, 2, 3):
            await runner.report_if_due({"PLC1": []}, [], iteration)
            await asyncio.sleep(0.01)
        in_flight = len(runner._in_flight)
        gate.set()
        await runner.drain()
        return in_flight, dict(runner._in_flight)

    with caplog.at_level("WARNING"):
        in_flight, after = asyncio.run(run())
    assert sends == [1]  # was one more for every due report, and drain() lost track of them
    assert in_flight == 1 and after == {}
    assert NotificationType.STATUS_REPORT.value in caplog.text
    assert "it will be retried" not in caplog.text  # nothing retries a status report


def test_interrupted_scan_does_not_count_unscanned_targets_as_successful():
    notifier = MagicMock()
    notifier.notify_scan_complete = AsyncMock(return_value={"hook": True})
    results = plc_scanner._RunResults(plcs=[MagicMock(), MagicMock(), MagicMock()], interrupted=True)
    results.add("10.0.0.1", True, None, [], set())  # Ctrl+C during the first of three

    asyncio.run(plc_scanner._notify_scan_end(notifier, "range", results, 1.0))
    assert notifier.notify_scan_complete.await_args.args[:3] == (1, 1, 0)  # was (3, 3, 0)

    results.interrupted = False
    asyncio.run(plc_scanner._notify_scan_end(notifier, "range", results, 1.0))
    assert notifier.notify_scan_complete.await_args.args[:3] == (3, 3, 0)


@pytest.mark.parametrize("port", ["70000", "0", "-1", "abc"])
def test_port_option_is_range_checked(monkeypatch, capsys, port):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--mode", "discover", f"--port={port}"])
    with pytest.raises(SystemExit) as exit_info:
        parse_args()
    assert exit_info.value.code == 2 and "1-65535" in capsys.readouterr().err


def test_unusable_output_directory_is_an_error_message(monkeypatch, tmp_path, capsys):
    occupied = tmp_path / "afile"
    occupied.write_text("x")
    audit = tmp_path / "audit.jsonl"
    argv = ["plc_scanner.py", "--mode", "discover", "--ip-range", "127.0.0.1", "-o", str(occupied)]
    monkeypatch.setattr(sys, "argv", argv + ["--no-rich", "--audit-log", str(audit)])
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())  # was a FileExistsError traceback
    assert exit_info.value.code == 1
    assert "Cannot use the output directory" in capsys.readouterr().out
    events = [json.loads(line)["event_type"] for line in audit.read_text(encoding="utf-8").splitlines()]
    assert events[0] == "SESSION_START" and events[-1] == "SESSION_END"  # the session is closed


FAST_100MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=100)


class _Device(BaseProtocolHandler):
    """Stays "connected"; ``answer(device_type, start, count)`` decides each request"""

    protocol = Protocol.MODBUS_TCP
    EDGE_PROBE_SHORTCUT = False

    def __init__(self, answer):
        super().__init__("10.0.0.1", 502, FAST_100MS)
        self._connected = True
        self.answer = answer
        self.requests: list = []

    async def connect(self):
        self._connected = True
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        self.requests.append((device_type, start_address, count))
        status = self.answer(device_type, start_address, count)
        if status == StatusCode.OK:
            return [7] * count, status
        return None, status


def test_other_ranges_are_still_read_after_the_first_one_went_unanswered():
    # A gateway that drops requests touching a missing holding register
    # looks like a dead link until something answers: the input registers do
    valid_hr = set(range(40, 61))

    def answer(device_type, start, count):
        if device_type == DeviceType.HR and any(a not in valid_hr for a in range(start, start + count)):
            return StatusCode.NG_TIMEOUT
        return StatusCode.OK

    async def run():
        handler = _Device(answer)
        hr = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 299))
        ir = await handler.read_device_range(DeviceRange(DeviceType.IR, 0, 99))
        return handler, hr, ir

    handler, hr, ir = asyncio.run(run())
    assert len(hr) == 300 and len(ir) == 100
    assert all(p.status == StatusCode.OK for p in ir)  # was never requested: 100 x NG_COMM_ERROR
    assert plc_answered(hr + ir)
    assert handler.circuit_breaker_state == "closed"


def test_plc_that_never_answers_costs_a_bounded_number_of_requests():
    async def run():
        handler = _Device(lambda *request: StatusCode.NG_TIMEOUT)
        per_cycle = []
        for _ in range(60):
            before = len(handler.requests)
            for device_type in (DeviceType.HR, DeviceType.IR, DeviceType.D):
                points = await handler.read_device_range(DeviceRange(device_type, 0, 999))
                assert len(points) == 1000 and plc_answered(points) is False
            per_cycle.append(len(handler.requests) - before)
        return handler, per_cycle

    handler, per_cycle = asyncio.run(run())
    # One request per range and cycle while the session budget lasts, then none
    assert max(per_cycle[1:]) <= 3
    assert sum(per_cycle) <= 13 + handler.UNANSWERED_SESSION_BUDGET + 60  # search, probes, breaker retries
    assert per_cycle[-1] <= 1


def test_interrupted_parallel_scan_writes_and_reports_what_was_read():
    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = False
            self.connect_error = None
            self.skip_reconnect = False
            self.data: list = []

        async def __aenter__(self):
            self.is_connected = True
            return self

        async def __aexit__(self, *exc):
            await asyncio.sleep(0.05)  # closing the connection takes a moment
            self.is_connected = False

        async def collect_range(self, device_type, start, end):
            for address in range(start, end + 1):
                self.data.append(DataPoint(address=f"D{address}", value=1, raw_hex="0001", timestamp=get_timestamp()))
                await asyncio.sleep(0.02)
            return self.data

        def get_collected_data(self):
            return self.data

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": len(self.data), "success_count": len(self.data), "error_count": 0}

    exporter = MagicMock(hex_addresses=False)
    plcs = [PLCInfo(f"10.0.0.{i}", protocol=Protocol.SLMP, port=5001) for i in (1, 2, 3)]

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_parallel_scan(
                    plcs,
                    NetworkConfig(max_concurrent=2),
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 999)],
                )
            )
            await asyncio.sleep(0.2)
            task.cancel()  # Ctrl+C
            return await asyncio.wait_for(task, timeout=10)

    results = asyncio.run(run())
    # The third target was still waiting for its turn: not scanned, not reported
    assert sorted(results) == ["10.0.0.1", "10.0.0.2"]
    for outcome in results.values():
        assert outcome.interrupted and len(outcome.data_points) >= 3
    # Was 0: the scanning targets were cancelled again before they had written
    assert exporter.export_plc_data.call_count == 2


def _unit(unit_id=None, ip="10.0.0.5"):
    options = {} if unit_id is None else {"unit_id": unit_id}
    return PLCInfo(ip, protocol=Protocol.MODBUS_TCP, port=502, options=options)


def test_single_target_on_an_endpoint_keeps_its_file_name_and_protocol(tmp_path):
    exporter = MagicMock(hex_addresses=False)
    db = MagicMock(is_enabled=True)
    writer = ResultWriter(_unit(1), exporter, db_exporter=db, label="10.0.0.5 (MODBUS_TCP:502)")
    writer.export_points([DataPoint(address="HR0", value=1)])
    assert exporter.export_plc_data.call_args.kwargs["target_tag"] == "MODBUS_TCP_502"
    assert db.export_plc_data.call_args.kwargs["protocol"] == "MODBUS_TCP"


FAST_500MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


class _Logix:
    """LogixDriver stand-in; ``state`` is shared by every instance"""

    state: dict = {}

    def __init__(self, path, init_tags=True):
        self.state.setdefault("created", []).append(init_tags)
        self._tags = (
            {f"T{i:03d}": {"tag_type": "atomic", "dimensions": [0, 0, 0]} for i in range(100)} if init_tags else {}
        )
        self._data_types: dict = {}
        self._cfg = {"use_instance_ids": True}

    tags = property(lambda self: self._tags)
    data_types = property(lambda self: self._data_types)
    info = property(lambda self: {"serial": self.state.get("serial", "A1"), "name": "Line1"})

    def open(self):
        self.state["opens"] = self.state.get("opens", 0) + 1
        if not self.state.get("up", True):
            raise CommError("failed to open a connection")
        return True

    def close(self):
        pass

    def read(self, *tags):
        if not self.state.get("up", True):
            raise CommError("failed to receive reply")
        if self.state.get("off_at") in tags:
            self.state["up"] = False
            raise CommError("failed to receive reply")
        self.state["instance_ids"] = self._cfg["use_instance_ids"]
        return [Tag(tag, 1, "DINT", None) for tag in tags]


@pytest.fixture
def logix(monkeypatch):
    _Logix.state = {}
    for driver in ("LogixDriver", "SLCDriver", "CIPDriver"):
        monkeypatch.setattr(pycomm3, driver, _Logix)
    return _Logix.state


def test_logix_full_scan_reads_tags_again_after_an_outage(logix):
    async def run():
        collector = PLCDataCollector(PLCInfo("10.0.0.2", port=44818, protocol=Protocol.ETHERNET_IP), FAST_500MS)
        assert await collector.connect()
        cycles = [await collector.collect_full_scan()]
        for up in (False, False, True, True):
            logix["up"] = up
            cycles.append(await collector.collect_full_scan())
        return cycles, collector.get_denied_addresses()

    cycles, denied = asyncio.run(run())
    assert [len(points) for points in cycles] == [100, 100, 1, 100, 100]
    # Back on: tags, not 512 rows of the SLC data files as NG_UNSUPPORTED
    assert all(p.is_tag and p.status == StatusCode.OK for p in cycles[3])
    assert denied == set()
    assert not plc_answered(cycles[1]) and not plc_answered(cycles[2])


def _collector_class(connect_seconds=0.0, disconnect_seconds=0.0, read_seconds=0.0):
    class Collector:
        def __init__(self, plc_info, config=None):
            self.is_connected = False
            self.connect_error = None
            self.skip_reconnect = False
            self.data: list = []

        async def __aenter__(self):
            await asyncio.sleep(connect_seconds)
            self.is_connected = True
            return self

        async def __aexit__(self, *exc):
            await asyncio.sleep(disconnect_seconds)
            self.is_connected = False

        async def disconnect(self):
            self.is_connected = False

        async def collect_range(self, device_type, start, end):
            await asyncio.sleep(read_seconds)
            self.data = [
                DataPoint(address=f"D{a}", value=1, raw_hex="0001", timestamp=get_timestamp())
                for a in range(start, end + 1)
            ]
            return self.data

        def get_collected_data(self):
            return self.data

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": len(self.data), "success_count": len(self.data), "error_count": 0}

    return Collector


def _interrupted_scan(collector_class, cancel_after):
    exporter = MagicMock(hex_addresses=False)

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", collector_class):
            task = asyncio.ensure_future(
                plc_scanner.run_single_scan(
                    PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                    FAST_500MS,
                    exporter,
                    MagicMock(),
                    ScanMode.RANGE,
                    [DeviceRange(DeviceType.D, 0, 9)],
                )
            )
            await asyncio.sleep(cancel_after)
            task.cancel()  # Ctrl+C
            return await asyncio.wait_for(task, timeout=10)

    return asyncio.run(run()), exporter


def test_complete_scan_is_written_although_interrupted_while_disconnecting():
    outcome, exporter = _interrupted_scan(_collector_class(disconnect_seconds=5), cancel_after=0.2)
    # Was CancelledError out of run_single_scan: nothing written, no report
    assert outcome.interrupted and outcome.success and len(outcome.data_points) == 10
    assert exporter.export_plc_data.call_count == 1


def test_interruption_while_connecting_is_reported_not_raised():
    outcome, exporter = _interrupted_scan(_collector_class(connect_seconds=5), cancel_after=0.2)
    # The run goes on to its report with the targets already scanned
    assert outcome.interrupted and not outcome.success and outcome.data_points == []
    assert "interrupted" in outcome.error
    assert exporter.export_plc_data.call_count == 0


class _Modbus(BaseProtocolHandler):
    protocol = Protocol.MODBUS_TCP
    EDGE_PROBE_SHORTCUT = False
    MAX_ADDRESS = 0xFFFF

    def __init__(self, status):
        super().__init__("10.0.0.1", 502, FAST_500MS)
        self._connected = True
        self.status = status

    async def connect(self):
        return True

    async def disconnect(self):
        pass

    async def read_device_raw(self, device_type, start_address, count):
        return ([7] * count if self.status == StatusCode.OK else None), self.status


def test_addresses_beyond_the_protocol_limit_are_no_answer_of_the_plc():
    crossing = DeviceRange(DeviceType.HR, 65500, 65600)
    silent = asyncio.run(_Modbus(StatusCode.NG_TIMEOUT).read_device_range(crossing))
    assert len(silent) == 101 and not plc_answered(silent)  # was "answered": success, never "down"

    answering = asyncio.run(_Modbus(StatusCode.OK).read_device_range(crossing))
    by_address = {p.address: p for p in answering}
    assert by_address["HR65535"].status == StatusCode.OK
    assert (by_address["HR65536"].status, by_address["HR65536"].cached) == (StatusCode.NG_ILLEGAL_ADDR, True)
    assert plc_answered(answering)


def test_unexpected_error_of_one_target_is_its_own_failure():
    async def run_single_scan(plc_info, *args, **kwargs):
        raise RuntimeError("driver bug")

    exporter = MagicMock(hex_addresses=False)

    async def run():
        with patch.object(plc_scanner, "run_single_scan", run_single_scan):
            return await plc_scanner.scan_target(
                PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001),
                FAST_500MS,
                exporter,
                MagicMock(),
                ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 3)],
                None,
                ByteOrder.LITTLE_ENDIAN,
                None,
                None,
                "10.0.0.1",
                None,
            )

    outcome = asyncio.run(run())  # raised in a sequential scan: the other targets were never scanned
    assert not outcome.success and outcome.error == "driver bug"
    assert [p.status for p in outcome.data_points] == [StatusCode.NG_COMM_ERROR] * 4
    assert exporter.export_plc_data.call_count == 1


def test_periodic_scan_goes_on_after_an_unexpected_error_of_a_read():
    class Collector(_collector_class()):
        reads = 0

        def __init__(self, plc_info, config=None):
            super().__init__(plc_info, config)
            self.is_connected = True

        def clear_data(self):
            pass

        async def collect_range(self, device_type, start, end):
            Collector.reads += 1
            if Collector.reads == 2:
                raise RuntimeError("driver bug")
            return await super().collect_range(device_type, start, end)

    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_unreachable = AsyncMock()
    notifier.notify_recovered = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)],
                    FAST_500MS,
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 0, 2)],
                    interval=0.01,
                    notifier=notifier,
                )
            )
            for _ in range(1000):
                if notifier.notify_recovered.await_count or task.done():
                    break
                await asyncio.sleep(0.005)
            assert not task.done()  # the monitoring ended with the exception
            task.cancel()
            return await asyncio.wait_for(task, timeout=10)

    asyncio.run(run())
    assert notifier.notify_unreachable.await_count == 1 and notifier.notify_recovered.await_count == 1


def test_arguments_are_checked_before_the_audit_log_and_database_are_opened(monkeypatch, tmp_path, capsys):
    audit, database = tmp_path / "audit.jsonl", tmp_path / "plc.db"
    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--device", "D", "--range", "0-1"]
    argv += ["--threshold", "D0>>x", "--audit-log", str(audit), "--database", str(database), "--no-rich"]
    monkeypatch.setattr(sys, "argv", argv + ["--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    # Was a session left open in the audit log, and a database already cleaned up
    assert not audit.exists() and not database.exists()


def test_locked_database_does_not_stop_the_scan(monkeypatch, tmp_path, capsys):
    database = MagicMock(is_enabled=True)
    database.begin_session.side_effect = RuntimeError("database is locked")
    monkeypatch.setattr(plc_scanner, "_create_db_exporter", lambda *args: database)
    monkeypatch.setattr(plc_scanner, "PLCDataCollector", _collector_class())
    argv = ["plc_scanner.py", "--mode", "range", "--target", "10.255.255.1", "--protocol", "slmp"]
    argv += ["--device", "D", "--range", "0-3", "--no-rich", "--output-dir", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", argv)
    asyncio.run(plc_scanner.main())  # exit 1 "database is locked", and no PLC was scanned
    assert "Database session could not be started" in capsys.readouterr().out
    assert len(list(tmp_path.glob("plc_data_*.csv"))) == 1


def _point(address, status=StatusCode.OK, value=1):
    ok = status == StatusCode.OK
    return DataPoint(address=address, value=value if ok else None, status=status, timestamp=get_timestamp())


def _run_scans(tmp_path, monkeypatch, detected, undetected):
    async def resolve(args, config_loader, config, display):
        return detected, undetected

    async def scan(plc_info, config, exporter, display, mode, ranges, data_type, byte_order, manager, db, label, inst):
        return plc_scanner.ScanOutcome(plc_info.ip_address, [_point("D0")], success=True, label=label)

    monkeypatch.setattr(plc_scanner, "_resolve_targets", resolve)
    monkeypatch.setattr(plc_scanner, "scan_target", scan)
    results = plc_scanner._RunResults()
    asyncio.run(
        plc_scanner._run_scans(
            SimpleNamespace(),
            None,
            ScanMode.FULL.value,
            0.0,
            NetworkConfig(),
            CSVExporter(str(tmp_path), "utf-8-sig"),
            MagicMock(),
            None,
            None,
            (None, ByteOrder.LITTLE_ENDIAN, None),
            [],
            results,
        )
    )
    return results


def test_undetected_target_keeps_its_rows_beside_a_detected_one_on_the_same_ip(tmp_path, monkeypatch):
    detected = [PLCInfo(ip_address="10.0.0.1", protocol=Protocol.SLMP, port=5001)]
    results = _run_scans(tmp_path, monkeypatch, detected, ["10.0.0.1", "10.0.0.1", "10.0.0.2"])
    assert list(results.data_points) == [
        "10.0.0.1 (protocol not detected)",
        "10.0.0.1 (protocol not detected) #2",
        "10.0.0.2",
        "10.0.0.1",
    ]
    # was: the detected target's data under the name of the failed one
    assert results.data_points["10.0.0.1"][0].status == StatusCode.OK
    assert results.data_points["10.0.0.1 (protocol not detected)"][0].status == StatusCode.NG_COMM_ERROR
    assert results.failed_targets == list(results.data_points)[:3]


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--mode", "range", "--target", "127.0.0.1", "--protocol", "slmp", "--range", "5-"], "Invalid address range"),
        (["--mode", "range", "--target", "127.0.0.1", "--protocol", "slmp", "--range", "9-3"], "start must be <= end"),
        (["--mode", "full", "--target", "127.0.0.1,bad host", "--protocol", "slmp"], "Invalid --target"),
        (["--mode", "discover", "--ip-range", "127.0.0.1", "--discover-protocols", "slmp,foo"], "Unknown protocol"),
    ],
)
def test_mistyped_arguments_end_the_run_before_anything_is_opened(tmp_path, monkeypatch, capsys, arguments, message):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"notifications": [{"name": "n", "type": "webhook", "url": "http://127.0.0.1:9/hook"}]}),
        encoding="utf-8",
    )
    audit = tmp_path / "audit.jsonl"
    database = tmp_path / "data.db"
    notify = AsyncMock(return_value=True)
    monkeypatch.setattr(plc_scanner, "_notify", notify)
    monkeypatch.setattr(
        "sys.argv",
        ["plc_scanner.py", "--no-rich", "-c", str(config), "-o", str(tmp_path / "out")]
        + ["--audit-log", str(audit), "--database", str(database)]
        + arguments,
    )
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.run_cli())
    assert exit_info.value.code == 1
    assert message in capsys.readouterr().out
    notify.assert_not_called()  # was a "PLC Scan Error" at priority HIGH
    # ... and no audit session or database is left behind for a run that never started
    assert not audit.exists() and not database.exists() and not (tmp_path / "out").exists()


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


def test_slow_notification_finishes_in_the_background(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.01)
    sends = []

    async def run():
        gate = asyncio.Event()  # the webhook answers when this is set (no wall-clock assumptions)

        async def notify(send):
            sends.append("started")
            await gate.wait()
            sends.append("delivered")
            return True

        runner = CycleRunner(None, notify=notify)
        # Returns although the send is not finished: the read cycle goes on
        await asyncio.wait_for(runner.track_outage("PLC1", False, "10.0.0.1"), timeout=5)
        assert sends == ["started"] and runner._reported_down == set()
        # Next cycles while it is still being sent: not sent a second time
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.track_outage("PLC1", False, "10.0.0.1")
        assert sends == ["started"]
        gate.set()
        await runner.drain()
        return set(runner._reported_down)

    assert asyncio.run(run()) == {"PLC1"}
    assert sends == ["started", "delivered"]


def test_slow_notification_that_fails_is_offered_again(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(scan_runner, "NOTIFY_RETRY_SECONDS", 0.0)
    outcomes = [False, True]
    calls = []

    async def notify(send):
        await asyncio.sleep(0.1)
        calls.append(1)
        return outcomes.pop(0)

    async def run():
        runner = CycleRunner(None, notify=notify)
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.drain()
        assert runner._reported_down == set()  # nobody was told
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.drain()
        return set(runner._reported_down)

    assert asyncio.run(run()) == {"PLC1"}
    assert len(calls) == 2


@pytest.fixture
def restore_root_logger():
    root = logging.getLogger()
    level, handlers = root.level, list(root.handlers)
    # _apply_config_logging also quietens the protocol libraries' loggers
    libraries = {name: logging.getLogger(name).level for name in ("pycomm3", "pymodbus")}
    yield root
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(level)
    for name, library_level in libraries.items():
        logging.getLogger(name).setLevel(library_level)


def _loader_2(logging_section):
    loader = ConfigLoader()
    loader.config["logging"].update(logging_section)
    loader._file_config = {"logging": dict(logging_section)}
    return loader


def test_config_log_level_and_file_are_applied(tmp_path, restore_root_logger):
    log_file = tmp_path / "logs" / "scan.log"
    loader = _loader_2({"level": "warning", "file": str(log_file)})
    plc_scanner._apply_config_logging(MagicMock(verbose=False, quiet=False), loader)
    assert restore_root_logger.level == logging.WARNING
    logging.getLogger("plc_discovery.test").warning("to the file")
    # Only the handler under test: other tests may leave handlers on the
    # root logger whose streams are closed by now
    for handler in restore_root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler.flush()
    assert "to the file" in log_file.read_text(encoding="utf-8")


def _loader_3(logging_section):
    loader = ConfigLoader()
    loader.config["logging"].update(logging_section)
    loader._file_config = {"logging": dict(logging_section)}
    return loader


def test_verbose_wins_over_the_config_log_level(restore_root_logger):
    restore_root_logger.setLevel(logging.DEBUG)
    plc_scanner._apply_config_logging(MagicMock(verbose=True, quiet=False), _loader_3({"level": "ERROR"}))
    assert restore_root_logger.level == logging.DEBUG


def test_no_broadcast_when_the_search_is_limited_to_ip_ranges():
    async def run(ip_ranges):
        with (
            patch.object(BroadcastDiscovery, "discover_all_broadcast", AsyncMock(return_value=[])) as broadcast,
            patch.object(plc_scanner, "discover_plcs", AsyncMock(return_value=[])),
        ):
            await plc_scanner.run_discovery(ip_ranges, FAST_200MS, MagicMock(), MagicMock())
        return broadcast.await_count

    assert asyncio.run(run(["192.168.10.0/24"])) == 0
    assert asyncio.run(run([])) == 1


def test_resolve_target_detects_on_the_given_port():
    seen = {}

    class Discovery:
        def __init__(self, config, port=None):
            seen["port"] = port

        async def _probe_host(self, ip):
            return PLCInfo(ip, protocol=Protocol.SLMP, port=seen["port"])

    async def run():
        with patch.object(plc_scanner, "PLCDiscovery", Discovery):
            return await plc_scanner.resolve_target("10.0.0.1", None, 5007, FAST_200MS, MagicMock())

    resolved = asyncio.run(run())
    assert seen["port"] == 5007 and resolved.port == 5007


def test_command_line_protocol_and_port_win_over_config_targets():
    args = MagicMock(target=None, protocol="modbus", port=1502)
    loader = MagicMock()
    loader.get_targets.return_value = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]

    async def run():
        return await plc_scanner._resolve_targets(args, loader, FAST_200MS, MagicMock())

    plc_infos, undetected = asyncio.run(run())
    assert undetected == []
    assert (plc_infos[0].protocol, plc_infos[0].port) == (Protocol.MODBUS_TCP, 1502)


def _loader_with_ranges():
    loader = ConfigLoader()
    loader.config["scan"]["device_ranges"] = [{"device": "D", "start": 0, "end": 10}]
    return loader


def test_device_option_without_range_is_not_ignored():
    def ranges(device, range_text=None):
        args = MagicMock(device=device, range=range_text)
        return [(r.device_type, r.start_address, r.end_address) for r in resolve_device_ranges_only(args, loader)]

    loader = _loader_with_ranges()
    assert ranges("W") == [(DeviceType.W, 0, 999)]
    assert ranges(None) == [(DeviceType.D, 0, 10)]  # no option: the config file's ranges
    assert ranges("W", "5-9") == [(DeviceType.W, 5, 9)]
    assert ranges(None, "5-9") == [(DeviceType.D, 5, 9)]
