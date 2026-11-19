"""
Regression tests for the command line (plc_scanner.py), found and fixed in code reviews.
"""

import argparse
import asyncio
import io
import json
import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import collector as collector_module
from plc_discovery import parallel
from plc_discovery.broadcast_discovery import BroadcastDiscovery
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
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.discovery import target_labels
from plc_discovery.output import CSVExporter

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
