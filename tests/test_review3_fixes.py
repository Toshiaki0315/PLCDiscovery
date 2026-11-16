"""
Regression tests for the third review's findings (T1-T6).
"""

import asyncio
import csv
import re
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
)
from plc_discovery.data_types import ByteOrder, DataType, DataTypeManager, DataTypeMapping
from plc_discovery.output import CSVExporter, csv_safe

ROOT = Path(__file__).resolve().parent.parent


def ok(address, value):
    return DataPoint(address, value, f"0x{value:04X}", StatusCode.OK)


def failed(address):
    return DataPoint(address, status=StatusCode.NG_TIMEOUT)


def converted(points):
    return [(dp.address, dp.converted_value) for dp in points if dp.converted_value is not None]


# ---------------------------------------------------------------------------
# T1: dependencies resolvable and complete
# ---------------------------------------------------------------------------

class TestDependencies:

    def deps(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return {re.split(r"[<>=!~ ]", d, 1)[0].lower(): d for d in data["project"]["dependencies"]}

    def test_pymcprotocol_version_exists_on_pypi(self):
        # 0.3.0 is the latest release; ">=0.4.0" could never be installed
        assert self.deps()["pymcprotocol"] == "pymcprotocol>=0.3.0"

    def test_yaml_is_a_dependency(self):
        assert "pyyaml" in self.deps()

    def test_requirements_without_python2_backport(self):
        text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert "ipaddress" not in text


# ---------------------------------------------------------------------------
# T2: multi-word values stay aligned
# ---------------------------------------------------------------------------

FLOATS = {1.0: (0x0000, 0x3F80), 2.0: (0x0000, 0x4000), 3.0: (0x0000, 0x4040), 4.0: (0x0000, 0x4080)}


def float_words(start, *values):
    points = []
    for n, v in enumerate(values):
        lo, hi = FLOATS[v]
        points += [ok(f"D{start + 2 * n}", lo), ok(f"D{start + 2 * n + 1}", hi)]
    return points


class TestAlignment:

    def test_failed_word_does_not_shift_following_values(self):
        points = float_words(100, 1.0, 2.0, 3.0, 4.0)
        points[4] = failed("D104")   # first word of 3.0
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D100", 1.0), ("D102", 2.0), ("D106", 4.0)]
        assert result[5].display_value == "(part of D104, incomplete)"
        assert [dp.address for dp in result] == [dp.address for dp in points]   # nothing dropped

    def test_failed_second_word_marks_value_incomplete(self):
        points = float_words(100, 1.0, 2.0)
        points[1] = failed("D101")
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D102", 2.0)]
        assert result[0].display_value.startswith("(incomplete FLOAT")

    def test_mapping_aligned_to_mapping_start(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        points = float_words(100, 1.0, 2.0)[1:]   # range starts at D101
        result = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)
        assert converted(result) == [("D102", 2.0)]
        assert result[0].display_value == "(part of D100, incomplete)"

    def test_without_mapping_aligned_to_range_start(self):
        points = float_words(101, 1.0, 2.0)       # requested range starts at D101
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D101", 1.0), ("D103", 2.0)]

    def test_each_range_has_its_own_alignment(self):
        points = float_words(0, 1.0) + float_words(51, 2.0)   # two separate ranges
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D0", 1.0), ("D51", 2.0)]


# ---------------------------------------------------------------------------
# T3: mappings are device-aware
# ---------------------------------------------------------------------------

class TestDeviceAwareMappings:

    def test_mapping_without_device_skips_bit_devices(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        result = plc_scanner.apply_data_type_conversion(
            [ok("M100", 1), ok("M101", 0)], None, ByteOrder.LITTLE_ENDIAN, manager
        )
        assert all(dp.data_type != "FLOAT" for dp in result)

    def test_mapping_with_device_only_applies_to_that_device(self):
        manager = DataTypeManager.from_config({"mappings": [
            {"device": "HR", "start": 0, "end": 1, "type": "FLOAT"},
        ]})
        d_points = plc_scanner.apply_data_type_conversion(
            float_words(0, 1.0), None, ByteOrder.LITTLE_ENDIAN, manager
        )
        # D0-D1 are not HR: only the default WORD type applies
        assert [dp.data_type for dp in d_points] == ["WORD", "WORD"]
        hr_points = [ok("HR0", 0x0000), ok("HR1", 0x3F80)]
        assert converted(plc_scanner.apply_data_type_conversion(
            hr_points, None, ByteOrder.LITTLE_ENDIAN, manager)) == [("HR0", 1.0)]

    def test_explicit_bit_device_mapping_allowed_for_single_word(self):
        mapping = DataTypeMapping(0, 10, DataType.BOOL, device="M")
        assert mapping.contains(5, "M") and not mapping.contains(5, "D")

    def test_multi_word_default_type_never_applied_to_bits(self):
        result = plc_scanner.apply_data_type_conversion(
            [ok("M0", 1), ok("M1", 1)], DataType.FLOAT, ByteOrder.LITTLE_ENDIAN
        )
        assert converted(result) == [] and all(dp.data_type is None for dp in result)

    def test_legacy_lookup_without_device(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        assert manager.get_type_for_address(150) == (DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)


# ---------------------------------------------------------------------------
# T4: write failures do not stop scanning
# ---------------------------------------------------------------------------

class FakeCollector:
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


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.asyncio
async def test_periodic_scan_survives_locked_csv():
    collector = FakeCollector()
    exporter = MagicMock()
    exporter.export_plc_data.side_effect = PermissionError("locked by Excel")
    exporter.export_denied_addresses.side_effect = [PermissionError("locked"), "denied.csv"]

    with patch.object(plc_scanner, "PLCDataCollector", lambda *a: collector):
        task = asyncio.ensure_future(plc_scanner.run_periodic_scan(
            [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)], NetworkConfig(), exporter,
            Display(), [DeviceRange(DeviceType.D, 0, 0)], interval=0.01,
        ))
        while collector.calls < 4:
            await asyncio.sleep(0.005)
        task.cancel()
        (outcome,) = await task

    assert collector.calls >= 4                       # monitoring kept running
    assert exporter.export_denied_addresses.call_count == 2   # failed write retried once, then done
    assert outcome.success is False and "write error" in outcome.error


@pytest.mark.asyncio
async def test_single_scan_reports_write_failure():
    exporter = MagicMock()
    exporter.export_plc_data.side_effect = OSError("disk full")
    with patch.object(plc_scanner, "PLCDataCollector", lambda *a: FakeCollector()):
        outcome = await plc_scanner.run_single_scan(
            PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001), NetworkConfig(), exporter,
            Display(), ScanMode.RANGE, [DeviceRange(DeviceType.D, 0, 0)],
        )
    assert outcome.success is False
    assert "disk full" in outcome.error
    assert outcome.data_points   # data was still collected


from plc_discovery.config import ScanMode  # noqa: E402  (used above)


# ---------------------------------------------------------------------------
# T5: CSV formula injection
# ---------------------------------------------------------------------------

class TestCSVSafe:

    @pytest.mark.parametrize("value, expected", [
        ('=HYPERLINK("http://x")', '\'=HYPERLINK("http://x")'),
        ("+cmd", "'+cmd"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("-2+3", "'-2+3"),
        ("-12.500000", "-12.500000"),   # negative number stays numeric
        ("0x3F80", "0x3F80"),
        ("Omron", "Omron"),
        (-5, -5),
        (None, None),
    ])
    def test_csv_safe(self, value, expected):
        assert csv_safe(value) == expected

    def test_discovery_csv_neutralizes_device_strings(self, tmp_path):
        plc = PLCInfo("10.0.0.5", manufacturer='=HYPERLINK("http://x","click")',
                      model="@cmd", protocol=Protocol.MODBUS_TCP)
        path = CSVExporter(str(tmp_path)).export_discovery_results([plc])
        row = next(csv.DictReader(open(path, encoding="utf-8")))
        assert row["manufacturer"].startswith("'=")
        assert row["model"] == "'@cmd"
        assert row["ip_address"] == "10.0.0.5"

    def test_data_csv_keeps_negative_numbers(self, tmp_path):
        dp = DataPoint("D0", 0xFFFF, "0xFFFF", StatusCode.OK, data_type="INT16",
                       converted_value=-1, display_value="-1")
        path = CSVExporter(str(tmp_path)).export_plc_data([dp], "1.2.3.4")
        row = next(csv.DictReader(open(path, encoding="utf-8")))
        assert row["converted_value"] == "-1" and row["display_value"] == "-1"


# ---------------------------------------------------------------------------
# T6: Docker ports match the simulators
# ---------------------------------------------------------------------------

def test_docker_compose_ports_match_run_all():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    run_all = (ROOT / "simulators" / "run_all.py").read_text(encoding="utf-8")
    for port in ("5001", "1502", "44818", "1102"):
        assert f"self.host, {port}" in run_all
        assert f'"127.0.0.1:{port}:{port}"' in compose
    assert '"127.0.0.1:9600:9600/udp"' in compose and '"127.0.0.1:9600:9600/tcp"' in compose
