"""
Regression tests for the fifth review's findings (V1-V4).
"""

import csv
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import DEFAULT_CONFIG, ConfigLoader, generate_config_template
from plc_discovery.output import CSVExporter, load_denied_addresses, normalize_csv_encoding

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# V1: Shift-JIS output never fails on unrepresentable characters
# ---------------------------------------------------------------------------


class TestShiftJIS:

    @pytest.mark.parametrize("name", ["shift-jis", "shift_jis", "SJIS", "cp932"])
    def test_aliases_map_to_cp932(self, name):
        assert normalize_csv_encoding(name) == "cp932"

    def test_unrepresentable_vendor_name_does_not_fail(self, tmp_path):
        plcs = [
            PLCInfo("10.0.0.9", manufacturer="Dürr Somac GmbH", protocol=Protocol.ETHERNET_IP),
            PLCInfo("10.0.0.1", manufacturer="三菱電機", model="①号機 ㈱テスト～", protocol=Protocol.SLMP),
        ]
        path = CSVExporter(str(tmp_path), "shift-jis").export_discovery_results(plcs)
        rows = list(csv.DictReader(open(path, encoding="cp932")))
        assert rows[0]["manufacturer"] == "D?rr Somac GmbH"
        assert rows[1]["manufacturer"] == "三菱電機"
        assert rows[1]["model"] == "①号機 ㈱テスト～"  # CP932-only characters kept

    @pytest.mark.asyncio
    async def test_discovery_results_shown_when_csv_fails(self):
        plcs = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]
        exporter = MagicMock()
        exporter.export_discovery_results.side_effect = PermissionError("locked")
        display = MagicMock()
        errors = []
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(plc_scanner.BroadcastDiscovery, "discover_all_broadcast", _async_return([]))
            mp.setattr(plc_scanner, "discover_plcs", _async_return(plcs))
            result = await plc_scanner.run_discovery([], NetworkConfig(), exporter, display, errors=errors)
        assert result == plcs
        display.print_discovery_results.assert_called_once()  # list still shown
        assert errors and "locked" in errors[0]


def _async_return(value):
    async def fn(*args, **kwargs):
        return value

    return fn


# ---------------------------------------------------------------------------
# V2: UTF-8 with BOM for Excel; BOM only once when appending
# ---------------------------------------------------------------------------


class TestUTF8BOM:

    def test_cli_default_is_utf8_with_bom(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["plc_scanner.py"])
        args = plc_scanner.parse_args()
        assert plc_scanner.resolve_output_settings(args, None)[1] == "utf-8-sig"
        assert DEFAULT_CONFIG["output"]["encoding"] == "utf-8-sig"

    def test_data_csv_starts_with_bom(self, tmp_path):
        path = CSVExporter(str(tmp_path), "utf-8-sig").export_discovery_results(
            [PLCInfo("10.0.0.1", manufacturer="三菱電機", protocol=Protocol.SLMP)]
        )
        raw = Path(path).read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")
        assert "三菱電機" in raw.decode("utf-8-sig")

    def test_denied_log_append_writes_bom_once(self, tmp_path):
        exporter = CSVExporter(str(tmp_path), "utf-8-sig")
        exporter.export_denied_addresses({"D10"}, "10.0.0.1")
        path = exporter.export_denied_addresses({"D20"}, "10.0.0.1")
        raw = Path(path).read_bytes()
        assert raw.count(b"\xef\xbb\xbf") == 1
        assert load_denied_addresses(path) == {"D10", "D20"}  # BOM stripped when reading

    def test_plain_utf8_has_no_bom(self, tmp_path):
        path = CSVExporter(str(tmp_path), "utf-8").export_plc_data(
            [DataPoint("D0", 1, "0x0001", StatusCode.OK)], "10.0.0.1"
        )
        assert not Path(path).read_bytes().startswith(b"\xef\xbb\xbf")


# ---------------------------------------------------------------------------
# V3: --generate-config never overwrites
# ---------------------------------------------------------------------------


class TestGenerateConfig:

    def test_existing_file_not_overwritten(self, tmp_path):
        path = tmp_path / "plc_config.yaml"
        path.write_text("# my settings\n", encoding="utf-8")
        with pytest.raises(FileExistsError):
            generate_config_template(str(path))
        assert path.read_text(encoding="utf-8") == "# my settings\n"

    def test_cli_refuses_and_accepts_path(self, tmp_path, monkeypatch, capsys):
        existing = tmp_path / "plc_config.yaml"
        existing.write_text("# my settings\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--generate-config"])
        with pytest.raises(SystemExit) as exc:
            plc_scanner.cli()
        assert exc.value.code == 1 and "already exists" in capsys.readouterr().out
        assert existing.read_text(encoding="utf-8") == "# my settings\n"

        monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--generate-config", "new.yaml"])
        plc_scanner.cli()
        assert (tmp_path / "new.yaml").exists()


# ---------------------------------------------------------------------------
# V4: templates default to the production-safe range mode
# ---------------------------------------------------------------------------


def test_generated_template_defaults_to_range(tmp_path):
    path = tmp_path / "template.yaml"
    generate_config_template(str(path))
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.get_scan_mode().value == "range"


def test_example_config_defaults_to_range():
    loader = ConfigLoader(str(ROOT / "plc_config.example.yaml"))
    loader.load()
    assert loader.get_scan_mode().value == "range"
