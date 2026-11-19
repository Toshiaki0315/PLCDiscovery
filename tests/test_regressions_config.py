"""
Regression tests for configuration files, found and fixed in code reviews.
"""

import json
import math
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

import plc_scanner
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import PLCInfo, Protocol
from plc_discovery.config_loader import ConfigLoader, generate_config_template, number_error
from plc_discovery.utils import MAX_IP_RANGE_HOSTS


def _loader(tmp_path, config):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(config))
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


def _args(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", *argv])
    return plc_scanner.parse_args()


def _loader_16(tmp_path, text):
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


MINIMAL = "scan:\n  mode: discover\n"


WITH_OUTPUT = "output:\n  directory: ./from_config\n  encoding: shift-jis\n"


def load(tmp_path, data):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


ROOT = Path(__file__).resolve().parent.parent


def test_config_validate_rejects_huge_range(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"discovery": {"ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"]}}))
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert len(errors) == 1 and errors[0].startswith("discovery.ip_ranges[1]:")
    assert f"{MAX_IP_RANGE_HOSTS:,}" in errors[0]


@pytest.mark.parametrize("mode", ["rang", "fulll", "scan"])
def test_unknown_scan_mode_is_config_error(tmp_path, mode):
    loader = _loader(tmp_path, {"scan": {"mode": mode}})
    assert any(e.startswith("scan.mode: unknown mode") for e in loader.validate())
    from plc_discovery.config import ScanMode

    assert loader.get_scan_mode() == ScanMode.DISCOVER  # previously FULL


@pytest.mark.parametrize(
    "config_text,argv,expected",
    [
        (None, [], ("./plc_scan_results", "utf-8-sig")),
        (MINIMAL, [], ("./plc_scan_results", "utf-8-sig")),
        (MINIMAL, ["-o", "out", "--encoding", "utf-8"], ("out", "utf-8")),
        (WITH_OUTPUT, [], ("./from_config", "shift-jis")),
        (WITH_OUTPUT, ["-o", "out"], ("out", "shift-jis")),
        (WITH_OUTPUT, ["--encoding", "utf-8"], ("./from_config", "utf-8")),
    ],
)
def test_output_settings_precedence(monkeypatch, tmp_path, config_text, argv, expected):
    loader = _loader_16(tmp_path, config_text) if config_text else None
    assert plc_scanner.resolve_output_settings(_args(monkeypatch, *argv), loader) == expected


def test_valid_numbers_pass(tmp_path):
    text = (
        "network:\n  request_timeout_ms: 1\n  packet_interval_ms: 0\n  max_concurrent: 2\n"
        "scan:\n  interval_seconds: 1.5\n  device_ranges:\n    - {device: D, start: 0, end: 9}\n"
    )
    assert _loader_16(tmp_path, text).validate() == []


def test_config_rejects_huge_range(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text("scan:\n  device_ranges:\n    - {device: D, start: 0, end: 16000000}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("scan.device_ranges[0]" in e and "at most" in e for e in loader.validate())


def test_config_rejects_invalid_target_ip(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text("targets:\n  - {ip: 192.168.1.300}\n  - {ip: simulators}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any(e.startswith("targets[0].ip:") for e in errors)
    assert not any(e.startswith("targets[1]") for e in errors)


def test_config_validates_max_history_days(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("output:\n  database:\n    max_history_days: -1\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("output.database.max_history_days" in e for e in loader.validate())


def test_missing_config_file_is_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--config", str(tmp_path / "nope.yaml")])
    with pytest.raises(SystemExit) as exc:
        plc_scanner.cli()
    assert exc.value.code == 1
    assert "file not found" in capsys.readouterr().out


class TestConfigValidation:

    def test_unknown_target_protocol(self, tmp_path):
        loader = load(tmp_path, {"targets": [{"ip": "10.0.0.1", "protocol": "fins_tpc"}]})
        assert any("unknown protocol 'fins_tpc'" in e for e in loader.validate())

    def test_unknown_discovery_protocol(self, tmp_path):
        loader = load(tmp_path, {"discovery": {"protocols": ["slmp", "modbuss"]}})
        assert any("modbuss" in e for e in loader.validate())

    def test_target_options(self, tmp_path):
        good = load(
            tmp_path,
            {
                "targets": [
                    {"ip": "10.0.0.1", "protocol": "fins", "options": {"dest_node": 5}},
                    {"ip": "10.0.0.2", "protocol": "s7", "options": {"rack": 0, "slot": 1, "db_number": 10}},
                ]
            },
        )
        assert good.validate() == []
        assert good.get_targets()[1].options == {"rack": 0, "slot": 1, "db_number": 10}
        bad = load(tmp_path, {"targets": [{"ip": "10.0.0.1", "protocol": "modbus", "options": {"slot": 1}}]})
        assert any("slot not supported for MODBUS_TCP" in e for e in bad.validate())

    def test_options_reach_the_handler(self):
        plc = PLCInfo("127.0.0.1", protocol=Protocol.S7, port=102, options={"db_number": 7, "slot": 1})
        collector = PLCDataCollector(plc)
        with patch("plc_discovery.protocols.s7.S7Handler.connect", AsyncMock(return_value=True)):
            import asyncio

            assert asyncio.run(collector.connect())
        assert collector._handler._db_number == 7 and collector._handler._slot == 1


def test_config_rejects_sub_second_interval(tmp_path):
    loader = load(tmp_path, {"scan": {"interval_seconds": 0.2}})
    assert any("interval_seconds" in e for e in loader.validate())


def test_shipped_example_config_is_valid():
    from pathlib import Path

    loader = ConfigLoader(str(Path(__file__).resolve().parent.parent / "plc_config.example.yaml"))
    loader.load()
    assert loader.validate() == []
    assert loader.get_targets() == []


def test_empty_yaml_section_keeps_default(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("targets:\n  # none yet\nscan:\n  device_ranges:\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.validate() == []
    assert loader.get_targets() == [] and loader.get_device_ranges() == []


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


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_rejected(value):
    assert "finite" in number_error(value, 0)


@pytest.mark.parametrize("text", [".nan", ".inf"])
def test_non_finite_interval_rejected_in_config(tmp_path, text):
    path = tmp_path / "c.yaml"
    path.write_text(f"scan:\n  mode: range\n  interval_seconds: {text}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("interval_seconds" in e and "finite" in e for e in loader.validate())
