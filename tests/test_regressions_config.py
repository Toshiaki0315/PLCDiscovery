"""
Regression tests for configuration files, found and fixed in code reviews.
"""

import argparse
import json
import logging
import math
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import settings_file
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import PLCInfo, Protocol
from plc_discovery.config_loader import ConfigLoader, generate_config_template, is_known_encoding, number_error
from plc_discovery.conversion import load_type_mapping
from plc_discovery.output import normalize_csv_encoding
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


@pytest.mark.parametrize("encoding", ["cp932", "sjis", "shift_jis", "utf8", "UTF8", "utf-8-sig", "utf-8-bom", "euc-jp"])
def test_encodings_the_csv_writer_can_use_are_accepted(encoding):
    loader = ConfigLoader()
    loader.config["output"]["encoding"] = encoding
    assert loader.validate() == []


@pytest.mark.parametrize("level", ["WARN", "warning", "CRITICAL", "debug"])
def test_log_levels_known_to_logging_are_accepted(level):
    loader = ConfigLoader()
    loader.config["logging"]["level"] = level
    assert loader.validate() == []


def test_unknown_encoding_and_log_level_are_still_errors():
    loader = ConfigLoader()
    loader.config["output"]["encoding"] = "no-such-encoding"
    loader.config["logging"]["level"] = "LOUD"
    errors = "\n".join(loader.validate())
    assert "output.encoding" in errors and "logging.level" in errors


def test_contiguous_is_a_valid_modbus_target_option():
    def errors(value):
        loader = ConfigLoader()
        loader.config["targets"] = [{"ip": "10.0.0.1", "protocol": "modbus", "options": {"contiguous": value}}]
        return loader.validate()

    assert errors(1) == [] and errors(0) == []
    assert any("contiguous" in e for e in errors(2))


@pytest.mark.parametrize(
    "section, key, value",
    [
        ("scan", "device_ranges", 5),
        ("discovery", "ip_ranges", "192.168.1.0/24"),  # the list dash was forgotten
        ("discovery", "protocols", "slmp"),
        ("output", "database", True),
    ],
)
def test_nested_setting_of_the_wrong_shape_is_one_clear_error(section, key, value):
    loader = ConfigLoader()
    loader.config[section][key] = value
    loader._file_config = {section: {key: value}}
    errors = loader.validate()  # no exception
    assert len(errors) == 1 and errors[0].startswith(f"{section}.{key} must be")


@pytest.mark.parametrize(
    "name, codec",
    [("shiftjis", "cp932"), (" cp932 ", "cp932"), (932, "cp932"), ("mskanji", "cp932"), ("UTF8", "utf-8")],
)
def test_any_spelling_of_an_encoding_is_understood(name, codec):
    assert normalize_csv_encoding(name) == codec and is_known_encoding(name)


def test_encodings_that_cannot_write_a_csv_are_rejected():
    assert not is_known_encoding("base64") and not is_known_encoding("no-such-codec")
    assert is_known_encoding("euc-jp")


def test_json_config_with_a_bom_loads(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"network": {"packet_interval_ms": 75}}), encoding="utf-8-sig")
    assert ConfigLoader().load(str(path))["network"]["packet_interval_ms"] == 75


def test_config_file_that_is_a_list_is_a_clear_error(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- ip: 10.0.0.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at the top level"):
        ConfigLoader().load(str(path))


def _db_config(tmp_path, database_section, **cli):
    loader = ConfigLoader()
    loader.config["output"]["database"] = database_section
    args = argparse.Namespace(no_database=False, database=None, db_track_history=None)
    vars(args).update(cli)
    exporter = plc_scanner._create_db_exporter(args, loader, MagicMock())
    if exporter is None:
        return None
    try:
        return exporter.config
    finally:
        exporter.close()


def test_database_option_keeps_the_retention_of_the_config_file(tmp_path):
    section = {"enabled": False, "path": str(tmp_path / "file.db"), "max_history_days": 0, "max_size_mb": 50}
    config = _db_config(tmp_path, section, database=str(tmp_path / "cli.db"))
    assert config.enabled and config.path == str(tmp_path / "cli.db")
    # Was 30 days: one run with --database deleted the history the file kept
    assert (config.max_history_days, config.max_size_mb, config.track_history) == (0, 50, True)


def test_track_history_option_applies_to_a_database_from_the_config_file(tmp_path):
    section = {"enabled": True, "path": str(tmp_path / "file.db"), "track_history": True}
    assert _db_config(tmp_path, section).track_history is True
    assert _db_config(tmp_path, section, db_track_history=False).track_history is False
    section["track_history"] = False
    assert _db_config(tmp_path, section).track_history is False
    assert _db_config(tmp_path, section, database=str(tmp_path / "cli.db")).track_history is False


def test_empty_database_section_does_not_crash(tmp_path):
    assert _db_config(tmp_path, None) is None  # "database:" with every line commented out
    assert _db_config(tmp_path, None, database=str(tmp_path / "cli.db")).enabled


def test_misplaced_and_misspelt_keys_of_targets_and_ranges_are_errors():
    loader = ConfigLoader()
    loader.config["targets"] = [{"ip": "10.0.0.5", "protocol": "modbus", "unit_id": 2, "name": "meter"}]
    loader.config["scan"]["device_ranges"] = [{"device": "HR", "start": 100, "stop": 200}]
    errors = loader.validate()  # was []: unit 1 was read, and HR100-999 instead of HR100-200
    assert any("targets[0]" in e and "unit_id" in e and "options" in e for e in errors)
    assert any("scan.device_ranges[0]" in e and "stop" in e for e in errors)

    loader.config["targets"] = [{"ip": "10.0.0.5", "protocol": "modbus", "options": {"unit_id": 2}, "model": 1500}]
    loader.config["scan"]["device_ranges"] = [{"device": "HR", "start": 100, "end": 200, "comment": "meter"}]
    assert loader.validate() == []
    assert loader.get_targets()[0].model == "1500"  # text: the HTML report failed on a number


def test_encodings_that_scramble_or_fail_a_csv_are_rejected():
    for name in ("idna", "punycode", "cp500", "utf-7", "unicode_escape"):
        assert not is_known_encoding(name), name
    for name in ("utf-16", "euc-jp", "latin-1", "cp932", "utf-8-sig", "ascii"):
        assert is_known_encoding(name), name


def test_files_with_a_bom_load_everywhere(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"network": {"packet_interval_ms": 75}}), encoding="utf-8-sig")
    assert settings_file.read_file(str(settings)) == {"network": {"packet_interval_ms": 75}}  # JSONDecodeError

    mapping = tmp_path / "types.json"
    mapping.write_text(json.dumps({"default_type": "INT16", "mappings": []}), encoding="utf-8-sig")
    assert load_type_mapping(str(mapping)).default_type.value == "INT16"


def test_generated_config_must_be_a_format_that_can_be_loaded(tmp_path):
    with pytest.raises(ValueError, match="yaml"):
        generate_config_template(str(tmp_path / "plc_config.txt"))  # wrote JSON that --config then refused
    assert not (tmp_path / "plc_config.txt").exists()
    generate_config_template(str(tmp_path / "plc_config.yaml"))
    assert ConfigLoader().load(str(tmp_path / "plc_config.yaml"))


@pytest.mark.parametrize("value", [3.0, 2.5, True, "3", 0])
def test_notification_retry_count_must_be_a_whole_number(value):
    loader = ConfigLoader()
    loader._merge_config(
        {"notifications": [{"name": "n", "url": "https://example.invalid/hook", "retry_count": value}]}
    )
    assert any("notifications[0].retry_count" in error for error in loader.validate())


def test_notification_retry_count_and_fractional_timeout_are_accepted():
    loader = ConfigLoader()
    loader._merge_config(
        {"notifications": [{"name": "n", "url": "https://example.invalid/hook", "retry_count": 2, "timeout": 2.5}]}
    )
    assert loader.validate() == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_settings_file_is_private_and_keeps_its_permissions(tmp_path):
    path = tmp_path / "plc_config.yaml"
    updates = {"notifications": [{"name": "ops", "type": "slack", "url": "https://hooks.example.com/secret"}]}

    _, errors = settings_file.save(str(path), updates)
    assert errors == []
    assert path.stat().st_mode & 0o777 == 0o600

    # The owner's choice is kept on later saves, in both directions
    for mode in (0o640, 0o600):
        os.chmod(path, mode)
        settings_file.save(str(path), updates)
        assert path.stat().st_mode & 0o777 == mode
    assert "hooks.example.com" in path.read_text(encoding="utf-8")


def test_unknown_log_level_is_a_config_error():
    loader = ConfigLoader()
    loader.config["logging"]["level"] = "LOUD"
    assert any("logging.level" in error for error in loader.validate())


@pytest.mark.parametrize(
    "section, value, fragment",
    [
        ("scan", "range", "scan must be a mapping"),
        ("discovery", ["192.168.1.0/24"], "discovery must be a mapping"),
        ("targets", {"ip": "10.0.0.1"}, "targets must be a list"),
        ("targets", ["10.0.0.1"], "targets[0] must be a mapping"),
    ],
)
def test_wrongly_typed_sections_are_errors_not_tracebacks(section, value, fragment):
    loader = ConfigLoader()
    loader.config[section] = value
    assert any(fragment in error for error in loader.validate())


def test_unknown_network_key_and_bad_port_are_rejected():
    loader = ConfigLoader()
    loader.config["network"]["packet_interval"] = 500  # meant packet_interval_ms
    loader.config["targets"] = [{"ip": "10.0.0.1", "port": "abc"}, {"ip": "10.0.0.2", "port": 99999}]
    errors = loader.validate()
    assert any("unknown key(s) packet_interval" in e for e in errors)
    assert any("targets[0].port" in e for e in errors) and any("targets[1].port" in e for e in errors)
    assert ConfigLoader().validate() == []


def test_config_validation_of_filters_limits_and_output():
    loader = ConfigLoader()
    loader.config["discovery"]["protocols"] = []
    loader._file_config = {"discovery": {"protocols": []}}
    loader.config["network"]["max_concurrent"] = 100000
    loader.config["output"]["encoding"] = "no-such-encoding"
    loader.config["output"]["directory"] = 5
    errors = "\n".join(loader.validate())
    for fragment in ("discovery.protocols", "network.max_concurrent", "output.encoding", "output.directory"):
        assert fragment in errors


def test_unknown_config_keys_are_reported(caplog):
    loader = ConfigLoader()
    loader.config["output"]["directry"] = "./x"
    loader.config["scna"] = {}
    with caplog.at_level(logging.WARNING):
        assert loader.validate() == []
    assert "output.directry" in caplog.text and "scna" in caplog.text


def test_settings_file_name_must_be_readable_by_the_cli(tmp_path):
    path = tmp_path / "plc.conf"
    _, errors = settings_file.save(str(path), {"network": {"packet_interval_ms": 100}})
    assert errors and not path.exists()
