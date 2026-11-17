"""
Tests for config_loader module
"""

import json
import os
import tempfile

import pytest

from plc_discovery.config import DeviceType, NetworkConfig, Protocol, ScanMode
from plc_discovery.config_loader import DEFAULT_CONFIG, ConfigLoader, generate_config_template, load_config


class TestConfigLoader:
    """Tests for ConfigLoader class"""

    def test_default_config(self):
        """Test loading default configuration"""
        loader = ConfigLoader()
        config = loader.config

        assert config is not None
        assert "version" in config
        assert "network" in config
        assert "discovery" in config
        assert "targets" in config
        assert "scan" in config
        assert "output" in config
        assert "logging" in config

    def test_load_json_config(self):
        """Test loading configuration from JSON file"""
        config_data = {
            "network": {
                "max_concurrent": 5,
                "packet_interval_ms": 100,
            },
            "targets": [{"ip": "192.168.1.10", "protocol": "slmp", "port": 5001}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loaded = loader.load()

            assert loaded["network"]["max_concurrent"] == 5
            assert loaded["network"]["packet_interval_ms"] == 100
            assert len(loaded["targets"]) == 1
            assert loaded["targets"][0]["ip"] == "192.168.1.10"
        finally:
            os.unlink(temp_path)

    def test_load_yaml_config(self):
        """Test loading configuration from YAML file"""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        config_data = {"network": {"max_concurrent": 3}, "discovery": {"enabled": False}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loaded = loader.load()

            assert loaded["network"]["max_concurrent"] == 3
            assert loaded["discovery"]["enabled"] is False
        finally:
            os.unlink(temp_path)

    def test_config_merge(self):
        """Test that file config merges with defaults"""
        config_data = {"network": {"max_concurrent": 10}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loaded = loader.load()

            # Overridden value
            assert loaded["network"]["max_concurrent"] == 10
            # Default values preserved
            assert loaded["network"]["packet_interval_ms"] == 50
            assert loaded["network"]["request_timeout_ms"] == 5000
        finally:
            os.unlink(temp_path)

    def test_get_network_config(self):
        """Test getting NetworkConfig from loaded configuration"""
        config_data = {
            "network": {
                "max_concurrent": 4,
                "packet_interval_ms": 75,
                "request_timeout_ms": 3000,
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            net_config = loader.get_network_config()

            assert isinstance(net_config, NetworkConfig)
            assert net_config.max_concurrent == 4
            assert net_config.packet_interval_ms == 75
            assert net_config.request_timeout_ms == 3000
        finally:
            os.unlink(temp_path)

    def test_get_targets(self):
        """Test getting target PLCs from configuration"""
        config_data = {
            "targets": [
                {"ip": "192.168.1.10", "protocol": "slmp", "port": 5001},
                {"ip": "192.168.1.20", "protocol": "modbus", "port": 502},
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            targets = loader.get_targets()

            assert len(targets) == 2
            assert targets[0].ip_address == "192.168.1.10"
            assert targets[0].protocol == Protocol.SLMP
            assert targets[1].ip_address == "192.168.1.20"
            assert targets[1].protocol == Protocol.MODBUS_TCP
        finally:
            os.unlink(temp_path)

    def test_get_device_ranges(self):
        """Test getting device ranges from configuration"""
        config_data = {
            "scan": {
                "device_ranges": [
                    {"device": "D", "start": 0, "end": 1000},
                    {"device": "M", "start": 100, "end": 500},
                ]
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            ranges = loader.get_device_ranges()

            assert len(ranges) == 2
            assert ranges[0].device_type == DeviceType.D
            assert ranges[0].start_address == 0
            assert ranges[0].end_address == 1000
            assert ranges[1].device_type == DeviceType.M
        finally:
            os.unlink(temp_path)

    def test_get_scan_mode(self):
        """Test getting scan mode from configuration"""
        config_data = {"scan": {"mode": "range"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            mode = loader.get_scan_mode()
            assert mode == ScanMode.RANGE
        finally:
            os.unlink(temp_path)

    def test_validate_valid_config(self):
        """Test validation of valid configuration"""
        loader = ConfigLoader()
        errors = loader.validate()
        assert errors == []

    def test_validate_invalid_max_concurrent(self):
        """Test validation catches invalid max_concurrent"""
        config_data = {"network": {"max_concurrent": 0}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            errors = loader.validate()
            assert any("max_concurrent" in e for e in errors)
        finally:
            os.unlink(temp_path)

    def test_validate_invalid_range(self):
        """Test validation catches invalid device range"""
        config_data = {"scan": {"device_ranges": [{"device": "D", "start": 1000, "end": 100}]}}  # Invalid: start > end

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            loader = ConfigLoader(temp_path)
            loader.load()

            errors = loader.validate()
            assert any("start must be" in e for e in errors)
        finally:
            os.unlink(temp_path)

    def test_missing_file_uses_defaults(self):
        """Test that missing config file uses defaults"""
        loader = ConfigLoader("nonexistent_config.yaml")
        config = loader.load()

        assert config == loader.config
        assert config["version"] == DEFAULT_CONFIG["version"]

    def test_save_template(self):
        """Test saving configuration template"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            template_path = os.path.join(tmp_dir, "template.json")

            loader = ConfigLoader()
            loader.save_template(template_path)

            assert os.path.exists(template_path)

            with open(template_path) as f:
                saved = json.load(f)

            assert "version" in saved
            assert "network" in saved


class TestConvenienceFunctions:
    """Tests for convenience functions"""

    def test_load_config(self):
        """Test load_config convenience function"""
        loader = load_config()

        assert isinstance(loader, ConfigLoader)
        assert loader.config is not None

    def test_generate_config_template(self):
        """Test generate_config_template function"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Use JSON format (always available)
            template_path = os.path.join(tmp_dir, "test_template.json")

            generate_config_template(template_path)

            assert os.path.exists(template_path)
