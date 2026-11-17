"""
Unit tests for database module
"""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime

from plc_discovery.database import (
    DatabaseExporter,
    DatabaseConfig,
    create_database,
    get_database_exporter,
)
from plc_discovery.config import PLCInfo, DataPoint, StatusCode, Protocol


class TestDatabaseConfig:
    """Test DatabaseConfig class"""

    def test_default_config(self):
        """Test default configuration"""
        config = DatabaseConfig()

        assert config.enabled is False
        assert config.path == "./plc_data.db"
        assert config.track_history is True
        assert config.max_history_days == 30

    def test_from_dict(self):
        """Test creating config from dictionary"""
        config_dict = {
            "enabled": True,
            "path": "/tmp/test.db",
            "track_history": False,
            "max_history_days": 7,
        }

        config = DatabaseConfig.from_dict(config_dict)

        assert config.enabled is True
        assert config.path == "/tmp/test.db"
        assert config.track_history is False
        assert config.max_history_days == 7

    def test_from_dict_defaults(self):
        """Test from_dict uses defaults for missing keys"""
        config = DatabaseConfig.from_dict({})

        assert config.enabled is False
        assert config.path == "./plc_data.db"


class TestDatabaseExporter:
    """Test DatabaseExporter class"""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield os.path.join(tmpdir, "test.db")

    @pytest.fixture
    def db_exporter(self, temp_db_path):
        """Create database exporter"""
        config = DatabaseConfig(
            enabled=True,
            path=temp_db_path,
            track_history=True
        )
        db = DatabaseExporter(config)
        yield db
        db.close()

    def test_disabled_exporter(self):
        """Test disabled exporter does nothing"""
        config = DatabaseConfig(enabled=False)
        db = DatabaseExporter(config)

        assert db.is_enabled is False

        # Should return 0 for all operations
        plcs = [PLCInfo(ip_address="192.168.1.10")]
        assert db.export_discovery_results(plcs) == 0

        data_points = [DataPoint(address="D0", value=100)]
        assert db.export_plc_data(data_points, "192.168.1.10") == 0

        db.close()

    def test_create_database(self, temp_db_path):
        """Test database creation"""
        db = DatabaseExporter.create(temp_db_path)

        assert db.is_enabled is True
        assert Path(temp_db_path).exists()

        db.close()

    def test_export_discovery_results(self, db_exporter):
        """Test exporting discovery results"""
        plcs = [
            PLCInfo(
                ip_address="192.168.1.10",
                protocol=Protocol.SLMP,
                port=5001,
                manufacturer="Mitsubishi"
            ),
            PLCInfo(
                ip_address="192.168.1.20",
                protocol=Protocol.MODBUS_TCP,
                port=502,
                manufacturer="Unknown"
            ),
        ]

        count = db_exporter.export_discovery_results(plcs)

        assert count == 2

        # Verify data was saved
        saved_plcs = db_exporter.get_plcs()
        assert len(saved_plcs) == 2

    def test_export_plc_data(self, db_exporter):
        """Test exporting PLC data points"""
        data_points = [
            DataPoint(
                address="D0",
                value=100,
                raw_hex="0064",
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat()
            ),
            DataPoint(
                address="D1",
                value=200,
                raw_hex="00C8",
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat()
            ),
        ]

        count = db_exporter.export_plc_data(data_points, "192.168.1.10")

        assert count == 2

        # Verify data was saved
        saved_data = db_exporter.get_latest_data("192.168.1.10")
        assert len(saved_data) == 2

    def test_export_denied_addresses(self, db_exporter):
        """Test exporting denied addresses"""
        denied = {"D5000", "D5001", "D5002"}

        count = db_exporter.export_denied_addresses(denied, "192.168.1.10")

        assert count == 3

    def test_session_context_manager(self, db_exporter):
        """Test session context manager"""
        with db_exporter.session(mode="full") as session_id:
            assert session_id is not None

            # Export some data
            data_points = [
                DataPoint(
                    address="D0",
                    value=100,
                    status=StatusCode.OK,
                    timestamp=datetime.now().isoformat()
                ),
            ]
            db_exporter.export_plc_data(data_points, "192.168.1.10", session_id)

        # Verify session was completed
        sessions = db_exporter.get_scan_sessions()
        assert len(sessions) == 1
        assert sessions[0]["status"] == "completed"

    def test_history_tracking(self, temp_db_path):
        """Test value change tracking"""
        config = DatabaseConfig(
            enabled=True,
            path=temp_db_path,
            track_history=True
        )
        db = DatabaseExporter(config)

        plc_ip = "192.168.1.10"

        # First value
        data_points = [
            DataPoint(
                address="D0",
                value=100,
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat()
            ),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Changed value
        data_points = [
            DataPoint(
                address="D0",
                value=200,
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat()
            ),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Verify change was recorded
        changes = db.get_changes(plc_ip)
        assert len(changes) == 1
        assert changes[0]["old_value"] == 100
        assert changes[0]["new_value"] == 200

        db.close()

    def test_get_address_history(self, db_exporter):
        """Test getting address history"""
        plc_ip = "192.168.1.10"

        # Export multiple values
        for i in range(3):
            data_points = [
                DataPoint(
                    address="D0",
                    value=100 + i,
                    status=StatusCode.OK,
                    timestamp=datetime.now().isoformat()
                ),
            ]
            db_exporter.export_plc_data(data_points, plc_ip)

        # Get history
        history = db_exporter.get_address_history(plc_ip, "D0", days=1)
        assert len(history) == 3

    def test_get_statistics(self, db_exporter):
        """Test getting database statistics"""
        # Export some data
        plcs = [PLCInfo(ip_address="192.168.1.10")]
        db_exporter.export_discovery_results(plcs)

        data_points = [
            DataPoint(
                address="D0",
                value=100,
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat()
            ),
        ]
        db_exporter.export_plc_data(data_points, "192.168.1.10")

        stats = db_exporter.get_statistics()

        assert stats["total_plcs"] == 1
        assert stats["total_data_points"] == 1
        assert "database_size_mb" in stats

    def test_upsert_plc(self, db_exporter):
        """Test PLC upsert (update on conflict)"""
        # First insert
        plcs = [PLCInfo(ip_address="192.168.1.10", manufacturer="Unknown")]
        db_exporter.export_discovery_results(plcs)

        # Update with new info
        plcs = [PLCInfo(ip_address="192.168.1.10", manufacturer="Mitsubishi")]
        db_exporter.export_discovery_results(plcs)

        # Should still be 1 PLC
        saved_plcs = db_exporter.get_plcs()
        assert len(saved_plcs) == 1
        assert saved_plcs[0]["manufacturer"] == "Mitsubishi"


class TestConvenienceFunctions:
    """Test convenience functions"""

    def test_create_database(self):
        """Test create_database function"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = create_database(db_path)

            assert db.is_enabled is True
            assert Path(db_path).exists()

            db.close()

    def test_get_database_exporter_disabled(self):
        """Test get_database_exporter with no config"""
        db = get_database_exporter()

        assert db.is_enabled is False

    def test_get_database_exporter_enabled(self):
        """Test get_database_exporter with config"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")

            config = {
                "enabled": True,
                "path": db_path,
            }

            db = get_database_exporter(config)

            assert db.is_enabled is True

            db.close()


class TestDatabaseWithDataTypes:
    """Test database with data type conversion"""

    @pytest.fixture
    def db_exporter(self):
        """Create database exporter"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            config = DatabaseConfig(enabled=True, path=db_path)
            db = DatabaseExporter(config)
            yield db
            db.close()

    def test_export_with_data_type(self, db_exporter):
        """Test exporting data with type conversion info"""
        data_points = [
            DataPoint(
                address="D100",
                value=16256,
                raw_hex="3F80",
                status=StatusCode.OK,
                timestamp=datetime.now().isoformat(),
                data_type="FLOAT",
                converted_value=1.0,
                display_value="1.000000"
            ),
        ]

        count = db_exporter.export_plc_data(data_points, "192.168.1.10")
        assert count == 1

        # Verify data was saved with type info
        saved_data = db_exporter.get_latest_data("192.168.1.10")
        assert len(saved_data) == 1
        assert saved_data[0]["data_type"] == "FLOAT"
        assert saved_data[0]["display_value"] == "1.000000"


class TestDatabaseOnOffSwitch:
    """Test database on/off switching functionality"""

    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield os.path.join(tmpdir, "test.db")

    def test_enabled_creates_file(self, temp_db_path):
        """Test that enabling database creates the file"""
        config = DatabaseConfig(enabled=True, path=temp_db_path)
        db = DatabaseExporter(config)

        assert db.is_enabled is True
        assert Path(temp_db_path).exists()

        db.close()

    def test_disabled_does_not_create_file(self, temp_db_path):
        """Test that disabling database does not create file"""
        config = DatabaseConfig(enabled=False, path=temp_db_path)
        db = DatabaseExporter(config)

        assert db.is_enabled is False
        assert not Path(temp_db_path).exists()

        db.close()

    def test_disabled_export_returns_zero(self, temp_db_path):
        """Test disabled database export operations return 0"""
        config = DatabaseConfig(enabled=False, path=temp_db_path)
        db = DatabaseExporter(config)

        # Discovery results
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP),
            PLCInfo(ip_address="192.168.1.20", protocol=Protocol.MODBUS_TCP),
        ]
        count = db.export_discovery_results(plcs)
        assert count == 0

        # Data points
        data_points = [
            DataPoint(address="D0", value=100, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
            DataPoint(address="D1", value=200, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        count = db.export_plc_data(data_points, "192.168.1.10")
        assert count == 0

        # Denied addresses
        denied = {"D5000", "D5001", "D5002"}
        count = db.export_denied_addresses(denied, "192.168.1.10")
        assert count == 0

        db.close()

    def test_disabled_query_returns_empty(self, temp_db_path):
        """Test disabled database query operations return empty"""
        config = DatabaseConfig(enabled=False, path=temp_db_path)
        db = DatabaseExporter(config)

        # All queries should return empty
        assert db.get_plcs() == []
        assert db.get_latest_data("192.168.1.10") == []
        assert db.get_address_history("192.168.1.10", "D0") == []
        assert db.get_changes() == []
        assert db.get_scan_sessions() == []
        assert db.get_statistics() == {}

        db.close()

    def test_disabled_session_yields_none(self, temp_db_path):
        """Test disabled database session yields None"""
        config = DatabaseConfig(enabled=False, path=temp_db_path)
        db = DatabaseExporter(config)

        with db.session(mode="full") as session_id:
            assert session_id is None

        db.close()

    def test_enabled_saves_data(self, temp_db_path):
        """Test enabled database saves data correctly"""
        config = DatabaseConfig(enabled=True, path=temp_db_path)
        db = DatabaseExporter(config)

        # Export data
        plcs = [PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)]
        db.export_discovery_results(plcs)

        data_points = [
            DataPoint(address="D0", value=100, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        db.export_plc_data(data_points, "192.168.1.10")

        # Verify data was saved
        assert len(db.get_plcs()) == 1
        assert len(db.get_latest_data("192.168.1.10")) == 1

        db.close()

    def test_switch_on_off_via_config_dict(self, temp_db_path):
        """Test switching on/off via config dictionary"""
        # Start with disabled
        config_off = DatabaseConfig.from_dict({"enabled": False, "path": temp_db_path})
        db_off = DatabaseExporter(config_off)

        assert db_off.is_enabled is False
        assert not Path(temp_db_path).exists()
        db_off.close()

        # Enable via config
        config_on = DatabaseConfig.from_dict({"enabled": True, "path": temp_db_path})
        db_on = DatabaseExporter(config_on)

        assert db_on.is_enabled is True
        assert Path(temp_db_path).exists()
        db_on.close()

    def test_get_database_exporter_on_off(self, temp_db_path):
        """Test get_database_exporter with on/off config"""
        # Off
        db_off = get_database_exporter({"enabled": False})
        assert db_off.is_enabled is False
        db_off.close()

        # On
        db_on = get_database_exporter({"enabled": True, "path": temp_db_path})
        assert db_on.is_enabled is True
        db_on.close()

    def test_enabled_with_history_tracking_off(self, temp_db_path):
        """Test enabled database with history tracking disabled"""
        config = DatabaseConfig(
            enabled=True,
            path=temp_db_path,
            track_history=False
        )
        db = DatabaseExporter(config)

        plc_ip = "192.168.1.10"

        # First value
        data_points = [
            DataPoint(address="D0", value=100, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Changed value
        data_points = [
            DataPoint(address="D0", value=200, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Should NOT record changes when track_history is False
        changes = db.get_changes(plc_ip)
        assert len(changes) == 0

        db.close()

    def test_enabled_with_history_tracking_on(self, temp_db_path):
        """Test enabled database with history tracking enabled"""
        config = DatabaseConfig(
            enabled=True,
            path=temp_db_path,
            track_history=True
        )
        db = DatabaseExporter(config)

        plc_ip = "192.168.1.10"

        # First value
        data_points = [
            DataPoint(address="D0", value=100, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Changed value
        data_points = [
            DataPoint(address="D0", value=200, status=StatusCode.OK, timestamp=datetime.now().isoformat()),
        ]
        db.export_plc_data(data_points, plc_ip)

        # Should record changes when track_history is True
        changes = db.get_changes(plc_ip)
        assert len(changes) == 1

        db.close()

    def test_reopen_existing_database(self, temp_db_path):
        """Test reopening existing database preserves data"""
        config = DatabaseConfig(enabled=True, path=temp_db_path)

        # Create and populate database
        db1 = DatabaseExporter(config)
        plcs = [PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)]
        db1.export_discovery_results(plcs)
        db1.close()

        # Reopen database
        db2 = DatabaseExporter(config)

        # Data should be preserved
        saved_plcs = db2.get_plcs()
        assert len(saved_plcs) == 1
        assert saved_plcs[0]["ip_address"] == "192.168.1.10"

        db2.close()

    def test_context_manager_with_enabled(self, temp_db_path):
        """Test context manager with enabled database"""
        config = DatabaseConfig(enabled=True, path=temp_db_path)

        with DatabaseExporter(config) as db:
            assert db.is_enabled is True

            plcs = [PLCInfo(ip_address="192.168.1.10")]
            count = db.export_discovery_results(plcs)
            assert count == 1

    def test_context_manager_with_disabled(self, temp_db_path):
        """Test context manager with disabled database"""
        config = DatabaseConfig(enabled=False, path=temp_db_path)

        with DatabaseExporter(config) as db:
            assert db.is_enabled is False

            plcs = [PLCInfo(ip_address="192.168.1.10")]
            count = db.export_discovery_results(plcs)
            assert count == 0
