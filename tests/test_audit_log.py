"""
Tests for audit_log module
"""

import json
import os
import tempfile

from plc_discovery.audit_log import (
    AuditEvent,
    AuditLogger,
    close_audit_logger,
    get_audit_logger,
    init_audit_logger,
)


class TestAuditEvent:
    """Tests for AuditEvent dataclass"""

    def test_to_dict(self):
        """Test converting event to dictionary"""
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00",
            event_type="READ_SUCCESS",
            session_id="test_session",
            plc_ip="192.168.1.10",
            device="D",
            address_start=0,
            address_end=100,
        )

        d = event.to_dict()

        assert d["timestamp"] == "2024-01-01T00:00:00"
        assert d["event_type"] == "READ_SUCCESS"
        assert d["plc_ip"] == "192.168.1.10"
        # None values should be excluded
        assert "error_message" not in d
        assert "duration_ms" not in d

    def test_to_json(self):
        """Test converting event to JSON"""
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00",
            event_type="CONNECT",
            session_id="test_session",
            plc_ip="192.168.1.10",
            status="SUCCESS",
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["plc_ip"] == "192.168.1.10"
        assert parsed["status"] == "SUCCESS"


class TestAuditLogger:
    """Tests for AuditLogger class"""

    def test_create_disabled_logger(self):
        """Test creating disabled audit logger"""
        logger = AuditLogger.__new__(AuditLogger)
        logger._initialized = False
        logger.__init__(enabled=False)

        assert logger.enabled is False

    def test_session_id_generation(self):
        """Test session ID is generated"""
        logger = AuditLogger.__new__(AuditLogger)
        logger._initialized = False
        logger.__init__(enabled=False)

        session_id = logger.get_session_id()

        assert session_id is not None
        assert len(session_id) > 0

    def test_log_to_file(self):
        """Test logging events to file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            # Create new logger instance
            logger = AuditLogger.__new__(AuditLogger)
            logger._initialized = False
            logger.__init__(log_file=log_path, enabled=True)

            # Log events
            logger.log_session_start({"test": True})
            logger.log_connect("192.168.1.10", "SLMP", 5001, True)
            logger.log_read_success("192.168.1.10", "SLMP", "D", 0, 100, 100, 50.0)
            logger.log_session_end()
            logger.close()

            # Read log file
            with open(log_path) as f:
                lines = f.readlines()

            assert len(lines) >= 4

            # Parse and verify
            for line in lines:
                event = json.loads(line)
                assert "timestamp" in event
                assert "event_type" in event
                assert "session_id" in event
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)

    def test_log_connect_events(self):
        """Test logging connect/disconnect events"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            logger = AuditLogger.__new__(AuditLogger)
            logger._initialized = False
            logger.__init__(log_file=log_path, enabled=True)

            logger.log_connect("192.168.1.10", "SLMP", 5001, True)
            logger.log_disconnect("192.168.1.10", "SLMP")
            logger.close()

            with open(log_path) as f:
                lines = f.readlines()

            connect_event = json.loads(lines[0])
            assert connect_event["event_type"] == "CONNECT"
            assert connect_event["status"] == "SUCCESS"

            disconnect_event = json.loads(lines[1])
            assert disconnect_event["event_type"] == "DISCONNECT"
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)

    def test_log_read_events(self):
        """Test logging read events"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            logger = AuditLogger.__new__(AuditLogger)
            logger._initialized = False
            logger.__init__(log_file=log_path, enabled=True)

            logger.log_read_request("192.168.1.10", "SLMP", "D", 0, 100)
            logger.log_read_success("192.168.1.10", "SLMP", "D", 0, 100, 100, 25.5)
            logger.log_read_error("192.168.1.10", "SLMP", "D", 200, 300, "Access denied", 10.0)
            logger.close()

            with open(log_path) as f:
                lines = f.readlines()

            request_event = json.loads(lines[0])
            assert request_event["event_type"] == "READ_REQUEST"
            assert request_event["address_start"] == 0
            assert request_event["address_end"] == 100

            success_event = json.loads(lines[1])
            assert success_event["event_type"] == "READ_SUCCESS"
            assert success_event["data_points"] == 100
            assert success_event["duration_ms"] == 25.5

            error_event = json.loads(lines[2])
            assert error_event["event_type"] == "READ_ERROR"
            assert "Access denied" in error_event["error_message"]
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)

    def test_log_scan_events(self):
        """Test logging scan events"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            logger = AuditLogger.__new__(AuditLogger)
            logger._initialized = False
            logger.__init__(log_file=log_path, enabled=True)

            logger.log_scan_start("192.168.1.10", "full", ["D0-D1000"])
            logger.log_scan_complete("192.168.1.10", 1000, 950, 50, 5000.0)
            logger.close()

            with open(log_path) as f:
                lines = f.readlines()

            start_event = json.loads(lines[0])
            assert start_event["event_type"] == "SCAN_START"
            assert start_event["metadata"]["mode"] == "full"

            complete_event = json.loads(lines[1])
            assert complete_event["event_type"] == "SCAN_COMPLETE"
            assert complete_event["data_points"] == 1000
            assert complete_event["metadata"]["success_count"] == 950
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)

    def test_disabled_logger_no_file(self):
        """Test that disabled logger doesn't create file"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = os.path.join(tmp_dir, "audit.log")

            logger = AuditLogger.__new__(AuditLogger)
            logger._initialized = False
            logger.__init__(log_file=log_path, enabled=False)

            logger.log_connect("192.168.1.10", "SLMP", 5001, True)
            logger.close()

            # File should not be created when disabled
            assert not os.path.exists(log_path)

    def test_set_enabled(self):
        """Test enabling/disabling logger"""
        logger = AuditLogger.__new__(AuditLogger)
        logger._initialized = False
        logger.__init__(enabled=False)

        assert logger.enabled is False

        logger.set_enabled(True)
        assert logger.enabled is True


class TestGlobalFunctions:
    """Tests for global audit logger functions"""

    def test_init_and_get_audit_logger(self):
        """Test initializing and getting global audit logger"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            logger = init_audit_logger(log_path, enabled=True)
            retrieved = get_audit_logger()

            assert logger is retrieved
            assert logger.enabled is True

            close_audit_logger()
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)
