"""
Regression tests for the second review's minor findings.
"""

import argparse
import asyncio
import json
import socket
import sqlite3
import sys
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import audit_log, notifications
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.report import ReportConfig, ReportFormat, create_report
from plc_discovery.retry import RetryConfig, RetryStrategy


# ---------------------------------------------------------------------------
# 1: audit logger can be re-initialized with another file
# ---------------------------------------------------------------------------

def test_audit_logger_reinit_uses_new_file(tmp_path):
    audit_log.get_audit_logger().log_error("before init")
    first, second = tmp_path / "a1.log", tmp_path / "a2.log"
    audit_log.init_audit_logger(str(first)).log_error("first")
    audit_log.close_audit_logger()
    audit_log.init_audit_logger(str(second)).log_error("second")
    audit_log.close_audit_logger()
    assert "first" in first.read_text(encoding="utf-8")
    assert "second" in second.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 2-3: FINS connection handling
# ---------------------------------------------------------------------------

def fins_reply(request: bytes) -> bytes:
    header = bytes([0xC0, 0x00, 0x02, request[6], request[7], request[8],
                    request[3], request[4], request[5], request[9]])
    return header + request[10:12] + b"\x00\x00" + b"\x00\x2A"


class UDPServer:
    def __init__(self, respond):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.respond = respond
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                continue
            reply = self.respond(data)
            if reply:
                self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(1)
        self.sock.close()


class TestFINSConnection:

    @pytest.mark.asyncio
    async def test_udp_connect_requires_fins_reply(self):
        config = NetworkConfig(request_timeout_ms=300)
        with UDPServer(lambda req: None) as silent:
            handler = FINSHandler("127.0.0.1", silent.port, config=config)
            assert await handler.connect() is False
            assert handler._transport is None
        with UDPServer(fins_reply) as server:
            handler = FINSHandler("127.0.0.1", server.port, config=config)
            assert await handler.connect() is True
            data, status = await handler.read_device_raw(DeviceType.DM, 0, 1)
            assert (data, status) == ([0x2A], StatusCode.OK)
            await handler.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_error_still_marks_disconnected(self):
        handler = FINSHandler("127.0.0.1", use_tcp=True)
        writer = MagicMock()
        writer.wait_closed = AsyncMock(side_effect=ConnectionResetError())
        handler._writer = writer
        handler._connected = True
        await handler.disconnect()
        assert handler.is_connected is False
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_tcp_handshake_failure_closes_socket(self):
        handler = FINSHandler("127.0.0.1", use_tcp=True, config=NetworkConfig(request_timeout_ms=300))
        reader = MagicMock()
        reader.readexactly = AsyncMock(return_value=b"NOPE" + b"\x00" * 20)
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        with patch("asyncio.open_connection", AsyncMock(return_value=(reader, writer))):
            assert await handler.connect() is False
        writer.close.assert_called_once()
        assert handler._writer is None


# ---------------------------------------------------------------------------
# 4: read sizes follow SAFE_READ_WORDS
# ---------------------------------------------------------------------------

def test_read_sizes_use_safe_values():
    assert ModbusHandler("127.0.0.1").max_read_size == 100
    assert FINSHandler("127.0.0.1").max_read_size == 400


# ---------------------------------------------------------------------------
# 5-6: database performance and sessions
# ---------------------------------------------------------------------------

def points(value):
    return [DataPoint("D0", value, f"0x{value:04X}", StatusCode.OK, "2026-01-01 00:00:00.000")]


class TestDatabase:

    def test_latest_values_loaded_once_and_history_kept(self, tmp_path):
        db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db"), track_history=True))
        with patch.object(db, "_get_latest_values", wraps=db._get_latest_values) as spy:
            db.export_plc_data(points(1), "10.0.0.1")
            db.export_plc_data(points(2), "10.0.0.1")
            db.export_plc_data(points(3), "10.0.0.1")
        assert spy.call_count == 1
        rows = db._connection.execute(
            "SELECT old_value, new_value FROM data_history ORDER BY id"
        ).fetchall()
        assert [tuple(r) for r in rows] == [(1, 2), (2, 3)]
        db.close()

    def test_composite_index_exists(self, tmp_path):
        db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "x.db")))
        names = {r[0] for r in db._connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_data_points_plc_addr_id" in names
        db.close()

    def test_cli_records_scan_session(self, tmp_path, monkeypatch):
        db_path = tmp_path / "scan.db"
        monkeypatch.setattr(sys, "argv", [
            "plc_scanner.py", "--mode", "range", "--protocol", "modbus", "--target", "127.0.0.1",
            "--port", "59997", "--range", "0-1", "--request-timeout", "300", "-q",
            "--database", str(db_path), "--output-dir", str(tmp_path),
        ])
        with pytest.raises(SystemExit):
            plc_scanner.cli()
        rows = sqlite3.connect(db_path).execute("SELECT mode, status FROM scan_sessions").fetchall()
        assert rows == [("range", "completed with errors")]


# ---------------------------------------------------------------------------
# 7: notifications are wired in and do not block the event loop
# ---------------------------------------------------------------------------

class TestNotifications:

    @pytest.mark.asyncio
    async def test_urllib_fallback_runs_in_thread(self, monkeypatch):
        monkeypatch.setattr(notifications, "AIOHTTP_AVAILABLE", False)
        monkeypatch.setattr(notifications, "_urlopen_status", lambda req, timeout: time.sleep(0.3) or 200)
        manager = notifications.NotificationManager()
        manager.add_webhook("hook", "http://127.0.0.1:9/")

        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.01)
                ticks += 1

        results, _ = await asyncio.gather(
            manager.notify_error("x"), ticker()
        )
        assert results == {"hook": True}
        assert ticks == 20  # loop kept running while the POST was in flight

    def test_cli_sends_scan_notifications(self, tmp_path, monkeypatch):
        config = tmp_path / "config.json"
        config.write_text(json.dumps({
            "targets": [{"ip": "127.0.0.1", "protocol": "modbus", "port": 59997}],
            "scan": {"mode": "range", "device_ranges": [{"device": "D", "start": 0, "end": 1}]},
            "network": {"request_timeout_ms": 300},
            "notifications": [{"name": "hook", "type": "webhook", "url": "http://127.0.0.1:9/"}],
        }), encoding="utf-8")
        manager = MagicMock()
        manager._handlers = {"hook": object()}
        manager.notify_error = AsyncMock()
        manager.notify_scan_complete = AsyncMock()
        monkeypatch.setattr(plc_scanner.NotificationManager, "from_config", lambda cfg: manager)
        monkeypatch.setattr(sys, "argv", [
            "plc_scanner.py", "--config", str(config), "-q", "--output-dir", str(tmp_path),
        ])
        with pytest.raises(SystemExit) as exc:
            plc_scanner.cli()
        assert exc.value.code == 1
        manager.notify_error.assert_awaited_once()
        assert manager.notify_error.await_args.kwargs["plc_ip"] == "127.0.0.1"
        assert manager.notify_error.await_args.kwargs["failed_targets"] == ["127.0.0.1"]
        args = manager.notify_scan_complete.await_args.args
        assert args[:3] == (1, 0, 1)  # plc_count, success, errors


# ---------------------------------------------------------------------------
# 8-9: config file handling
# ---------------------------------------------------------------------------

def make_args(**kw):
    base = dict(packet_interval=None, retry_interval=None, request_timeout=None, max_concurrent=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_cli_timing_overrides_config(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"network": {"packet_interval_ms": 300, "request_timeout_ms": 9000}}))
    loader = ConfigLoader(str(path))
    loader.load()
    config = plc_scanner.create_network_config(make_args(packet_interval=80), loader)
    assert config.packet_interval_ms == 80       # CLI wins
    assert config.request_timeout_ms == 9000     # from config file
    assert plc_scanner.create_network_config(make_args(), None) == NetworkConfig()


def test_missing_config_file_is_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--config", str(tmp_path / "nope.yaml")])
    with pytest.raises(SystemExit) as exc:
        plc_scanner.cli()
    assert exc.value.code == 1
    assert "file not found" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 10-11: denied status and statistics
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unsupported_status_kept_in_cache_and_csv(tmp_path):
    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            self._connected = True
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start, count):
            return None, StatusCode.NG_UNSUPPORTED

    handler = Handler("127.0.0.1", 1, NetworkConfig(packet_interval_ms=0, retry_interval_ms=0),
                      retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=0, initial_delay_ms=0),
                      use_circuit_breaker=False)
    handler._connected = True
    rng = DeviceRange(DeviceType.SM, 0, 2)
    await handler.read_device_range(rng)
    second = await handler.read_device_range(rng)  # served from cache

    assert {dp.status for dp in second} == {StatusCode.NG_UNSUPPORTED}
    statuses = handler.get_denied_statuses()
    assert statuses == {f"SM{i}": StatusCode.NG_UNSUPPORTED for i in range(3)}

    path = CSVExporter(str(tmp_path)).export_denied_addresses(set(statuses), "1.2.3.4", statuses=statuses)
    assert "SM0,NG_UNSUPPORTED," in open(path, encoding="utf-8").read()


def test_statistics_count_unsupported():
    collector = PLCDataCollector(PLCInfo("127.0.0.1", protocol=Protocol.SLMP))
    collector._collected_data = [
        DataPoint("D0", 1, status=StatusCode.OK),
        DataPoint("SM0", status=StatusCode.NG_UNSUPPORTED),
    ]
    stats = collector.get_statistics()
    assert stats["unsupported_count"] == 1
    assert stats["success_count"] + stats["unsupported_count"] == stats["total_points"]


# ---------------------------------------------------------------------------
# 12: explicit report path is used as given
# ---------------------------------------------------------------------------

def test_report_output_path_used_as_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = ReportConfig(format=ReportFormat.JSON, output_path=str(tmp_path / "results"))
    generator, data = create_report([], {}, {}, "range", None, None, config)

    explicit = generator.save(data, "reports/out.json")
    assert explicit == "reports/out.json"
    assert (tmp_path / "reports" / "out.json").exists()

    auto = generator.save(data)
    assert auto.startswith(str(tmp_path / "results"))
