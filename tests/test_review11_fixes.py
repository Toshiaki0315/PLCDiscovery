"""
Regression tests for the eleventh review's findings.

B1: FINS end codes follow Omron's table (0x1103/0x1104 = address range error).
B2: the database keeps one PLC row per IP, protocol and port (schema v2).
B3: periodic scans keep retrying targets that were offline at the start.
"""

import asyncio
import collections
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.database import SCHEMA_VERSION, DatabaseConfig, DatabaseExporter
from plc_discovery.protocols.fins import FINSHandler

# ---------------------------------------------------------------------------
# B1: FINS end codes
# ---------------------------------------------------------------------------


def fins_error(sid, end_code):
    return bytes([0xC0, 0, 2, 0, 1, 0, 0, 1, 0, sid, 1, 1, end_code >> 8, end_code & 0xFF])


@pytest.mark.parametrize(
    "end_code, status",
    [
        (0x1103, StatusCode.NG_ILLEGAL_ADDR),  # address range error
        (0x1104, StatusCode.NG_ILLEGAL_ADDR),  # address range exceeded
        (0x1101, StatusCode.NG_UNSUPPORTED),  # area classification missing
        (0x0401, StatusCode.NG_UNSUPPORTED),  # undefined command
        (0x0402, StatusCode.NG_UNSUPPORTED),  # not supported by model/version
        (0x0205, StatusCode.NG_TIMEOUT),  # response timeout (relayed)
        (0x1001, StatusCode.NG_COMM_ERROR),  # command too long: a format error, not an address
        (0x1002, StatusCode.NG_COMM_ERROR),  # command too short
    ],
)
def test_fins_end_code_classification(end_code, status):
    assert FINSHandler("127.0.0.1")._parse_read_response(fins_error(1, end_code))[1] == status


@pytest.mark.asyncio
async def test_fins_partly_valid_range_found_by_binary_search():
    """A CPU with H0-H49 only: H0-H49 are read, H50-H99 learned as inaccessible"""
    handler = FINSHandler("127.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True

    async def plc(frame, sid):
        start, count = (frame[13] << 8) | frame[14], (frame[16] << 8) | frame[17]
        if start + count > 50:
            return fins_error(sid, 0x1103)
        return fins_error(sid, 0)[:12] + b"\x00\x00" + b"\x00\x07" * count

    handler._send_udp = plc
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 99))
    assert collections.Counter(p.status for p in points) == {
        StatusCode.OK: 50,
        StatusCode.NG_ILLEGAL_ADDR: 50,
    }  # previously 100 x NG_COMM_ERROR
    assert handler.get_denied_addresses() == {f"HR{a}" for a in range(50, 100)}
    assert handler.circuit_breaker_state == "closed"


def test_fins_simulator_uses_address_range_error():
    from simulators.fins_simulator import INACCESSIBLE_RANGES, FINSSimulator

    area, start, _ = INACCESSIBLE_RANGES[0]
    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, area, start >> 8, start & 0xFF, 0, 0, 1])
    response = FINSSimulator().handle_frame(request, ("127.0.0.1", 9600))
    assert response[12:14] == b"\x11\x03"


# ---------------------------------------------------------------------------
# B2: database PLC rows per IP, protocol and port
# ---------------------------------------------------------------------------

V1_PLCS = """
CREATE TABLE schema_info (version INTEGER PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE plcs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT, manufacturer TEXT, model TEXT, protocol TEXT, port INTEGER,
    cpu_type TEXT, firmware_version TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(ip_address)
);
CREATE INDEX idx_plcs_ip ON plcs(ip_address);
INSERT INTO schema_info VALUES (1, '2026-01-01');
INSERT INTO plcs (ip_address, manufacturer, protocol, port, first_seen, last_seen)
    VALUES ('10.0.0.1', 'Mitsubishi', 'SLMP', 5001, '2026-01-01', '2026-01-01');
"""


def rows(db):
    return sorted((p["ip_address"], p["protocol"], p["port"], p["model"]) for p in db.get_plcs())


def test_database_keeps_each_protocol_of_one_ip(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    plcs = [
        PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=5001),
        PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=1502),
    ]
    assert db.export_discovery_results(plcs) == 2
    assert db.export_discovery_results(plcs) == 2  # second run updates, no duplicates
    assert rows(db) == [("127.0.0.1", "MODBUS_TCP", 1502, None), ("127.0.0.1", "SLMP", 5001, None)]


def test_database_rows_without_protocol_are_not_duplicated(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    db.export_discovery_results([PLCInfo("10.0.0.9")])
    db.export_discovery_results([PLCInfo("10.0.0.9", model="X")])
    assert rows(db) == [("10.0.0.9", None, None, "X")]


def test_v1_database_is_migrated(tmp_path):
    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    conn.executescript(V1_PLCS)
    conn.close()

    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(path)))
    db.export_discovery_results(
        [
            PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, model="Q03UDE"),
            PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP, port=502),
        ]
    )
    assert rows(db) == [("10.0.0.1", "MODBUS_TCP", 502, None), ("10.0.0.1", "SLMP", 5001, "Q03UDE")]
    old = [p for p in db.get_plcs() if p["protocol"] == "SLMP"][0]
    assert old["manufacturer"] == "Mitsubishi" and old["first_seen"] == "2026-01-01"  # existing data kept
    assert (
        db._connection.execute("SELECT MAX(version) FROM schema_info").fetchone()[0] == SCHEMA_VERSION
    )  # migrated to the current version
    db.close()
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(path))).close()  # reopening is a no-op


def test_setup_script_uses_scanner_schema():
    from plc_discovery import database
    from scripts import setup_database

    assert setup_database.CREATE_TABLES_SQL is database.CREATE_TABLES_SQL


# ---------------------------------------------------------------------------
# B3: periodic scan keeps targets that were offline at the start
# ---------------------------------------------------------------------------


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


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


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
