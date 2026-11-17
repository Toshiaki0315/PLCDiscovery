"""
Regression tests for the seventeenth review.

1: FINS never reads DM in place of a device type it does not map.
2: Addresses beyond a protocol's encodable range are NG_ILLEGAL_ADDR,
   decided locally (no wrapped address, no fake communication failure).
3: Database time windows compare local timestamps with local time; the
   cleanup script accepts only a positive number of days.
"""

import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, StatusCode
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.protocols.fins import FINS_AREA_CODES, FINSHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.protocols.slmp import SLMPHandler

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fast_config():
    return NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


# ---------------------------------------------------------------------------
# 1: FINS device types
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("device", [d for d in DeviceType if d not in FINS_AREA_CODES])
async def test_fins_unmapped_device_unsupported_without_request(fast_config, device):
    handler = FINSHandler("192.168.0.10", config=fast_config)
    handler._connected = True
    handler._send_udp = AsyncMock()
    data, status = await handler.read_device_raw(device, 0, 10)
    assert (data, status) == (None, StatusCode.NG_UNSUPPORTED)
    handler._send_udp.assert_not_called()


# ---------------------------------------------------------------------------
# 2: address limits
# ---------------------------------------------------------------------------

def _connected(handler):
    handler._connected = True
    handler._client = MagicMock()
    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize("factory,device,start,count", [
    (lambda c: FINSHandler("192.168.0.10", config=c), DeviceType.DM, 65541, 1),
    (lambda c: FINSHandler("192.168.0.10", config=c), DeviceType.DM, 65530, 10),
    (lambda c: ModbusHandler("192.168.0.10", config=c), DeviceType.HR, 70000, 1),
    (lambda c: SLMPHandler("192.168.0.10", config=c), DeviceType.D, 0x1000000, 1),
])
async def test_beyond_address_limit_is_illegal_and_not_sent(fast_config, factory, device, start, count):
    handler = _connected(factory(fast_config))
    handler.read_device_raw = AsyncMock()
    handler._comm_failure_streak = 2
    data, status = await handler._tracked_read(device, start, count)
    assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
    handler.read_device_raw.assert_not_called()
    assert handler._comm_failure_streak == 2   # link state untouched


@pytest.mark.asyncio
async def test_last_encodable_address_still_read(fast_config):
    handler = _connected(ModbusHandler("192.168.0.10", config=fast_config))
    handler.read_device_raw = AsyncMock(return_value=([7], StatusCode.OK))
    assert await handler._tracked_read(DeviceType.HR, 65535, 1) == ([7], StatusCode.OK)


@pytest.mark.asyncio
async def test_range_across_limit_reads_valid_part(fast_config):
    """HR65500-65599: up to 65535 read, the rest NG_ILLEGAL_ADDR (not COMM_ERROR)"""
    handler = _connected(ModbusHandler("192.168.0.10", config=fast_config))

    async def fake_read(device_type, start, count):
        return [start + i for i in range(count)], StatusCode.OK

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 65500, 65599))
    assert len(points) == 100
    assert all(p.status == StatusCode.OK for p in points[:36])
    assert points[35].address == "HR65535" and points[35].value == 65535
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points[36:])
    assert handler._needs_reconnect is False


# ---------------------------------------------------------------------------
# 3: database time windows and the cleanup script
# ---------------------------------------------------------------------------

def test_cleanup_window_uses_local_time(tmp_path):
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "t.db")))
    try:
        conn = db._connection
        now = datetime.now()
        # One row just inside a 1-day window, one just outside (local time)
        for minutes, address in ((-(24 * 60 - 30), "D1"), (-(24 * 60 + 30), "D2")):
            stamp = (now + timedelta(minutes=minutes)).isoformat()
            conn.execute(
                "INSERT INTO data_history (plc_ip, address, old_value, new_value, changed_at) "
                "VALUES (?, ?, 0, 1, ?)", ("10.0.0.1", address, stamp)
            )
        conn.commit()
        assert [r["address"] for r in db.get_changes(days=1)] == ["D1"]
        db._cleanup_old_data(days=1)
        rows = conn.execute("SELECT address FROM data_history").fetchall()
        assert [r[0] for r in rows] == ["D1"]
    finally:
        db.close()


def test_no_utc_comparison_left():
    for path in ("plc_discovery/database.py", "scripts/manage_database.sh"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "datetime('now', ?)" not in text
        assert "datetime('now', '-" not in text


@pytest.mark.skipif(subprocess.run(["which", "sqlite3"], capture_output=True).returncode != 0,
                    reason="sqlite3 command not available")
@pytest.mark.parametrize("days", ["abc", "1'); DELETE FROM plcs; --", "0", ""])
def test_cleanup_script_rejects_bad_days(tmp_path, days):
    db_path = tmp_path / "t.db"
    DatabaseExporter(DatabaseConfig(enabled=True, path=str(db_path))).close()
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "manage_database.sh"), "cleanup", str(db_path), days],
        capture_output=True, text=True,
    )
    if days == "":
        # Empty argument falls back to the default 30 days
        assert result.returncode == 0
    else:
        assert result.returncode == 1
        assert "positive integer" in result.stdout


# ---------------------------------------------------------------------------
# Second pass: S7 address limit, Docker output path, sorted denied addresses
# ---------------------------------------------------------------------------

from plc_discovery.protocols.s7 import S7Handler
from plc_discovery.report import create_report
from plc_discovery.utils import address_sort_key, sorted_addresses


@pytest.mark.asyncio
@pytest.mark.parametrize("start,count,expected", [
    (0xFFFFF, 1, None),                      # last encodable word: sent
    (1_048_581, 1, StatusCode.NG_ILLEGAL_ADDR),   # wrapped to DBW10 before
    (0xFFFF0, 32, StatusCode.NG_ILLEGAL_ADDR),
])
async def test_s7_address_limit(fast_config, start, count, expected):
    handler = _connected(S7Handler("192.168.0.10", config=fast_config))
    handler.read_device_raw = AsyncMock(return_value=([0] * count, StatusCode.OK))
    data, status = await handler._tracked_read(DeviceType.DB, start, count)
    if expected is None:
        assert status == StatusCode.OK
        handler.read_device_raw.assert_called_once()
    else:
        assert (data, status) == (None, expected)
        handler.read_device_raw.assert_not_called()


@pytest.mark.asyncio
async def test_s7_wrapped_address_not_read_from_simulator(fast_config):
    pytest.importorskip("snap7")
    from simulators.s7_simulator import COTPProtocol, S7Device

    seen = []
    device = S7Device()
    original = device.read_db
    device.read_db = lambda db, start, size: (seen.append(start), original(db, start, size))[1]

    import asyncio
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: COTPProtocol(device), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = S7Handler("127.0.0.1", port=port, config=fast_config)
    try:
        assert await handler.connect()
        points = await handler.read_device_range(DeviceRange(DeviceType.DB, 1_048_581, 1_048_581))
        assert [p.status for p in points] == [StatusCode.NG_ILLEGAL_ADDR]
        assert seen == []   # nothing reached the PLC
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


def test_docker_default_output_is_the_mounted_directory():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    production = dockerfile.split("FROM base as production", 1)[1].split("FROM base as", 1)[0]
    assert "ln -s /app/output /app/plc_scan_results" in production
    assert plc_scanner_default_output() == "./plc_scan_results"
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./plc_scan_results:/app/output" in compose


def plc_scanner_default_output():
    from plc_discovery.output import DEFAULT_OUTPUT_DIR
    return DEFAULT_OUTPUT_DIR


def test_addresses_sorted_by_device_and_number():
    assert sorted_addresses({"D5003", "D17", "M0", "D5000", "DM2", "x?"}) == [
        "D17", "D5000", "D5003", "DM2", "M0", "x?"
    ]
    assert address_sort_key("D9") < address_sort_key("D10")


def test_report_lists_denied_addresses_in_order():
    generator, data = create_report(
        plcs=[], data_points={},
        denied_addresses={"10.0.0.1": ["D5003", "D17", "D5000"]},
    )
    html_text = generator._generate_denied_section(data)
    assert "D17, D5000, D5003" in html_text
