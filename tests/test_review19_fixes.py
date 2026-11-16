"""
Regression tests for the nineteenth review.

1: S7 item return codes from the CPU (e.g. 0x0A "object does not exist"
   for a read past the end of a DB) are address errors, not
   communication failures, and never trigger a reconnect.
2: A report that cannot be generated makes the run exit with 1.
3: FLOAT / DOUBLE values are displayed with significant digits.
"""

import asyncio
import sys
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, StatusCode
from plc_discovery.data_types import DataType, DataTypeConverter
from plc_discovery.protocols.s7 import S7Handler, classify_s7_error


# ---------------------------------------------------------------------------
# 1: S7 error classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("message,expected", [
    ("Read operation failed: Object does not exist (0x0a)", StatusCode.NG_ILLEGAL_ADDR),   # snap7 3.x
    ("Read operation failed: Invalid address (0x05)", StatusCode.NG_ILLEGAL_ADDR),
    ("Read operation failed: Accessing the object not allowed (0x03)", StatusCode.NG_ILLEGAL_ADDR),
    ("Read operation failed: Data type not supported (0x06)", StatusCode.NG_UNSUPPORTED),
    ("Read operation failed: Hardware error (0x01)", StatusCode.NG_COMM_ERROR),
    ("CPU : Item not available", StatusCode.NG_ILLEGAL_ADDR),                              # snap7 1.x
    ("CPU : Address out of range", StatusCode.NG_ILLEGAL_ADDR),
    ("CPU : Invalid Transport size", StatusCode.NG_UNSUPPORTED),
    ("TCP : Connection reset", None),
    ("CLI : Job Timeout", None),
    ("ISO : An error occurred during recv TCP : Connection timed out", None),
])
def test_classify_s7_error(message, expected):
    assert classify_s7_error(Exception(message)) == expected


@pytest.mark.asyncio
async def test_cpu_answer_does_not_reconnect():
    handler = S7Handler("10.0.0.1", config=NetworkConfig())
    handler._connected = True
    client = MagicMock()
    client.db_read.side_effect = Exception("Read operation failed: Object does not exist (0x0a)")
    handler._client = client
    data, status = await handler.read_device_raw(DeviceType.DB, 100, 10)
    assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
    assert handler._needs_reconnect is False


@pytest.mark.asyncio
async def test_transport_error_still_reconnects():
    handler = S7Handler("10.0.0.1", config=NetworkConfig())
    handler._connected = True
    client = MagicMock()
    client.db_read.side_effect = Exception("TCP : Connection reset")
    handler._client = client
    _, status = await handler.read_device_raw(DeviceType.DB, 0, 1)
    assert status == StatusCode.NG_COMM_ERROR
    assert handler._needs_reconnect is True


@pytest.mark.asyncio
async def test_denied_words_do_not_hide_readable_ones_simulator():
    """Simulator denies bytes 500-550 (words 250-275): only those are NG"""
    pytest.importorskip("snap7")
    from simulators.s7_simulator import COTPProtocol, S7Device

    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: COTPProtocol(S7Device([(500, 550)])), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    handler = S7Handler("127.0.0.1", port=port,
                        config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=2000))
    reconnects = []
    original_connect = handler.connect

    async def counting_connect():
        reconnects.append(1)
        return await original_connect()

    try:
        assert await handler.connect()
        handler.connect = counting_connect
        points = await handler.read_device_range(DeviceRange(DeviceType.DB, 0, 1000))
        bad = [int(p.address[2:]) for p in points if p.status != StatusCode.OK]
        assert bad == list(range(250, 276))
        assert {p.status for p in points if p.status != StatusCode.OK} == {StatusCode.NG_ILLEGAL_ADDR}
        assert reconnects == []
    finally:
        await handler.disconnect()
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# 2: report failure exit code
# ---------------------------------------------------------------------------

@pytest.fixture
def restore_logging():
    """main() reconfigures the root logger onto pytest's captured stdout"""
    import logging
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def test_failed_report_exits_with_1(monkeypatch, tmp_path, capsys, restore_logging):
    from plc_discovery.report import ReportGenerator

    def broken_save(self, data, output_path=None):
        raise ImportError("PDF generation requires 'weasyprint' or 'pdfkit'")

    monkeypatch.setattr(ReportGenerator, "save", broken_save)

    async def no_discovery(*args, **kwargs):
        return []

    monkeypatch.setattr(plc_scanner, "run_discovery", no_discovery)
    monkeypatch.setattr(sys, "argv", [
        "plc_scanner.py", "--mode", "discover", "--no-rich", "-o", str(tmp_path), "--report", "pdf",
    ])
    with pytest.raises(SystemExit) as exc:
        asyncio.run(plc_scanner.main())
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Report generation failed" in out
    assert "Scan completed successfully" not in out


# ---------------------------------------------------------------------------
# 3: float display
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,float_text,double_text", [
    (23.5, "23.5", "23.5"),
    (1e30, "1e+30", "1e+30"),
    (0.000012345, "1.2345e-05", "1.2345e-05"),
    (-1.46e-12, "-1.46e-12", "-1.46e-12"),
    (123456.789, "123456.8", "123456.789"),
])
def test_float_display_uses_significant_digits(value, float_text, double_text):
    assert DataTypeConverter.to_string(value, DataType.FLOAT) == float_text
    assert DataTypeConverter.to_string(value, DataType.DOUBLE) == double_text


# ---------------------------------------------------------------------------
# Second pass: request-size answers are split; target addresses validated
# ---------------------------------------------------------------------------

from collections import Counter

from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.utils import target_address_error


class _Registers:
    def __init__(self, count):
        self.registers = list(range(count))
        self.bits = []

    def isError(self):
        return False


@pytest.mark.asyncio
async def test_modbus_device_with_small_request_limit_is_fully_read():
    """A device reading at most 32 registers answers exception 03 to 100"""
    from pymodbus.pdu import ExceptionResponse

    handler = ModbusHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    client = MagicMock()
    requests = []

    def read(address, count, **kwargs):
        requests.append(count)
        return ExceptionResponse(0x03, 0x03) if count > 32 else _Registers(count)

    client.read_holding_registers = read
    handler._client = client
    points = await handler.read_device_range(DeviceRange(DeviceType.HR, 0, 999))
    assert Counter(p.status for p in points) == {StatusCode.OK: 1000}   # was 1000 x NG_COMM_ERROR
    assert handler._needs_reconnect is False
    assert len(requests) < 200


def test_fins_response_too_long_is_split():
    handler = FINSHandler("10.0.0.1")
    response = bytes(12) + bytes([0x11, 0x0B])
    assert handler._parse_read_response(response) == (None, StatusCode.NG_ILLEGAL_ADDR)


@pytest.mark.parametrize("value,ok", [
    ("192.168.1.10", True), ("simulators", True), ("plc-01.factory.local", True),
    ("", False), ("192.168.1.300", False), ("1.2.3", False), ("127.0.0.1 ;rm", False),
    ("../x", False), ("-bad", False),
])
def test_target_address_error(value, ok):
    assert (target_address_error(value) is None) == ok


def test_cli_targets_skip_empty_and_reject_invalid():
    assert plc_scanner.parse_targets("127.0.0.1,,10.0.0.2, ") == ["127.0.0.1", "10.0.0.2"]
    with pytest.raises(ValueError, match="192.168.1.300"):
        plc_scanner.parse_targets("127.0.0.1,192.168.1.300")


def test_config_rejects_invalid_target_ip(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text("targets:\n  - {ip: 192.168.1.300}\n  - {ip: simulators}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any(e.startswith("targets[0].ip:") for e in errors)
    assert not any(e.startswith("targets[1]") for e in errors)


def test_gui_validates_target_address():
    from pathlib import Path
    source = (Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "target_address_error(ip)" in source
