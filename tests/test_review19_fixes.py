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
