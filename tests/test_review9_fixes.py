"""
Regression tests for the ninth review (Z1, Z2 and output-encoding crash).
"""

import io
import logging
import sys
from unittest.mock import AsyncMock, patch

import pytest

import plc_scanner
from plc_discovery import progress
from plc_discovery.config import NetworkConfig
from plc_discovery.progress import RichProgressDisplay
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler


def cp932_stream(errors="strict"):
    return io.TextIOWrapper(io.BytesIO(), encoding="cp932", errors=errors)


# ---------------------------------------------------------------------------
# Output encoding: redirected output on Japanese Windows (CP932)
# ---------------------------------------------------------------------------


def test_ascii_markers_when_symbols_not_encodable(monkeypatch):
    stream = cp932_stream()
    monkeypatch.setattr(sys, "stdout", stream)
    display = RichProgressDisplay(use_rich=False)
    display.print_info("接続中")
    display.print_error("失敗")
    display.print_success("完了")
    stream.flush()
    text = stream.buffer.getvalue().decode("cp932")
    assert "[INFO] 接続中" in text and "[ERROR] 失敗" in text and "[OK] 完了" in text


def test_symbols_kept_when_encodable(monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", stream)
    RichProgressDisplay(use_rich=False).print_info("x")
    stream.flush()
    assert stream.buffer.getvalue().decode("utf-8").startswith("ℹ x")


def test_make_streams_safe_replaces_unencodable(monkeypatch):
    out, err = cp932_stream(), cp932_stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    plc_scanner.make_streams_safe()
    print("Dürr ✓ 三菱電機")  # would raise UnicodeEncodeError before
    out.flush()
    assert out.buffer.getvalue().decode("cp932").strip() == "D?rr ? 三菱電機"


# ---------------------------------------------------------------------------
# Z2: --no-rich gives plain output
# ---------------------------------------------------------------------------


def test_no_rich_disables_console():
    assert RichProgressDisplay(use_rich=False).console is None
    if progress.RICH_AVAILABLE:
        assert RichProgressDisplay().console is not None


def test_rich_markup_in_messages_is_escaped():
    if not progress.RICH_AVAILABLE:
        pytest.skip("rich not installed")
    display = RichProgressDisplay()
    with display.console.capture() as captured:
        display.print_info("value [bold]x[/bold] and [/unbalanced]")
    assert "[bold]x[/bold] and [/unbalanced]" in captured.get()


# ---------------------------------------------------------------------------
# Z1: library log noise and EtherNet/IP reconnects
# ---------------------------------------------------------------------------


def test_third_party_loggers_quiet_unless_verbose():
    plc_scanner.quiet_third_party_loggers(verbose=False)
    assert logging.getLogger("pycomm3").level == logging.CRITICAL
    assert logging.getLogger("pymodbus").level == logging.CRITICAL
    plc_scanner.quiet_third_party_loggers(verbose=True)
    assert logging.getLogger("pycomm3").level == logging.DEBUG
    plc_scanner.quiet_third_party_loggers(verbose=False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plc_type, expected",
    [
        ("slc", "_connect_slc"),
        ("generic", "_connect_generic"),
        (None, "_connect_logix_first"),
        ("logix", "_connect_logix_first"),
    ],
)
async def test_reconnect_uses_detected_driver(plc_type, expected):
    handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
    handler._plc_type = plc_type
    mocks = {
        name: AsyncMock(return_value=True) for name in ("_connect_slc", "_connect_generic", "_connect_logix_first")
    }
    with patch.multiple(handler, **mocks):
        assert await handler.connect()
    assert mocks[expected].await_count == 1
    assert sum(m.await_count for m in mocks.values()) == 1
