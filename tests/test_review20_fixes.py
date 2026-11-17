"""
Regression tests for the twentieth review.

1: Slack / Teams treat any 2xx answer as delivered (Teams workflow
   webhooks answer 202; checking for 200 re-sent each message
   retry_count times and logged it as failed).
2: Discovery identity queries are bounded by the discovery timeout, and
   the S7 query also tries slot 2 (S7-300/400).
"""

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.notifications import (
    NotificationConfig,
    NotificationEvent,
    NotificationPriority,
    NotificationType,
    SlackHandler,
    TeamsHandler,
)


@pytest.fixture
def webhook_server():
    """Local HTTP server answering every POST with the given status"""
    state = {"status": 202, "posts": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            state["posts"] += 1
            self.send_response(state["status"])
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}/hook"
    yield state
    server.shutdown()


def _event():
    return NotificationEvent(
        type=NotificationType.SCAN_COMPLETE,
        title="Scan complete",
        message="ok",
        priority=NotificationPriority.NORMAL,
    )


@pytest.mark.parametrize("handler_class", [TeamsHandler, SlackHandler])
@pytest.mark.parametrize("status", [200, 202, 204])
def test_2xx_is_delivered_once(webhook_server, handler_class, status):
    webhook_server["status"] = status
    config = NotificationConfig(name="n", type="teams", url=webhook_server["url"], retry_count=3, timeout_seconds=2)
    assert asyncio.run(handler_class(config).send(_event())) is True
    assert webhook_server["posts"] == 1  # was 3 posts and "failed" for 202


@pytest.mark.parametrize("handler_class", [TeamsHandler, SlackHandler])
def test_error_status_is_retried_and_fails(webhook_server, handler_class):
    webhook_server["status"] = 500
    config = NotificationConfig(name="n", type="teams", url=webhook_server["url"], retry_count=2, timeout_seconds=2)
    real_sleep = asyncio.sleep

    async def no_wait(*_):
        await real_sleep(0)

    with patch("plc_discovery.notifications.asyncio.sleep", new=no_wait):
        assert asyncio.run(handler_class(config).send(_event())) is False
    assert webhook_server["posts"] == 2


def test_modbus_identity_query_uses_discovery_timeout():
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=700, request_timeout_ms=5000))
    created = {}

    class FakeClient:
        def __init__(self, host, port=502, timeout=None, retries=None):
            created["timeout"] = timeout

        def connect(self):
            return False

    with patch("pymodbus.client.ModbusTcpClient", FakeClient):
        asyncio.run(discovery._query_modbus_info(PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP, port=502)))
    assert created["timeout"] == pytest.approx(0.7)


def test_s7_identity_query_tries_slot_2():
    pytest.importorskip("snap7")
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=1000))
    client = MagicMock()
    slots = []

    def connect(ip, rack, slot, port):
        slots.append(slot)
        if slot == 0:
            raise RuntimeError("TCP : Connection refused (slot 0)")

    client.connect.side_effect = connect
    client.read_szl.side_effect = RuntimeError("SZL not available")
    client.get_cpu_info.return_value = MagicMock(ModuleTypeName=b"CPU 315-2 PN/DP", ASName=b"S7-300")
    with patch("snap7.client.Client", return_value=client):
        plc = asyncio.run(discovery._query_s7_info(PLCInfo("10.0.0.1", protocol=Protocol.S7, port=102)))
    assert slots == [0, 2]
    assert (plc.manufacturer, plc.model, plc.cpu_type) == ("シーメンス", "CPU 315-2 PN/DP", "S7-300")


def test_s7_identity_query_is_bounded():
    pytest.importorskip("snap7")
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100))
    client = MagicMock()
    client.connect.side_effect = lambda *a: time.sleep(2)  # host that never answers

    async def run():
        # Timed inside the loop: asyncio.run() itself waits for the worker
        # thread when it shuts down, discovery does not
        started = time.monotonic()
        plc = await discovery._query_s7_info(PLCInfo("10.0.0.1", protocol=Protocol.S7, port=102))
        return plc, time.monotonic() - started

    with patch("snap7.client.Client", return_value=client):
        plc, elapsed = asyncio.run(run())
    assert elapsed < 1.0
    # The late thread does not change the result; the probe-verified
    # protocol still names the manufacturer
    assert (plc.manufacturer, plc.model) == ("シーメンス", "S7 PLC")
