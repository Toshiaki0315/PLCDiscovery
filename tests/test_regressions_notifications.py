"""
Regression tests for notifications, found and fixed in code reviews.
"""

import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery import notifications
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

        results, _ = await asyncio.gather(manager.notify_error("x"), ticker())
        assert results == {"hook": True}
        assert ticks == 20  # loop kept running while the POST was in flight

    def test_cli_sends_scan_notifications(self, tmp_path, monkeypatch):
        config = tmp_path / "config.json"
        config.write_text(
            json.dumps(
                {
                    "targets": [{"ip": "127.0.0.1", "protocol": "modbus", "port": 59997}],
                    "scan": {"mode": "range", "device_ranges": [{"device": "D", "start": 0, "end": 1}]},
                    "network": {"request_timeout_ms": 300},
                    "notifications": [{"name": "hook", "type": "webhook", "url": "http://127.0.0.1:9/"}],
                }
            ),
            encoding="utf-8",
        )
        manager = MagicMock()
        manager._handlers = {"hook": object()}
        manager.notify_error = AsyncMock()
        manager.notify_scan_complete = AsyncMock()
        monkeypatch.setattr(plc_scanner.NotificationManager, "from_config", lambda cfg: manager)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "plc_scanner.py",
                "--config",
                str(config),
                "-q",
                "--output-dir",
                str(tmp_path),
            ],
        )
        with pytest.raises(SystemExit) as exc:
            plc_scanner.cli()
        assert exc.value.code == 1
        manager.notify_error.assert_awaited_once()
        assert manager.notify_error.await_args.kwargs["plc_ip"] == "127.0.0.1"
        assert manager.notify_error.await_args.kwargs["failed_targets"] == ["127.0.0.1"]
        args = manager.notify_scan_complete.await_args.args
        assert args[:3] == (1, 0, 1)  # plc_count, success, errors
