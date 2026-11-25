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
from plc_discovery import notifications, scan_runner
from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.conversion import apply_data_type_conversion
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.notifications import (
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
    NotificationPriority,
    NotificationType,
    SlackHandler,
    TeamsHandler,
)
from plc_discovery.scan_runner import CycleRunner
from plc_discovery.thresholds import Threshold, ThresholdMonitor, numeric_value, parse_thresholds
from plc_discovery.utils import number_text


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


def _manager(send_ok):
    manager = NotificationManager()
    manager.min_interval_seconds = 3600
    manager.add_custom("test", lambda event: None)
    handler = manager._handlers["test"]
    handler.send = AsyncMock(side_effect=lambda event: send_ok[0])
    return manager, handler


def test_failed_send_does_not_throttle_the_next_one():
    send_ok = [False]
    manager, handler = _manager(send_ok)
    event = NotificationEvent(type=NotificationType.PLC_UNREACHABLE, title="t", message="m", throttle_key="PLC1")

    async def run():
        assert not NotificationManager.delivered(await manager.notify(event))
        assert not manager.is_suppressed(NotificationType.PLC_UNREACHABLE, "PLC1")
        send_ok[0] = True
        assert NotificationManager.delivered(await manager.notify(event))
        assert manager.is_suppressed(NotificationType.PLC_UNREACHABLE, "PLC1")

    asyncio.run(run())
    assert handler.send.await_count == 2


def test_undelivered_threshold_notifications_are_offered_again(monkeypatch):
    monkeypatch.setattr("plc_discovery.scan_runner.NOTIFY_RETRY_SECONDS", 0.0)
    notifier = MagicMock()
    exceeded = [{"hook": False}, {"hook": True}]
    cleared = [{"hook": False}, {"hook": True}]
    notifier.notify_threshold = AsyncMock(side_effect=lambda *a, **k: exceeded.pop(0))
    notifier.notify_threshold_cleared = AsyncMock(side_effect=lambda *a, **k: cleared.pop(0))

    async def notify(send):
        return NotificationManager.delivered(await send(notifier))

    def point(value):
        return [DataPoint(address="D1", status=StatusCode.OK, value=value)]

    async def run():
        runner = CycleRunner(None, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))
        for value in (20, 20, 20, 5, 5, 5):
            await runner.check_thresholds("PLC1", point(value), "10.0.0.1")

    asyncio.run(run())
    assert notifier.notify_threshold.await_count == 2  # failed, then delivered; not sent a third time
    assert notifier.notify_threshold_cleared.await_count == 2


def test_threshold_ignores_raw_word_of_incomplete_float():
    # D100-D101 hold a FLOAT; D101 timed out, D100's raw word is 0xC000 = 49152
    points = apply_data_type_conversion(
        [
            DataPoint(address="D100", status=StatusCode.OK, value=0xC000),
            DataPoint(address="D101", status=StatusCode.NG_TIMEOUT),
        ],
        DataType.FLOAT,
        ByteOrder.LITTLE_ENDIAN,
        None,
    )
    assert numeric_value(points[0]) is None
    monitor = ThresholdMonitor([Threshold("D100", ">", 80)])
    assert monitor.evaluate("PLC1", points).crossed == []


def test_threshold_ignores_nan_infinity_and_later_words():
    # 0x7FC0 0x1234 (NaN), +inf, and the second word of a complete FLOAT
    nan = DataPoint(address="D0", status=StatusCode.OK, value=0x1234, data_type="FLOAT", converted_value=float("nan"))
    inf = DataPoint(address="D2", status=StatusCode.OK, value=0, data_type="FLOAT", converted_value=float("inf"))
    part = DataPoint(address="D5", status=StatusCode.OK, value=0x42C8, data_type="FLOAT", display_value="(part of D4)")
    assert [numeric_value(p) for p in (nan, inf, part)] == [None, None, None]


def test_threshold_still_uses_raw_and_converted_values():
    raw = DataPoint(address="D1", status=StatusCode.OK, value=90)
    converted = DataPoint(address="D2", status=StatusCode.OK, value=0, data_type="FLOAT", converted_value=81.5)
    tag = DataPoint(address="Speed", status=StatusCode.OK, data_type="REAL", converted_value=12.5)
    assert [numeric_value(p) for p in (raw, converted, tag)] == [90.0, 81.5, 12.5]


def test_cleared_waits_for_the_exceeded_notification_still_being_sent(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.01)
    received = []
    release = asyncio.Event

    notifier = MagicMock()

    async def run():
        gate = release()

        async def slow_exceeded(*args, **kwargs):
            await gate.wait()  # the webhook is slow for "exceeded"
            received.append("exceeded")
            return {"hook": True}

        async def cleared(*args, **kwargs):
            received.append("cleared")
            return {"hook": True}

        notifier.notify_threshold = slow_exceeded
        notifier.notify_threshold_cleared = cleared

        async def notify(send):
            return scan_runner.NotificationManager.delivered(await send(notifier))

        runner = CycleRunner(None, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))

        def point(value):
            return [DataPoint(address="D1", status=StatusCode.OK, value=value)]

        await runner.check_thresholds("PLC1", point(90), "10.0.0.1")  # exceeded: send starts
        await runner.check_thresholds("PLC1", point(5), "10.0.0.1")  # back inside while it is in flight
        assert received == []  # "cleared" must not overtake it
        gate.set()
        await runner.drain()
        await runner.check_thresholds("PLC1", point(5), "10.0.0.1")
        await runner.drain()

    asyncio.run(run())
    assert received == ["exceeded", "cleared"]


def test_numbers_are_shown_in_full():
    assert [number_text(v) for v in (1234567, 81.5, 0.1 + 0.2, 80, -3.0)] == ["1234567", "81.5", "0.3", "80", "-3"]
    first, second = parse_thresholds(["D100>1234567", "D100>1234568"])
    # Both were "D100 > 1.23457e+06": one label, one notification key
    assert (first.label, second.label) == ("D100 > 1234567", "D100 > 1234568")


def test_a_limit_listed_twice_counts_its_cycles_once():
    limit = Threshold("D1", ">", 5, for_cycles=2)
    monitor = ThresholdMonitor([limit, limit])
    assert monitor.thresholds == [limit]
    point = [DataPoint(address="D1", status=StatusCode.OK, value=9)]
    assert monitor.evaluate("PLC1", point).crossed == []  # first cycle outside: not yet (was exceeded)
    assert len(monitor.evaluate("PLC1", point).crossed) == 1


def test_thresholds_on_array_elements_and_large_numbers():
    limits = parse_thresholds(["Matrix[0,0]>5, D1>=2", "D100>1234567890123", "D100>1234567890124"])
    assert [t.address for t in limits] == ["Matrix[0,0]", "D1", "D100", "D100"]  # was "invalid threshold 'Matrix[0'"
    assert (limits[2].label, limits[3].label) == ("D100 > 1234567890123", "D100 > 1234567890124")
    assert number_text(0.1 + 0.2) == "0.3" and number_text(2**62) == str(2**62)


def test_waiting_threshold_notification_goes_out_while_the_value_is_not_read():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10)])
    ok = [DataPoint(address="D1", status=StatusCode.OK, value=20)]
    ng = [DataPoint(address="D1", status=StatusCode.NG_TIMEOUT)]

    # Exceeded, but the notification is throttled
    assert monitor.evaluate("PLC1", ok, lambda t, kind: False).exceeded == []
    # Next cycles: the address times out; the notification may go out now
    check = monitor.evaluate("PLC1", ng, lambda t, kind: True)
    assert [(e.threshold.address, e.value) for e in check.exceeded] == [("D1", 20.0)]
    assert monitor.evaluate("PLC1", ng, lambda t, kind: True).exceeded == []  # once
    # An address never read has nothing to report
    assert ThresholdMonitor([Threshold("D1", ">", 10)]).evaluate("PLC1", ng).exceeded == []
