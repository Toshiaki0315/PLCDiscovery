"""
Threshold monitoring during periodic scans: parsing, edge-triggered
checks, config validation, CLI option and the periodic scan hook.
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.notifications import NotificationManager, NotificationType
from plc_discovery.scan_runner import CycleRunner
from plc_discovery.thresholds import (
    Threshold,
    ThresholdMonitor,
    numeric_value,
    parse_threshold,
    parse_thresholds,
    threshold_from_dict,
)


def _point(address, value, status=StatusCode.OK, converted=None):
    return DataPoint(address=address, status=status, value=value, converted_value=converted)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("D100>80", Threshold("D100", ">", 80.0)),
        (" Motor.Speed <= 0.5 ", Threshold("Motor.Speed", "<=", 0.5)),
        ("Program:Main.Step!=3", Threshold("Program:Main.Step", "!=", 3.0)),
        ("D0 == -1", Threshold("D0", "==", -1.0)),
    ],
)
def test_parse_threshold(text, expected):
    assert parse_threshold(text) == expected


@pytest.mark.parametrize("text", ["D100", "D100>", ">80", "D100>abc", "D100=>80", "D100>nan", ""])
def test_parse_threshold_rejects_malformed(text):
    with pytest.raises(ValueError):
        parse_threshold(text)


def test_parse_thresholds_splits_commas_and_repeats():
    assert [t.condition for t in parse_thresholds(["D1>1, D2<2", "D3>=3", " "])] == ["D1 > 1", "D2 < 2", "D3 >= 3"]


def test_threshold_from_dict_and_label():
    t = threshold_from_dict({"address": "D100", "op": ">", "value": 80, "name": "Furnace"})
    assert t.label == "Furnace (D100 > 80)"
    for bad in (
        {"op": ">", "value": 1},
        {"address": "D1", "op": "=>", "value": 1},
        {"address": "D1", "op": ">"},
        {"address": "D1", "op": ">", "value": "x"},
        {"address": "D1", "op": ">", "value": True},
        "D1>1",
    ):
        with pytest.raises(ValueError):
            threshold_from_dict(bad)


def test_numeric_value_prefers_converted_and_skips_failures():
    assert numeric_value(_point("D0", 0x4120, converted=10.0)) == 10.0
    assert numeric_value(_point("D0", 5)) == 5.0
    assert numeric_value(_point("D0", None, StatusCode.NG_TIMEOUT)) is None
    assert numeric_value(_point("S", "text")) is None


def test_monitor_notifies_once_per_excursion():
    monitor = ThresholdMonitor([Threshold("d100", ">", 80)])  # case-insensitive address
    values = [70, 81, 90, None, 79, 85]
    fired = []
    for v in values:
        point = _point("D100", v) if v is not None else _point("D100", None, StatusCode.NG_TIMEOUT)
        fired.append([value for _, value in monitor.check("PLC1", [point])])
    # 81 fires; 90 still exceeded; unread keeps state; 79 resets; 85 fires again
    assert fired == [[], [81.0], [], [], [], [85.0]]
    # per target
    assert monitor.check("PLC2", [_point("D100", 99)]) != []


def test_config_validation_and_loading(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(
        "thresholds:\n"
        "  - {address: D100, op: '>', value: 80, name: Furnace}\n"
        "  - {address: D1, op: '=>', value: 1}\n"
        "  - {op: '<', value: 1}\n",
        encoding="utf-8",
    )
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert any("thresholds[1].op" in e for e in errors)
    assert any("thresholds[2].address" in e for e in errors)
    path.write_text("thresholds:\n  - {address: D100, op: '>', value: 80}\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.validate() == [] and loader.get_thresholds() == [Threshold("D100", ">", 80.0)]


def test_notify_threshold_event():
    sent = []
    manager = NotificationManager()
    manager.add_custom("t", lambda e: sent.append(e), events=[NotificationType.THRESHOLD_EXCEEDED])
    asyncio.run(manager.notify_threshold("PLC1", "D100 > 80", 85.0, plc_ip="10.0.0.1", address="D100"))
    assert sent[0].message == "PLC1: D100 > 80 (value 85)" and sent[0].data["address"] == "D100"


class _Collector:
    """Connected collector returning D100 = 70, 90, 95, 60, 85 in turn"""

    values = [70, 90, 95, 60, 85]

    def __init__(self, plc_info, config=None):
        self.is_connected = True
        self.connect_error = None
        self.reads = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    def clear_data(self):
        pass

    async def collect_range(self, device_type, start, end):
        value = self.values[min(self.reads, len(self.values) - 1)]
        self.reads += 1
        return [DataPoint(address="D100", status=StatusCode.OK, value=value)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


def test_periodic_scan_sends_threshold_notifications():
    notifier = MagicMock(report_interval_seconds=0)
    notifier.notify_threshold = AsyncMock()
    notifier.notify_unreachable = AsyncMock()

    async def run():
        with patch.object(plc_scanner, "PLCDataCollector", _Collector):
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)],
                    NetworkConfig(),
                    MagicMock(hex_addresses=False, periodic_csv="per_cycle"),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 100, 100)],
                    interval=0.01,
                    notifier=notifier,
                    thresholds=[Threshold("D100", ">", 80)],
                )
            )
            while notifier.notify_threshold.await_count < 2:
                await asyncio.sleep(0.005)
            task.cancel()
            await task

    asyncio.run(run())
    values = [c.args[2] for c in notifier.notify_threshold.await_args_list]
    assert values[:2] == [90.0, 85.0]  # 95 was the same excursion
    notifier.notify_unreachable.assert_not_awaited()


def test_cli_rejects_malformed_threshold(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.9",
            "--range",
            "0-0",
            "--interval",
            "5",
            "--threshold",
            "D100=>80",
            "--output-dir",
            str(tmp_path),
            "--no-rich",
        ],
    )
    with patch.object(plc_scanner, "run_periodic_scan", AsyncMock()) as periodic:
        with pytest.raises(SystemExit) as exit_info:
            asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    assert "invalid threshold" in capsys.readouterr().out
    periodic.assert_not_called()


def test_threshold_outside_scanned_ranges_is_warned_once(caplog):
    async def run():
        runner = CycleRunner(None, thresholds=ThresholdMonitor([Threshold("D100", ">", 1), Threshold("d0", ">", 1)]))
        await runner.check_thresholds("PLC1", [], "10.0.0.1")  # nothing read yet: no verdict
        for _ in range(2):
            await runner.check_thresholds("PLC1", [_point("D0", 0)], "10.0.0.1")

    with caplog.at_level("WARNING", logger="plc_discovery.scan_runner"):
        asyncio.run(run())
    warnings = [r.getMessage() for r in caplog.records if "never checked" in r.getMessage()]
    assert warnings == ["PLC1: threshold D100 > 1 is never checked: D100 is not in the scanned ranges / tags"]


def _throttled_runner(monkeypatch, clock, sent):
    monkeypatch.setattr("plc_discovery.notifications.time.monotonic", lambda: clock[0])
    manager = NotificationManager(min_interval_seconds=600)
    manager.add_custom("c", lambda e: sent.append(e.message))

    async def notify(send):
        await send(manager)

    return CycleRunner(None, notifier=manager, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))


def test_throttled_outage_is_reported_once_the_interval_passes(monkeypatch):
    """A PLC that flaps and then stays down must not be left looking reachable"""
    clock, sent = [1000.0], []

    async def run():
        runner = _throttled_runner(monkeypatch, clock, sent)
        for minute, up in enumerate([False, True, False] + [False] * 10):
            clock[0] = 1000 + 60 * minute
            await runner.track_outage("PLC1", up, "10.0.0.1")
            if minute == 9:
                assert sent[-1].startswith("PLC1 is reachable again")  # still within 10 min

    asyncio.run(run())
    assert sent[0] == "PLC1 is not reachable" and sent[1].startswith("PLC1 is reachable again")
    assert sent[2:] == ["PLC1 is not reachable"]  # sent at minute 10, not lost


def test_throttled_threshold_is_reported_while_still_exceeded(monkeypatch):
    clock, sent = [1000.0], []

    async def run():
        runner = _throttled_runner(monkeypatch, clock, sent)
        for minute, value in enumerate([50, 5] + [60] * 12):
            clock[0] = 1000 + 60 * minute
            await runner.check_thresholds("PLC1", [_point("D1", value)], "10.0.0.1")

    asyncio.run(run())
    assert sent == [
        "PLC1: D1 > 10 (value 50)",
        "PLC1: D1 > 10 back to normal (value 5, outside for 60s)",
        "PLC1: D1 > 10 (value 60)",  # throttled at minute 2, sent at minute 10
    ]


def test_short_excursion_within_interval_stays_suppressed(monkeypatch, caplog):
    """Not notified, but every crossing still reaches the log (console / GUI log pane)"""
    clock, sent = [1000.0], []

    async def run():
        runner = _throttled_runner(monkeypatch, clock, sent)
        for minute, value in enumerate([50, 5, 60, 5] + [5] * 12):
            clock[0] = 1000 + 60 * minute
            await runner.check_thresholds("PLC1", [_point("D1", value)], "10.0.0.1")

    with caplog.at_level("WARNING", logger="plc_discovery.scan_runner"):
        asyncio.run(run())
    # 60 was back inside before it could be sent: neither it nor its end is notified
    assert sent == ["PLC1: D1 > 10 (value 50)", "PLC1: D1 > 10 back to normal (value 5, outside for 60s)"]
    logged = [r.getMessage() for r in caplog.records if "exceeded" in r.getMessage()]
    assert logged == [
        "PLC1: threshold D1 > 10 exceeded (value 50)",
        "PLC1: threshold D1 > 10 exceeded (value 60)",
    ]


def test_evaluate_separates_crossings_from_notifications():
    t = Threshold("D1", ">", 10)
    monitor = ThresholdMonitor([t])
    blocked = lambda threshold, kind: False  # noqa: E731
    check = monitor.evaluate("PLC1", [_point("D1", 50)], blocked)
    assert [(e.threshold, e.value) for e in check.crossed] == [(t, 50.0)] and check.exceeded == []
    # still outside: not a new crossing, but offered for notification again
    check = monitor.evaluate("PLC1", [_point("D1", 55)])
    assert check.crossed == [] and [(e.threshold, e.value) for e in check.exceeded] == [(t, 55.0)]
    assert monitor.evaluate("PLC1", [_point("D1", 60)]) == ([], [], [], [])


def _run_main(monkeypatch, tmp_path, *args):
    argv = ["plc_scanner.py", *args, "--threshold", "D100>80", "--output-dir", str(tmp_path), "--no-rich"]
    monkeypatch.setattr(sys, "argv", argv)
    with (
        patch.object(plc_scanner, "run_periodic_scan", AsyncMock(return_value=[])) as periodic,
        patch.object(plc_scanner, "run_single_scan", AsyncMock()),
        patch.object(plc_scanner, "_run_discover", AsyncMock()),
    ):
        try:
            asyncio.run(plc_scanner.main())
        except SystemExit:
            pass
    return periodic


@pytest.mark.parametrize(
    "args",
    [
        ["--mode", "discover"],
        ["--mode", "range", "--target", "10.0.0.9", "--protocol", "slmp", "--range", "0-0"],
    ],
)
def test_thresholds_not_watched_say_so(monkeypatch, tmp_path, capsys, args):
    _run_main(monkeypatch, tmp_path, *args)
    out = capsys.readouterr().out
    assert "Watching" not in out and "ignored" in out


def test_periodic_range_scan_says_watching(monkeypatch, tmp_path, capsys):
    periodic = _run_main(
        monkeypatch,
        tmp_path,
        *["--mode", "range", "--target", "10.0.0.9", "--protocol", "slmp", "--range", "0-0", "--interval", "5"],
    )
    out = capsys.readouterr().out
    assert "Watching 1 threshold(s): D100 > 80" in out and "ignored" not in out
    periodic.assert_awaited_once()


def _values(monitor, target, values, plc_ip=None, kind="exceeded"):
    """Run one cycle per value (None: not read); the values notified as ``kind``, per cycle"""
    out = []
    for minute, v in enumerate(values):
        point = _point("D1", v) if v is not None else _point("D1", None, StatusCode.NG_TIMEOUT)
        check = monitor.evaluate(target, [point], plc_ip=plc_ip, now=60.0 * minute)
        out.append([e.value for e in getattr(check, kind)])
    return out


def test_threshold_limited_to_a_target():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10, target="10.0.0.1"), Threshold("D1", ">", 90, target="Line2")])
    assert _values(monitor, "10.0.0.1 (SLMP:5001)", [50], plc_ip="10.0.0.1") == [[50.0]]  # by IP
    assert _values(monitor, "line2", [50, 95]) == [[], [95.0]]  # by label, case-insensitive
    assert _values(monitor, "10.0.0.2", [99], plc_ip="10.0.0.2") == [[]]
    assert monitor.unknown_targets(["10.0.0.1", "10.0.0.1 (SLMP:5001)"]) == [monitor.thresholds[1]]


def test_hysteresis_keeps_the_excursion_until_inside_by_the_margin():
    monitor = ThresholdMonitor([Threshold("D1", ">", 80, hysteresis=2)])
    assert _values(monitor, "PLC1", [81, 79, 81, 78, 81]) == [[81.0], [], [], [], [81.0]]
    monitor = ThresholdMonitor([Threshold("D1", "<=", 10, hysteresis=5)])
    assert _values(monitor, "PLC1", [10, 14, 15.5, 9], kind="cleared") == [[], [], [15.5], []]


def test_for_cycles_needs_consecutive_read_cycles_outside():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10, for_cycles=3)])
    # 50, 50, 5 resets; unread cycles neither count nor reset
    values = [50, 50, 5, 50, None, 50, 50, 60]
    assert _values(monitor, "PLC1", values) == [[], [], [], [], [], [], [50.0], []]


def test_cleared_carries_the_duration_and_only_follows_a_notified_excursion():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10, for_cycles=2)])
    events = []
    for minute, v in enumerate([50, 5, 50, 50, 50, 5]):
        check = monitor.evaluate("PLC1", [_point("D1", v)], now=60.0 * minute)
        events += [("exceeded", e.value) for e in check.exceeded]
        events += [("cleared", e.value, e.duration) for e in check.cleared]
    # the one-cycle 50 never counted; the excursion started at minute 2
    assert events == [("exceeded", 50.0), ("cleared", 5.0, 180.0)]


def test_throttled_clear_is_sent_later_with_the_original_values():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10)])
    allow = {"exceeded": True, "cleared": False}
    monitor.evaluate("PLC1", [_point("D1", 50)], lambda t, k: allow[k], now=0)
    check = monitor.evaluate("PLC1", [_point("D1", 5)], lambda t, k: allow[k], now=60)
    assert check.returned and not check.cleared
    allow["cleared"] = True
    check = monitor.evaluate("PLC1", [_point("D1", 7)], lambda t, k: allow[k], now=120)
    assert [(e.value, e.duration) for e in check.cleared] == [(5.0, 60.0)]


def test_config_extras_validation():
    t = threshold_from_dict(
        {"address": "D1", "op": ">", "value": 1, "target": " 10.0.0.1 ", "hysteresis": 0.5, "for_cycles": 3}
    )
    assert (t.target, t.hysteresis, t.for_cycles) == ("10.0.0.1", 0.5, 3)
    for extra in (
        {"target": ""},
        {"target": 5},
        {"hysteresis": -1},
        {"hysteresis": "x"},
        {"for_cycles": 0},
        {"for_cycles": 1.5},
        {"for_cycles": True},
    ):
        with pytest.raises(ValueError):
            threshold_from_dict({"address": "D1", "op": ">", "value": 1, **extra})
    with pytest.raises(ValueError, match="hysteresis cannot be used with =="):
        threshold_from_dict({"address": "D1", "op": "==", "value": 1, "hysteresis": 1})


def test_threshold_cleared_reaches_threshold_exceeded_subscribers():
    sent = []
    manager = NotificationManager()
    manager.add_custom("t", lambda e: sent.append(e), events=[NotificationType.THRESHOLD_EXCEEDED])
    asyncio.run(manager.notify_threshold_cleared("PLC1", "D100 > 80", 70.0, duration_seconds=125, address="D100"))
    assert sent[0].type == NotificationType.THRESHOLD_CLEARED
    assert sent[0].message == "PLC1: D100 > 80 back to normal (value 70, outside for 125s)"
    assert sent[0].data["duration_seconds"] == 125


def test_unknown_threshold_target_is_warned(caplog):
    async def run():
        runner = CycleRunner(None, thresholds=ThresholdMonitor([Threshold("D1", ">", 1, target="10.0.0.99")]))
        runner.warn_unknown_threshold_targets(["10.0.0.1", "10.0.0.1"])

    with caplog.at_level("WARNING", logger="plc_discovery.scan_runner"):
        asyncio.run(run())
    assert [r.getMessage() for r in caplog.records] == [
        "threshold D1 > 1 is never checked: target 10.0.0.99 is not scanned (use one of: 10.0.0.1)"
    ]


def test_runner_sends_cleared_notification():
    notifier = MagicMock()
    sent = []

    async def notify(send):
        await send(notifier)

    notifier.notify_threshold = AsyncMock(side_effect=lambda *a, **k: sent.append("exceeded"))
    notifier.notify_threshold_cleared = AsyncMock(side_effect=lambda *a, **k: sent.append(("cleared", a, k)))

    async def run():
        runner = CycleRunner(None, notify=notify, thresholds=ThresholdMonitor([Threshold("D1", ">", 10)]))
        await runner.check_thresholds("PLC1", [_point("D1", 50)], "10.0.0.1")
        await runner.check_thresholds("PLC1", [_point("D1", 5)], "10.0.0.1")

    asyncio.run(run())
    assert sent[0] == "exceeded"
    _, args, kwargs = sent[1]
    assert args[:3] == ("PLC1", "D1 > 10", 5.0) and kwargs["plc_ip"] == "10.0.0.1" and kwargs["address"] == "D1"
