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
