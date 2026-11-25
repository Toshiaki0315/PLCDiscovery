"""
A periodic scan stopped during its first read (a long range can take
minutes) keeps what it had read, like an interrupted single scan. Once a
cycle is written, stopping writes nothing more: the completed cycles are
the result (CLI here; the GUI follows the same rule).
"""

import asyncio
import csv
from unittest.mock import MagicMock

import plc_scanner
from plc_discovery.config import DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol
from plc_discovery.output import CSVExporter
from simulators.control import SimulatorController


def _stop_periodic(tmp_path, end_address, packet_interval_ms, stop_after):
    controller = SimulatorController()
    try:
        port = controller.start("slmp", "127.0.0.1", 0)

        async def run():
            task = asyncio.ensure_future(
                plc_scanner.run_periodic_scan(
                    [PLCInfo("127.0.0.1", protocol=Protocol.SLMP, port=port)],
                    NetworkConfig(packet_interval_ms=packet_interval_ms, retry_interval_ms=0),
                    CSVExporter(str(tmp_path)),
                    MagicMock(),
                    [DeviceRange(DeviceType.D, 0, end_address)],
                    interval=60,
                )
            )
            await asyncio.sleep(stop_after)
            task.cancel()
            return await task

        (outcome,) = asyncio.run(run())
    finally:
        controller.shutdown()
    files = sorted(tmp_path.glob("plc_data_*.csv"))
    rows = [list(csv.DictReader(open(f, encoding="utf-8"))) for f in files]
    return outcome, rows


def test_stop_during_the_first_read_saves_what_was_read(tmp_path):
    # D0-D4499: 5 requests of 900 words, 0.3 s apart; stopped after about 2
    outcome, rows = _stop_periodic(tmp_path, 4499, 300, 0.5)
    assert outcome.interrupted
    assert len(rows) == 1 and 0 < len(rows[0]) < 4500
    assert rows[0][0]["address"] == "D0" and rows[0][0]["status"] == "OK"
    assert len(outcome.data_points) == len(rows[0])


def test_stop_after_a_cycle_writes_nothing_more(tmp_path):
    outcome, rows = _stop_periodic(tmp_path, 9, 0, 0.5)  # one quick cycle, then waiting
    assert outcome.interrupted
    assert [len(r) for r in rows] == [10]
