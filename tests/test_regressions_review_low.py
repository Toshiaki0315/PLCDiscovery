"""
Regressions from the second code review (low findings):
- a slow webhook does not hold up the read cycle
- the settings file (webhook URLs) is private and keeps its permissions
- the config file's logging section is applied and validated
- simulators answer like real devices (FINS end codes, CIP "not supported",
  S7 item layout and PDU size) and survive a malformed TPKT header
"""

import asyncio
import logging
import os
import struct
import sys
import threading
import time
from unittest.mock import MagicMock

import pytest

import plc_scanner
from plc_discovery import scan_runner, settings_file
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.scan_runner import CycleRunner

# ----------------------------------------------------------------------
# Notifications do not hold up the read cycle
# ----------------------------------------------------------------------


def test_slow_notification_finishes_in_the_background(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.05)
    sent = []

    async def notify(send):
        await asyncio.sleep(0.3)  # a webhook that takes its time
        sent.append("unreachable")
        return True

    async def run():
        runner = CycleRunner(None, notify=notify)
        loop = asyncio.get_running_loop()
        started = loop.time()
        await runner.track_outage("PLC1", False, "10.0.0.1")
        waited = loop.time() - started
        # Next cycles while it is still being sent: not sent a second time
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.track_outage("PLC1", False, "10.0.0.1")
        in_flight = len(sent) == 0
        await runner.drain()
        return waited, in_flight, set(runner._reported_down)

    waited, in_flight, reported = asyncio.run(run())
    assert waited < 0.25  # the cycle went on after NOTIFY_WAIT_SECONDS
    assert in_flight
    assert sent == ["unreachable"] and reported == {"PLC1"}


def test_slow_notification_that_fails_is_offered_again(monkeypatch):
    monkeypatch.setattr(scan_runner, "NOTIFY_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(scan_runner, "NOTIFY_RETRY_SECONDS", 0.0)
    outcomes = [False, True]
    calls = []

    async def notify(send):
        await asyncio.sleep(0.1)
        calls.append(1)
        return outcomes.pop(0)

    async def run():
        runner = CycleRunner(None, notify=notify)
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.drain()
        assert runner._reported_down == set()  # nobody was told
        await runner.track_outage("PLC1", False, "10.0.0.1")
        await runner.drain()
        return set(runner._reported_down)

    assert asyncio.run(run()) == {"PLC1"}
    assert len(calls) == 2


# ----------------------------------------------------------------------
# Settings file permissions
# ----------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_settings_file_is_private_and_keeps_its_permissions(tmp_path):
    path = tmp_path / "plc_config.yaml"
    updates = {"notifications": [{"name": "ops", "type": "slack", "url": "https://hooks.example.com/secret"}]}

    _, errors = settings_file.save(str(path), updates)
    assert errors == []
    assert path.stat().st_mode & 0o777 == 0o600

    # The owner's choice is kept on later saves, in both directions
    for mode in (0o640, 0o600):
        os.chmod(path, mode)
        settings_file.save(str(path), updates)
        assert path.stat().st_mode & 0o777 == mode
    assert "hooks.example.com" in path.read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# logging section of the config file
# ----------------------------------------------------------------------


@pytest.fixture
def restore_root_logger():
    root = logging.getLogger()
    level, handlers = root.level, list(root.handlers)
    # _apply_config_logging also quietens the protocol libraries' loggers
    libraries = {name: logging.getLogger(name).level for name in ("pycomm3", "pymodbus")}
    yield root
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(level)
    for name, library_level in libraries.items():
        logging.getLogger(name).setLevel(library_level)


def _loader(logging_section):
    loader = ConfigLoader()
    loader.config["logging"].update(logging_section)
    loader._file_config = {"logging": dict(logging_section)}
    return loader


def test_config_log_level_and_file_are_applied(tmp_path, restore_root_logger):
    log_file = tmp_path / "logs" / "scan.log"
    loader = _loader({"level": "warning", "file": str(log_file)})
    plc_scanner._apply_config_logging(MagicMock(verbose=False, quiet=False), loader)
    assert restore_root_logger.level == logging.WARNING
    logging.getLogger("plc_discovery.test").warning("to the file")
    # Only the handler under test: other tests may leave handlers on the
    # root logger whose streams are closed by now
    for handler in restore_root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler.flush()
    assert "to the file" in log_file.read_text(encoding="utf-8")


def test_verbose_wins_over_the_config_log_level(restore_root_logger):
    restore_root_logger.setLevel(logging.DEBUG)
    plc_scanner._apply_config_logging(MagicMock(verbose=True, quiet=False), _loader({"level": "ERROR"}))
    assert restore_root_logger.level == logging.DEBUG


def test_unknown_log_level_is_a_config_error():
    loader = ConfigLoader()
    loader.config["logging"]["level"] = "LOUD"
    assert any("logging.level" in error for error in loader.validate())


# ----------------------------------------------------------------------
# Simulators answer like real devices
# ----------------------------------------------------------------------


def _fins_read(area, address, count):
    from simulators.fins_simulator import FINSSimulator

    request = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 5, 1, 1, area, address >> 8, address & 0xFF, 0])
    response = FINSSimulator().handle_frame(request + struct.pack(">H", count), ("127.0.0.1", 9600))
    return response[12:14], response[14:]


@pytest.mark.parametrize(
    "area, address, count, end_code",
    [
        (0x82, 0, 10, b"\x00\x00"),  # DM: fine
        (0x99, 0, 1, b"\x11\x01"),  # no such memory area
        (0x82, 0, 0, b"\x11\x0c"),  # nothing requested
        (0x82, 0, 1000, b"\x11\x0b"),  # more than one response holds
        (0x82, 32760, 20, b"\x11\x04"),  # past the end of DM
        (0xB2, 510, 5, b"\x11\x04"),  # past the end of HR
    ],
)
def test_fins_simulator_end_codes(area, address, count, end_code):
    code, data = _fins_read(area, address, count)
    assert code == end_code
    assert len(data) == (2 * count if end_code == b"\x00\x00" else 0)


def test_eip_simulator_rejects_unknown_services():
    from simulators.ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol

    protocol = EtherNetIPProtocol(EtherNetIPDevice())
    reply = protocol._process_cip_request(bytes([0x4D, 0x02, 0x20, 0x6B, 0x24, 0x01]))  # Write Tag
    assert reply[0] == 0x4D | 0x80 and reply[2] == 0x08  # service not supported


def _s7_protocol():
    from simulators.s7_simulator import COTPProtocol, S7Device

    protocol = COTPProtocol(S7Device())
    protocol.transport = MagicMock()
    protocol.peer = ("127.0.0.1", 1)
    return protocol


def test_s7_simulator_survives_a_tpkt_length_below_the_header_size():
    protocol = _s7_protocol()
    finished = threading.Event()

    def feed():
        protocol.data_received(b"\x03\x00\x00\x00")
        finished.set()

    threading.Thread(target=feed, daemon=True).start()
    assert finished.wait(2), "data_received never returned (endless loop)"
    assert protocol.buffer == b""


def test_s7_simulator_failed_item_is_four_bytes_and_pdu_size_follows_the_request():
    from simulators.s7_simulator import S7_RET_OK

    protocol = _s7_protocol()
    sent = []
    protocol._make_s7_response = lambda ref, params, data: sent.append((params, data)) or b""

    protocol._make_read_response(1, [(0x0A, None), (S7_RET_OK, b"\x12\x34")])
    params, data = sent[-1]
    assert params[1] == 2
    assert data[:4] == bytes([0x0A, 0, 0, 0])  # return code, null transport size, length 0
    assert data[4:] == bytes([S7_RET_OK, 0x04]) + struct.pack(">H", 16) + b"\x12\x34"

    for requested, granted in ((240, 240), (480, 480), (4096, 960)):
        protocol._handle_setup_comm(1, bytes([0xF0, 0, 0, 1, 0, 1]) + struct.pack(">H", requested))
        assert struct.unpack(">H", sent[-1][0][6:8])[0] == granted


def test_run_all_starts_without_signal_handlers(monkeypatch):
    """Windows event loops raise NotImplementedError from add_signal_handler"""
    from simulators import run_all

    class Manager:
        def __init__(self, host):
            self.stopped = False
            created.append(self)

        async def start_all(self):
            pass

        async def run_forever(self):
            pass

        async def stop_all(self):
            self.stopped = True

    created = []
    monkeypatch.setattr(run_all, "SimulatorManager", Manager)

    async def run():
        loop = asyncio.get_running_loop()

        def unsupported(*args):
            raise NotImplementedError

        monkeypatch.setattr(loop, "add_signal_handler", unsupported)
        started = time.monotonic()
        await run_all.main("127.0.0.1")
        return time.monotonic() - started

    assert asyncio.run(run()) < 2
    assert created[0].stopped
