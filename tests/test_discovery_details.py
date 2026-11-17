"""
Discovery details: FINS CPU model (Controller Data Read), EtherNet/IP read
method from the identity, and the GUI tag picker helpers.
"""

import asyncio
import sys
import threading
from unittest.mock import MagicMock

import pytest

from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import (
    READ_METHOD_ADDRESS,
    READ_METHOD_LOGIX,
    READ_METHOD_NAMED,
    READ_METHOD_SLC,
    PLCDiscovery,
    eip_read_method,
)


def _serve(protocol_factory):
    """Run an asyncio server on a free loopback port in a thread; returns (port, stop)"""
    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(protocol_factory, "127.0.0.1", 0))
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    def stop():
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        server.close()

    return server.sockets[0].getsockname()[1], stop


def test_fins_controller_data_gives_cpu_model():
    from simulators.fins_simulator import FINSSimulator, FINSTCPServerProtocol

    simulator = FINSSimulator()
    port, stop = _serve(lambda: FINSTCPServerProtocol(simulator))
    try:
        plc = asyncio.run(
            PLCDiscovery(NetworkConfig())._get_detailed_info(
                PLCInfo("127.0.0.1", protocol=Protocol.FINS_TCP, port=port)
            )
        )
    finally:
        stop()
    assert (plc.manufacturer, plc.model, plc.firmware_version) == ("オムロン", "CJ2M-CPU33 Sim", "02.01")
    assert plc.read_method == READ_METHOD_ADDRESS


@pytest.mark.parametrize(
    "identity, expected",
    [
        ({"vendor_id": 1, "product_type": 0x0E, "product_name": "1756-L83E/B LOGIX5583E"}, READ_METHOD_LOGIX),
        ({"vendor_id": 1, "product_type": 0x0E, "product_name": "1766-L32BWA MicroLogix 1400"}, READ_METHOD_SLC),
        ({"vendor_id": 47, "product_type": 0x0C, "product_name": "NJ501-1300"}, READ_METHOD_NAMED),
        ({"vendor_id": 47, "product_type": 0x0C, "product_name": "CJ2M-EIP21"}, None),
        ({"vendor_id": 1000, "product_name": "Robot"}, None),
        (None, None),
    ],
)
def test_eip_read_method(identity, expected):
    assert eip_read_method(identity) == expected


def test_eip_read_method_from_simulator():
    from simulators.ethernet_ip_simulator import EtherNetIPDevice, EtherNetIPProtocol

    results = {}
    for mode in ("slc", "logix", "omron"):
        port, stop = _serve(lambda m=mode: EtherNetIPProtocol(EtherNetIPDevice(mode=m)))
        try:
            plc = asyncio.run(
                PLCDiscovery(NetworkConfig())._get_detailed_info(
                    PLCInfo("127.0.0.1", protocol=Protocol.ETHERNET_IP, port=port)
                )
            )
        finally:
            stop()
        results[mode] = plc.read_method
    assert results == {"slc": READ_METHOD_SLC, "logix": READ_METHOD_LOGIX, "omron": READ_METHOD_NAMED}


def test_read_method_in_discovery_csv(tmp_path):
    from plc_discovery.output import DISCOVERY_HEADERS, CSVExporter

    assert "read_method" in DISCOVERY_HEADERS
    path = CSVExporter(str(tmp_path)).export_discovery_results(
        [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, read_method=READ_METHOD_ADDRESS)]
    )
    assert READ_METHOD_ADDRESS in open(path, encoding="utf-8-sig").read()


# ---------------------------------------------------------------------------
# GUI tag picker helpers
# ---------------------------------------------------------------------------


def _import_tags(monkeypatch):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        monkeypatch.setitem(sys.modules, "tkinter.ttk", tk.ttk)
        monkeypatch.delitem(sys.modules, "plc_gui_tags", raising=False)
    import plc_gui_tags

    return plc_gui_tags


def test_filter_tags(monkeypatch):
    tags = _import_tags(monkeypatch)
    names = ["Speed", "Motor", "Program:Main.Step", "MotorTemp"]
    assert tags.filter_tags(names, "motor") == ["Motor", "MotorTemp"]
    assert tags.filter_tags(names, "MOTOR temp") == ["MotorTemp"]
    assert tags.filter_tags(names, "") == names


def test_fetch_tag_list(monkeypatch):
    tags = _import_tags(monkeypatch)

    class Handler:
        def __init__(self, ip, port, config=None):
            self.port, self.disconnected = port, False

        async def connect(self):
            return True

        def tag_scan_list(self):
            return list(Handler.tags)

        async def disconnect(self):
            Handler.disconnected = True

    monkeypatch.setattr(tags, "EtherNetIPHandler", Handler)
    Handler.tags = ["Speed", "Motor"]
    assert asyncio.run(tags.fetch_tag_list("10.0.0.1", None, NetworkConfig())) == (["Speed", "Motor"], "")
    assert Handler.disconnected
    Handler.tags = []  # Omron NJ/NX: no tag list
    result, reason = asyncio.run(tags.fetch_tag_list("10.0.0.1", None, NetworkConfig()))
    assert result is None and reason == tags.NO_TAG_LIST_MESSAGE
