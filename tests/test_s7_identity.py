"""
S7 CPU identification in discovery: SZL 0x001C records (both snap7 data
layouts), the simulator's USER_DATA reply, and the Siemens defaults kept
when the identification fails or times out.
"""

import asyncio
import struct
import threading
from unittest.mock import MagicMock, patch

import pytest

from plc_discovery.config import NetworkConfig, PLCInfo, Protocol
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.protocols.s7 import parse_szl_component_ids, parse_szl_module_ids, read_s7_identity


def _records(items):
    return b"".join(struct.pack(">H", i) + t.encode().ljust(32, b"\x00") for i, t in items)


RECORDS = _records([(1, "S7-300 Station"), (2, "PLC_1"), (7, "CPU 315-2 PN/DP")])


def test_szl_records_without_header():  # snap7 1.x: records only
    assert parse_szl_component_ids(RECORDS) == {1: "S7-300 Station", 2: "PLC_1", 7: "CPU 315-2 PN/DP"}


def test_szl_records_with_header():  # python-snap7 3.x: LENTHDR / N_DR first
    data = struct.pack(">HH", 34, 3) + RECORDS
    assert parse_szl_component_ids(data)[7] == "CPU 315-2 PN/DP"


def test_szl_flat_layout_is_not_records():
    flat = b"CPU 315-2 PN/DP".ljust(32, b"\x00") + b"S C-1".ljust(24, b"\x00")
    assert parse_szl_component_ids(flat) == {}


def test_szl_module_ids_order_code_and_firmware():
    records = (
        struct.pack(">H", 1)
        + b"6ES7 315-2EH14-0AB0 "
        + struct.pack(">HHH", 0, 0, 3)
        + struct.pack(">H", 7)
        + b" " * 20
        + struct.pack(">HHH", 0, 0x5603, 0x0302)
    )
    assert parse_szl_module_ids(records) == {"order_code": "6ES7 315-2EH14-0AB0", "firmware_version": "V3.3.2"}
    assert parse_szl_module_ids(struct.pack(">HH", 28, 2) + records)["firmware_version"] == "V3.3.2"
    assert parse_szl_module_ids(b"garbage") == {}


def test_identity_falls_back_to_get_cpu_info():
    client = MagicMock()
    client.read_szl.side_effect = RuntimeError("SZL not available")
    client.get_cpu_info.return_value = MagicMock(ModuleTypeName=b"CPU 1214C", ASName=b"S7-1200")
    assert read_s7_identity(client) == {"model": "CPU 1214C", "cpu_type": "S7-1200"}


def test_failed_identification_keeps_siemens_defaults():
    pytest.importorskip("snap7")
    client = MagicMock()
    client.read_szl.side_effect = RuntimeError("timeout")
    client.get_cpu_info.side_effect = RuntimeError("timeout")
    with patch("snap7.client.Client", return_value=client):
        plc = asyncio.run(
            PLCDiscovery(NetworkConfig())._query_s7_info(PLCInfo("10.0.0.1", protocol=Protocol.S7, port=102))
        )
    assert (plc.manufacturer, plc.model) == ("シーメンス", "S7 PLC")


def test_simulator_answers_cpu_identification():
    pytest.importorskip("snap7")
    from simulators.s7_simulator import COTPProtocol, S7Device

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(lambda: COTPProtocol(S7Device()), "127.0.0.1", 0))
    port = server.sockets[0].getsockname()[1]
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        plc = asyncio.run(
            PLCDiscovery(NetworkConfig())._query_s7_info(PLCInfo("127.0.0.1", protocol=Protocol.S7, port=port))
        )
        assert (plc.manufacturer, plc.model, plc.cpu_type, plc.firmware_version) == (
            "シーメンス",
            "CPU 1515-2 PN Sim",
            "6ES7 515-2AM02-0AB0",
            "V2.9.4",
        )
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        server.close()


@pytest.mark.parametrize(
    "protocol, expected",
    [
        (Protocol.FINS, ("オムロン", "FINS対応PLC")),
        (Protocol.FINS_TCP, ("オムロン", "FINS対応PLC")),
        (Protocol.S7, ("シーメンス", "S7 PLC")),
        (Protocol.MODBUS_TCP, (None, "Modbus/TCP対応機器")),
        (Protocol.ETHERNET_IP, (None, "EtherNet/IP対応機器")),
    ],
)
def test_failed_identification_uses_protocol_defaults(protocol, expected):
    """Every protocol's identity query fails: the row still names what the protocol implies"""
    discovery = PLCDiscovery(NetworkConfig())
    failing = MagicMock(side_effect=RuntimeError("no answer"))
    with patch.multiple(
        discovery, _query_fins_info=failing, _query_s7_info=failing, _query_modbus_info=failing, _query_eip_info=failing
    ):
        plc = asyncio.run(discovery._get_detailed_info(PLCInfo("10.0.0.1", protocol=protocol, port=1)))
    assert (plc.manufacturer, plc.model) == expected


def test_identified_values_are_kept():
    discovery = PLCDiscovery(NetworkConfig())

    async def identify(plc):
        plc.manufacturer, plc.model = "Schneider Electric", "M580"
        return plc

    with patch.object(discovery, "_query_modbus_info", identify):
        plc = asyncio.run(discovery._get_detailed_info(PLCInfo("10.0.0.1", protocol=Protocol.MODBUS_TCP)))
    assert (plc.manufacturer, plc.model) == ("Schneider Electric", "M580")
