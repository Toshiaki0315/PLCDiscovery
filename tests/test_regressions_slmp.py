"""
Regression tests for SLMP / MC protocol, found and fixed in code reviews.
"""

import asyncio
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest
from pymcprotocol.mcprotocolerror import MCProtocolError

from plc_discovery.config import DeviceType, NetworkConfig, StatusCode
from plc_discovery.protocols.slmp import SLMPHandler, slmp_head_device

# tomllib is in the standard library from Python 3.11; 3.10 (still
# supported, tested in CI) uses the identical tomli package
if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = pytest.importorskip("tomli")


ROOT = Path(__file__).resolve().parent.parent


def slmp_response(words):
    body = b"\x00\x00" + b"".join(struct.pack("<H", w & 0xFFFF) for w in words)
    return b"\xd0\x00\x00\xff\xff\x03\x00" + struct.pack("<H", len(body)) + body


class FakeSLMP:
    """Word reads return value = base + address. mode: normal|split|slow_first|close_after_first"""

    def __init__(self, mode="normal", base=0):
        self.mode, self.base = mode, base
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen()
        self.srv.settimeout(0.1)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.requests = 0
        self.connections = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                continue
            self.connections += 1
            with conn:
                conn.settimeout(0.1)
                while not self.stop.is_set():
                    try:
                        req = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not req:
                        break
                    self.requests += 1
                    head = struct.unpack("<I", req[15:18] + b"\x00")[0]
                    count = struct.unpack("<H", req[19:21])[0]
                    resp = slmp_response([self.base + head + i for i in range(count)])
                    if self.mode == "split":
                        conn.sendall(resp[:100])
                        time.sleep(0.05)
                        conn.sendall(resp[100:])
                    elif self.mode == "slow_first" and self.requests == 1:
                        time.sleep(1.5)
                        try:
                            conn.sendall(resp)
                        except OSError:
                            pass
                    elif self.mode == "close_after_first" and self.requests == 1:
                        conn.sendall(resp)
                        self.mode = "normal"
                        break  # drop the connection after the first reply
                    else:
                        conn.sendall(resp)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.thread.join(2)
        self.srv.close()


async def connected_handler(server, timeout_ms=1000):
    # Settings given: the fake server answers reads only (no detection probe first)
    handler = SLMPHandler("127.0.0.1", server.port, frame=3, config=NetworkConfig(request_timeout_ms=timeout_ms))
    assert await handler.connect()
    return handler


@pytest.mark.parametrize("address", [0, 9, 10, 100, 160, 900, 2047])
@pytest.mark.parametrize("device", [DeviceType.X, DeviceType.Y, DeviceType.B, DeviceType.W])
def test_hex_device_number_on_the_wire(device, address):
    pymcprotocol = pytest.importorskip("pymcprotocol")
    client = pymcprotocol.Type3E()
    encoded = client._make_devicedata(slmp_head_device(device, address))
    assert int.from_bytes(encoded[:3], "little") == address


@pytest.mark.parametrize("device", [DeviceType.D, DeviceType.M, DeviceType.R, DeviceType.SM])
def test_decimal_devices_unchanged(device):
    assert slmp_head_device(device, 100) == f"{device.value}100"


class TestDependencies:

    def deps(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return {re.split(r"[<>=!~ ]", d, 1)[0].lower(): d for d in data["project"]["dependencies"]}

    def test_pymcprotocol_version_exists_on_pypi(self):
        # 0.3.0 is the latest release; ">=0.4.0" could never be installed
        assert self.deps()["pymcprotocol"] == "pymcprotocol>=0.3.0"

    def test_yaml_is_a_dependency(self):
        assert "pyyaml" in self.deps()

    def test_requirements_without_python2_backport(self):
        text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert "ipaddress" not in text


@pytest.mark.asyncio
async def test_u2_slmp_closed_connection_no_fake_data_and_recovers():
    with FakeSLMP("close_after_first") as server:
        handler = await connected_handler(server)
        try:
            assert await handler.read_device_raw(DeviceType.D, 10, 3) == ([10, 11, 12], StatusCode.OK)
            await asyncio.sleep(0.2)
            data, status = await handler.read_device_raw(DeviceType.D, 10, 3)
            assert data is None and status == StatusCode.NG_COMM_ERROR  # previously [0, 0, 0] / OK
            assert handler._needs_reconnect
            assert await handler.read_device_raw(DeviceType.D, 10, 3) == ([10, 11, 12], StatusCode.OK)
            assert server.connections == 2
        finally:
            await handler.disconnect()


@pytest.mark.asyncio
async def test_u3_slmp_values_unsigned():
    with FakeSLMP(base=0x8000) as server:
        handler = await connected_handler(server)
        try:
            assert await handler.read_device_raw(DeviceType.D, 0, 2) == ([0x8000, 0x8001], StatusCode.OK)
        finally:
            await handler.disconnect()


@pytest.mark.asyncio
async def test_u5_late_reply_not_reused():
    with FakeSLMP("slow_first") as server:
        handler = await connected_handler(server, timeout_ms=500)
        try:
            assert (await handler.read_device_raw(DeviceType.D, 100, 2))[1] == StatusCode.NG_TIMEOUT
            assert handler._needs_reconnect
            await asyncio.sleep(1.2)  # the late reply to D100 arrives on the old socket
            assert await handler.read_device_raw(DeviceType.D, 500, 2) == ([500, 501], StatusCode.OK)
        finally:
            await handler.disconnect()


def test_u5_socket_timeout_handled_explicitly():
    """socket.timeout is not asyncio.TimeoutError on Python 3.10; the handler
    must catch the builtin TimeoutError as well"""
    source = (ROOT / "plc_discovery" / "protocols" / "slmp.py").read_text(encoding="utf-8")
    assert "except (asyncio.TimeoutError, TimeoutError)" in source


def test_slmp_cpu_device_range_end_codes_are_address_errors():
    for code in (0x4030, 0x4031, 0xC056):
        status = SLMPHandler._classify_error(MCProtocolError(code), DeviceType.D, 12000)
        assert status == StatusCode.NG_ILLEGAL_ADDR, hex(code)
    # Not about the address: CPU busy / other errors stay communication errors
    assert SLMPHandler._classify_error(MCProtocolError(0x4001), DeviceType.D, 0) == StatusCode.NG_COMM_ERROR
