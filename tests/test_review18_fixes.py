"""
Regression tests for the eighteenth review.

1: A range that fails with NG_ILLEGAL_ADDR and whose two end addresses are
   invalid on their own is reported as a whole instead of being split
   down to single addresses (~2N requests).
2: A user-specified address range is limited to MAX_RANGE_POINTS.
"""


import pytest

import plc_scanner
from plc_discovery.config import (
    MAX_RANGE_POINTS, DeviceRange, DeviceType, NetworkConfig, StatusCode, range_size_error,
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.protocols.slmp import SLMPHandler


async def _scan(end, valid):
    """Read D0-end from a fake PLC where valid(address) tells readability"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    requests = []

    async def fake_read(device_type, start, count):
        requests.append((start, count))
        if all(valid(a) for a in range(start, start + count)):
            return [a & 0xFFFF for a in range(start, start + count)], StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler.read_device_range(DeviceRange(DeviceType.D, 0, end))
    return handler, points, requests


def _misreported(points, valid):
    return [p.address for i, p in enumerate(points) if (p.status == StatusCode.OK) != valid(i)]


@pytest.mark.asyncio
async def test_wholly_invalid_device_costs_few_requests():
    handler, points, requests = await _scan(32767, lambda a: False)
    assert len(points) == 32768
    assert all(p.status == StatusCode.NG_ILLEGAL_ADDR for p in points)
    # 37 chunks x (chunk read + 2 edge probes); was ~65,000 requests
    assert len(requests) <= 3 * 37
    assert len(handler.get_denied_addresses()) == 32768


@pytest.mark.asyncio
@pytest.mark.parametrize("end,valid,max_requests", [
    (8191, lambda a: a <= 7999, 60),                                        # past device end
    (9999, lambda a: not (5000 <= a <= 5100 or 7000 <= a <= 7050), 160),   # gaps
    (9999, lambda a: a != 4321, 60),                                        # one bad word
])
async def test_mixed_ranges_still_exact(end, valid, max_requests):
    _, points, requests = await _scan(end, valid)
    assert _misreported(points, valid) == []
    assert len(requests) <= max_requests


@pytest.mark.asyncio
async def test_small_ranges_are_split_without_probes():
    """Below EDGE_PROBE_MIN_COUNT the range is split as before"""
    _, points, requests = await _scan(2, lambda a: a == 1)
    assert [p.status for p in points] == [
        StatusCode.NG_ILLEGAL_ADDR, StatusCode.OK, StatusCode.NG_ILLEGAL_ADDR
    ]
    assert all(count != 1 or start in (0, 1, 2) for start, count in requests)


@pytest.mark.asyncio
async def test_transient_probe_failure_falls_back_to_splitting():
    """A timeout on an edge probe is not taken as proof of an invalid range"""
    handler = SLMPHandler("10.0.0.1", config=NetworkConfig(packet_interval_ms=0, retry_interval_ms=0))
    handler._connected = True
    handler._client = object()
    calls = []

    async def fake_read(device_type, start, count):
        calls.append((start, count))
        if (start, count) == (0, 1) and calls.count((0, 1)) == 1:
            return None, StatusCode.NG_TIMEOUT
        if start + count - 1 <= 3:
            return [0] * count, StatusCode.OK
        return None, StatusCode.NG_ILLEGAL_ADDR

    handler.read_device_raw = fake_read
    points = await handler._binary_search_read(
        DeviceType.D, 0, 7, known_failure=StatusCode.NG_ILLEGAL_ADDR
    )
    assert [p.status for p in points] == [StatusCode.OK] * 4 + [StatusCode.NG_ILLEGAL_ADDR] * 4


# ---------------------------------------------------------------------------
# 2: range size limit
# ---------------------------------------------------------------------------

def test_range_size_error():
    assert range_size_error(0, MAX_RANGE_POINTS - 1) is None
    assert "at most" in range_size_error(0, MAX_RANGE_POINTS)


def test_cli_rejects_huge_range():
    assert plc_scanner.parse_address_range(f"0-{MAX_RANGE_POINTS - 1}") == (0, MAX_RANGE_POINTS - 1)
    with pytest.raises(ValueError, match="at most"):
        plc_scanner.parse_address_range("0-16000000")


def test_config_rejects_huge_range(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text("scan:\n  device_ranges:\n    - {device: D, start: 0, end: 16000000}\n",
                    encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert any("scan.device_ranges[0]" in e and "at most" in e for e in loader.validate())


def test_gui_checks_range_size():
    source = (plc_scanner.Path(__file__).resolve().parent.parent / "plc_gui.py").read_text(encoding="utf-8")
    assert "MAX_RANGE_POINTS" in source and "end - start + 1 > MAX_RANGE_POINTS" in source
