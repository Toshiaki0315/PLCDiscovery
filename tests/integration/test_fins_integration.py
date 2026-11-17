"""
FINS Integration Tests

Tests actual communication with FINS simulator.
"""

import pytest

from plc_discovery.config import Protocol, DeviceType, PLCInfo, DeviceRange, StatusCode
from plc_discovery.collector import PLCDataCollector


# Mark all tests to require FINS simulator
pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]


class TestFINSConnection:
    """Test FINS connection handling"""

    async def test_connect_success(self, fins_simulator, fins_plc_info, network_config):
        """Test successful connection to FINS simulator"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            assert collector._handler.is_connected is True

    async def test_connect_wrong_port(self, fins_simulator, network_config):
        """Test connection failure with wrong port"""
        plc_info = PLCInfo(
            ip_address="127.0.0.1",
            protocol=Protocol.FINS,
            port=59999,  # Wrong port
        )

        # UDP itself has no handshake; connect() verifies that a FINS node
        # answers, so a port without a FINS server must not be "connected".
        async with PLCDataCollector(plc_info, network_config) as collector:
            assert collector._handler.is_connected is False
            # Reading retries the connection and reports the address as a
            # communication error rather than returning nothing
            points = await collector.collect_range(DeviceType.DM, 0, 0)
            assert [(p.address, p.status) for p in points] == [("DM0", StatusCode.NG_COMM_ERROR)]
            assert collector._handler.is_connected is False


class TestFINSDataRead:
    """Test FINS data reading"""

    async def test_read_single_address(self, fins_simulator, fins_plc_info, network_config):
        """Test reading a single address"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DM, 0, 0)

        assert len(data_points) == 1
        assert data_points[0].status == StatusCode.OK
        assert data_points[0].value is not None

    async def test_read_address_range(self, fins_simulator, fins_plc_info, network_config):
        """Test reading an address range"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DM, 0, 99)

        assert len(data_points) == 100

        # Check all have valid status
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

    async def test_read_large_range(self, fins_simulator, fins_plc_info, network_config):
        """Test reading a large address range (triggers chunking)"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DM, 0, 599)  # FINS max is 499, this will split

        assert len(data_points) == 600
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 600

    async def test_read_hr_device(self, fins_simulator, fins_plc_info, network_config):
        """Test reading HR (holding) device"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 10)

        assert len(data_points) == 11
        for dp in data_points:
            assert dp.status == StatusCode.OK
            assert dp.value is not None

    async def test_read_w_device(self, fins_simulator, fins_plc_info, network_config):
        """Test reading W (work) device"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.W, 0, 10)

        assert len(data_points) == 11
        for dp in data_points:
            assert dp.status == StatusCode.OK
            assert dp.value is not None


class TestFINSDeniedAddresses:
    """Test FINS denied address handling with binary search"""

    async def test_denied_address_range(self, fins_simulator, fins_plc_info, network_config):
        """Test handling of denied address range (DM5000-DM5100)"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DM, 5000, 5050)
            denied = collector.get_denied_addresses()

        assert len(data_points) == 51

        illegal_count = sum(
            1 for dp in data_points
            if dp.status == StatusCode.NG_ILLEGAL_ADDR
        )
        assert illegal_count == 51
        assert len(denied) > 0

    async def test_binary_search_isolates_denied(
        self, fins_simulator, fins_plc_info, network_config
    ):
        """Test binary search correctly isolates denied addresses"""
        async with PLCDataCollector(fins_plc_info, network_config) as collector:
            # DM4990-DM5010 includes denied range DM5000-DM5010
            data_points = await collector.collect_range(DeviceType.DM, 4990, 5010)
            denied = collector.get_denied_addresses()

        assert len(data_points) == 21

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(
            1 for dp in data_points
            if dp.status == StatusCode.NG_ILLEGAL_ADDR
        )

        # DM4990-DM4999 should be OK (10 addresses)
        # DM5000-DM5010 should be denied (11 addresses)
        assert ok_count == 10
        assert denied_count == 11
        assert "DM5000" in denied


class TestFINSFullScan:
    """Test FINS full scan functionality"""

    async def test_full_scan(self, fins_simulator, fins_plc_info, network_config):
        """Test full scan of FINS device"""
        custom_ranges = [
            DeviceRange(DeviceType.DM, 0, 10),
            DeviceRange(DeviceType.HR, 0, 10),
        ]

        from plc_discovery import config
        original_ranges = config.DEFAULT_DEVICE_RANGES.get(Protocol.FINS)
        config.DEFAULT_DEVICE_RANGES[Protocol.FINS] = custom_ranges

        try:
            async with PLCDataCollector(fins_plc_info, network_config) as collector:
                data_points = await collector.collect_full_scan()

            assert len(data_points) == 22
        finally:
            config.DEFAULT_DEVICE_RANGES[Protocol.FINS] = original_ranges
