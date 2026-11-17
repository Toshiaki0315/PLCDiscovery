"""
Modbus/TCP Integration Tests

Tests actual communication with Modbus simulator.
"""

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceType, PLCInfo, Protocol, StatusCode

# Mark all tests to require Modbus simulator
pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]


class TestModbusConnection:
    """Test Modbus connection handling"""

    async def test_connect_success(self, modbus_simulator, modbus_plc_info, network_config):
        """Test successful connection to Modbus simulator"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            assert collector._handler.is_connected is True

    async def test_connect_wrong_port(self, modbus_simulator, network_config):
        """Test connection failure with wrong port"""
        plc_info = PLCInfo(
            ip_address="127.0.0.1",
            protocol=Protocol.MODBUS_TCP,
            port=59998,  # Wrong port
        )
        async with PLCDataCollector(plc_info, network_config) as collector:
            # Handler returns False on failure, does not raise
            assert not collector._handler.is_connected


class TestModbusDataRead:
    """Test Modbus data reading"""

    async def test_read_holding_registers(self, modbus_simulator, modbus_plc_info, network_config):
        """Test reading holding registers"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 99)

        assert len(data_points) == 100

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

    async def test_read_input_registers(self, modbus_simulator, modbus_plc_info, network_config):
        """Test reading input registers"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.IR, 0, 49)

        assert len(data_points) == 50

    async def test_read_large_range(self, modbus_simulator, modbus_plc_info, network_config):
        """Test reading large range (triggers chunking due to 125 word limit)"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 249)

        assert len(data_points) == 250


class TestModbusDeniedAddresses:
    """Test Modbus denied address handling"""

    async def test_denied_address_range(self, modbus_simulator, modbus_plc_info, network_config):
        """Test handling of denied address range"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            # Read range that includes denied addresses (5000-5100)
            data_points = await collector.collect_range(DeviceType.HR, 5000, 5100)

        assert len(data_points) == 101

        # All should be marked as illegal
        illegal_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert illegal_count == 101

    async def test_binary_search_mixed_range(self, modbus_simulator, modbus_plc_info, network_config):
        """Test binary search with mixed valid/invalid addresses"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            # Read range that spans valid and invalid
            data_points = await collector.collect_range(DeviceType.HR, 4900, 5200)

        assert len(data_points) == 301

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # 4900-4999 and 5101-5200 should be OK
        assert ok_count == 200
        # 5000-5100 should be denied
        assert denied_count == 101


class TestModbusDataValues:
    """Test Modbus data value handling"""

    async def test_register_values(self, modbus_simulator, modbus_plc_info, network_config):
        """Test that register values are valid"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 9)

        for dp in data_points:
            if dp.status == StatusCode.OK:
                assert 0 <= dp.value <= 65535
                assert dp.raw_hex is not None

    async def test_timestamp_present(self, modbus_simulator, modbus_plc_info, network_config):
        """Test that timestamps are recorded"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 0)

        assert data_points[0].timestamp != ""


class TestModbusStatistics:
    """Test Modbus statistics"""

    async def test_statistics_tracking(self, modbus_simulator, modbus_plc_info, network_config):
        """Test statistics are correctly tracked"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            await collector.collect_range(DeviceType.HR, 0, 99)
            stats = collector.get_statistics()

        assert stats["total_points"] == 100
        assert stats["success_count"] == 100


class TestModbusCoils:
    """Test Modbus coil handling"""

    async def test_read_coils_as_bit_device(self, modbus_simulator, modbus_plc_info, network_config):
        """Test reading coils (M device type maps to coils)"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            # M device type should map to coils in Modbus
            data_points = await collector.collect_range(DeviceType.M, 0, 15)

        # Should have 16 data points
        assert len(data_points) == 16

        # Coil values should be 0 or 1
        for dp in data_points:
            if dp.status == StatusCode.OK:
                assert dp.value in [0, 1]
