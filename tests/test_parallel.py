"""
Tests for parallel module
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from plc_discovery.parallel import (
    ParallelPLCScanner, PLCScanResult, scan_plcs_parallel
)
from plc_discovery.config import (
    Protocol, DeviceType, ScanMode, PLCInfo, DataPoint,
    NetworkConfig, DeviceRange, StatusCode
)


def make_data_point(address: str, value: int, status: StatusCode = StatusCode.OK) -> DataPoint:
    """Helper to create DataPoint"""
    return DataPoint(address=address, value=value, raw_hex=f"{value:04X}", status=status)


# Use correct status code names
STATUS_OK = StatusCode.OK
STATUS_ERROR = StatusCode.NG_ILLEGAL_ADDR


class MockCollector:
    """Mock collector with proper async context manager"""
    
    def __init__(self, data_points, denied_addresses=None, connected=True):
        self.data_points = data_points
        self._denied_addresses = denied_addresses or set()
        self.is_connected = connected
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        pass
    
    async def collect_full_scan(self):
        return self.data_points
    
    async def collect_range(self, *args, **kwargs):
        return self.data_points
    
    def get_denied_addresses(self):
        return self._denied_addresses


class TestPLCScanResult:
    """Tests for PLCScanResult dataclass"""
    
    def test_duration_ms(self):
        """Test duration calculation"""
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 1, 0, 0, 1)  # 1 second later
        
        result = PLCScanResult(
            plc_info=PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP),
            data_points=[],
            denied_addresses=set(),
            success=True,
            error_message=None,
            start_time=start,
            end_time=end,
        )
        
        assert result.duration_ms == 1000.0
    
    def test_statistics_empty(self):
        """Test statistics with no data points"""
        result = PLCScanResult(
            plc_info=PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP),
            data_points=[],
            denied_addresses=set(),
            success=True,
            error_message=None,
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
        
        stats = result.statistics
        
        assert stats["total_points"] == 0
        assert stats["success_count"] == 0
        assert stats["error_count"] == 0
        assert stats["success_rate"] == "N/A"
    
    def test_statistics_with_data(self):
        """Test statistics with data points"""
        data_points = [
            make_data_point("D0", 100, STATUS_OK),
            make_data_point("D1", 200, STATUS_OK),
            make_data_point("D2", 0, STATUS_ERROR),
        ]
        
        result = PLCScanResult(
            plc_info=PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP),
            data_points=data_points,
            denied_addresses={2},
            success=True,
            error_message=None,
            start_time=datetime.now(),
            end_time=datetime.now(),
        )
        
        stats = result.statistics
        
        assert stats["total_points"] == 3
        assert stats["success_count"] == 2
        assert stats["error_count"] == 1
        assert stats["denied_addresses"] == 1
        assert "66.67%" in stats["success_rate"]


class TestParallelPLCScanner:
    """Tests for ParallelPLCScanner class"""
    
    @pytest.mark.asyncio
    async def test_scan_empty_list(self):
        """Test scanning empty list of PLCs"""
        scanner = ParallelPLCScanner()
        results = await scanner.scan_multiple_plcs([])
        
        assert results == {}
    
    @pytest.mark.asyncio
    async def test_scan_single_plc(self):
        """Test scanning single PLC"""
        config = NetworkConfig(max_concurrent=1)
        plc = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.SLMP,
            port=5001
        )
        
        mock_data_points = [
            make_data_point("D0", 100, STATUS_OK)
        ]
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector(mock_data_points)
            
            scanner = ParallelPLCScanner(config)
            results = await scanner.scan_multiple_plcs([plc])
        
        assert "192.168.1.10" in results
        assert results["192.168.1.10"].success is True
        assert len(results["192.168.1.10"].data_points) == 1

    @pytest.mark.asyncio
    async def test_connection_failure_is_not_success(self):
        """A PLC that cannot be connected must be reported as failed"""
        config = NetworkConfig(max_concurrent=1)
        plc = PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP, port=5001)

        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector([], connected=False)

            scanner = ParallelPLCScanner(config)
            results = await scanner.scan_multiple_plcs([plc])

        result = results["192.168.1.10"]
        assert result.success is False
        assert "Failed to connect" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_multiple_plcs_parallel(self):
        """Test scanning multiple PLCs in parallel"""
        config = NetworkConfig(max_concurrent=3)
        plcs = [
            PLCInfo(ip_address=f"192.168.1.{i}", protocol=Protocol.SLMP, port=5001)
            for i in range(10, 13)
        ]
        
        mock_data_points = [
            make_data_point("D0", 100, STATUS_OK)
        ]
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector(mock_data_points)
            
            scanner = ParallelPLCScanner(config)
            results = await scanner.scan_multiple_plcs(plcs)
        
        assert len(results) == 3
        for ip in ["192.168.1.10", "192.168.1.11", "192.168.1.12"]:
            assert ip in results
            assert results[ip].success is True
    
    @pytest.mark.asyncio
    async def test_scan_with_range_mode(self):
        """Test scanning with range mode"""
        config = NetworkConfig(max_concurrent=1)
        plc = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.SLMP,
            port=5001
        )
        device_ranges = [DeviceRange(DeviceType.D, 0, 100)]
        
        mock_data_points = [
            make_data_point(f"D{i}", i, STATUS_OK)
            for i in range(101)
        ]
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector(mock_data_points)
            
            scanner = ParallelPLCScanner(config)
            results = await scanner.scan_multiple_plcs(
                [plc], ScanMode.RANGE, device_ranges
            )
        
        assert "192.168.1.10" in results
        assert len(results["192.168.1.10"].data_points) == 101
    
    @pytest.mark.asyncio
    async def test_scan_handles_errors(self):
        """Test that scanner handles individual PLC errors"""
        config = NetworkConfig(max_concurrent=2)
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP, port=5001),
            PLCInfo(ip_address="192.168.1.11", protocol=Protocol.SLMP, port=5001),
        ]
        
        call_count = [0]
        
        class FailingMockCollector:
            def __init__(self):
                pass
            
            async def __aenter__(self):
                nonlocal call_count
                call_count[0] += 1
                if call_count[0] == 1:
                    raise ConnectionError("Connection failed")
                return self
            
            async def __aexit__(self, *args):
                pass
            
            async def collect_full_scan(self):
                return []
            
            def get_denied_addresses(self):
                return set()
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = FailingMockCollector()
            
            scanner = ParallelPLCScanner(config)
            results = await scanner.scan_multiple_plcs(plcs)
        
        # First should fail
        assert "192.168.1.10" in results
        assert results["192.168.1.10"].success is False
        assert "Connection failed" in results["192.168.1.10"].error_message
    
    @pytest.mark.asyncio
    async def test_aggregate_statistics(self):
        """Test aggregate statistics calculation"""
        config = NetworkConfig(max_concurrent=2)
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP, port=5001),
            PLCInfo(ip_address="192.168.1.11", protocol=Protocol.SLMP, port=5001),
        ]
        
        mock_data_points = [
            make_data_point("D0", 100, STATUS_OK),
            make_data_point("D1", 200, STATUS_OK),
        ]
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector(mock_data_points)
            
            scanner = ParallelPLCScanner(config)
            await scanner.scan_multiple_plcs(plcs)
            stats = scanner.get_aggregate_statistics()
        
        assert stats["total_plcs"] == 2
        assert stats["successful_plcs"] == 2
        assert stats["total_data_points"] == 4


class TestScanPLCsParallel:
    """Tests for scan_plcs_parallel convenience function"""
    
    @pytest.mark.asyncio
    async def test_convenience_function(self):
        """Test the convenience function"""
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP, port=5001)
        ]
        
        with patch('plc_discovery.parallel.PLCDataCollector') as mock_collector_class:
            mock_collector_class.return_value = MockCollector([])
            
            results = await scan_plcs_parallel(plcs)
        
        assert "192.168.1.10" in results
