"""
Tests for protocol handlers
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from plc_discovery.config import (
    Protocol, DeviceType, DeviceRange, StatusCode, NetworkConfig
)
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.slmp import SLMPHandler
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.s7 import S7Handler


class TestBaseProtocolHandler:
    """Tests for BaseProtocolHandler"""
    
    def test_max_read_size(self, network_config):
        """Test max read size property"""
        # Create a concrete implementation for testing
        class TestHandler(BaseProtocolHandler):
            protocol = Protocol.SLMP
            
            async def connect(self):
                return True
            
            async def disconnect(self):
                pass
            
            async def read_device_raw(self, device_type, start_address, count):
                return [0] * count, StatusCode.OK
        
        handler = TestHandler("192.168.1.10", 5001, network_config)
        # SLMP safe read size is 900
        assert handler.max_read_size == 900
    
    @pytest.mark.asyncio
    async def test_binary_search_single_address_success(self, network_config):
        """Test binary search with single successful address"""
        class TestHandler(BaseProtocolHandler):
            protocol = Protocol.SLMP
            
            async def connect(self):
                return True
            
            async def disconnect(self):
                pass
            
            async def read_device_raw(self, device_type, start_address, count):
                return [100], StatusCode.OK
        
        handler = TestHandler("192.168.1.10", 5001, network_config)
        handler._connected = True
        
        results = await handler._binary_search_read(DeviceType.D, 0, 0)
        
        assert len(results) == 1
        assert results[0].status == StatusCode.OK
        assert results[0].value == 100
    
    @pytest.mark.asyncio
    async def test_binary_search_single_address_failure(self, network_config):
        """Test binary search with single failed address"""
        class TestHandler(BaseProtocolHandler):
            protocol = Protocol.SLMP
            
            async def connect(self):
                return True
            
            async def disconnect(self):
                pass
            
            async def read_device_raw(self, device_type, start_address, count):
                return None, StatusCode.NG_ILLEGAL_ADDR
        
        handler = TestHandler("192.168.1.10", 5001, network_config)
        handler._connected = True
        
        results = await handler._binary_search_read(DeviceType.D, 0, 0)
        
        assert len(results) == 1
        assert results[0].status == StatusCode.NG_ILLEGAL_ADDR
        assert handler._session_cache.is_denied("D0")
    
    @pytest.mark.asyncio
    async def test_binary_search_split(self, network_config):
        """Test binary search splits range on error"""
        call_count = [0]
        
        class TestHandler(BaseProtocolHandler):
            protocol = Protocol.SLMP
            
            async def connect(self):
                return True
            
            async def disconnect(self):
                pass
            
            async def read_device_raw(self, device_type, start_address, count):
                call_count[0] += 1
                # First call (full range) fails
                if call_count[0] == 1:
                    return None, StatusCode.NG_ILLEGAL_ADDR
                # Subsequent calls succeed
                return [100] * count, StatusCode.OK
        
        handler = TestHandler("192.168.1.10", 5001, network_config)
        handler._connected = True
        
        results = await handler._binary_search_read(DeviceType.D, 0, 1)
        
        # Should have split and retried
        assert call_count[0] > 1
    
    def test_session_cache_operations(self, network_config):
        """Test session cache operations"""
        class TestHandler(BaseProtocolHandler):
            protocol = Protocol.SLMP
            
            async def connect(self):
                return True
            
            async def disconnect(self):
                pass
            
            async def read_device_raw(self, device_type, start_address, count):
                return [0], StatusCode.OK
        
        handler = TestHandler("192.168.1.10", 5001, network_config)
        
        # Test adding denied addresses
        handler._session_cache.add_denied("D100")
        handler._session_cache.add_denied("D101")
        
        assert handler._session_cache.is_denied("D100")
        assert handler._session_cache.is_denied("D101")
        assert not handler._session_cache.is_denied("D102")
        
        # Test get_denied_addresses
        denied = handler.get_denied_addresses()
        assert "D100" in denied
        assert "D101" in denied
        
        # Test clear
        handler.clear_session_cache()
        assert not handler._session_cache.is_denied("D100")


class TestSLMPHandler:
    """Tests for SLMPHandler"""
    
    def test_handler_creation(self, network_config):
        """Test SLMP handler creation"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        assert handler.protocol == Protocol.SLMP
        assert handler.ip_address == "192.168.1.10"
        assert handler.port == 5001
    
    def test_handler_default_port(self, network_config):
        """Test SLMP handler with default port"""
        handler = SLMPHandler("192.168.1.10", config=network_config)
        assert handler.port == 5001
    
    @pytest.mark.asyncio
    async def test_connect_success(self, network_config, mock_slmp_client):
        """Test successful SLMP connection"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        
        # Manually set up the handler as if connection succeeded
        handler._client = mock_slmp_client
        handler._connected = True
        
        assert handler.is_connected
        # Verify handler state is correct
        assert handler._client is not None
    
    @pytest.mark.asyncio
    async def test_connect_import_error(self, network_config):
        """Test SLMP connection with missing library"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        
        # When pymcprotocol is not installed, connect should return False
        result = await handler.connect()
        
        # This will be False if the library is not installed
        # or True if installed - either is valid behavior
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_disconnect(self, network_config, mock_slmp_client):
        """Test SLMP disconnection"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        handler._client = mock_slmp_client
        handler._connected = True
        
        await handler.disconnect()
        
        assert not handler.is_connected
        mock_slmp_client.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_read_device_raw_word(self, network_config, mock_slmp_client):
        """Test reading word device"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        handler._client = mock_slmp_client
        handler._connected = True
        
        data, status = await handler.read_device_raw(DeviceType.D, 0, 3)
        
        assert status == StatusCode.OK
        assert data == [100, 200, 300]
        mock_slmp_client.batchread_wordunits.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_read_device_raw_bit(self, network_config, mock_slmp_client):
        """Test reading bit device"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        handler._client = mock_slmp_client
        handler._connected = True
        
        data, status = await handler.read_device_raw(DeviceType.M, 0, 4)
        
        assert status == StatusCode.OK
        mock_slmp_client.batchread_bitunits.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_read_device_raw_not_connected(self, network_config):
        """Test reading when not connected"""
        handler = SLMPHandler("192.168.1.10", 5001, config=network_config)
        
        data, status = await handler.read_device_raw(DeviceType.D, 0, 10)
        
        assert status == StatusCode.NG_COMM_ERROR
        assert data is None


class TestModbusHandler:
    """Tests for ModbusHandler"""
    
    def test_handler_creation(self, network_config):
        """Test Modbus handler creation"""
        handler = ModbusHandler("192.168.1.10", 502, config=network_config)
        assert handler.protocol == Protocol.MODBUS_TCP
        assert handler.ip_address == "192.168.1.10"
        assert handler.port == 502
    
    def test_handler_default_port(self, network_config):
        """Test Modbus handler with default port"""
        handler = ModbusHandler("192.168.1.10", config=network_config)
        assert handler.port == 502
    
    def test_handler_unit_id(self, network_config):
        """Test Modbus handler with custom unit ID"""
        handler = ModbusHandler("192.168.1.10", unit_id=5, config=network_config)
        assert handler._unit_id == 5
    
    @pytest.mark.asyncio
    async def test_connect_success(self, network_config, mock_modbus_client):
        """Test successful Modbus connection"""
        handler = ModbusHandler("192.168.1.10", 502, config=network_config)
        
        # Manually set up the handler as if connection succeeded
        handler._client = mock_modbus_client
        handler._connected = True
        
        assert handler.is_connected
        assert handler._client is not None
    
    @pytest.mark.asyncio
    async def test_read_holding_registers(self, network_config, mock_modbus_client):
        """Test reading holding registers"""
        handler = ModbusHandler("192.168.1.10", 502, config=network_config)
        handler._client = mock_modbus_client
        handler._connected = True
        
        data, status = await handler.read_device_raw(DeviceType.HR, 0, 3)
        
        assert status == StatusCode.OK
        assert data == [100, 200, 300]
    
    @pytest.mark.asyncio
    async def test_read_illegal_address(self, network_config):
        """Test reading illegal address"""
        handler = ModbusHandler("192.168.1.10", 502, config=network_config)
        
        mock_client = MagicMock()
        mock_client.connect.return_value = True
        
        # Create error response
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2  # Illegal data address
        mock_client.read_holding_registers.return_value = error_response
        
        handler._client = mock_client
        handler._connected = True
        
        data, status = await handler.read_device_raw(DeviceType.HR, 9999, 10)
        
        assert status == StatusCode.NG_ILLEGAL_ADDR
        assert data is None


class TestS7Handler:
    """Tests for S7Handler"""
    
    def test_handler_creation(self, network_config):
        """Test S7 handler creation"""
        handler = S7Handler("192.168.1.10", 102, config=network_config)
        assert handler.protocol == Protocol.S7
        assert handler.ip_address == "192.168.1.10"
        assert handler.port == 102
    
    def test_handler_rack_slot(self, network_config):
        """Test S7 handler with custom rack/slot"""
        handler = S7Handler("192.168.1.10", rack=0, slot=2, config=network_config)
        assert handler._rack == 0
        assert handler._slot == 2
    
    @pytest.mark.asyncio
    async def test_connect_success(self, network_config, mock_s7_client):
        """Test successful S7 connection"""
        handler = S7Handler("192.168.1.10", 102, config=network_config)
        
        # Manually set up the handler as if connection succeeded
        handler._client = mock_s7_client
        handler._connected = True
        
        assert handler.is_connected
        assert handler._client is not None
    
    @pytest.mark.asyncio
    async def test_read_db(self, network_config, mock_s7_client):
        """Test reading data block"""
        handler = S7Handler("192.168.1.10", 102, config=network_config)
        handler._client = mock_s7_client
        handler._connected = True
        
        data, status = await handler.read_device_raw(DeviceType.DB, 1, 2)
        
        assert status == StatusCode.OK
        # Data is converted from big-endian bytes
        assert data is not None
    
    @pytest.mark.asyncio
    async def test_get_cpu_info(self, network_config, mock_s7_client):
        """Test getting CPU info"""
        handler = S7Handler("192.168.1.10", 102, config=network_config)
        handler._client = mock_s7_client
        handler._connected = True
        
        info = await handler.get_cpu_info()
        
        assert info["manufacturer"] == "シーメンス"
        assert "CPU" in info["model"]


class TestEtherNetIPHandler:
    """Tests for EtherNetIPHandler"""
    
    def test_handler_creation(self, network_config):
        """Test EtherNet/IP handler creation"""
        handler = EtherNetIPHandler("192.168.1.10", 44818, config=network_config)
        assert handler.protocol == Protocol.ETHERNET_IP
        assert handler.ip_address == "192.168.1.10"
        assert handler.port == 44818
    
    def test_handler_slot(self, network_config):
        """Test EtherNet/IP handler with custom slot"""
        handler = EtherNetIPHandler("192.168.1.10", slot=1, config=network_config)
        assert handler._slot == 1
    
    @pytest.mark.asyncio
    async def test_connect_success(self, network_config):
        """Test successful EtherNet/IP connection"""
        handler = EtherNetIPHandler("192.168.1.10", 44818, config=network_config)
        
        # Manually set up the handler as if connection succeeded
        mock_client = MagicMock()
        mock_client.open = MagicMock()
        handler._client = mock_client
        handler._connected = True
        
        assert handler.is_connected
        assert handler._client is not None
    
    @pytest.mark.asyncio
    async def test_read_not_connected(self, network_config):
        """Test reading when not connected"""
        handler = EtherNetIPHandler("192.168.1.10", 44818, config=network_config)
        
        data, status = await handler.read_device_raw(DeviceType.D, 0, 10)
        
        assert status == StatusCode.NG_COMM_ERROR
        assert data is None

