"""
Tests for broadcast_discovery module
"""

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery.broadcast_discovery import (
    EIP_LIST_IDENTITY_CMD,
    BroadcastDiscovery,
    UDPDiscoveryProtocol,
    discover_broadcast,
)
from plc_discovery.config import NetworkConfig, PLCInfo, Protocol


class TestUDPDiscoveryProtocol:
    """Tests for UDPDiscoveryProtocol class"""

    def test_datagram_received(self):
        """Test handling received datagrams"""
        responses = {}
        protocol = UDPDiscoveryProtocol(responses, 1.0)

        # Simulate receiving a datagram
        data = b"\x00\x01\x02\x03"
        addr = ("192.168.1.10", 44818)

        protocol.datagram_received(data, addr)

        assert "192.168.1.10" in responses
        assert responses["192.168.1.10"] == data

    def test_connection_made(self):
        """Test connection_made callback"""
        responses = {}
        protocol = UDPDiscoveryProtocol(responses, 1.0)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        assert protocol.transport is mock_transport


class TestBroadcastDiscovery:
    """Tests for BroadcastDiscovery class"""

    def test_init(self):
        """Test initialization"""
        discovery = BroadcastDiscovery()

        assert discovery.config is not None
        assert isinstance(discovery.discovered_plcs, dict)

    def test_init_with_config(self):
        """Test initialization with custom config"""
        config = NetworkConfig(discovery_timeout_ms=2000)
        discovery = BroadcastDiscovery(config)

        assert discovery.config.discovery_timeout_ms == 2000

    def test_build_slmp_discovery_request(self):
        """Test building SLMP discovery request"""
        discovery = BroadcastDiscovery()
        request = discovery._build_slmp_discovery_request()

        assert isinstance(request, bytes)
        assert len(request) > 0
        # Subheader bytes "50 00" (3E binary request)
        assert request[:2] == b"\x50\x00"

    def test_build_eip_list_identity_request(self):
        """Test building EtherNet/IP List Identity request"""
        discovery = BroadcastDiscovery()
        request = discovery._build_eip_list_identity_request()

        assert isinstance(request, bytes)
        assert len(request) == 24  # Standard EtherNet/IP header

        # Check command (List Identity = 0x0063)
        command = struct.unpack("<H", request[0:2])[0]
        assert command == EIP_LIST_IDENTITY_CMD

    def test_parse_slmp_response_valid(self):
        """Test parsing valid SLMP response"""
        discovery = BroadcastDiscovery()

        # Build a valid SLMP response (D000 subheader)
        response = b"\xd0\x00" + b"\x00" * 20

        result = discovery._parse_slmp_response("192.168.1.10", response)

        assert result is not None
        assert result.ip_address == "192.168.1.10"
        assert result.protocol == Protocol.SLMP_UDP

    def test_parse_slmp_response_invalid(self):
        """Test parsing invalid SLMP response"""
        discovery = BroadcastDiscovery()

        # Invalid subheader
        response = struct.pack("<H", 0x1234) + b"\x00" * 20

        result = discovery._parse_slmp_response("192.168.1.10", response)

        assert result is None

    def test_parse_slmp_response_too_short(self):
        """Test parsing too short SLMP response"""
        discovery = BroadcastDiscovery()

        response = b"\x00\x01"  # Only 2 bytes

        result = discovery._parse_slmp_response("192.168.1.10", response)

        assert result is None

    def test_parse_eip_response_valid(self):
        """Test parsing valid EtherNet/IP response"""
        discovery = BroadcastDiscovery()

        # Build a basic valid EtherNet/IP List Identity response
        response = struct.pack("<H", EIP_LIST_IDENTITY_CMD)  # Command
        response += struct.pack("<H", 10)  # Length
        response += b"\x00" * 20  # Rest of header

        result = discovery._parse_eip_response("192.168.1.10", response)

        assert result is not None
        assert result.ip_address == "192.168.1.10"
        assert result.protocol == Protocol.ETHERNET_IP

    def test_parse_eip_response_invalid(self):
        """Test parsing invalid EtherNet/IP response"""
        discovery = BroadcastDiscovery()

        # Wrong command
        response = struct.pack("<H", 0x0001) + b"\x00" * 22

        result = discovery._parse_eip_response("192.168.1.10", response)

        assert result is None

    def test_set_progress_callback(self):
        """Test setting progress callback"""
        discovery = BroadcastDiscovery()

        callback = MagicMock()
        discovery.set_progress_callback(callback)

        assert discovery._progress_callback is callback

    def test_get_results(self):
        """Test getting discovered PLCs"""
        discovery = BroadcastDiscovery()

        # Add some mock discoveries
        plc1 = PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)
        plc2 = PLCInfo(ip_address="192.168.1.20", protocol=Protocol.ETHERNET_IP)

        discovery.discovered_plcs["192.168.1.10"] = plc1
        discovery.discovered_plcs["192.168.1.20"] = plc2

        results = discovery.get_results()

        assert len(results) == 2
        assert any(p.ip_address == "192.168.1.10" for p in results)
        assert any(p.ip_address == "192.168.1.20" for p in results)

    @pytest.mark.asyncio
    async def test_discover_slmp_broadcast(self):
        """Test SLMP broadcast discovery"""
        discovery = BroadcastDiscovery()

        # Mock the _send_broadcast method
        mock_response = b"\xd0\x00" + b"\x00" * 20

        async def mock_send_broadcast(port, data, timeout):
            return {"192.168.1.10": mock_response}

        with patch.object(discovery, "_send_broadcast", mock_send_broadcast):
            plcs = await discovery.discover_slmp_broadcast()

        assert len(plcs) == 1
        assert plcs[0].ip_address == "192.168.1.10"
        assert plcs[0].protocol == Protocol.SLMP_UDP

    @pytest.mark.asyncio
    async def test_discover_eip_broadcast(self):
        """Test EtherNet/IP broadcast discovery"""
        discovery = BroadcastDiscovery()

        # Mock response
        mock_response = struct.pack("<H", EIP_LIST_IDENTITY_CMD)
        mock_response += struct.pack("<H", 10)
        mock_response += b"\x00" * 20

        async def mock_send_broadcast(port, data, timeout):
            return {"192.168.1.20": mock_response}

        with patch.object(discovery, "_send_broadcast", mock_send_broadcast):
            plcs = await discovery.discover_eip_broadcast()

        assert len(plcs) == 1
        assert plcs[0].ip_address == "192.168.1.20"
        assert plcs[0].protocol == Protocol.ETHERNET_IP

    @pytest.mark.asyncio
    async def test_discover_all_broadcast(self):
        """Test discovering all protocols"""
        discovery = BroadcastDiscovery()

        # Mock responses for both protocols
        slmp_response = b"\xd0\x00" + b"\x00" * 20
        eip_response = struct.pack("<H", EIP_LIST_IDENTITY_CMD) + struct.pack("<H", 10) + b"\x00" * 20

        call_count = [0]

        async def mock_send_broadcast(port, data, timeout):
            call_count[0] += 1
            if port == 5001:  # SLMP
                return {"192.168.1.10": slmp_response}
            elif port == 44818:  # EtherNet/IP
                return {"192.168.1.20": eip_response}
            return {}

        with patch.object(discovery, "_send_broadcast", mock_send_broadcast):
            plcs = await discovery.discover_all_broadcast()

        assert len(plcs) == 2
        ips = [p.ip_address for p in plcs]
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips


class TestDiscoverBroadcast:
    """Tests for discover_broadcast convenience function"""

    @pytest.mark.asyncio
    async def test_convenience_function(self):
        """Test the convenience function"""
        with patch.object(BroadcastDiscovery, "discover_all_broadcast", new_callable=AsyncMock) as mock_discover:
            mock_discover.return_value = [PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)]

            plcs = await discover_broadcast()

        assert len(plcs) == 1
        assert plcs[0].ip_address == "192.168.1.10"

    @pytest.mark.asyncio
    async def test_with_config(self):
        """Test with custom config"""
        config = NetworkConfig(discovery_timeout_ms=3000)

        with patch.object(BroadcastDiscovery, "discover_all_broadcast", new_callable=AsyncMock) as mock_discover:
            mock_discover.return_value = []

            await discover_broadcast(config=config)

        mock_discover.assert_called_once()
