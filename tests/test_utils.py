"""
Tests for utils module
"""

from unittest.mock import MagicMock, patch

import pytest

from plc_discovery.utils import (
    RateLimiter,
    SessionCache,
    format_mac_address,
    get_file_timestamp,
    get_local_ip,
    get_manufacturer_from_mac,
    get_timestamp,
    hex_to_value,
    is_port_open,
    parse_ip_range,
    split_range,
    value_to_hex,
)


class TestIPFunctions:
    """Tests for IP-related functions"""

    def test_get_local_ip_returns_string(self):
        """Test get_local_ip returns a string"""
        ip = get_local_ip()
        assert isinstance(ip, str)
        # Should be either a valid IP or localhost fallback
        assert ip == "127.0.0.1" or len(ip.split(".")) == 4

    def test_parse_ip_range_cidr(self):
        """Test parsing CIDR notation"""
        ips = parse_ip_range("192.168.1.0/30")
        # /30 gives 4 addresses, 2 usable hosts
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_parse_ip_range_cidr_24(self):
        """Test parsing /24 CIDR"""
        ips = parse_ip_range("192.168.1.0/24")
        assert len(ips) == 254  # 256 - network - broadcast
        assert "192.168.1.1" in ips
        assert "192.168.1.254" in ips

    def test_parse_ip_range_hyphen(self):
        """Test parsing hyphen notation"""
        ips = parse_ip_range("192.168.1.1-5")
        assert len(ips) == 5
        assert "192.168.1.1" in ips
        assert "192.168.1.5" in ips

    def test_parse_ip_range_single(self):
        """Test parsing single IP"""
        ips = parse_ip_range("192.168.1.10")
        assert len(ips) == 1
        assert ips[0] == "192.168.1.10"

    def test_parse_ip_range_invalid(self):
        """Test parsing invalid IP range"""
        ips = parse_ip_range("invalid")
        assert ips == []


class TestMACFunctions:
    """Tests for MAC address functions"""

    def test_get_manufacturer_from_mac_mitsubishi(self):
        """Test Mitsubishi MAC OUI"""
        manufacturer = get_manufacturer_from_mac("00:26:92:12:34:56")
        assert manufacturer == "三菱電機"

    def test_get_manufacturer_from_mac_omron(self):
        """Test Omron MAC OUI"""
        manufacturer = get_manufacturer_from_mac("00:00:0A:AB:CD:EF")
        assert manufacturer == "オムロン"

    def test_get_manufacturer_from_mac_siemens(self):
        """Test Siemens MAC OUI"""
        manufacturer = get_manufacturer_from_mac("00:1B:1B:11:22:33")
        assert manufacturer == "シーメンス"

    def test_get_manufacturer_from_mac_unknown(self):
        """Test unknown MAC OUI"""
        manufacturer = get_manufacturer_from_mac("FF:FF:FF:12:34:56")
        assert manufacturer is None

    def test_get_manufacturer_from_mac_empty(self):
        """Test empty MAC"""
        manufacturer = get_manufacturer_from_mac("")
        assert manufacturer is None

    def test_get_manufacturer_from_mac_none(self):
        """Test None MAC"""
        manufacturer = get_manufacturer_from_mac(None)
        assert manufacturer is None

    def test_format_mac_address(self):
        """Test formatting MAC bytes to string"""
        mac_bytes = bytes([0x00, 0x0A, 0xDC, 0xAB, 0xCD, 0xEF])
        formatted = format_mac_address(mac_bytes)
        assert formatted == "00:0A:DC:AB:CD:EF"


class TestValueConversion:
    """Tests for value conversion functions"""

    def test_value_to_hex_word(self):
        """Test word to hex conversion"""
        assert value_to_hex(0) == "0x0000"
        assert value_to_hex(100) == "0x0064"
        assert value_to_hex(255) == "0x00FF"
        assert value_to_hex(65535) == "0xFFFF"

    def test_value_to_hex_dword(self):
        """Test dword to hex conversion"""
        assert value_to_hex(0, word_size=2) == "0x00000000"
        assert value_to_hex(65536, word_size=2) == "0x00010000"

    def test_hex_to_value(self):
        """Test hex to value conversion"""
        assert hex_to_value("0x0000") == 0
        assert hex_to_value("0x0064") == 100
        assert hex_to_value("0xFFFF") == 65535
        assert hex_to_value("0x10000") == 65536


class TestTimestampFunctions:
    """Tests for timestamp functions"""

    def test_get_timestamp_format(self):
        """Test timestamp format"""
        ts = get_timestamp()
        # Format: YYYY-MM-DD HH:MM:SS.mmm
        assert len(ts) == 23
        assert ts[4] == "-"
        assert ts[7] == "-"
        assert ts[10] == " "
        assert ts[13] == ":"
        assert ts[16] == ":"
        assert ts[19] == "."

    def test_get_file_timestamp_format(self):
        """Test file timestamp format"""
        ts = get_file_timestamp()
        # Format: YYYYMMDD_HHMMSS
        assert len(ts) == 15
        assert ts[8] == "_"
        assert ts.replace("_", "").isdigit()


class TestSplitRange:
    """Tests for split_range function"""

    def test_split_range_even(self):
        """Test splitting even range"""
        first, second = split_range(0, 99)
        assert first == (0, 49)
        assert second == (50, 99)

    def test_split_range_odd(self):
        """Test splitting odd range"""
        first, second = split_range(0, 100)
        assert first == (0, 50)
        assert second == (51, 100)

    def test_split_range_small(self):
        """Test splitting small range"""
        first, second = split_range(0, 1)
        assert first == (0, 0)
        assert second == (1, 1)


class TestIsPortOpen:
    """Tests for is_port_open function"""

    @patch("socket.socket")
    def test_port_open(self, mock_socket_class):
        """Test detecting open port"""
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        result = is_port_open("192.168.1.1", 5001, timeout=1.0)
        assert result is True
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_port_closed(self, mock_socket_class):
        """Test detecting closed port"""
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_socket

        result = is_port_open("192.168.1.1", 5001, timeout=1.0)
        assert result is False


class TestRateLimiter:
    """Tests for RateLimiter class"""

    def test_rate_limiter_creation(self):
        """Test RateLimiter creation"""
        rl = RateLimiter(100)
        assert rl.interval_ms == 100

    @pytest.mark.asyncio
    async def test_rate_limiter_wait(self):
        """Test RateLimiter wait"""
        import time

        rl = RateLimiter(50)  # 50ms interval

        start = time.time()
        await rl.wait()  # First call should not wait
        await rl.wait()  # Second call should wait
        elapsed = (time.time() - start) * 1000

        # Should have waited approximately 50ms
        assert elapsed >= 40  # Allow some tolerance


class TestSessionCache:
    """Tests for SessionCache class"""

    def test_session_cache_add_denied(self):
        """Test adding denied address"""
        cache = SessionCache()
        cache.add_denied("D100")
        assert cache.is_denied("D100")
        assert not cache.is_denied("D101")

    def test_session_cache_multiple_denied(self):
        """Test adding multiple denied addresses"""
        cache = SessionCache()
        cache.add_denied("D100")
        cache.add_denied("D101")
        cache.add_denied("D102")

        denied = cache.get_all_denied()
        assert len(denied) == 3
        assert "D100" in denied
        assert "D101" in denied
        assert "D102" in denied

    def test_session_cache_clear(self):
        """Test clearing cache"""
        cache = SessionCache()
        cache.add_denied("D100")
        cache.add_denied("D101")

        cache.clear()

        assert not cache.is_denied("D100")
        assert len(cache.get_all_denied()) == 0

    def test_session_cache_duplicate(self):
        """Test adding duplicate address"""
        cache = SessionCache()
        cache.add_denied("D100")
        cache.add_denied("D100")  # Duplicate

        denied = cache.get_all_denied()
        assert len(denied) == 1
