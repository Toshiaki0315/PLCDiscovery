"""
Base Protocol Handler - Abstract interface for PLC communication
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
import logging

from ..config import (
    Protocol, DeviceType, DeviceRange, DataPoint, StatusCode,
    NetworkConfig, SAFE_READ_WORDS
)
from ..utils import get_timestamp, value_to_hex, RateLimiter, SessionCache
from ..retry import (
    RetryConfig, RetryHandler, RetryStrategy, 
    CircuitBreaker, CircuitBreakerConfig, RetryError,
    PLC_RETRY_CONFIG
)

logger = logging.getLogger(__name__)


class BaseProtocolHandler(ABC):
    """
    Abstract base class for PLC protocol handlers.
    
    All protocol-specific implementations must inherit from this class
    and implement the abstract methods.
    """
    
    # Class-level protocol identifier
    protocol: Protocol = None
    
    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        config: Optional[NetworkConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        use_circuit_breaker: bool = True
    ):
        self.ip_address = ip_address
        self.port = port
        self.config = config or NetworkConfig()
        self._connected = False
        self._rate_limiter = RateLimiter(self.config.packet_interval_ms)
        self._session_cache = SessionCache()
        
        # Initialize retry handler with exponential backoff
        self._retry_config = retry_config or PLC_RETRY_CONFIG
        self._circuit_breaker = None
        if use_circuit_breaker:
            self._circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
                failure_threshold=5,
                success_threshold=2,
                timeout_seconds=30.0
            ))
        self._retry_handler = RetryHandler(self._retry_config, self._circuit_breaker)
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the PLC.
        
        Returns:
            True if connection successful, False otherwise.
        """
        pass
    
    @abstractmethod
    async def disconnect(self):
        """
        Close connection to the PLC.
        """
        pass
    
    @abstractmethod
    async def read_device_raw(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read raw device data from PLC.
        
        Args:
            device_type: Type of device/register to read
            start_address: Starting address
            count: Number of points to read
        
        Returns:
            Tuple of (data list or None, status code)
        """
        pass
    
    @property
    def max_read_size(self) -> int:
        """Maximum number of words that can be read in a single request"""
        return SAFE_READ_WORDS.get(self.protocol, 100)
    
    @property
    def is_connected(self) -> bool:
        """Check if connected to PLC"""
        return self._connected
    
    async def read_device_range(
        self,
        device_range: DeviceRange
    ) -> List[DataPoint]:
        """
        Read a range of device data with automatic chunking.
        
        Automatically splits requests that exceed protocol limits.
        
        Args:
            device_range: Device range specification
        
        Returns:
            List of DataPoint objects
        """
        results = []
        start = device_range.start_address
        end = device_range.end_address
        device_type = device_range.device_type
        
        # Split into chunks based on max read size
        while start <= end:
            chunk_size = min(self.max_read_size, end - start + 1)
            
            # Skip known-bad addresses
            address_key = f"{device_type.value}{start}"
            if self._session_cache.is_denied(address_key):
                # Mark as denied and move to next
                results.append(DataPoint(
                    address=address_key,
                    status=StatusCode.NG_ILLEGAL_ADDR,
                    timestamp=get_timestamp()
                ))
                start += 1
                continue
            
            # Rate limiting
            await self._rate_limiter.wait()
            
            # Try to read chunk
            data, status = await self._read_with_retry(
                device_type, start, chunk_size
            )
            
            if status == StatusCode.OK and data:
                # Success - add all data points
                for i, value in enumerate(data):
                    results.append(DataPoint(
                        address=f"{device_type.value}{start + i}",
                        value=value,
                        raw_hex=value_to_hex(value),
                        status=StatusCode.OK,
                        timestamp=get_timestamp()
                    ))
                start += chunk_size
            else:
                # Error - use binary search to find bad addresses
                chunk_results = await self._binary_search_read(
                    device_type, start, start + chunk_size - 1
                )
                results.extend(chunk_results)
                start += chunk_size
        
        return results
    
    async def _read_with_retry(
        self,
        device_type: DeviceType,
        start_address: int,
        count: int,
        max_retries: int = None
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Read with retry logic using exponential backoff.
        
        Args:
            device_type: Device type to read
            start_address: Starting address
            count: Number of points
            max_retries: Maximum retry attempts (uses config if None)
        
        Returns:
            Tuple of (data or None, status code)
        """
        async def do_read():
            data, status = await self.read_device_raw(
                device_type, start_address, count
            )
            
            if status == StatusCode.OK:
                return data, status
            
            # Don't retry on certain errors
            if status == StatusCode.NG_ILLEGAL_ADDR:
                return None, status
            if status == StatusCode.NG_UNSUPPORTED:
                return None, status
            
            # Raise exception to trigger retry
            raise ConnectionError(f"Read failed with status: {status.value}")
        
        try:
            return await self._retry_handler.execute(do_read)
        except RetryError as e:
            logger.debug(f"All retries exhausted: {e}")
            return None, StatusCode.NG_COMM_ERROR
        except Exception as e:
            # Non-retryable error returned from do_read
            if isinstance(e, tuple):
                return e
            return None, StatusCode.NG_COMM_ERROR
    
    async def _binary_search_read(
        self,
        device_type: DeviceType,
        start: int,
        end: int,
        depth: int = 0
    ) -> List[DataPoint]:
        """
        Binary search algorithm for finding accessible addresses.
        
        When a read fails, this method recursively splits the range
        to identify exactly which addresses are inaccessible.
        
        Args:
            device_type: Device type to read
            start: Start address
            end: End address
            depth: Current recursion depth
        
        Returns:
            List of DataPoint objects with status
        """
        import asyncio
        
        results = []
        
        # Maximum depth check (log2(4096) = 12)
        if depth > 12:
            # Mark all as error
            for addr in range(start, end + 1):
                address_key = f"{device_type.value}{addr}"
                self._session_cache.add_denied(address_key)
                results.append(DataPoint(
                    address=address_key,
                    status=StatusCode.NG_TIMEOUT,
                    timestamp=get_timestamp()
                ))
            return results
        
        count = end - start + 1
        
        # Base case: single address
        if count == 1:
            await self._rate_limiter.wait()
            data, status = await self.read_device_raw(device_type, start, 1)
            
            address_key = f"{device_type.value}{start}"
            
            if status == StatusCode.OK and data:
                results.append(DataPoint(
                    address=address_key,
                    value=data[0],
                    raw_hex=value_to_hex(data[0]),
                    status=StatusCode.OK,
                    timestamp=get_timestamp()
                ))
            else:
                # Mark as inaccessible
                self._session_cache.add_denied(address_key)
                results.append(DataPoint(
                    address=address_key,
                    status=status,
                    timestamp=get_timestamp()
                ))
            
            return results
        
        # Try to read the full range first
        await self._rate_limiter.wait()
        data, status = await self.read_device_raw(device_type, start, count)
        
        if status == StatusCode.OK and data:
            # Success - all addresses readable
            for i, value in enumerate(data):
                results.append(DataPoint(
                    address=f"{device_type.value}{start + i}",
                    value=value,
                    raw_hex=value_to_hex(value),
                    status=StatusCode.OK,
                    timestamp=get_timestamp()
                ))
            return results
        
        # Error - split and recurse
        mid = (start + end) // 2
        
        # Wait before retry
        await asyncio.sleep(self.config.retry_interval_ms / 1000)
        
        # Process first half
        first_half = await self._binary_search_read(
            device_type, start, mid, depth + 1
        )
        results.extend(first_half)
        
        # Process second half
        second_half = await self._binary_search_read(
            device_type, mid + 1, end, depth + 1
        )
        results.extend(second_half)
        
        return results
    
    def get_denied_addresses(self) -> set:
        """Get all addresses marked as inaccessible in this session"""
        return self._session_cache.get_all_denied()
    
    def clear_session_cache(self):
        """Clear the session cache of denied addresses"""
        self._session_cache.clear()
    
    def get_retry_statistics(self) -> dict:
        """Get retry handler statistics"""
        return self._retry_handler.statistics
    
    def reset_circuit_breaker(self):
        """Reset circuit breaker to initial state"""
        if self._circuit_breaker:
            self._circuit_breaker.reset()
    
    @property
    def circuit_breaker_state(self) -> Optional[str]:
        """Get current circuit breaker state"""
        if self._circuit_breaker:
            return self._circuit_breaker.state.value
        return None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
        return False

