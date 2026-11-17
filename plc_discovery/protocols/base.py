"""
Base Protocol Handler - Abstract interface for PLC communication
"""

import asyncio
import dataclasses
import logging
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Tuple, TypeVar

from ..config import SAFE_READ_WORDS, DataPoint, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from ..retry import (
    PLC_RETRY_CONFIG,
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig,
    RetryError,
    RetryHandler,
)
from ..utils import RateLimiter, SessionCache, get_timestamp, value_to_hex

logger = logging.getLogger(__name__)


_T = TypeVar("_T")


class BaseProtocolHandler(ABC):
    """
    Abstract base class for PLC protocol handlers.

    All protocol-specific implementations must inherit from this class
    and implement the abstract methods.
    """

    # Class-level protocol identifier
    protocol: Optional[Protocol] = None

    # Binary search limits (log2(4096) = 12)
    MAX_SPLIT_DEPTH = 12

    # Ranges of at least this many addresses that fail with NG_ILLEGAL_ADDR
    # get their two end addresses probed before being split (see
    # _binary_search_read); smaller ranges are simply split
    EDGE_PROBE_MIN_COUNT = 4

    # Highest address the protocol can encode (None = no local limit).
    # Requests beyond it are answered NG_ILLEGAL_ADDR without being sent:
    # libraries either wrap the address silently (wrong data) or raise
    # before sending (misread as a communication failure).
    MAX_ADDRESS: Optional[int] = None

    # Consecutive transport-level failures after which the link is
    # considered down and binary search stops issuing requests
    COMM_FAILURE_ABORT_THRESHOLD = 3

    # Failures reported by the PLC itself (learned in the session cache)
    _PERMANENT_FAILURES = (StatusCode.NG_ILLEGAL_ADDR, StatusCode.NG_UNSUPPORTED)

    # Transport-level failures (never learned as inaccessible)
    _TRANSIENT_FAILURES = (StatusCode.NG_TIMEOUT, StatusCode.NG_COMM_ERROR)

    def __init__(
        self,
        ip_address: str,
        port: Optional[int] = None,
        config: Optional[NetworkConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        use_circuit_breaker: bool = True,
    ):
        self.ip_address = ip_address
        self.port = port
        self.config = config or NetworkConfig()
        self._connected = False
        self._rate_limiter = RateLimiter(self.config.packet_interval_ms)
        self._session_cache = SessionCache()
        self._comm_failure_streak = 0

        # Set when a blocking request timed out while its worker thread may
        # still be using the client; the connection is re-established before
        # the next request so a late response cannot be read as a new one.
        self._needs_reconnect = False

        # Initialize retry handler with exponential backoff.
        # The first retry waits retry_interval_ms (--retry-interval).
        self._retry_config = retry_config or dataclasses.replace(
            PLC_RETRY_CONFIG,
            initial_delay_ms=self.config.retry_interval_ms,
            max_delay_ms=max(PLC_RETRY_CONFIG.max_delay_ms, self.config.retry_interval_ms),
        )
        self._circuit_breaker = None
        if use_circuit_breaker:
            self._circuit_breaker = CircuitBreaker(
                CircuitBreakerConfig(failure_threshold=5, success_threshold=2, timeout_seconds=30.0)
            )
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
        self, device_type: DeviceType, start_address: int, count: int
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
        return SAFE_READ_WORDS.get(self.protocol, 100) if self.protocol else 100

    @property
    def is_connected(self) -> bool:
        """Check if connected to PLC"""
        return self._connected

    async def read_device_range(self, device_range: DeviceRange) -> List[DataPoint]:
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
                # Report with the status that was learned and move to next
                results.append(
                    DataPoint(
                        address=address_key,
                        status=self._session_cache.get_status(address_key) or StatusCode.NG_ILLEGAL_ADDR,
                        timestamp=get_timestamp(),
                    )
                )
                start += 1
                continue

            # End the chunk before the next known-bad address so a cached
            # denial in the middle of a chunk does not fail the whole read
            # (and trigger a new binary search) on every scan
            chunk_size = self._clip_before_denied(device_type, start, chunk_size)

            # Rate limiting
            await self._rate_limiter.wait()

            # Try to read chunk
            data, status = await self._read_with_retry(device_type, start, chunk_size)

            if status == StatusCode.OK and data:
                # Success - add all data points
                results.extend(self._ok_points(device_type, start, data))
            else:
                # Error - use binary search to find bad addresses.
                # The full chunk has just failed, so skip re-reading it.
                chunk_results = await self._binary_search_read(
                    device_type, start, start + chunk_size - 1, known_failure=status
                )
                results.extend(chunk_results)
            start += chunk_size

        return results

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def _clip_before_denied(self, device_type: DeviceType, start: int, chunk_size: int) -> int:
        """Shorten a chunk so it stops before the first cached denied address"""
        if not len(self._session_cache):
            return chunk_size
        for offset in range(1, chunk_size):
            if self._session_cache.is_denied(f"{device_type.value}{start + offset}"):
                return offset
        return chunk_size

    def _ok_points(self, device_type: DeviceType, start: int, data: List[int]) -> List[DataPoint]:
        """Build OK data points for consecutive addresses starting at start"""
        return [
            DataPoint(
                address=f"{device_type.value}{start + i}",
                value=value,
                raw_hex=value_to_hex(value),
                status=StatusCode.OK,
                timestamp=get_timestamp(),
            )
            for i, value in enumerate(data)
        ]

    def _failed_points(
        self, device_type: DeviceType, start: int, end: int, status: StatusCode, learn: bool = True
    ) -> List[DataPoint]:
        """
        Build failed data points for a range.

        Only addresses the PLC itself reported as invalid/unsupported are
        added to the session cache. Timeouts and communication errors are
        transient and must not be learned as "inaccessible".
        """
        learn = learn and status in self._PERMANENT_FAILURES
        results = []
        for addr in range(start, end + 1):
            address_key = f"{device_type.value}{addr}"
            if learn:
                self._session_cache.add_denied(address_key, status)
            results.append(DataPoint(address=address_key, status=status, timestamp=get_timestamp()))
        return results

    async def _tracked_read(
        self, device_type: DeviceType, start_address: int, count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Call read_device_raw, validate the response length and keep track
        of consecutive communication failures (to detect a lost link).
        """
        if start_address < 0 or (self.MAX_ADDRESS is not None and start_address + count - 1 > self.MAX_ADDRESS):
            # Decided locally: nothing sent, the link state is unchanged
            logger.debug(
                f"{device_type.value}{start_address} x{count} exceeds the "
                f"{self.protocol.name if self.protocol else ''} address limit {self.MAX_ADDRESS}"
            )
            return None, StatusCode.NG_ILLEGAL_ADDR

        try:
            data, status = await self.read_device_raw(device_type, start_address, count)
        except Exception as e:
            logger.debug(f"read_device_raw raised: {e}")
            data, status = None, StatusCode.NG_COMM_ERROR

        plc_answered = status not in self._TRANSIENT_FAILURES

        if status == StatusCode.OK:
            if data is None or len(data) < count:
                # A short response cannot be mapped to addresses safely
                logger.debug(
                    f"Short response for {device_type.value}{start_address}: "
                    f"expected {count}, got {0 if data is None else len(data)}"
                )
                data, status = None, StatusCode.NG_COMM_ERROR
            else:
                data = list(data[:count])

        if plc_answered:
            # The PLC answered (successfully, with an address error or with
            # a malformed response), so the link itself is alive
            self._comm_failure_streak = 0
        else:
            self._comm_failure_streak += 1

        return data, status

    @property
    def _link_down(self) -> bool:
        """True when recent requests failed consecutively at the transport level"""
        return self._comm_failure_streak >= self.COMM_FAILURE_ABORT_THRESHOLD

    async def _read_with_retry(
        self, device_type: DeviceType, start_address: int, count: int, max_retries: Optional[int] = None
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
        last_status = [StatusCode.NG_COMM_ERROR]

        async def do_read():
            data, status = await self._tracked_read(device_type, start_address, count)
            last_status[0] = status

            if status == StatusCode.OK:
                return data, status

            # Don't retry on errors reported by the PLC itself
            if status in self._PERMANENT_FAILURES:
                return None, status

            # Raise exception to trigger retry
            raise ConnectionError(f"Read failed with status: {status.value}")

        try:
            result: Tuple[Optional[List[int]], StatusCode] = await self._retry_handler.execute(do_read)
            return result
        except RetryError as e:
            logger.debug(f"All retries exhausted: {e}")
            if last_status[0] in self._TRANSIENT_FAILURES:
                return None, last_status[0]
            return None, StatusCode.NG_COMM_ERROR
        except Exception as e:
            logger.debug(f"Read failed: {e}")
            return None, StatusCode.NG_COMM_ERROR

    async def _binary_search_read(
        self, device_type: DeviceType, start: int, end: int, depth: int = 0, known_failure: Optional[StatusCode] = None
    ) -> List[DataPoint]:
        """
        Binary search algorithm for finding accessible addresses.

        When a read fails, this method recursively splits the range
        to identify exactly which addresses are inaccessible.

        Splitting stops early (and the remaining range is reported with the
        failure status, without being learned as inaccessible) when:
        - the device type is unsupported (the result does not depend on the range)
        - the link appears to be down (consecutive transport-level failures),
          so a dead PLC does not cost 2N-1 timed-out requests per chunk

        Args:
            device_type: Device type to read
            start: Start address
            end: End address
            depth: Current recursion depth
            known_failure: Status of a read of [start, end] that has just
                failed; when given, the range is not read again

        Returns:
            List of DataPoint objects with status
        """
        count = end - start + 1

        if known_failure is not None:
            status = known_failure
        else:
            await self._rate_limiter.wait()
            data, status = await self._tracked_read(device_type, start, count)
            if status == StatusCode.OK and data is not None:
                return self._ok_points(device_type, start, data)

        # Base case: single address
        if count == 1:
            return self._failed_points(device_type, start, end, status)

        # Range-independent failure: splitting cannot help
        if status == StatusCode.NG_UNSUPPORTED:
            return self._failed_points(device_type, start, end, status)

        # Link lost or depth exhausted: report without further requests
        # (not learned: individual addresses were not confirmed)
        if self._link_down or depth >= self.MAX_SPLIT_DEPTH:
            return self._failed_points(device_type, start, end, status, learn=False)

        # Wholly invalid range (device not configured, range past the end of
        # the device): if both end addresses are invalid on their own, report
        # the whole range without splitting it down to single addresses,
        # which cost about 2N requests (R0-R32767: ~65,000 requests, hours of
        # waiting on a production PLC). A readable island strictly inside a
        # range whose both ends are invalid is the accepted trade-off.
        if status == StatusCode.NG_ILLEGAL_ADDR and count >= self.EDGE_PROBE_MIN_COUNT:
            if await self._edges_illegal(device_type, start, end):
                logger.debug(
                    f"{device_type.value}{start}-{device_type.value}{end}: both ends invalid; "
                    f"whole range reported as {StatusCode.NG_ILLEGAL_ADDR.value}"
                )
                return self._failed_points(device_type, start, end, StatusCode.NG_ILLEGAL_ADDR)

        # Error - split and recurse
        mid = (start + end) // 2

        # Wait before retry
        await asyncio.sleep(self.config.retry_interval_ms / 1000)

        results = await self._binary_search_read(device_type, start, mid, depth + 1)
        results.extend(await self._binary_search_read(device_type, mid + 1, end, depth + 1))
        return results

    async def _edges_illegal(self, device_type: DeviceType, start: int, end: int) -> bool:
        """True if the first and the last address both fail with NG_ILLEGAL_ADDR"""
        for address in (start, end):
            await self._rate_limiter.wait()
            _, status = await self._tracked_read(device_type, address, 1)
            if status != StatusCode.NG_ILLEGAL_ADDR:
                return False
        return True

    # ------------------------------------------------------------------
    # Blocking client helpers (for handlers built on synchronous libraries)
    # ------------------------------------------------------------------

    async def _run_blocking(self, func: Callable[[], _T], timeout: Optional[float] = None) -> _T:
        """
        Run a blocking client call in the executor with a timeout.

        On timeout the worker thread keeps running and may still consume the
        late response, so the connection is flagged for re-establishment
        before the next request.

        Raises:
            asyncio.TimeoutError: when the call does not finish in time
        """
        if timeout is None:
            timeout = self.config.request_timeout_ms / 1000
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, func), timeout=timeout)
        except asyncio.TimeoutError:
            self._needs_reconnect = True
            raise

    async def _ensure_fresh_connection(self) -> bool:
        """
        Re-establish the connection if a previous request timed out.

        Returns:
            False if a reconnect was needed and failed
        """
        if not self._needs_reconnect:
            return True
        self._needs_reconnect = False
        logger.info(f"Reconnecting to {self.ip_address}")
        try:
            await self.disconnect()
        except Exception as e:
            logger.debug(f"Disconnect before reconnect failed: {e}")
        try:
            ok = bool(await self.connect())
        except Exception as e:
            logger.debug(f"Reconnect failed: {e}")
            ok = False
        if not ok:
            # Try again on the next request
            self._needs_reconnect = True
        return ok

    def get_denied_addresses(self) -> set:
        """Get all addresses marked as inaccessible in this session"""
        return self._session_cache.get_all_denied()

    def get_denied_statuses(self) -> Dict[str, StatusCode]:
        """Get inaccessible addresses with the status that caused it"""
        return self._session_cache.get_all_statuses()

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
