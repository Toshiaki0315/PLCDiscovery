"""
Base Protocol Handler - Abstract interface for PLC communication
"""

import asyncio
import dataclasses
import logging
import time
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Set, Tuple, TypeVar

from ..audit_log import get_audit_logger
from ..config import SAFE_READ_WORDS, DataPoint, DeviceRange, DeviceType, NetworkConfig, Protocol, StatusCode
from ..retry import (
    PLC_RETRY_CONFIG,
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig,
    RetryError,
    RetryHandler,
)
from ..utils import RateLimiter, SessionCache, get_timestamp, value_to_hex, wait_for

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

    # Whether a failed range whose two end addresses are invalid may be
    # reported as wholly invalid without reading the addresses in between.
    # Only safe where a device's addresses are one contiguous block (PLC
    # device memory). Handlers of protocols with sparse address maps
    # (Modbus register maps) turn it off: valid registers between two
    # invalid ones would be reported - and learned - as inaccessible.
    EDGE_PROBE_SHORTCUT = True

    # Highest address the protocol can encode (None = no local limit).
    # Requests beyond it are answered NG_ILLEGAL_ADDR without being sent:
    # libraries either wrap the address silently (wrong data) or raise
    # before sending (misread as a communication failure).
    MAX_ADDRESS: Optional[int] = None

    # Consecutive transport-level failures after which the link is
    # considered down and binary search stops issuing requests
    COMM_FAILURE_ABORT_THRESHOLD = 3

    # Unanswered requests (each costs a full request timeout) that one
    # read_device_range() call may spend on narrowing down ranges the PLC
    # does not answer: enough to isolate one or two addresses in a chunk.
    # With the default 5 s timeout the search adds at most about 80 s per
    # call. Beyond it, a chunk that is not answered costs one request: it is
    # not retried once a chunk of the same call went unanswered, and it is
    # not split like an address error.
    UNANSWERED_SEARCH_BUDGET = 16

    # The same for the whole session (all scans of a periodic run): enough
    # to learn a handful of unanswered addresses. A device with a wide
    # unanswered range would otherwise cost the per-call budget in every
    # cycle for good; once this is spent, such chunks are read with a
    # single request per scan and reported with their status.
    UNANSWERED_SESSION_BUDGET = 96

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
        # An address the PLC last answered a read of (successfully): read
        # again to tell "the link is down" from "the PLC does not answer
        # requests for this range" (see _search_unanswered)
        self._last_ok: Optional[Tuple[DeviceType, int]] = None
        self._unanswered_budget = self.UNANSWERED_SEARCH_BUDGET
        # Unanswered requests left for such searches in this session
        self._unanswered_session_budget = self.UNANSWERED_SESSION_BUDGET
        # Chunks (device, start, size) that went unanswered while the link
        # was up: read with one request, without retries, from then on
        self._unanswered_chunks: Set[Tuple[DeviceType, int, int]] = set()
        # A liveness probe went unanswered during the current chunk
        self._probe_failed = False
        # Points read so far by a read_device_range() call in progress
        self.partial_points: List[DataPoint] = []
        # True when the last _tracked_read() was answered here, without a request
        self._last_read_local = False
        # Requests sent and the PLC's response times (answered requests only,
        # in ms): how long a DeviceGateway collection cycle of the same reads
        # would take at least
        self.request_count = 0
        self.answered_count = 0
        self.response_ms_total = 0.0
        self.response_ms_max = 0.0

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
    def protocol_label(self) -> str:
        """The protocol name in the audit log (see config.protocol_label)"""
        return self.protocol.name if self.protocol else "UNKNOWN"

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
        results: List[DataPoint] = []
        # What has been read so far, for a caller that is interrupted
        # (Ctrl+C) in the middle of a long range
        self.partial_points = results
        start = device_range.start_address
        end = device_range.end_address
        device_type = device_range.device_type
        # Unanswered requests this call may spend on narrowing down ranges
        # the PLC does not answer. Without a known-good address the link
        # cannot be told from the range: look for one with half the budget.
        self._unanswered_budget = min(
            self.UNANSWERED_SEARCH_BUDGET if self._last_ok is not None else self.UNANSWERED_SEARCH_BUDGET // 2,
            self._unanswered_session_budget,
        )
        # Nothing was ever read and an earlier range went unanswered: the
        # link cannot be told from that range (a device that drops requests
        # for invalid addresses looks just like a dead one). This range may
        # be one the PLC answers, so its first chunk is asked once, whatever
        # the circuit breaker says. An unanswered one is counted against the
        # session budget, which bounds what a PLC that is really off costs.
        probe = self._last_ok is None and self._comm_failure_streak > 0 and self._unanswered_session_budget > 0
        # Set once a chunk of this call went unanswered: the chunks after it
        # are asked once, without retries. They most likely go unanswered
        # for the same reason, and four timeouts each (a wide range the
        # device drops requests for) made one scan wait for minutes.
        ask_once = False

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
                        cached=True,
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

            if ask_once and self._link_down:
                # A chunk of this call went unanswered and the link could
                # not be shown to be alive: nothing more is sent
                results.extend(self._unsent_points(device_type, start, end, StatusCode.NG_COMM_ERROR))
                break

            # Try to read chunk
            probing, probe = probe, False
            if probing:
                self._comm_failure_streak = 0
            link_was_up = self._comm_failure_streak == 0
            chunk_key = (device_type, start, chunk_size)
            if probing:
                data, status = await self._tracked_read(device_type, start, chunk_size)
                if self._comm_failure_streak:
                    # Not answered either: still nothing to tell the link
                    # from the range. The rest is reported without requests.
                    self._spend_unanswered()
                    self._comm_failure_streak = max(self._comm_failure_streak, self.COMM_FAILURE_ABORT_THRESHOLD)
                    results.extend(self._failed_points(device_type, start, start + chunk_size - 1, status, learn=False))
                    results.extend(self._unsent_points(device_type, start + chunk_size, end, status))
                    break
                # The PLC is there (data or an error answer): the failures
                # of the other range must not block the reads of this one
                self.reset_circuit_breaker()
            elif ask_once or chunk_key in self._unanswered_chunks:
                # Went unanswered before: one request, no retries. A periodic
                # scan must not wait several timeouts for it in every cycle.
                data, status = await self._tracked_read(device_type, start, chunk_size)
            else:
                data, status = await self._read_with_retry(device_type, start, chunk_size)

            if status == StatusCode.OK and data:
                # Success - add all data points
                self._unanswered_chunks.discard(chunk_key)
                results.extend(self._ok_points(device_type, start, data))
            else:
                unanswered = status in self._TRANSIENT_FAILURES and link_was_up and self._comm_failure_streak > 0
                self._probe_failed = False
                if unanswered:
                    self._unanswered_chunks.add(chunk_key)
                    ask_once = True
                if unanswered and chunk_size > 1 and self._unanswered_budget > 0:
                    # No answer although the PLC answered the request before
                    # this chunk: either the link just went down, or the
                    # device drops requests for some address in the chunk
                    # without answering (common on Modbus gateways). Find
                    # out which, within the budget.
                    results.extend(await self._search_unanswered(device_type, start, start + chunk_size - 1, status))
                elif status in self._TRANSIENT_FAILURES and self._comm_failure_streak > 0:
                    # Not answered, and nothing left to search it with (the
                    # budget is spent, or the link already looked down):
                    # reported as it is, not learned, without another
                    # request. Splitting it like an address error cost five
                    # to eight more timeouts per chunk, in every cycle.
                    results.extend(self._failed_points(device_type, start, start + chunk_size - 1, status, learn=False))
                else:
                    # Error - use binary search to find bad addresses.
                    # The full chunk has just failed, so skip re-reading it.
                    chunk_results = await self._binary_search_read(
                        device_type, start, start + chunk_size - 1, known_failure=status
                    )
                    results.extend(chunk_results)
                if unanswered and not self._probe_failed and self._comm_failure_streak:
                    # The chunk ended on unanswered requests. If the PLC
                    # still answers a known-good address, the link is fine:
                    # the following chunks are read (and searched) normally
                    # instead of being taken for a dead link.
                    await self._link_alive()
                if self._probe_failed and start + chunk_size <= end:
                    # The address the PLC answered last is not answered any
                    # more: the link is down. The rest of the range is
                    # reported without sending another request per chunk.
                    results.extend(self._unsent_points(device_type, start + chunk_size, end, status))
                    break
            start += chunk_size

        self.partial_points = []
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
        self,
        device_type: DeviceType,
        start: int,
        end: int,
        status: StatusCode,
        learn: bool = True,
        learn_unanswered: bool = False,
    ) -> List[DataPoint]:
        """
        Build failed data points for a range.

        Only addresses the PLC itself reported as invalid/unsupported are
        added to the session cache. Timeouts and communication errors are
        transient and must not be learned as "inaccessible" - except
        (``learn_unanswered``) a single address confirmed to be the one the
        PLC does not answer, see _search_unanswered.
        """
        learn = (learn and status in self._PERMANENT_FAILURES) or learn_unanswered
        # Beyond the protocol's address limit: decided here, no request was
        # sent. Such a point is not an answer of the PLC (DataPoint.cached).
        not_requested = self._last_read_local and status == StatusCode.NG_ILLEGAL_ADDR
        results = []
        for addr in range(start, end + 1):
            address_key = f"{device_type.value}{addr}"
            if learn:
                self._session_cache.add_denied(address_key, status)
            results.append(
                DataPoint(address=address_key, status=status, timestamp=get_timestamp(), cached=not_requested)
            )
        return results

    def _unsent_points(self, device_type: DeviceType, start: int, end: int, status: StatusCode) -> List[DataPoint]:
        """
        Points for a range no request is sent for (the link is down): the
        failure status, not learned; an address learned earlier keeps its
        learned status, as in every other scan.
        """
        results = []
        for addr in range(start, end + 1):
            address_key = f"{device_type.value}{addr}"
            learned = (
                self._session_cache.get_status(address_key) if self._session_cache.is_denied(address_key) else None
            )
            results.append(
                DataPoint(
                    address=address_key,
                    status=learned or status,
                    timestamp=get_timestamp(),
                    cached=learned is not None,
                )
            )
        return results

    async def _tracked_read(
        self, device_type: DeviceType, start_address: int, count: int
    ) -> Tuple[Optional[List[int]], StatusCode]:
        """
        Call read_device_raw, validate the response length and keep track
        of consecutive communication failures (to detect a lost link).
        """
        self._last_read_local = False
        if start_address < 0 or (self.MAX_ADDRESS is not None and start_address + count - 1 > self.MAX_ADDRESS):
            # Decided locally: nothing sent, the link state is unchanged
            self._last_read_local = True
            logger.debug(
                f"{device_type.value}{start_address} x{count} exceeds the "
                f"{self.protocol.name if self.protocol else ''} address limit {self.MAX_ADDRESS}"
            )
            return None, StatusCode.NG_ILLEGAL_ADDR

        started = time.monotonic()
        try:
            data, status = await self.read_device_raw(device_type, start_address, count)
        except Exception as e:
            logger.debug(f"read_device_raw raised: {e}")
            data, status = None, StatusCode.NG_COMM_ERROR
        self._audit_read(device_type.value, start_address, count, status, started)

        plc_answered = status not in self._TRANSIENT_FAILURES
        # NG_UNSUPPORTED is mostly decided by the handler without a request
        # (a device type the protocol does not have): not counted, so the
        # PLC's response times are not lowered by answers it never gave
        if status != StatusCode.NG_UNSUPPORTED:
            self.request_count += 1
        if plc_answered and status != StatusCode.NG_UNSUPPORTED:
            elapsed_ms = (time.monotonic() - started) * 1000
            self.answered_count += 1
            self.response_ms_total += elapsed_ms
            self.response_ms_max = max(self.response_ms_max, elapsed_ms)

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
                self._last_ok = (device_type, start_address)

        if plc_answered:
            # The PLC answered (successfully, with an address error or with
            # a malformed response), so the link itself is alive
            self._comm_failure_streak = 0
        else:
            self._comm_failure_streak += 1

        return data, status

    def _audit_read(self, device: str, start_address: int, count: int, status: StatusCode, started: float) -> None:
        """Record one read request and its outcome in the audit log (when one is open)"""
        audit = get_audit_logger()
        if not audit.active:
            return
        audit.log_read(
            self.ip_address,
            self.protocol_label,
            device,
            start_address,
            count,
            status.value,
            round((time.monotonic() - started) * 1000, 1),
        )

    def _audit_tag_read(self, tags: List[str], status: StatusCode, started: float) -> None:
        """Record one tag read request and its outcome in the audit log"""
        audit = get_audit_logger()
        if not audit.active:
            return
        audit.log_tag_read(
            self.ip_address,
            self.protocol_label,
            tags,
            status.value,
            round((time.monotonic() - started) * 1000, 1),
        )

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
        attempts = [0]

        async def do_read():
            attempts[0] += 1
            if attempts[0] > 1:
                # A retry is a request like any other: the retry delay may be
                # shorter than the packet interval (or 0)
                await self._rate_limiter.wait()
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
        elif self._link_down:
            # The link was lost while another part of the range was being
            # split: nothing more is sent for the parts still waiting
            return self._failed_points(device_type, start, end, StatusCode.NG_COMM_ERROR, learn=False)
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
        if self.EDGE_PROBE_SHORTCUT and status == StatusCode.NG_ILLEGAL_ADDR and count >= self.EDGE_PROBE_MIN_COUNT:
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

    def _spend_unanswered(self) -> None:
        """Count one unanswered request of a search against the budgets"""
        self._unanswered_budget -= 1
        self._unanswered_session_budget -= 1
        if self._unanswered_session_budget == 0:
            logger.warning(
                f"{self.ip_address}: some address ranges are not answered and could not be narrowed down "
                f"within {self.UNANSWERED_SESSION_BUDGET} requests; they are reported as read (NG_TIMEOUT / "
                "NG_COMM_ERROR) and no longer searched in this session"
            )

    async def _link_alive(self) -> Optional[bool]:
        """
        Whether the PLC answers a read of the address it last answered.

        One request. None when nothing has been read successfully yet: the
        link cannot be told apart from the range then.
        """
        if self._last_ok is None:
            return None
        device_type, address = self._last_ok
        await self._rate_limiter.wait()
        _, status = await self._tracked_read(device_type, address, 1)
        if status in self._TRANSIENT_FAILURES:
            self._spend_unanswered()
            self._probe_failed = True
            return False
        # The PLC is there: failures counted against the link while a range
        # went unanswered must not block the next reads
        self.reset_circuit_breaker()
        return True

    async def _search_unanswered(
        self, device_type: DeviceType, start: int, end: int, status: StatusCode
    ) -> List[DataPoint]:
        """
        Narrow down a range the PLC did not answer (timeout / communication
        error) while the link itself seemed fine.

        Some devices drop a request touching an invalid address instead of
        answering with an error. Reporting the whole chunk as NG_TIMEOUT
        would then hide every readable address in it. The range is halved;
        a half that is not answered either is searched further only while
        the PLC proves to be alive (it answers a read of a known-good
        address), so a link that really went down costs a few requests,
        not 2N timeouts.

        Every unanswered request costs a full timeout, so the search stops
        after UNANSWERED_SEARCH_BUDGET of them per read_device_range() call;
        what is left is reported with its status and not learned (the next
        cycle continues where the learned addresses end). Before anything
        was ever read there is no known-good address: the halves are then
        searched for one within the (halved) budget.

        A single address that stays unanswered - checked twice, with the
        PLC alive before and after - is learned for the session with its
        status, like an address error, so periodic scans do not wait for
        its timeout in every cycle.
        """
        count = end - start + 1
        if self._unanswered_budget <= 0:
            return self._failed_points(device_type, start, end, status, learn=False)

        if count == 1:
            if not await self._link_alive():  # down, or never confirmed
                return self._failed_points(device_type, start, end, status, learn=False)
            await self._rate_limiter.wait()
            data, retry_status = await self._tracked_read(device_type, start, 1)
            if retry_status == StatusCode.OK and data is not None:
                return self._ok_points(device_type, start, data)
            if retry_status in self._PERMANENT_FAILURES:
                return self._failed_points(device_type, start, end, retry_status)
            self._spend_unanswered()
            confirmed = await self._link_alive() is True
            return self._failed_points(device_type, start, end, retry_status, learn=False, learn_unanswered=confirmed)

        mid = (start + end) // 2
        halves = [(start, mid), (mid + 1, end)]
        await asyncio.sleep(self.config.retry_interval_ms / 1000)

        # Read both halves before judging the link: the first chunk of a scan
        # has no known-good address until one of its halves is answered
        outcomes = []
        for half_start, half_end in halves:
            await self._rate_limiter.wait()
            data, half_status = await self._tracked_read(device_type, half_start, half_end - half_start + 1)
            # Answered with an error or a malformed response: the PLC is there
            answered = self._comm_failure_streak == 0
            if not answered:
                self._spend_unanswered()
            outcomes.append((data, half_status, answered))

        # A half the PLC answered with an error is split first: searching
        # the unanswered half may end with the link taken to be down, and
        # the answered half would then be reported wholly invalid unsplit
        parts: Dict[int, List[DataPoint]] = {}
        for index in sorted(range(len(halves)), key=lambda i: not outcomes[i][2]):
            (half_start, half_end), (data, half_status, answered) = halves[index], outcomes[index]
            if half_status == StatusCode.OK and data is not None:
                parts[index] = self._ok_points(device_type, half_start, data)
            elif answered:
                self._comm_failure_streak = 0  # it answered: the other half's silence is not a dead link
                parts[index] = await self._binary_search_read(
                    device_type, half_start, half_end, known_failure=half_status
                )
            elif self._probe_failed or await self._link_alive() is False:
                # The link is down (found now, or while the other half was
                # searched): not learned, nothing more is sent
                parts[index] = self._failed_points(device_type, half_start, half_end, half_status, learn=False)
            else:
                # Alive, or not known yet (nothing read so far): keep
                # looking, within the budget
                parts[index] = await self._search_unanswered(device_type, half_start, half_end, half_status)
        return [point for index in sorted(parts) for point in parts[index]]

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
            return await wait_for(loop.run_in_executor(None, func), timeout=timeout)
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

    def mark_needs_reconnect(self) -> None:
        """Re-establish the connection before the next request"""
        self._needs_reconnect = True

    async def reconnect(self) -> bool:
        """
        Reconnect after the link was lost (PLC power-cycled, cable pulled).

        On success the failures from the outage are forgotten, so the circuit
        breaker and lost-link detection do not block the first reads.

        Returns:
            False if the PLC still cannot be reached
        """
        self._needs_reconnect = True
        if not await self._ensure_fresh_connection():
            return False
        self._comm_failure_streak = 0
        self.reset_circuit_breaker()
        return True

    @property
    def uses_address_ranges(self) -> bool:
        """
        True when a full scan reads the protocol's default numeric ranges.

        Handlers of symbolic-tag devices override this; an unreachable full
        scan of such a device is reported as a single "ALL" row.
        """
        return True

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
