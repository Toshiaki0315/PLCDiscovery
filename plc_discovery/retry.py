"""
Retry Module - Advanced Retry Strategies

Provides configurable retry mechanisms with:
- Fixed interval retry
- Exponential backoff
- Exponential backoff with jitter
- Circuit breaker pattern
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategy types"""

    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    EXPONENTIAL_JITTER = "exponential_jitter"


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior.

    Attributes:
        strategy: Retry strategy (fixed, exponential, exponential_jitter)
        max_retries: Maximum number of retry attempts
        initial_delay_ms: Initial delay between retries in milliseconds
        max_delay_ms: Maximum delay between retries in milliseconds
        multiplier: Multiplier for exponential backoff
        jitter_factor: Random jitter factor (0.0 - 1.0)
        retryable_exceptions: Exception types that should trigger retry
    """

    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_JITTER
    max_retries: int = 3
    initial_delay_ms: int = 100
    max_delay_ms: int = 5000
    multiplier: float = 2.0
    jitter_factor: float = 0.25
    retryable_exceptions: tuple = field(
        default_factory=lambda: (
            ConnectionError,
            TimeoutError,
            OSError,
        )
    )

    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt number.

        Args:
            attempt: Current attempt number (0-based)

        Returns:
            Delay in seconds
        """
        delay_ms: float
        if self.strategy == RetryStrategy.FIXED:
            delay_ms = self.initial_delay_ms

        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay_ms = self.initial_delay_ms * (self.multiplier**attempt)

        elif self.strategy == RetryStrategy.EXPONENTIAL_JITTER:
            base_delay = self.initial_delay_ms * (self.multiplier**attempt)
            jitter = base_delay * self.jitter_factor * random.random()
            delay_ms = base_delay + jitter

        else:
            delay_ms = self.initial_delay_ms

        # Cap at max delay
        delay_ms = min(delay_ms, self.max_delay_ms)

        return delay_ms / 1000.0  # Convert to seconds

    def should_retry(self, exception: Exception) -> bool:
        """Check if exception should trigger retry"""
        return isinstance(exception, self.retryable_exceptions)


@dataclass
class CircuitBreakerConfig:
    """
    Configuration for circuit breaker.

    Attributes:
        failure_threshold: Number of failures before opening circuit
        success_threshold: Number of successes in half-open to close
        timeout_seconds: Time to wait before trying half-open
    """

    failure_threshold: int = 5
    success_threshold: int = 2
    timeout_seconds: float = 30.0


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.

    Prevents cascading failures by temporarily blocking requests
    when a service is failing.
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None

    @property
    def state(self) -> CircuitState:
        """Get current circuit state"""
        if self._state == CircuitState.OPEN:
            # Check if timeout has passed
            if self._last_failure_time:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.config.timeout_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0

        return self._state

    def is_available(self) -> bool:
        """Check if requests should be allowed"""
        return self.state != CircuitState.OPEN

    def record_success(self):
        """Record a successful request"""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                logger.info("Circuit breaker closed - service recovered")
        else:
            self._failure_count = 0

    def record_failure(self):
        """Record a failed request"""
        self._failure_count += 1
        # Monotonic: a wall-clock step (NTP) must not keep the circuit open longer
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            logger.warning("Circuit breaker opened - half-open test failed")

        elif self._failure_count >= self.config.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(f"Circuit breaker opened after {self._failure_count} failures")

    def reset(self):
        """Reset circuit breaker to initial state"""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None


class RetryError(Exception):
    """Raised when all retry attempts are exhausted"""

    def __init__(self, message: str, last_exception: Optional[Exception] = None):
        super().__init__(message)
        self.last_exception = last_exception


class RetryHandler:
    """
    Handles retry logic with configurable strategies.
    """

    def __init__(self, config: Optional[RetryConfig] = None, circuit_breaker: Optional[CircuitBreaker] = None):
        self.config = config or RetryConfig()
        self.circuit_breaker = circuit_breaker
        self._stats = {
            "total_attempts": 0,
            "successful_attempts": 0,
            "failed_attempts": 0,
            "retries": 0,
        }

    @property
    def statistics(self) -> dict:
        """Get retry statistics"""
        return self._stats.copy()

    async def execute(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Execute function with retry logic.

        Args:
            func: Async function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Result of successful function execution

        Raises:
            RetryError: When all retries are exhausted
        """
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            self._stats["total_attempts"] += 1

            # Check circuit breaker
            if self.circuit_breaker and not self.circuit_breaker.is_available():
                raise RetryError("Circuit breaker is open", last_exception)

            try:
                result = await func(*args, **kwargs)

                self._stats["successful_attempts"] += 1
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                if attempt > 0:
                    logger.debug(f"Succeeded after {attempt} retries")

                return result

            except Exception as e:
                last_exception = e
                self._stats["failed_attempts"] += 1

                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()

                # Check if we should retry
                if not self.config.should_retry(e):
                    logger.warning(f"Non-retryable exception: {type(e).__name__}")
                    raise

                # Check if we have retries left
                if attempt >= self.config.max_retries:
                    logger.warning(f"All {self.config.max_retries} retries exhausted")
                    raise RetryError(f"Failed after {attempt + 1} attempts: {str(e)}", last_exception)

                # Calculate delay
                delay = self.config.calculate_delay(attempt)
                self._stats["retries"] += 1

                logger.debug(f"Attempt {attempt + 1} failed: {e}. " f"Retrying in {delay:.2f}s...")

                await asyncio.sleep(delay)

        # Should not reach here
        raise RetryError("Unexpected retry loop exit", last_exception)

    def execute_sync(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Execute synchronous function with retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Result of successful function execution
        """
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            self._stats["total_attempts"] += 1

            if self.circuit_breaker and not self.circuit_breaker.is_available():
                raise RetryError("Circuit breaker is open", last_exception)

            try:
                result = func(*args, **kwargs)

                self._stats["successful_attempts"] += 1
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                return result

            except Exception as e:
                last_exception = e
                self._stats["failed_attempts"] += 1

                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()

                if not self.config.should_retry(e):
                    raise

                if attempt >= self.config.max_retries:
                    raise RetryError(f"Failed after {attempt + 1} attempts: {str(e)}", last_exception)

                delay = self.config.calculate_delay(attempt)
                self._stats["retries"] += 1

                time.sleep(delay)

        raise RetryError("Unexpected retry loop exit", last_exception)

    def reset_stats(self):
        """Reset statistics"""
        self._stats = {
            "total_attempts": 0,
            "successful_attempts": 0,
            "failed_attempts": 0,
            "retries": 0,
        }


def with_retry(
    config: Optional[RetryConfig] = None, circuit_breaker: Optional[CircuitBreaker] = None
) -> Callable[[Callable], Callable]:
    """
    Decorator for adding retry logic to async functions.

    Usage:
        @with_retry(RetryConfig(max_retries=5))
        async def my_function():
            ...
    """

    def decorator(func: Callable) -> Callable:
        handler = RetryHandler(config, circuit_breaker)

        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await handler.execute(func, *args, **kwargs)

        # Attach handler for stats access
        setattr(wrapper, "retry_handler", handler)
        return wrapper

    return decorator


def with_retry_sync(
    config: Optional[RetryConfig] = None, circuit_breaker: Optional[CircuitBreaker] = None
) -> Callable[[Callable], Callable]:
    """
    Decorator for adding retry logic to sync functions.

    Usage:
        @with_retry_sync(RetryConfig(max_retries=5))
        def my_function():
            ...
    """

    def decorator(func: Callable) -> Callable:
        handler = RetryHandler(config, circuit_breaker)

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return handler.execute_sync(func, *args, **kwargs)

        setattr(wrapper, "retry_handler", handler)
        return wrapper

    return decorator


# Default configurations for common use cases
DEFAULT_RETRY_CONFIG = RetryConfig(
    strategy=RetryStrategy.EXPONENTIAL_JITTER,
    max_retries=3,
    initial_delay_ms=100,
    max_delay_ms=5000,
    multiplier=2.0,
    jitter_factor=0.25,
)

AGGRESSIVE_RETRY_CONFIG = RetryConfig(
    strategy=RetryStrategy.EXPONENTIAL_JITTER,
    max_retries=5,
    initial_delay_ms=50,
    max_delay_ms=10000,
    multiplier=2.0,
    jitter_factor=0.5,
)

CONSERVATIVE_RETRY_CONFIG = RetryConfig(
    strategy=RetryStrategy.FIXED,
    max_retries=2,
    initial_delay_ms=500,
    max_delay_ms=1000,
)

PLC_RETRY_CONFIG = RetryConfig(
    strategy=RetryStrategy.EXPONENTIAL_JITTER,
    max_retries=3,
    initial_delay_ms=100,
    max_delay_ms=3000,
    multiplier=1.5,
    jitter_factor=0.2,
    retryable_exceptions=(
        ConnectionError,
        TimeoutError,
        OSError,
        ConnectionRefusedError,
        ConnectionResetError,
    ),
)
