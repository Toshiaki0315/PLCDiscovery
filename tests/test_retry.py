"""
Unit tests for retry module
"""

import pytest
import time

from plc_discovery.retry import (
    RetryStrategy,
    RetryConfig,
    RetryHandler,
    RetryError,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    with_retry,
    with_retry_sync,
    DEFAULT_RETRY_CONFIG,
    PLC_RETRY_CONFIG,
)


class TestRetryConfig:
    """Test RetryConfig class"""

    def test_default_config(self):
        """Test default configuration"""
        config = RetryConfig()
        assert config.strategy == RetryStrategy.EXPONENTIAL_JITTER
        assert config.max_retries == 3
        assert config.initial_delay_ms == 100
        assert config.max_delay_ms == 5000
        assert config.multiplier == 2.0

    def test_fixed_strategy_delay(self):
        """Test fixed strategy delay calculation"""
        config = RetryConfig(
            strategy=RetryStrategy.FIXED,
            initial_delay_ms=200
        )

        # Delay should be constant for all attempts
        assert config.calculate_delay(0) == 0.2
        assert config.calculate_delay(1) == 0.2
        assert config.calculate_delay(5) == 0.2

    def test_exponential_strategy_delay(self):
        """Test exponential strategy delay calculation"""
        config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=100,
            multiplier=2.0,
            max_delay_ms=10000
        )

        # Delays should double each attempt
        assert config.calculate_delay(0) == 0.1    # 100ms
        assert config.calculate_delay(1) == 0.2    # 200ms
        assert config.calculate_delay(2) == 0.4    # 400ms
        assert config.calculate_delay(3) == 0.8    # 800ms

    def test_max_delay_cap(self):
        """Test that delay is capped at max_delay_ms"""
        config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_delay_ms=1000,
            multiplier=3.0,
            max_delay_ms=2000
        )

        # Should be capped at 2 seconds
        assert config.calculate_delay(0) == 1.0
        assert config.calculate_delay(1) == 2.0  # Capped (3000 -> 2000)
        assert config.calculate_delay(5) == 2.0  # Still capped

    def test_should_retry_matching_exception(self):
        """Test should_retry returns True for matching exceptions"""
        config = RetryConfig(
            retryable_exceptions=(ConnectionError, TimeoutError)
        )

        assert config.should_retry(ConnectionError())
        assert config.should_retry(TimeoutError())

    def test_should_retry_non_matching_exception(self):
        """Test should_retry returns False for non-matching exceptions"""
        config = RetryConfig(
            retryable_exceptions=(ConnectionError,)
        )

        assert not config.should_retry(ValueError())
        assert not config.should_retry(KeyError())


class TestCircuitBreaker:
    """Test CircuitBreaker class"""

    def test_initial_state_closed(self):
        """Test circuit breaker starts in closed state"""
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.is_available()

    def test_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures"""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert not cb.is_available()

    def test_success_resets_failure_count(self):
        """Test success resets failure counter"""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)

        cb.record_failure()
        cb.record_failure()
        cb.record_success()

        # Counter reset, need 3 more failures
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_timeout(self):
        """Test circuit breaker goes half-open after timeout"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            timeout_seconds=0.1
        )
        cb = CircuitBreaker(config)

        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for timeout
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_closes_on_success(self):
        """Test half-open circuit closes after success threshold"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            timeout_seconds=0.1
        )
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure()
        cb.record_failure()

        # Wait and go half-open
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        # Record successes
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        """Test half-open circuit reopens on failure"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            timeout_seconds=0.1
        )
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure()
        cb.record_failure()

        # Wait and go half-open
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        # Failure reopens circuit
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_reset(self):
        """Test reset method"""
        cb = CircuitBreaker()

        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.is_available()


class TestRetryHandler:
    """Test RetryHandler class"""

    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        """Test successful execution on first try"""
        handler = RetryHandler(RetryConfig(max_retries=3))

        async def success_func():
            return "success"

        result = await handler.execute(success_func)
        assert result == "success"
        assert handler.statistics["total_attempts"] == 1
        assert handler.statistics["successful_attempts"] == 1
        assert handler.statistics["retries"] == 0

    @pytest.mark.asyncio
    async def test_success_after_retries(self):
        """Test success after some retries"""
        config = RetryConfig(
            max_retries=3,
            initial_delay_ms=10,  # Fast for testing
            strategy=RetryStrategy.FIXED
        )
        handler = RetryHandler(config)

        call_count = 0

        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Simulated failure")
            return "success"

        result = await handler.execute(flaky_func)
        assert result == "success"
        assert call_count == 3
        assert handler.statistics["retries"] == 2

    @pytest.mark.asyncio
    async def test_exhaust_retries(self):
        """Test RetryError when retries exhausted"""
        config = RetryConfig(
            max_retries=2,
            initial_delay_ms=10,
            strategy=RetryStrategy.FIXED
        )
        handler = RetryHandler(config)

        async def always_fail():
            raise ConnectionError("Always fails")

        with pytest.raises(RetryError) as exc_info:
            await handler.execute(always_fail)

        assert "Failed after 3 attempts" in str(exc_info.value)
        assert handler.statistics["failed_attempts"] == 3

    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        """Test non-retryable exception is not retried"""
        config = RetryConfig(
            max_retries=3,
            retryable_exceptions=(ConnectionError,)
        )
        handler = RetryHandler(config)

        async def raise_value_error():
            raise ValueError("Not retryable")

        with pytest.raises(ValueError):
            await handler.execute(raise_value_error)

        # Should have tried only once
        assert handler.statistics["total_attempts"] == 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_requests(self):
        """Test circuit breaker blocks requests when open"""
        cb_config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker(cb_config)

        config = RetryConfig(max_retries=0)
        handler = RetryHandler(config, cb)

        async def always_fail():
            raise ConnectionError("Fail")

        # Fail twice to open circuit
        for _ in range(2):
            try:
                await handler.execute(always_fail)
            except (RetryError, ConnectionError):
                pass

        # Circuit should be open
        with pytest.raises(RetryError) as exc_info:
            await handler.execute(always_fail)

        assert "Circuit breaker is open" in str(exc_info.value)

    def test_sync_retry_success(self):
        """Test synchronous retry success"""
        config = RetryConfig(
            max_retries=2,
            initial_delay_ms=10,
            strategy=RetryStrategy.FIXED
        )
        handler = RetryHandler(config)

        call_count = 0

        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Fail")
            return "success"

        result = handler.execute_sync(flaky_func)
        assert result == "success"
        assert call_count == 2


class TestDecorators:
    """Test retry decorators"""

    @pytest.mark.asyncio
    async def test_with_retry_decorator(self):
        """Test async retry decorator"""
        call_count = 0

        @with_retry(RetryConfig(max_retries=2, initial_delay_ms=10))
        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Fail")
            return "success"

        result = await flaky_func()
        assert result == "success"
        assert call_count == 2

    def test_with_retry_sync_decorator(self):
        """Test sync retry decorator"""
        call_count = 0

        @with_retry_sync(RetryConfig(max_retries=2, initial_delay_ms=10))
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise TimeoutError("Fail")
            return "success"

        result = flaky_func()
        assert result == "success"
        assert call_count == 2


class TestPredefinedConfigs:
    """Test predefined retry configurations"""

    def test_default_config(self):
        """Test DEFAULT_RETRY_CONFIG"""
        assert DEFAULT_RETRY_CONFIG.strategy == RetryStrategy.EXPONENTIAL_JITTER
        assert DEFAULT_RETRY_CONFIG.max_retries == 3

    def test_plc_config(self):
        """Test PLC_RETRY_CONFIG"""
        assert PLC_RETRY_CONFIG.strategy == RetryStrategy.EXPONENTIAL_JITTER
        assert PLC_RETRY_CONFIG.max_retries == 3
        assert ConnectionError in PLC_RETRY_CONFIG.retryable_exceptions
        assert TimeoutError in PLC_RETRY_CONFIG.retryable_exceptions
