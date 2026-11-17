"""
Regression tests for the eighth review's finding (Y1): batch discovery must
not be throttled by the small shared default thread pool.
"""

import asyncio
import concurrent.futures
import threading
import time
from unittest.mock import patch

import pytest

from plc_discovery import discovery as discovery_module
from plc_discovery.config import NetworkConfig
from plc_discovery.discovery import MAX_PROBE_THREADS, PLCDiscovery


def slow_closed(ip, port, timeout):
    time.sleep(0.3)
    return False


def slow_silent(ip, port, protocol, timeout):
    time.sleep(0.3)
    return False


@pytest.mark.asyncio
async def test_batch_does_not_queue_on_small_default_pool():
    # Simulate a small PC: the shared default pool has only 2 threads
    asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=2))
    discovery = PLCDiscovery(NetworkConfig())
    hosts = [f"192.0.2.{i}" for i in range(1, 11)]
    with (
        patch.object(discovery_module, "is_port_open", side_effect=slow_closed),
        patch.object(discovery_module, "verify_protocol", side_effect=slow_silent),
    ):
        started = time.monotonic()
        await discovery._probe_hosts(hosts, {})
        elapsed = time.monotonic() - started
    # 10 hosts x 6 checks of 0.3 s: ~0.3 s in parallel, ~9 s on a 2-thread pool
    assert elapsed < 1.5


@pytest.mark.asyncio
async def test_probe_pool_is_released_after_scan():
    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", return_value=False),
        patch.object(discovery_module, "verify_protocol", return_value=False),
    ):
        await discovery._probe_hosts(["192.0.2.1", "192.0.2.2"], {})
    assert discovery._probe_executor is None
    await asyncio.sleep(0.2)
    assert not [t for t in threading.enumerate() if t.name.startswith("plc-probe") and t.is_alive()]


@pytest.mark.asyncio
async def test_single_host_probe_works_without_batch_pool():
    discovery = PLCDiscovery(NetworkConfig())
    with (
        patch.object(discovery_module, "is_port_open", return_value=False),
        patch.object(discovery_module, "verify_protocol", return_value=False),
    ):
        assert await discovery._probe_host("192.0.2.1") is None
    assert discovery._probe_executor is None


def test_pool_size_bound():
    assert MAX_PROBE_THREADS == 64
