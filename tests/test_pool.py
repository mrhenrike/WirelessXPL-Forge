"""Tests for wirelessxpl.core.pool - SmartPool, PoolStrategy."""

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wirelessxpl.core.pool import PoolStrategy, SmartPool, cpu_count

# ---------------------------------------------------------------------------
# cpu_count
# ---------------------------------------------------------------------------

def test_cpu_count_positive() -> None:
    assert cpu_count() >= 1


# ---------------------------------------------------------------------------
# PoolStrategy
# ---------------------------------------------------------------------------

def test_pool_strategy_values() -> None:
    assert PoolStrategy.THREADS.value == "threads"
    assert PoolStrategy.PROCESSES.value == "processes"
    assert PoolStrategy.AUTO.value == "auto"


# ---------------------------------------------------------------------------
# SmartPool creation
# ---------------------------------------------------------------------------

def test_smartpool_default_strategy_threads() -> None:
    pool = SmartPool()
    assert pool.strategy == "threads"
    assert pool.max_workers > 0
    pool.shutdown()


def test_smartpool_explicit_workers() -> None:
    pool = SmartPool(max_workers=4)
    assert pool.max_workers == 4
    pool.shutdown()


def test_smartpool_processes_strategy() -> None:
    pool = SmartPool(strategy=PoolStrategy.PROCESSES)
    assert pool.strategy == "processes"
    pool.shutdown()


def test_smartpool_threads_strategy() -> None:
    pool = SmartPool(strategy=PoolStrategy.THREADS)
    assert pool.strategy == "threads"
    pool.shutdown()


# ---------------------------------------------------------------------------
# SmartPool.submit
# ---------------------------------------------------------------------------

def test_smartpool_submit_returns_future() -> None:
    with SmartPool(max_workers=2) as pool:
        future = pool.submit(lambda x: x * 2, 21)
        assert future.result(timeout=5) == 42


def test_smartpool_submit_multiple() -> None:
    with SmartPool(max_workers=4) as pool:
        futures = [pool.submit(lambda x: x ** 2, i) for i in range(10)]
        results = [f.result(timeout=5) for f in futures]
        assert results == [i ** 2 for i in range(10)]


# ---------------------------------------------------------------------------
# SmartPool.map_unordered
# ---------------------------------------------------------------------------

def test_smartpool_map_unordered_basic() -> None:
    with SmartPool(max_workers=2) as pool:
        results = pool.map_unordered(lambda x: x + 1, [1, 2, 3])
        result_dict = dict(results)
        assert result_dict == {1: 2, 2: 3, 3: 4}


def test_smartpool_map_unordered_with_callback() -> None:
    collected = []

    def on_result(item, result):
        collected.append((item, result))

    with SmartPool(max_workers=2) as pool:
        pool.map_unordered(lambda x: x * 10, [1, 2], on_result=on_result)

    assert len(collected) == 2
    assert set(r for _, r in collected) == {10, 20}


def test_smartpool_map_unordered_with_error_callback() -> None:
    errors = []

    def failing_fn(x):
        if x == 2:
            raise ValueError("boom")
        return x

    def on_error(item, exc):
        errors.append((item, str(exc)))

    with SmartPool(max_workers=2) as pool:
        results = pool.map_unordered(failing_fn, [1, 2, 3], on_error=on_error)

    result_items = {item for item, _ in results}
    assert 1 in result_items
    assert 3 in result_items
    assert len(errors) == 1
    assert errors[0][0] == 2


# ---------------------------------------------------------------------------
# SmartPool.run_threaded_workers
# ---------------------------------------------------------------------------

def test_smartpool_run_threaded_workers() -> None:
    results = []
    stop = threading.Event()
    stop.set()

    def worker(stop_event):
        results.append(threading.current_thread().name)

    pool = SmartPool(max_workers=4, thread_name_prefix="test-pool")
    elapsed = pool.run_threaded_workers(3, worker, stop)
    assert elapsed >= 0
    assert len(results) == 3
    pool.shutdown()


# ---------------------------------------------------------------------------
# SmartPool context manager
# ---------------------------------------------------------------------------

def test_smartpool_context_manager() -> None:
    with SmartPool(max_workers=2) as pool:
        result = pool.submit(lambda: 42).result(timeout=5)
        assert result == 42


# ---------------------------------------------------------------------------
# SmartPool repr
# ---------------------------------------------------------------------------

def test_smartpool_repr() -> None:
    pool = SmartPool(max_workers=8, strategy=PoolStrategy.THREADS)
    r = repr(pool)
    assert "SmartPool" in r
    assert "threads" in r
    assert "8" in r
    pool.shutdown()


# ---------------------------------------------------------------------------
# SmartPool shutdown idempotent
# ---------------------------------------------------------------------------

def test_smartpool_double_shutdown() -> None:
    pool = SmartPool(max_workers=2)
    pool.submit(lambda: 1).result(timeout=5)
    pool.shutdown()
    pool.shutdown()
