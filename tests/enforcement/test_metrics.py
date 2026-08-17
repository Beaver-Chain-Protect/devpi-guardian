from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from devpi_guardian.enforcement import metrics


def test_in_process_block_counter_has_thread_safe_snapshot_api() -> None:
    counter_type = getattr(metrics, "InMemoryBlockMetricRecorder", None)
    assert counter_type is not None
    counter = counter_type()
    dimensions = metrics.BlockMetricDimensions(
        route="+f",
        sha256="a" * 64,
        effective_decision="DENY",
        block_category="not_allowed",
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for _ in range(1_000):
            future = executor.submit(counter.record_block, dimensions)
            futures.append(future)
        for future in futures:
            future.result()

    assert counter.snapshot() == {dimensions: 1_000}
