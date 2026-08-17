from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from devpi_guardian.enforcement import metrics


def _dimensions(number: int) -> metrics.BlockMetricDimensions:
    return metrics.BlockMetricDimensions(
        route="+f",
        sha256=f"{number:064x}",
        effective_decision="DENY",
        block_category="not_allowed",
    )


def _overflow() -> metrics.BlockMetricDimensions:
    return metrics.BlockMetricDimensions(
        route="unknown",
        sha256="unknown",
        effective_decision="unknown",
        block_category="cardinality_overflow",
    )


@pytest.mark.parametrize(
    "max_series",
    [0, -1, True, False, 1.0, "1", None, object()],
)
def test_counter_rejects_invalid_cap_before_initializing_state(
    max_series: object,
) -> None:
    recorder_type = metrics.InMemoryBlockMetricRecorder
    counter = recorder_type.__new__(recorder_type)

    with pytest.raises(ValueError, match="positive integer"):
        counter.__init__(max_series=max_series)

    assert not hasattr(counter, "_counts")
    assert not hasattr(counter, "_lock")
    assert not hasattr(counter, "_max_series")


def test_default_cap_keeps_4096_series_and_one_fixed_overflow() -> None:
    counter = metrics.InMemoryBlockMetricRecorder()

    for number in range(4_097):
        counter.record_block(_dimensions(number))

    snapshot = counter.snapshot()
    assert len(snapshot) == 4_097
    assert snapshot[_overflow()] == 1
    assert sum(snapshot.values()) == 4_097


def test_sequential_unique_cardinality_is_bounded_with_exact_total() -> None:
    max_series = 128
    counter = metrics.InMemoryBlockMetricRecorder(max_series=max_series)

    for number in range(100_000):
        counter.record_block(_dimensions(number))

    snapshot = counter.snapshot()
    assert len(snapshot) == max_series + 1
    for number in range(max_series):
        assert snapshot[_dimensions(number)] == 1
    assert snapshot[_overflow()] == 100_000 - max_series
    assert sum(snapshot.values()) == 100_000


def test_existing_keys_keep_incrementing_after_cap_under_concurrency() -> None:
    counter = metrics.InMemoryBlockMetricRecorder(max_series=2)
    existing = _dimensions(0)
    retained = _dimensions(1)
    counter.record_block(existing)
    counter.record_block(retained)
    repeat_count = 20_000
    unique_count = 20_000

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = []
        for _ in range(repeat_count):
            futures.append(executor.submit(counter.record_block, existing))
        for number in range(2, unique_count + 2):
            dimensions = _dimensions(number)
            futures.append(executor.submit(counter.record_block, dimensions))
        for future in futures:
            future.result()

    snapshot = counter.snapshot()
    assert snapshot == {
        existing: repeat_count + 1,
        retained: 1,
        _overflow(): unique_count,
    }
    assert sum(snapshot.values()) == repeat_count + unique_count + 2


def test_snapshot_is_an_isolated_copy() -> None:
    counter = metrics.InMemoryBlockMetricRecorder(max_series=1)
    dimensions = _dimensions(0)
    counter.record_block(dimensions)

    snapshot = counter.snapshot()
    snapshot.clear()
    snapshot[_overflow()] = 999

    assert counter.snapshot() == {dimensions: 1}


@pytest.mark.parametrize(
    "dimensions",
    [
        object(),
        metrics.BlockMetricDimensions(
            route="https://user:secret@example.invalid/+f",
            sha256="a" * 64,
            effective_decision="DENY",
            block_category="not_allowed",
        ),
        metrics.BlockMetricDimensions(
            route="+f",
            sha256="https://example.invalid/?token=secret",
            effective_decision="DENY",
            block_category="not_allowed",
        ),
        metrics.BlockMetricDimensions(
            route="+f",
            sha256="a" * 64,
            effective_decision="secret-decision",
            block_category="not_allowed",
        ),
        metrics.BlockMetricDimensions(
            route="+f",
            sha256="a" * 64,
            effective_decision="DENY",
            block_category="https://example.invalid/?token=secret",
        ),
    ],
)
def test_hostile_dimensions_are_rejected_without_counter_mutation(
    dimensions: object,
) -> None:
    counter = metrics.InMemoryBlockMetricRecorder(max_series=1)

    with pytest.raises(ValueError, match="valid block metric dimensions"):
        counter.record_block(dimensions)

    assert counter.snapshot() == {}
