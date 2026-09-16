"""Unit tests verifying sliding-window concept drift detection logic."""

from __future__ import annotations

import pytest
from dashield.domain.types import Verdict
from dashield.drift.detector import DriftDetector


def test_nominal_traffic_no_drift() -> None:
    """Verify clean operational window produces zero ambiguity and no drift alarms."""
    detector = DriftDetector(window_size=50, threshold=0.05, min_samples=20)

    for _ in range(30):
        detector.record_verdict(Verdict.BENIGN)
    for _ in range(20):
        detector.record_verdict(Verdict.ATTACK)

    status = detector.get_status()
    assert not status.is_drift_detected
    assert status.ambiguity_ratio == 0.0
    assert status.total_samples == 50
    assert status.ambiguous_samples == 0


def test_warmup_guard_prevents_premature_alarm() -> None:
    """Verify that ambiguity spikes before min_samples do not trigger false alarms."""
    detector = DriftDetector(window_size=100, threshold=0.05, min_samples=20)

    # Inject 2 ambiguous verdicts out of 5 total observations (40% ratio)
    for _ in range(3):
        detector.record_verdict(Verdict.BENIGN)
    detector.record_verdict(Verdict.AMBIGUOUS)
    status = detector.record_verdict(Verdict.AMBIGUOUS)

    assert status.ambiguity_ratio == 0.40
    assert not status.is_drift_detected  # Suppressed by min_samples guard (5 < 20)


def test_concept_drift_alarm_trigger() -> None:
    """Verify that exceeding 5% threshold past warm-up flags concept drift."""
    detector = DriftDetector(window_size=100, threshold=0.05, min_samples=20)

    # 90 benign samples
    for _ in range(90):
        detector.record_verdict(Verdict.BENIGN)

    # 10 ambiguous samples -> 10% ratio > 5% threshold
    for _ in range(10):
        detector.record_verdict(Verdict.AMBIGUOUS)

    status = detector.get_status()
    assert status.is_drift_detected
    assert pytest.approx(status.ambiguity_ratio, 0.001) == 0.10
    assert status.ambiguous_samples == 10


def test_fifo_sliding_window_recovery() -> None:
    """Verify that old ambiguous samples fall out of the window as new traffic arrives."""
    detector = DriftDetector(window_size=30, threshold=0.10, min_samples=20)

    # Inject 10 benign, then 10 ambiguous (50% ratio in 20 samples -> drift active)
    for _ in range(10):
        detector.record_verdict(Verdict.BENIGN)
    for _ in range(10):
        detector.record_verdict(Verdict.AMBIGUOUS)

    assert detector.is_drift_detected()

    # Flush the window by feeding 30 consecutive nominal packets
    for _ in range(30):
        detector.record_verdict(Verdict.BENIGN)

    status = detector.get_status()
    assert not status.is_drift_detected
    assert status.ambiguity_ratio == 0.0
    assert status.ambiguous_samples == 0


def test_detector_reset() -> None:
    """Verify manual reset clears window history."""
    detector = DriftDetector(window_size=50, threshold=0.05, min_samples=10)
    for _ in range(15):
        detector.record_verdict(Verdict.AMBIGUOUS)

    assert detector.is_drift_detected()
    detector.reset()

    status = detector.get_status()
    assert not status.is_drift_detected
    assert status.total_samples == 0
    assert status.ambiguity_ratio == 0.0


def test_invalid_parameters_raise_value_error() -> None:
    """Verify defensive constructor parameter validations."""
    with pytest.raises(ValueError, match="window_size must be strictly positive"):
        DriftDetector(window_size=0)

    with pytest.raises(ValueError, match="threshold must reside in the open interval"):
        DriftDetector(threshold=1.5)

    with pytest.raises(ValueError, match="min_samples cannot exceed window_size"):
        DriftDetector(window_size=50, min_samples=100)
