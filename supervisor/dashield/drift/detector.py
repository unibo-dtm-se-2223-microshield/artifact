"""Concept drift detection engine based on sliding-window ambiguity monitoring.

Monitors classification telemetry emitted by edge nodes, tracking the ratio of
VERDICT_AMBIGUOUS outcomes to detect boundary erosion and trigger retraining.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque
from dashield.domain.types import Verdict

DEFAULT_WINDOW_SIZE = 100
DEFAULT_DRIFT_THRESHOLD = 0.05  # 5% ambiguity ceiling
DEFAULT_MIN_SAMPLES = 20        # Minimum observations before asserting drift


@dataclass(frozen=True)
class DriftStatus:
    """Immutable snapshot of the current concept drift detector state."""

    is_drift_detected: bool
    ambiguity_ratio: float
    total_samples: int
    ambiguous_samples: int
    threshold: float


class DriftDetector:
    """Sliding-window monitor evaluating edge model reliability and concept drift."""

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        threshold: float = DEFAULT_DRIFT_THRESHOLD,
        min_samples: int = DEFAULT_MIN_SAMPLES,
    ) -> None:
        """Initialize the drift detector with bounded FIFO memory.

        Args:
            window_size: Maximum capacity of the rolling observation window.
            threshold: Ambiguity ratio ceiling above which drift is flagged.
            min_samples: Warm-up observation threshold before triggering alarms.

        Raises:
            ValueError: If parameters violate numerical boundary conditions.
        """
        if window_size <= 0:
            raise ValueError("window_size must be strictly positive.")
        if not (0.0 < threshold < 1.0):
            raise ValueError("threshold must reside in the open interval (0.0, 1.0).")
        if min_samples > window_size:
            raise ValueError("min_samples cannot exceed window_size.")

        self.window_size = window_size
        self.threshold = threshold
        self.min_samples = min_samples
        self._window: Deque[Verdict] = deque(maxlen=window_size)

    def record_verdict(self, verdict: Verdict) -> DriftStatus:
        """Push a newly observed classification verdict into the rolling window.

        Args:
            verdict: The classification verdict emitted by the edge microcontroller.

        Returns:
            Updated DriftStatus snapshot after ingestion.
        """
        self._window.append(verdict)
        return self.get_status()

    def get_ambiguity_ratio(self) -> float:
        """Compute the instantaneous fraction of ambiguous outcomes in the active window.

        Returns:
            Float value in [0.0, 1.0]. Returns 0.0 if window is empty.
        """
        if not self._window:
            return 0.0
        ambiguous_count = sum(1 for v in self._window if v == Verdict.AMBIGUOUS)
        return float(ambiguous_count) / float(len(self._window))

    def is_drift_detected(self) -> bool:
        """Determine whether the rolling ambiguity ratio exceeds the safety threshold.

        Returns:
            True if sample count >= min_samples and ambiguity ratio > threshold.
        """
        if len(self._window) < self.min_samples:
            return False
        return self.get_ambiguity_ratio() > self.threshold

    def get_status(self) -> DriftStatus:
        """Retrieve complete structural telemetry for supervisory dashboards.

        Returns:
            DriftStatus snapshot.
        """
        total = len(self._window)
        ambiguous = sum(1 for v in self._window if v == Verdict.AMBIGUOUS)
        ratio = self.get_ambiguity_ratio()
        drift = self.is_drift_detected()

        return DriftStatus(
            is_drift_detected=drift,
            ambiguity_ratio=ratio,
            total_samples=total,
            ambiguous_samples=ambiguous,
            threshold=self.threshold,
        )

    def reset(self) -> None:
        """Purge internal history (e.g., following model retraining and redeployment)."""
        self._window.clear()
